//! `/metrics` HTTP 端点。
//!
//! 用最小的 `hyper` 服务实现，避免引入额外 web 框架。仅响应 `GET /metrics`，
//! 其余路径返回 404，未授权或非 GET 一律 405。

use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;

use bytes::Bytes;
use http_body_util::Full;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use tokio::net::TcpListener;
use tracing::{info, warn};

use crate::metrics::Metrics;

/// 启动指标 HTTP 服务。永不返回（直到外部取消 task）。
pub async fn serve(addr: SocketAddr, metrics: Arc<Metrics>) -> anyhow::Result<()> {
    let listener = TcpListener::bind(addr).await?;
    info!(%addr, "Prometheus /metrics 已就绪");
    loop {
        let (stream, _peer) = listener.accept().await?;
        let metrics = metrics.clone();
        let svc = service_fn(move |req| {
            let m = metrics.clone();
            async move { handle(req, m).await }
        });
        tokio::spawn(async move {
            if let Err(e) = http1::Builder::new()
                .serve_connection(TokioIo::new(stream), svc)
                .await
            {
                warn!(error = %e, "metrics 连接异常");
            }
        });
    }
}

/// 单请求处理函数。
async fn handle(
    req: Request<hyper::body::Incoming>,
    metrics: Arc<Metrics>,
) -> Result<Response<Full<Bytes>>, Infallible> {
    if req.method() != Method::GET {
        return Ok(empty(StatusCode::METHOD_NOT_ALLOWED));
    }
    if req.uri().path() != "/metrics" {
        return Ok(empty(StatusCode::NOT_FOUND));
    }
    let body = metrics.render();
    Ok(Response::builder()
        .status(StatusCode::OK)
        .header("Content-Type", "text/plain; version=0.0.4")
        .body(Full::new(Bytes::from(body)))
        .unwrap())
}

/// 空响应快捷构造。
fn empty(status: StatusCode) -> Response<Full<Bytes>> {
    Response::builder()
        .status(status)
        .body(Full::new(Bytes::new()))
        .unwrap()
}
