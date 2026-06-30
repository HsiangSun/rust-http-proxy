//! HTTP / HTTPS 正向代理核心。
//!
//! 处理两种请求模式：
//!
//! 1. **普通 HTTP**：客户端发送带绝对 URI 的请求，例如
//!    `GET http://example.com/foo HTTP/1.1`。代理解析 host 后建立到上游
//!    的 TCP 连接，剥掉 hop-by-hop 头部后转发请求与响应。
//!
//! 2. **HTTPS CONNECT 隧道**：客户端先发 `CONNECT host:443 HTTP/1.1`，
//!    代理建立到上游的 TCP 连接，回复 200 后将客户端 socket 与上游
//!    socket 做全双工字节透传，让 TLS 握手与数据流端到端进行。
//!
//! 关键设计：
//! - 上游连接通过 [`UpstreamPool`] 复用（HTTP 场景）；CONNECT 隧道则每次
//!   现连，因为隧道生命周期与客户端绑定。
//! - 所有上游建连都走 [`DnsCache`]，结合连接池可显著降低 syscall/端口压力。
//! - 通过流式拷贝（`tokio::io::copy_bidirectional` + 计数器包装）记录上下行字节。

use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::server::conn::http1 as server_http1;
use hyper::service::service_fn;
use hyper::{header, Method, Request, Response, StatusCode, Uri};
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::Client;
use hyper_util::rt::{TokioExecutor, TokioIo};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tracing::{debug, warn};
use uuid::Uuid;

use crate::config::UpstreamConfig;
use crate::dns::DnsCache;
use crate::logger::{LogEntry, LogSink};
use crate::metrics::Metrics;

/// 复用的 hyper HTTP/1 上游客户端类型别名。请求体使用 `Full<Bytes>`。
pub type HttpClient = Client<HttpConnector, Full<Bytes>>;

/// 代理处理上下文，所有请求处理函数共享同一份只读引用。
#[derive(Clone)]
pub struct ProxyContext {
    pub metrics: Arc<Metrics>,
    pub dns: Arc<DnsCache>,
    pub log: LogSink,
    pub upstream: UpstreamConfig,
    pub io_timeout: Duration,
    /// 复用 keep-alive 的 HTTP/1 上游客户端；自带连接池。
    pub http_client: HttpClient,
}

/// 按配置构造一个带连接池、SO_NODELAY、建连超时的 HTTP/1 客户端。
///
/// 池由 `pool_max_idle_per_host` / `pool_idle_timeout_secs` 控制；
/// 通过对相同上游目标的 keep-alive 复用，显著减少 TCP 建连与本机
/// 出向端口消耗（避免高并发下 `EADDRNOTAVAIL`）。
pub fn build_http_client(cfg: &UpstreamConfig) -> HttpClient {
    let mut connector = HttpConnector::new();
    connector.set_nodelay(true);
    connector.set_connect_timeout(Some(Duration::from_secs(cfg.connect_timeout_secs)));
    connector.enforce_http(true); // 仅 HTTP（HTTPS 走 CONNECT 隧道路径）。

    Client::builder(TokioExecutor::new())
        .pool_idle_timeout(Duration::from_secs(cfg.pool_idle_timeout_secs))
        .pool_max_idle_per_host(cfg.pool_max_idle_per_host)
        .build::<_, Full<Bytes>>(connector)
}

/// 入口：在新 task 中托管一条客户端 TCP 连接，处理其上的全部 HTTP 请求。
///
/// 之所以让 `serve_connection` 跑在独立 task：单条 keep-alive 客户端
/// 连接上可能复用多条 HTTP 请求，这里希望与其它连接完全并行。
pub async fn handle_client(stream: TcpStream, peer: SocketAddr, ctx: Arc<ProxyContext>) {
    ctx.metrics.active_connections.inc();
    // 关闭 Nagle，减小代理转发的延迟抖动。
    let _ = stream.set_nodelay(true);

    let io = TokioIo::new(stream);
    let service_ctx = ctx.clone();
    let svc = service_fn(move |req| {
        let c = service_ctx.clone();
        async move { handle_request(req, peer, c).await }
    });

    if let Err(e) = server_http1::Builder::new()
        // 允许 CONNECT 升级为半双工流。
        .preserve_header_case(true)
        .serve_connection(io, svc)
        .with_upgrades()
        .await
    {
        debug!(error = %e, "客户端 HTTP/1 连接异常关闭");
    }
    ctx.metrics.active_connections.dec();
}

/// 处理单个 HTTP 请求；返回值类型固定为 `Response<Full<Bytes>>` 以适配
/// hyper 的 service 签名（错误类型用 `Infallible`，所有失败都转换为响应）。
async fn handle_request(
    req: Request<Incoming>,
    peer: SocketAddr,
    ctx: Arc<ProxyContext>,
) -> Result<Response<Full<Bytes>>, Infallible> {
    let started = Instant::now();
    ctx.metrics.requests_total.inc();

    // CONNECT 走隧道分支。
    if req.method() == Method::CONNECT {
        return Ok(handle_connect(req, peer, ctx, started).await);
    }

    // 普通 HTTP 转发分支。
    let elapsed_secs;
    match forward_http(req, peer, &ctx).await {
        Ok((resp, host_port, status_code)) => {
            elapsed_secs = started.elapsed().as_secs_f64();
            ctx.metrics
                .requests_success
                .with_label_values(&["http"])
                .inc();
            ctx.metrics.request_duration.observe(elapsed_secs);
            // host 维度耗时：用真实上游响应码的 status class。
            ctx.metrics
                .request_duration_by_host
                .with_label_values(&[&host_port, crate::metrics::status_class(status_code)])
                .observe(elapsed_secs);
            Ok(resp)
        }
        Err((err, host_port_opt)) => {
            elapsed_secs = started.elapsed().as_secs_f64();
            ctx.metrics
                .requests_failure
                .with_label_values(&[err.reason()])
                .inc();
            ctx.metrics.request_duration.observe(elapsed_secs);
            // 失败也按 host 计入耗时，host 未知则用 "unknown"，status=error。
            let host_label = host_port_opt.as_deref().unwrap_or("unknown");
            ctx.metrics
                .request_duration_by_host
                .with_label_values(&[host_label, "error"])
                .observe(elapsed_secs);
            Ok(build_error_response(err.status(), err.to_string()))
        }
    }
}

/// HTTP 转发错误分类，用于在 metrics 标签里区分失败原因。
#[derive(Debug, thiserror::Error)]
enum ForwardError {
    #[error("缺少 host 信息")]
    MissingHost,
    #[error("上游请求失败: {0}")]
    Upstream(String),
    #[error("请求体读取失败: {0}")]
    Body(hyper::Error),
    #[error("处理超时")]
    Timeout,
}

impl ForwardError {
    /// 转化为 Prometheus 标签字符串。
    ///
    /// 对上游错误进一步细分：用 `hyper_util::client::legacy::Error` 的内置
    /// `is_connect()` 把端口耗尽 / SYN 拒绝单独归类，方便和真正的 HTTP 层
    /// 异常区分。
    fn reason(&self) -> &'static str {
        match self {
            ForwardError::MissingHost => "missing_host",
            ForwardError::Upstream(s) => {
                if s.contains("connect") {
                    "connect"
                } else if s.contains("dns") {
                    "dns"
                } else {
                    "upstream"
                }
            }
            ForwardError::Body(_) => "body",
            ForwardError::Timeout => "timeout",
        }
    }
    /// 转化为 HTTP 状态码（返回给客户端）。
    fn status(&self) -> StatusCode {
        match self {
            ForwardError::MissingHost => StatusCode::BAD_REQUEST,
            ForwardError::Timeout => StatusCode::GATEWAY_TIMEOUT,
            _ => StatusCode::BAD_GATEWAY,
        }
    }
}

/// 处理普通 HTTP 请求：复用 `hyper_util` 连接池向上游发起请求。
///
/// 这里 **不再** 自己 `TcpStream::connect` + `handshake`，而是把这一步交给
/// `hyper_util::client::legacy::Client`。它内部维护 per-host keep-alive 池，
/// 大幅减少高并发下的本机出向端口消耗与 SYN 风暴。
async fn forward_http(
    req: Request<Incoming>,
    peer: SocketAddr,
    ctx: &Arc<ProxyContext>,
) -> Result<(Response<Full<Bytes>>, String, u16), (ForwardError, Option<String>)> {
    // 解析目标 host:port。代理收到的请求通常带绝对 URI；若没有，从 Host 头补齐。
    let (host, port) = extract_host_port(&req).map_err(|e| (e, None))?;
    let host_port = format!("{host}:{port}");

    // 收集请求体；按优先级生成 trace_id：
    // header `X-PROXY-TRACE-ID` > 请求体 `dis_order_no` > UUID。
    let (parts, body) = req.into_parts();
    let method_str = parts.method.as_str().to_string();
    let collected = body
        .collect()
        .await
        .map_err(|e| (ForwardError::Body(e), Some(host_port.clone())))?;
    let body_bytes = collected.to_bytes();
    let trace_id = extract_trace_id(&parts.headers, &body_bytes);

    // 构造发往上游的 Request。注意：使用 hyper Client 时 URI 必须是
    // 绝对形式（带 scheme + authority），它内部据此查池/建连。
    let upstream_req =
        build_upstream_request_for_pool(parts, body_bytes.clone(), &host_port, &host, port);
    ctx.metrics.bytes_up.inc_by(body_bytes.len() as u64);

    // 发起请求，附整体超时。
    let connect_started = Instant::now();
    let resp =
        match tokio::time::timeout(ctx.io_timeout, ctx.http_client.request(upstream_req)).await {
            Err(_) => {
                warn!(client = %peer, host = %host_port, "HTTP 上游请求超时");
                return Err((ForwardError::Timeout, Some(host_port)));
            }
            Ok(Err(e)) => {
                // hyper_util legacy::Error 的 Display 通常会带 "client error (Connect)" 字样，
                // 我们据此把 connect 失败单独归类，并打详细原因。
                let s = format!("{e}");
                warn!(client = %peer, host = %host_port, error = %s, "HTTP 上游请求失败");
                return Err((ForwardError::Upstream(s), Some(host_port)));
            }
            Ok(Ok(r)) => r,
        };
    ctx.metrics
        .upstream_connect_duration
        .observe(connect_started.elapsed().as_secs_f64());

    // 读取响应体并下行回客户端。
    let (resp_parts, resp_body) = resp.into_parts();
    let status_code = resp_parts.status.as_u16();
    let resp_bytes = match resp_body.collect().await {
        Ok(c) => c.to_bytes(),
        Err(e) => {
            warn!(client = %peer, host = %host_port, error = %e, "HTTP 响应体读取失败");
            return Err((ForwardError::Upstream(e.to_string()), Some(host_port)));
        }
    };
    ctx.metrics.bytes_down.inc_by(resp_bytes.len() as u64);

    // 异步上报访问日志。
    ctx.log.emit(LogEntry {
        timestamp: now_rfc3339(),
        trace_id,
        level: "INFO",
        event: "proxy.request",
        fields: serde_json::json!({
            "client": peer.to_string(),
            "host": host_port,
            "method": method_str,
            "status": resp_parts.status.as_u16(),
            "bytes_up": body_bytes.len(),
            "bytes_down": resp_bytes.len(),
        }),
    });

    // 把状态码与响应头转发给客户端，依旧剥 hop-by-hop。
    let mut builder = Response::builder().status(resp_parts.status);
    for (k, v) in resp_parts.headers.iter() {
        if is_hop_by_hop(k.as_str()) {
            continue;
        }
        builder = builder.header(k, v);
    }
    // 由于我们已经把响应体读完并通过 Content-Length 暗示长度，移除
    // Transfer-Encoding 可避免与下游协议冲突。
    Ok((
        builder.body(Full::new(resp_bytes)).unwrap(),
        host_port,
        status_code,
    ))
}

/// 处理 CONNECT：回 200 后将客户端与上游做双向透传。
async fn handle_connect(
    req: Request<Incoming>,
    peer: SocketAddr,
    ctx: Arc<ProxyContext>,
    started: Instant,
) -> Response<Full<Bytes>> {
    let authority = match req.uri().authority().cloned() {
        Some(a) => a,
        None => {
            warn!(client = %peer, "CONNECT 缺少 authority");
            ctx.metrics
                .requests_failure
                .with_label_values(&["missing_host"])
                .inc();
            ctx.metrics
                .request_duration_by_host
                .with_label_values(&["unknown", "error"])
                .observe(started.elapsed().as_secs_f64());
            return build_error_response(StatusCode::BAD_REQUEST, "CONNECT 缺少 authority");
        }
    };
    let host_port = authority.to_string();

    // 与上游建立 TCP。CONNECT 隧道每次都需要独立连接（端到端 TLS）。
    let addrs = match ctx.dns.lookup(&host_port).await {
        Ok(v) => v,
        Err(e) => {
            warn!(client = %peer, host = %host_port, kind = ?e.kind(), error = %e, "CONNECT DNS 解析失败");
            ctx.metrics
                .requests_failure
                .with_label_values(&["dns"])
                .inc();
            ctx.metrics
                .request_duration_by_host
                .with_label_values(&[&host_port, "error"])
                .observe(started.elapsed().as_secs_f64());
            return build_error_response(StatusCode::BAD_GATEWAY, format!("DNS 失败: {e}"));
        }
    };
    let target = addrs[0];

    let connect_started = Instant::now();
    let upstream = match tokio::time::timeout(
        Duration::from_secs(ctx.upstream.connect_timeout_secs),
        TcpStream::connect(target),
    )
    .await
    {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => {
            warn!(client = %peer, host = %host_port, target = %target, kind = ?e.kind(), error = %e, "CONNECT 上游建连失败");
            ctx.metrics
                .requests_failure
                .with_label_values(&["connect"])
                .inc();
            ctx.metrics
                .request_duration_by_host
                .with_label_values(&[&host_port, "error"])
                .observe(started.elapsed().as_secs_f64());
            return build_error_response(StatusCode::BAD_GATEWAY, format!("建连失败: {e}"));
        }
        Err(_) => {
            warn!(client = %peer, host = %host_port, target = %target, timeout_secs = ctx.upstream.connect_timeout_secs, "CONNECT 上游建连超时");
            ctx.metrics
                .requests_failure
                .with_label_values(&["timeout"])
                .inc();
            ctx.metrics
                .request_duration_by_host
                .with_label_values(&[&host_port, "error"])
                .observe(started.elapsed().as_secs_f64());
            return build_error_response(StatusCode::GATEWAY_TIMEOUT, "建连超时");
        }
    };
    let _ = upstream.set_nodelay(true);
    ctx.metrics
        .upstream_connect_duration
        .observe(connect_started.elapsed().as_secs_f64());

    ctx.metrics.https_tunnels_total.inc();
    ctx.metrics
        .requests_success
        .with_label_values(&["https"])
        .inc();

    let metrics = ctx.metrics.clone();
    let log = ctx.log.clone();
    let io_timeout = ctx.io_timeout;
    // CONNECT 隧道下请求体端到端加密，代理不可见；trace_id 只能来自
    // 客户端显式设置的 X-PROXY-TRACE-ID 头，否则退化为 UUID。
    let trace_id =
        trace_id_from_headers(req.headers()).unwrap_or_else(|| Uuid::new_v4().to_string());
    let log_host = host_port.clone();

    // 这里 spawn 一个 task 在 200 响应发送之后接管 upgrade。
    tokio::spawn(async move {
        match hyper::upgrade::on(req).await {
            Ok(upgraded) => {
                let mut client_io = TokioIo::new(upgraded);
                let mut upstream_io = upstream;
                let (up, down) = tunnel_copy(&mut client_io, &mut upstream_io, io_timeout).await;
                metrics.bytes_up.inc_by(up);
                metrics.bytes_down.inc_by(down);
                let elapsed_secs = started.elapsed().as_secs_f64();
                // 隧道整体生命周期耗时纳入按 host 视图，status=tunnel。
                metrics
                    .request_duration_by_host
                    .with_label_values(&[&log_host, "tunnel"])
                    .observe(elapsed_secs);
                log.emit(LogEntry {
                    timestamp: now_rfc3339(),
                    trace_id,
                    level: "INFO",
                    event: "proxy.connect",
                    fields: serde_json::json!({
                        "client": peer.to_string(),
                        "host": log_host,
                        "bytes_up": up,
                        "bytes_down": down,
                        "duration_ms": (elapsed_secs * 1000.0) as u64,
                    }),
                });
            }
            Err(e) => debug!(error = %e, "CONNECT upgrade 失败"),
        }
    });

    // 立即返回 200，让客户端开始 TLS 握手。
    Response::builder()
        .status(StatusCode::OK)
        .body(Full::new(Bytes::new()))
        .unwrap()
}

/// 双向流式透传，返回 (上行字节数, 下行字节数)。
///
/// 使用裸 `read/write` 循环而非 `copy_bidirectional`，是因为需要分开统计
/// 上下行字节并能对总体施加 IO 超时。
async fn tunnel_copy<C, U>(client: &mut C, upstream: &mut U, io_timeout: Duration) -> (u64, u64)
where
    C: AsyncReadExt + AsyncWriteExt + Unpin,
    U: AsyncReadExt + AsyncWriteExt + Unpin,
{
    let mut up_bytes = 0u64;
    let mut down_bytes = 0u64;
    let mut buf_c = vec![0u8; 16 * 1024];
    let mut buf_u = vec![0u8; 16 * 1024];

    loop {
        let read_c = tokio::time::timeout(io_timeout, client.read(&mut buf_c));
        let read_u = tokio::time::timeout(io_timeout, upstream.read(&mut buf_u));
        tokio::select! {
            res = read_c => {
                match res {
                    Ok(Ok(0)) => break,                  // client EOF
                    Ok(Ok(n)) => {
                        if upstream.write_all(&buf_c[..n]).await.is_err() { break; }
                        up_bytes += n as u64;
                    }
                    _ => break,                          // 读错或超时
                }
            }
            res = read_u => {
                match res {
                    Ok(Ok(0)) => break,                  // upstream EOF
                    Ok(Ok(n)) => {
                        if client.write_all(&buf_u[..n]).await.is_err() { break; }
                        down_bytes += n as u64;
                    }
                    _ => break,
                }
            }
        }
    }
    let _ = client.shutdown().await;
    let _ = upstream.shutdown().await;
    (up_bytes, down_bytes)
}

/// 提取 `host:port`。优先用 URI authority，其次用 Host 头。
fn extract_host_port(req: &Request<Incoming>) -> Result<(String, u16), ForwardError> {
    if let Some(authority) = req.uri().authority().cloned() {
        let host = authority.host().to_string();
        let port = authority
            .port_u16()
            .unwrap_or_else(|| default_port(req.uri()));
        return Ok((host, port));
    }
    if let Some(host_header) = req
        .headers()
        .get(header::HOST)
        .and_then(|v| v.to_str().ok())
    {
        if let Some((host, port)) = host_header.rsplit_once(':') {
            if let Ok(p) = port.parse::<u16>() {
                return Ok((host.to_string(), p));
            }
        }
        return Ok((host_header.to_string(), default_port(req.uri())));
    }
    Err(ForwardError::MissingHost)
}

/// HTTP 默认端口推断。
fn default_port(uri: &Uri) -> u16 {
    match uri.scheme_str() {
        Some("https") => 443,
        _ => 80,
    }
}

/// 为 hyper Client 重建发往上游的请求。
///
/// `hyper_util::client::legacy::Client` 用 URI 的 scheme+authority 来查
/// 连接池/建连，因此这里必须组装为 **绝对 URI**（`http://host:port/path?q`）。
/// 同时剥掉 hop-by-hop 头，并强制覆盖 Host 头。
fn build_upstream_request_for_pool(
    parts: hyper::http::request::Parts,
    body: Bytes,
    host_port: &str,
    host: &str,
    port: u16,
) -> Request<Full<Bytes>> {
    let path_and_query = parts
        .uri
        .path_and_query()
        .map(|p| p.as_str().to_string())
        .unwrap_or_else(|| "/".to_string());
    // 默认 80 端口在 URI 中可省略；非 80 端口需要显式带上。
    let absolute = if port == 80 {
        format!("http://{host}{path_and_query}")
    } else {
        format!("http://{host}:{port}{path_and_query}")
    };

    let mut builder = Request::builder()
        .method(parts.method.clone())
        .uri(absolute);
    for (k, v) in parts.headers.iter() {
        if is_hop_by_hop(k.as_str()) || k == header::HOST {
            continue;
        }
        builder = builder.header(k, v);
    }
    builder = builder.header(header::HOST, host_port);
    builder.body(Full::new(body)).unwrap()
}

/// 判断是否为 hop-by-hop 头部（RFC 7230 §6.1）。
///
/// 除标准 hop-by-hop 头外，我们也把代理自有的 `X-PROXY-TRACE-ID`
/// 视为 hop-by-hop，不向上游透传（避免污染上游日志或被上游回显）。
fn is_hop_by_hop(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    matches!(
        n.as_str(),
        "connection"
            | "proxy-connection"
            | "keep-alive"
            | "transfer-encoding"
            | "te"
            | "trailer"
            | "upgrade"
            | "proxy-authorization"
            | "proxy-authenticate"
    ) || n == TRACE_ID_HEADER
}

/// 客户端可显式指定 trace_id 的 HTTP 头名。
///
/// 优先级最高 —— 即使请求体里也有 `dis_order_no`，也以 header 为准。
/// HTTPS CONNECT 隧道由于请求体端到端加密无法窥探，此 header 是唯一
/// 让代理拿到业务 trace_id 的渠道。
const TRACE_ID_HEADER: &str = "x-proxy-trace-id";

/// 从请求头中提取 trace_id；返回非空值即采用。
fn trace_id_from_headers(headers: &hyper::HeaderMap) -> Option<String> {
    headers
        .get(TRACE_ID_HEADER)
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
}

/// 试图按优先级生成 trace_id：
///
/// 1. 请求头 `X-PROXY-TRACE-ID`（客户端显式指定）
/// 2. JSON 请求体中的 `dis_order_no` 字段
/// 3. 兜底：随机 UUID v4
fn extract_trace_id(headers: &hyper::HeaderMap, body: &Bytes) -> String {
    if let Some(v) = trace_id_from_headers(headers) {
        return v;
    }
    if !body.is_empty() {
        if let Ok(v) = serde_json::from_slice::<serde_json::Value>(body) {
            if let Some(s) = v.get("dis_order_no").and_then(|x| x.as_str()) {
                if !s.is_empty() {
                    return s.to_string();
                }
            }
        }
    }
    Uuid::new_v4().to_string()
}

/// 当前时间的 RFC3339 字符串（不引入 chrono，直接用 std + 简单格式化）。
fn now_rfc3339() -> String {
    // 用秒级 unix 时间换算成简易 RFC3339 / ISO 字符串。这里精度到秒即可
    // 满足日志诉求；如需毫秒精度可再升级。
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    let secs = now.as_secs();
    // 借助系统的 `time` crate 可以做时区，但我们这里保持零额外依赖：
    // 输出 epoch 毫秒字符串即可被 OpenObserve 识别。
    let millis = now.subsec_millis();
    format!("{secs}.{millis:03}")
}

/// 构造一个简单的错误响应。
fn build_error_response<S: Into<String>>(status: StatusCode, msg: S) -> Response<Full<Bytes>> {
    Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "text/plain; charset=utf-8")
        .body(Full::new(Bytes::from(msg.into())))
        .unwrap()
}
