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
//! - 上游连接通过 `hyper_util` 连接池复用（HTTP 场景）；CONNECT 隧道则每次
//!   现连，因为隧道生命周期与客户端绑定。
//! - 所有上游建连都走 [`DnsCache`]，结合连接池可显著降低 syscall/端口压力。
//! - 内存有界：响应体流式转发，大请求体流式上传（见 [`crate::body`]），每条
//!   连接的读写缓冲上限为 [`MAX_BUF_SIZE`]，空闲 / 慢速客户端连接按
//!   `client_idle_timeout_secs` 回收；单个请求的内存占用与 body 大小无关。
//! - 通过流式拷贝与计数器包装记录上下行字节。

use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::Bytes;
use http_body_util::BodyExt;
use hyper::body::Incoming;
use hyper::http::uri::Authority;
use hyper::server::conn::http1 as server_http1;
use hyper::service::service_fn;
use hyper::{header, HeaderMap, Method, Request, Response, StatusCode, Uri};
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::Client;
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::OwnedSemaphorePermit;
use tracing::{debug, warn};
use uuid::Uuid;

use crate::body::{
    buffer_or_stream, full, idle_timeout, Activity, BoxError, ProxyBody, RequestBody, ResponseBody,
};
use crate::config::UpstreamConfig;
use crate::dns::DnsCache;
use crate::logger::{LogEntry, LogSink};
use crate::metrics::Metrics;
use crate::security::{self, SafeResolver, SecurityError, SecurityPolicy};

/// 复用的 hyper HTTP/1 上游客户端类型别名。请求体为缓冲或流式的 [`ProxyBody`]。
pub type HttpClient = Client<HttpConnector<SafeResolver>, ProxyBody>;

/// 单条连接（客户端侧与上游侧）的读写缓冲上限，也是请求头 / 响应头的大小上限。
///
/// hyper 默认约 400 KiB：几千条连接各自涨到上限时，小内存机器会被耗尽。
/// 64 KiB 足够容纳正常的头部，同时让流式转发时每条连接的缓冲保持在几十 KiB。
pub const MAX_BUF_SIZE: usize = 64 * 1024;

/// 代理处理上下文，所有请求处理函数共享同一份只读引用。
#[derive(Clone)]
pub struct ProxyContext {
    pub metrics: Arc<Metrics>,
    pub dns: Arc<DnsCache>,
    pub log: LogSink,
    pub upstream: UpstreamConfig,
    /// 目标地址安全策略（SSRF / 端口 / 域名黑白名单）。
    pub security: Arc<SecurityPolicy>,
    /// 上游 IO 空闲超时（请求体上传、等待响应头、响应体下载、CONNECT 隧道）。
    pub io_timeout: Duration,
    /// 客户端连接等待完整请求头的时限（含 keep-alive 空闲期）；`None` 表示不限制。
    pub client_idle_timeout: Option<Duration>,
    /// 请求体整体缓冲的上限，超过则流式转发。
    pub max_buffered_body: usize,
    /// 复用 keep-alive 的 HTTP/1 上游客户端；自带连接池。
    pub http_client: HttpClient,
}

/// 按配置构造一个带连接池、SO_NODELAY、建连超时的 HTTP/1 客户端。
///
/// 池由 `pool_max_idle_per_host` / `pool_idle_timeout_secs` 控制；
/// 通过对相同上游目标的 keep-alive 复用，显著减少 TCP 建连与本机
/// 出向端口消耗（避免高并发下 `EADDRNOTAVAIL`）。
pub fn build_http_client(
    cfg: &UpstreamConfig,
    dns: Arc<DnsCache>,
    security: Arc<SecurityPolicy>,
) -> HttpClient {
    // 用自定义解析器替换默认 getaddrinfo：复用 DnsCache，并在建连前按
    // 安全策略过滤私网/保留地址（防 DNS rebinding 绕过）。
    let mut connector = HttpConnector::new_with_resolver(SafeResolver::new(dns, security));
    connector.set_nodelay(true);
    connector.set_connect_timeout(Some(Duration::from_secs(cfg.connect_timeout_secs)));
    connector.enforce_http(true); // 仅 HTTP（HTTPS 走 CONNECT 隧道路径）。

    Client::builder(TokioExecutor::new())
        .pool_idle_timeout(Duration::from_secs(cfg.pool_idle_timeout_secs))
        .pool_max_idle_per_host(cfg.pool_max_idle_per_host)
        // 没有 timer 时 hyper-util 不会启动空闲连接回收任务，pool_idle_timeout
        // 只在复用时才检查，长期不再访问的上游连接会一直占着内存与 fd。
        .pool_timer(TokioTimer::new())
        .http1_max_buf_size(MAX_BUF_SIZE)
        .build::<_, ProxyBody>(connector)
}

/// 一条客户端连接的生命周期守卫：创建时计入 `proxy_active_connections`，
/// 释放时扣除，并归还 `server.max_connections` 名额。
///
/// CONNECT 升级后 hyper 的连接 future 就结束了，隧道在独立 task 中继续运行，
/// 所以守卫要一路传进隧道 task：连接与隧道都结束才释放。否则隧道既不计入
/// 活跃连接数，也不受并发连接上限约束。
pub struct ConnGuard {
    metrics: Arc<Metrics>,
    _permit: Option<OwnedSemaphorePermit>,
}

impl ConnGuard {
    fn new(metrics: Arc<Metrics>, permit: Option<OwnedSemaphorePermit>) -> Self {
        metrics.active_connections.inc();
        Self {
            metrics,
            _permit: permit,
        }
    }
}

impl Drop for ConnGuard {
    fn drop(&mut self) {
        self.metrics.active_connections.dec();
    }
}

/// 进程正在退出。运行时销毁时会直接丢弃进行中的请求，这些请求不应被记成
/// 客户端断开或响应体未送达。
static SHUTTING_DOWN: AtomicBool = AtomicBool::new(false);

/// 收到退出信号后调用：之后被运行时丢弃的请求不再补记失败计数与日志。
pub fn begin_shutdown() {
    SHUTTING_DOWN.store(true, Ordering::Relaxed);
}

fn shutting_down() -> bool {
    SHUTTING_DOWN.load(Ordering::Relaxed)
}

/// 客户端在代理给出响应前断开时的失败原因标签。
const CLIENT_CLOSED: &str = "client_closed";

/// 一个请求从受理到代理给出响应之间的记账上下文。
///
/// 请求通常以响应结束：成功时访问日志在响应体传完（HTTP）或隧道结束（CONNECT）
/// 时记录，失败时由 [`PendingRequest::fail`] 计数并上报 WARN 事件。客户端在代理
/// 给出响应前断开时（典型是客户端自己的超时早于上游响应，如 Go
/// `http.Client.Timeout`），hyper 会直接丢弃请求处理的 future，返回路径上的
/// 计数与日志都不会执行；这时由 Drop 记为 `reason=client_closed`。
struct PendingRequest {
    ctx: Arc<ProxyContext>,
    peer: SocketAddr,
    started: Instant,
    method: Method,
    /// 目标 `host:port`，解析出来之后才有。
    host: Option<String>,
    /// 已知的 trace_id：先取请求头，HTTP 读完请求体后换成最终值（含 `dis_order_no`）。
    trace_id: Option<String>,
    /// 代理已给出响应，Drop 时不再补记。
    responded: bool,
}

impl PendingRequest {
    fn new(
        ctx: &Arc<ProxyContext>,
        peer: SocketAddr,
        started: Instant,
        req: &Request<Incoming>,
    ) -> Self {
        Self {
            ctx: ctx.clone(),
            peer,
            started,
            method: req.method().clone(),
            host: None,
            trace_id: trace_id_from_headers(req.headers()),
            responded: false,
        }
    }

    fn host_label(&self) -> &str {
        self.host.as_deref().unwrap_or("unknown")
    }

    fn mark_responded(&mut self) {
        self.responded = true;
    }

    /// 失败计数与按 host 耗时（status=error）；HTTP 另计入全局耗时直方图，
    /// 与成功路径口径一致。
    fn record_failure(&self, reason: &str) {
        let elapsed_secs = self.started.elapsed().as_secs_f64();
        let metrics = &self.ctx.metrics;
        metrics.requests_failure.with_label_values(&[reason]).inc();
        if self.method != Method::CONNECT {
            metrics.request_duration.observe(elapsed_secs);
        }
        metrics.observe_by_host(self.host_label(), "error", elapsed_secs);
    }

    /// 以错误响应结束请求：计数、上报 WARN 事件，并构造返回给客户端的响应。
    /// 被安全策略拦截的请求另有 `proxy.blocked` 事件，不走这里。
    fn fail(&mut self, status: StatusCode, reason: &str, msg: String) -> Response<ProxyBody> {
        self.record_failure(reason);
        self.log_failure(Some(status), reason, &msg);
        build_error_response(status, msg)
    }

    /// 上报一条失败的 `proxy.request` / `proxy.connect` 事件（level=WARN）。
    fn log_failure(&mut self, status: Option<StatusCode>, reason: &str, error: &str) {
        let mut fields = serde_json::json!({
            "client": self.peer.to_string(),
            "host": self.host_label(),
            "reason": reason,
            "error": error,
            "duration_ms": self.started.elapsed().as_millis() as u64,
        });
        let event = if self.method == Method::CONNECT {
            "proxy.connect"
        } else {
            fields["method"] = self.method.as_str().into();
            "proxy.request"
        };
        if let Some(status) = status {
            fields["status"] = status.as_u16().into();
        }
        self.ctx.log.emit(LogEntry {
            timestamp: now_rfc3339(),
            trace_id: self
                .trace_id
                .take()
                .unwrap_or_else(|| Uuid::new_v4().to_string()),
            level: "WARN",
            event,
            fields,
        });
    }
}

impl Drop for PendingRequest {
    fn drop(&mut self) {
        if self.responded || shutting_down() {
            return;
        }
        self.record_failure(CLIENT_CLOSED);
        let elapsed_ms = self.started.elapsed().as_millis() as u64;
        warn!(client = %self.peer, host = %self.host_label(), elapsed_ms, "客户端在代理返回响应前断开连接");
        self.log_failure(None, CLIENT_CLOSED, "客户端在代理返回响应前断开连接");
    }
}

/// 入口：在新 task 中托管一条客户端 TCP 连接，处理其上的全部 HTTP 请求。
///
/// 之所以让 `serve_connection` 跑在独立 task：单条 keep-alive 客户端
/// 连接上可能复用多条 HTTP 请求，这里希望与其它连接完全并行。`permit` 是
/// `max_connections` 名额，随 [`ConnGuard`] 在连接（含隧道）结束时归还。
pub async fn handle_client(
    stream: TcpStream,
    peer: SocketAddr,
    ctx: Arc<ProxyContext>,
    permit: Option<OwnedSemaphorePermit>,
) {
    let guard = Arc::new(ConnGuard::new(ctx.metrics.clone(), permit));
    // 关闭 Nagle，减小代理转发的延迟抖动。
    let _ = stream.set_nodelay(true);

    let io = TokioIo::new(stream);
    let service_ctx = ctx.clone();
    let svc = service_fn(move |req| {
        let c = service_ctx.clone();
        let g = guard.clone();
        async move { handle_request(req, peer, c, g).await }
    });

    let mut builder = server_http1::Builder::new();
    builder
        .preserve_header_case(true)
        // hyper 的超时需要 timer；不设置时连默认的 30s 请求头超时也不生效，
        // 空闲 keep-alive 连接与 slowloris 慢速连接会一直占着内存与 fd。
        .timer(TokioTimer::new())
        // 等待完整请求头的时限，覆盖 keep-alive 两次请求之间的空闲期。
        .header_read_timeout(ctx.client_idle_timeout)
        .max_buf_size(MAX_BUF_SIZE);
    // with_upgrades：允许 CONNECT 升级为双向字节流。
    if let Err(e) = builder.serve_connection(io, svc).with_upgrades().await {
        debug!(error = %e, "客户端 HTTP/1 连接异常关闭");
    }
}

/// 处理单个 HTTP 请求；返回值类型固定为 `Response<ProxyBody>` 以适配
/// hyper 的 service 签名（错误类型用 `Infallible`，所有失败都转换为响应）。
async fn handle_request(
    req: Request<Incoming>,
    peer: SocketAddr,
    ctx: Arc<ProxyContext>,
    guard: Arc<ConnGuard>,
) -> Result<Response<ProxyBody>, Infallible> {
    let started = Instant::now();
    ctx.metrics.requests_total.inc();
    // 处理函数完成前客户端断开时，hyper 会丢弃整个 future，由它的 Drop 补记。
    let mut pending = PendingRequest::new(&ctx, peer, started, &req);

    // CONNECT 走隧道分支。
    if req.method() == Method::CONNECT {
        let resp = handle_connect(req, peer, ctx, started, guard, &mut pending).await;
        pending.mark_responded();
        return Ok(resp);
    }

    // 普通 HTTP 转发分支。成功时的耗时、host 维度直方图与访问日志在响应体
    // 传完时由 ResponseBody 回调记录。
    let result = forward_http(req, peer, &ctx, started, &mut pending).await;
    pending.mark_responded();
    Ok(match result {
        Ok(resp) => {
            ctx.metrics
                .requests_success
                .with_label_values(&["http"])
                .inc();
            resp
        }
        // 拦截已记为 proxy.blocked 事件，这里只计数。
        Err(err @ ForwardError::Blocked(_)) => {
            pending.record_failure(err.reason());
            build_error_response(err.status(), err.to_string())
        }
        Err(err) => pending.fail(err.status(), err.reason(), err.to_string()),
    })
}

/// HTTP 转发错误分类，用于在 metrics 标签里区分失败原因。
#[derive(Debug, thiserror::Error)]
enum ForwardError {
    #[error("缺少 host 信息")]
    MissingHost,
    #[error("DNS 解析失败: {0}")]
    Dns(String),
    /// Display 即返回给客户端的文本：只含原因标签，不回显解析出的地址。
    #[error("{}", .0.client_message())]
    Blocked(SecurityError),
    /// 与上游建立 TCP 连接失败（拒绝、端口耗尽、建连超时等）。
    #[error("上游建连失败: {0}")]
    Connect(String),
    #[error("上游请求失败: {0}")]
    Upstream(String),
    #[error("请求体读取失败: {0}")]
    Body(BoxError),
    #[error("处理超时")]
    Timeout,
}

impl ForwardError {
    /// 转化为 Prometheus 标签字符串。
    fn reason(&self) -> &'static str {
        match self {
            ForwardError::MissingHost => "missing_host",
            ForwardError::Dns(_) => "dns",
            ForwardError::Blocked(_) => "blocked",
            ForwardError::Connect(_) => "connect",
            ForwardError::Upstream(_) => "upstream",
            ForwardError::Body(_) => "body",
            ForwardError::Timeout => "timeout",
        }
    }
    /// 转化为 HTTP 状态码（返回给客户端）。
    fn status(&self) -> StatusCode {
        match self {
            ForwardError::MissingHost => StatusCode::BAD_REQUEST,
            ForwardError::Blocked(_) => StatusCode::FORBIDDEN,
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
///
/// 解析出的目标与 trace_id 随时写入 `pending`，供失败计数与日志使用。
async fn forward_http(
    req: Request<Incoming>,
    peer: SocketAddr,
    ctx: &Arc<ProxyContext>,
    started: Instant,
    pending: &mut PendingRequest,
) -> Result<Response<ProxyBody>, ForwardError> {
    // 解析目标 host:port。代理收到的请求通常带绝对 URI；若没有，从 Host 头补齐。
    // 同时校验请求形态：协议白名单、userinfo、重复 Host 头。
    let (raw_host, port) = match extract_host_port(req.uri(), req.headers()) {
        Ok(v) => v,
        Err(e) => {
            if let ForwardError::Blocked(se) = &e {
                // 不记录原始 authority：userinfo 里可能带着凭证。
                record_security_block(ctx, peer, None, se, header_trace_id(req.headers()));
                warn!(client = %peer, reason = se.reason(), error = %se, "HTTP 请求形态被安全策略拒绝");
            }
            return Err(e);
        }
    };

    // 第一层校验：域名格式、端口白名单、IP 字面量、内部域名、域名黑白名单。
    let host = match ctx.security.check_target(&raw_host, port) {
        Ok(host) => host,
        Err(e) => {
            let host_port = format_authority(&raw_host, port);
            record_security_block(
                ctx,
                peer,
                Some(&host_port),
                &e,
                header_trace_id(req.headers()),
            );
            warn!(client = %peer, host = %host_port, reason = e.reason(), error = %e, "HTTP 目标被安全策略拒绝");
            pending.host = Some(host_port);
            return Err(ForwardError::Blocked(e));
        }
    };
    let host_port = format_authority(&host, port);
    pending.host = Some(host_port.clone());

    // 预先解析并校验地址：既能尽早给出 403、顺便预热 DNS 缓存，也让后续
    // hyper 连接池新建连接时命中同一份缓存。真正建连前 SafeResolver 会对
    // 实际使用的地址再校验一次，因此这里与建连之间不存在未校验的解析。
    let addrs = match ctx.dns.lookup_host(&host, port).await {
        Ok(addrs) => addrs,
        Err(e) => {
            warn!(client = %peer, host = %host_port, kind = ?e.kind(), error = %e, "HTTP DNS 解析失败");
            return Err(ForwardError::Dns(e.to_string()));
        }
    };
    if let Err(e) = ctx.security.check_resolved(&host, addrs) {
        record_security_block(
            ctx,
            peer,
            Some(&host_port),
            &e,
            header_trace_id(req.headers()),
        );
        warn!(client = %peer, host = %host_port, reason = e.reason(), error = %e, "HTTP 目标解析到受限地址");
        return Err(ForwardError::Blocked(e));
    }

    // 读取请求体并按优先级生成 trace_id：
    // header `X-PROXY-TRACE-ID` > 请求体 `dis_order_no` > UUID。
    // 只有不超过 max_buffered_body_bytes 的请求体才整体缓冲（用于提取
    // dis_order_no）；更大的请求体流式转发，内存占用与请求体大小无关。
    let (parts, body) = req.into_parts();
    let method_str = parts.method.as_str().to_string();
    let activity = Activity::new(ctx.metrics.bytes_up.clone());
    let buffered = buffer_or_stream(body, ctx.max_buffered_body, &activity);
    let body = match idle_timeout(ctx.io_timeout, &activity, buffered).await {
        None => {
            warn!(client = %peer, host = %host_port, "HTTP 请求体读取超时");
            return Err(ForwardError::Timeout);
        }
        Some(Err(e)) => return Err(ForwardError::Body(e)),
        Some(Ok(body)) => body,
    };
    let (trace_id, upstream_body) = match body {
        RequestBody::Buffered(bytes) => (extract_trace_id(&parts.headers, &bytes), full(bytes)),
        RequestBody::Streaming(body) => (header_trace_id(&parts.headers), body),
    };
    pending.trace_id = Some(trace_id.clone());

    // 构造发往上游的 Request。注意：使用 hyper Client 时 URI 必须是
    // 绝对形式（带 scheme + authority），它内部据此查池/建连。
    let upstream_req =
        build_upstream_request_for_pool(parts, upstream_body, &host_port, &host, port);

    // 发起请求：超过 io_timeout 没有任何数据流动（请求体停止上传，或请求体
    // 发完后上游迟迟不回响应头）即超时。持续上传的大请求体不会被误杀。
    let connect_started = Instant::now();
    let resp = match idle_timeout(
        ctx.io_timeout,
        &activity,
        ctx.http_client.request(upstream_req),
    )
    .await
    {
        None => {
            warn!(client = %peer, host = %host_port, "HTTP 上游请求超时");
            return Err(ForwardError::Timeout);
        }
        Some(Err(e)) => {
            // 预检查之后 DNS 结果发生了变化（缓存恰好过期且被 rebinding 到受限
            // 地址）时，SafeResolver 会在建连前拒绝；还原出安全错误按 403 处理。
            if let Some(se) = security::find_security_error(&e).cloned() {
                record_security_block(ctx, peer, Some(&host_port), &se, trace_id.clone());
                warn!(client = %peer, host = %host_port, reason = se.reason(), error = %se, "HTTP 目标在建连时被安全策略拒绝（DNS 结果已变化）");
                return Err(ForwardError::Blocked(se));
            }
            // legacy::Error 自身的 Display 只有 "client error (Connect)"，根因
            // （拒绝连接、端口耗尽、超时……）在 source 链里，要一起带上。
            let s = error_chain(&e);
            warn!(client = %peer, host = %host_port, error = %s, "HTTP 上游请求失败");
            return Err(if e.is_connect() {
                ForwardError::Connect(s)
            } else {
                ForwardError::Upstream(s)
            });
        }
        Some(Ok(r)) => r,
    };
    ctx.metrics
        .upstream_connect_duration
        .observe(connect_started.elapsed().as_secs_f64());

    // 响应头到达后立即回给客户端，响应体流式转发（不再整体读入内存）。
    // 下行字节随数据流动实时计数；耗时与访问日志在响应体结束时记录，
    // 口径仍是"从受理到响应体传完"。
    let (resp_parts, resp_body) = resp.into_parts();
    let status = resp_parts.status;
    let metrics = ctx.metrics.clone();
    let log = ctx.log.clone();
    let on_finish = move |bytes_down: u64, error: Option<String>| {
        // 进程退出时运行时丢弃的响应不算未送达。
        if error.is_some() && shutting_down() {
            return;
        }
        let elapsed_secs = started.elapsed().as_secs_f64();
        metrics.request_duration.observe(elapsed_secs);
        metrics.observe_by_host(
            &host_port,
            crate::metrics::status_class(status.as_u16()),
            elapsed_secs,
        );
        let mut fields = serde_json::json!({
            "client": peer.to_string(),
            "host": host_port,
            "method": method_str,
            "status": status.as_u16(),
            "bytes_up": activity.bytes(),
            "bytes_down": bytes_down,
        });
        let level = match error {
            // 响应体没有完整传给客户端：上游出错、空闲超时或客户端提前断开。
            Some(err) => {
                fields["error"] = serde_json::Value::String(err);
                "WARN"
            }
            None => "INFO",
        };
        log.emit(LogEntry {
            timestamp: now_rfc3339(),
            trace_id,
            level,
            event: "proxy.request",
            fields,
        });
    };
    let body = ResponseBody::new(
        resp_body,
        ctx.io_timeout,
        ctx.metrics.bytes_down.clone(),
        on_finish,
    )
    .boxed_unsync();

    // 把状态码与响应头转发给客户端，依旧剥 hop-by-hop（含 Transfer-Encoding，
    // 由 hyper 按实际响应体重新决定 Content-Length 或 chunked）。
    let mut builder = Response::builder().status(status);
    for (k, v) in resp_parts.headers.iter() {
        if is_hop_by_hop(k.as_str()) {
            continue;
        }
        builder = builder.header(k, v);
    }
    Ok(builder.body(body).unwrap())
}

/// 处理 CONNECT：回 200 后将客户端与上游做双向透传。
///
/// 解析出的目标写入 `pending`；建隧道失败时经它计数并上报 WARN 事件。
async fn handle_connect(
    req: Request<Incoming>,
    peer: SocketAddr,
    ctx: Arc<ProxyContext>,
    started: Instant,
    guard: Arc<ConnGuard>,
    pending: &mut PendingRequest,
) -> Response<ProxyBody> {
    let authority = match req.uri().authority().cloned() {
        Some(a) => a,
        None => {
            warn!(client = %peer, "CONNECT 缺少 authority");
            return pending.fail(
                StatusCode::BAD_REQUEST,
                "missing_host",
                "CONNECT 缺少 authority".to_string(),
            );
        }
    };
    let raw_host = authority.host().to_string();
    // CONNECT 的 authority 按 RFC 应带端口；缺失时按 HTTPS 默认 443 处理。
    let port = authority.port_u16().unwrap_or(443);

    // 请求形态校验：userinfo 常被用来伪装真实目标（`trusted.com@evil.com`）。
    // 日志与指标只使用 host 部分，避免记录 userinfo 中的凭证。
    if let Err(e) = security::check_no_userinfo(authority.as_str()) {
        let host_port = format_authority(&raw_host, port);
        let trace_id = header_trace_id(req.headers());
        return reject_connect(
            &ctx,
            peer,
            &host_port,
            started,
            &e,
            trace_id,
            "CONNECT 请求形态被安全策略拒绝",
        );
    }

    // 第一层校验：域名格式、端口白名单、IP 字面量、内部域名、域名黑白名单。
    let host = match ctx.security.check_target(&raw_host, port) {
        Ok(host) => host,
        Err(e) => {
            let host_port = format_authority(&raw_host, port);
            let trace_id = header_trace_id(req.headers());
            return reject_connect(
                &ctx,
                peer,
                &host_port,
                started,
                &e,
                trace_id,
                "CONNECT 目标被安全策略拒绝",
            );
        }
    };
    let host_port = format_authority(&host, port);
    pending.host = Some(host_port.clone());

    // 与上游建立 TCP。CONNECT 隧道每次都需要独立连接（端到端 TLS）。
    let addrs = match ctx.dns.lookup_host(&host, port).await {
        Ok(v) => v,
        Err(e) => {
            warn!(client = %peer, host = %host_port, kind = ?e.kind(), error = %e, "CONNECT DNS 解析失败");
            return pending.fail(StatusCode::BAD_GATEWAY, "dns", format!("DNS 失败: {e}"));
        }
    };
    // 第二层校验：解析结果中任一地址受限即拒绝（防 DNS rebinding）。之后只连接
    // 这里校验过的地址，不再做第二次解析。
    let addrs = match ctx.security.check_resolved(&host, addrs) {
        Ok(v) => v,
        Err(e) => {
            let trace_id = header_trace_id(req.headers());
            return reject_connect(
                &ctx,
                peer,
                &host_port,
                started,
                &e,
                trace_id,
                "CONNECT 目标解析到受限地址",
            );
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
            return pending.fail(StatusCode::BAD_GATEWAY, "connect", format!("建连失败: {e}"));
        }
        Err(_) => {
            warn!(client = %peer, host = %host_port, target = %target, timeout_secs = ctx.upstream.connect_timeout_secs, "CONNECT 上游建连超时");
            return pending.fail(
                StatusCode::GATEWAY_TIMEOUT,
                "timeout",
                "建连超时".to_string(),
            );
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
    let trace_id = header_trace_id(req.headers());
    let log_host = host_port.clone();

    // 这里 spawn 一个 task 在 200 响应发送之后接管 upgrade。
    tokio::spawn(async move {
        // 隧道存续期间继续占用连接名额与活跃连接计数。
        let _guard = guard;
        match hyper::upgrade::on(req).await {
            Ok(upgraded) => {
                let mut client_io = TokioIo::new(upgraded);
                let mut upstream_io = upstream;
                let (up, down) = tunnel_copy(&mut client_io, &mut upstream_io, io_timeout).await;
                metrics.bytes_up.inc_by(up);
                metrics.bytes_down.inc_by(down);
                let elapsed_secs = started.elapsed().as_secs_f64();
                // 隧道整体生命周期耗时纳入按 host 视图，status=tunnel。
                metrics.observe_by_host(&log_host, "tunnel", elapsed_secs);
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
        .body(full(Bytes::new()))
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

/// CONNECT 被安全策略拒绝：计数、告警并返回 403。
fn reject_connect(
    ctx: &ProxyContext,
    peer: SocketAddr,
    host_port: &str,
    started: Instant,
    e: &SecurityError,
    trace_id: String,
    msg: &'static str,
) -> Response<ProxyBody> {
    record_security_block(ctx, peer, Some(host_port), e, trace_id);
    ctx.metrics
        .requests_failure
        .with_label_values(&["blocked"])
        .inc();
    ctx.metrics
        .observe_by_host(host_port, "error", started.elapsed().as_secs_f64());
    warn!(client = %peer, host = %host_port, reason = e.reason(), error = %e, "{msg}");
    build_error_response(StatusCode::FORBIDDEN, e.client_message())
}

/// 记录一次安全策略拦截：`proxy_security_blocked_total{reason}` 计数，并发出
/// `proxy.blocked` 访问日志事件，便于在 OpenObserve 中按 client / reason 追查
/// SSRF 尝试。日志保留完整原因（含解析出的地址），客户端只拿到原因标签。
fn record_security_block(
    ctx: &ProxyContext,
    peer: SocketAddr,
    host_port: Option<&str>,
    e: &SecurityError,
    trace_id: String,
) {
    ctx.metrics
        .security_blocked_total
        .with_label_values(&[e.reason()])
        .inc();
    ctx.log.emit(LogEntry {
        timestamp: now_rfc3339(),
        trace_id,
        level: "WARN",
        event: "proxy.blocked",
        fields: serde_json::json!({
            "client": peer.to_string(),
            "host": host_port.unwrap_or("unknown"),
            "reason": e.reason(),
            "error": e.to_string(),
        }),
    });
}

/// 提取 `host:port`，并完成请求形态层面的安全校验。
///
/// - 绝对 URI 只接受 `http`（见 [`security::check_forward_scheme`]）；
/// - 拒绝带 userinfo 的 authority 与 Host 头（RFC 9110 §4.2.4）；
/// - 绝对 URI 优先，忽略 Host 头（RFC 9112 §3.2.2）；origin-form 才从 Host 头
///   取目标，且出现多个 Host 头时直接拒绝（RFC 9112 §3.2），避免不同组件
///   读出不同目标。
///
/// Host 头通过 [`Authority`] 解析，避免手写 `rsplit_once(':')` 在 IPv6
/// 字面量（`[::1]:8080`）上解析错误。
fn extract_host_port(uri: &Uri, headers: &HeaderMap) -> Result<(String, u16), ForwardError> {
    security::check_forward_scheme(uri.scheme_str()).map_err(ForwardError::Blocked)?;

    if let Some(authority) = uri.authority() {
        security::check_no_userinfo(authority.as_str()).map_err(ForwardError::Blocked)?;
        return Ok((
            authority.host().to_string(),
            authority.port_u16().unwrap_or(80),
        ));
    }

    let mut values = headers.get_all(header::HOST).iter();
    let host_header = match (values.next(), values.next()) {
        (None, _) => return Err(ForwardError::MissingHost),
        (Some(_), Some(_)) => {
            return Err(ForwardError::Blocked(SecurityError::InvalidHost(
                "重复的 Host 头".to_string(),
            )))
        }
        (Some(v), None) => v.to_str().map_err(|_| ForwardError::MissingHost)?,
    };
    security::check_no_userinfo(host_header).map_err(ForwardError::Blocked)?;
    if let Ok(authority) = host_header.parse::<Authority>() {
        return Ok((
            authority.host().to_string(),
            authority.port_u16().unwrap_or(80),
        ));
    }
    // 解析失败时先把原始值交给安全策略的格式校验，统一返回 403。
    Ok((host_header.to_string(), 80))
}

/// 格式化 `host:port`，IPv6 自动加方括号（用于日志 / metrics）。
fn format_authority(host: &str, port: u16) -> String {
    if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

/// 格式化 URI 的 authority（80 端口可省略）。
fn format_uri_authority(host: &str, port: u16) -> String {
    if port == 80 {
        if host.contains(':') {
            format!("[{host}]")
        } else {
            host.to_string()
        }
    } else {
        format_authority(host, port)
    }
}

/// 为 hyper Client 重建发往上游的请求。
///
/// `hyper_util::client::legacy::Client` 用 URI 的 scheme+authority 来查
/// 连接池/建连，因此这里必须组装为 **绝对 URI**（`http://host:port/path?q`）。
/// 同时剥掉 hop-by-hop 头，并强制覆盖 Host 头。
fn build_upstream_request_for_pool(
    parts: hyper::http::request::Parts,
    body: ProxyBody,
    host_port: &str,
    host: &str,
    port: u16,
) -> Request<ProxyBody> {
    let path_and_query = parts
        .uri
        .path_and_query()
        .map(|p| p.as_str().to_string())
        .unwrap_or_else(|| "/".to_string());
    // 默认 80 端口在 URI 中可省略；非 80 端口需要显式带上。
    // IPv6 字面量必须使用方括号形式。
    let absolute = format!(
        "http://{}{}",
        format_uri_authority(host, port),
        path_and_query
    );

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
    builder.body(body).unwrap()
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

/// 只看请求头的 trace_id：`X-PROXY-TRACE-ID`，缺失时退化为 UUID。
fn header_trace_id(headers: &HeaderMap) -> String {
    trace_id_from_headers(headers).unwrap_or_else(|| Uuid::new_v4().to_string())
}

/// 试图按优先级生成 trace_id：
///
/// 1. 请求头 `X-PROXY-TRACE-ID`（客户端显式指定）
/// 2. JSON 请求体中的 `dis_order_no` 字段
/// 3. 兜底：随机 UUID v4
fn extract_trace_id(headers: &hyper::HeaderMap, body: &Bytes) -> String {
    trace_id_from_headers(headers)
        .or_else(|| dis_order_no(body))
        .unwrap_or_else(|| Uuid::new_v4().to_string())
}

/// 取 JSON 请求体顶层的非空字符串字段 `dis_order_no`。
///
/// 用只含这一个字段的结构体反序列化：其余字段由 serde 跳过而不分配内存。
/// 原先解析成 `serde_json::Value` 会为整个请求体建一棵 JSON 树，内存是请求体
/// 大小的数倍。
fn dis_order_no(body: &[u8]) -> Option<String> {
    #[derive(serde::Deserialize)]
    struct Probe<'a> {
        #[serde(borrow, default)]
        dis_order_no: Option<std::borrow::Cow<'a, str>>,
    }
    // 只认 JSON 对象：结构体反序列化也接受数组（按位置取字段），与原先
    // `Value::get` 只看对象键的语义不同。
    if body.iter().find(|b| !b.is_ascii_whitespace()) != Some(&b'{') {
        return None;
    }
    let probe: Probe = serde_json::from_slice(body).ok()?;
    probe
        .dis_order_no
        .filter(|s| !s.is_empty())
        .map(std::borrow::Cow::into_owned)
}

/// 错误及其完整 source 链，形如 `client error (Connect): tcp connect error: Connection refused`。
fn error_chain(e: &(dyn std::error::Error + 'static)) -> String {
    let mut s = e.to_string();
    let mut source = e.source();
    while let Some(cause) = source {
        s.push_str(": ");
        s.push_str(&cause.to_string());
        source = cause.source();
    }
    s
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
fn build_error_response<S: Into<String>>(status: StatusCode, msg: S) -> Response<ProxyBody> {
    Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "text/plain; charset=utf-8")
        .body(full(msg.into()))
        .unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn uri(s: &str) -> Uri {
        s.parse().unwrap()
    }

    fn hosts(values: &[&str]) -> HeaderMap {
        let mut h = HeaderMap::new();
        for v in values {
            h.append(header::HOST, v.parse().unwrap());
        }
        h
    }

    fn blocked_reason(r: Result<(String, u16), ForwardError>) -> Option<&'static str> {
        match r {
            Err(ForwardError::Blocked(e)) => Some(e.reason()),
            _ => None,
        }
    }

    #[test]
    fn extracts_target_from_absolute_uri() {
        let none = HeaderMap::new();
        assert_eq!(
            extract_host_port(&uri("http://example.com/a?b"), &none).unwrap(),
            ("example.com".to_string(), 80)
        );
        assert_eq!(
            extract_host_port(&uri("HTTP://example.com:8080/"), &none).unwrap(),
            ("example.com".to_string(), 8080)
        );
        // 绝对 URI 优先，Host 头被忽略（RFC 9112 §3.2.2）。
        assert_eq!(
            extract_host_port(&uri("http://example.com/"), &hosts(&["10.0.0.1"])).unwrap(),
            ("example.com".to_string(), 80)
        );
    }

    #[test]
    fn rejects_unsupported_schemes() {
        let none = HeaderMap::new();
        for s in [
            "https://example.com/",
            "ftp://example.com/",
            "gopher://example.com:70/_x",
            "file://example.com/etc/passwd",
        ] {
            assert_eq!(
                blocked_reason(extract_host_port(&uri(s), &none)),
                Some("scheme"),
                "{s}"
            );
        }
    }

    #[test]
    fn rejects_userinfo() {
        let none = HeaderMap::new();
        for s in [
            "http://user:pass@example.com/",
            "http://example.com@127.0.0.1/",
        ] {
            assert_eq!(
                blocked_reason(extract_host_port(&uri(s), &none)),
                Some("userinfo"),
                "{s}"
            );
        }
        assert_eq!(
            blocked_reason(extract_host_port(
                &uri("/"),
                &hosts(&["example.com@10.0.0.1"])
            )),
            Some("userinfo")
        );
    }

    #[test]
    fn origin_form_requires_single_host_header() {
        assert_eq!(
            extract_host_port(&uri("/path"), &hosts(&["Example.com:8080"])).unwrap(),
            ("Example.com".to_string(), 8080)
        );
        assert_eq!(
            blocked_reason(extract_host_port(
                &uri("/"),
                &hosts(&["a.example.com", "b.example.com"])
            )),
            Some("invalid_host")
        );
        assert!(matches!(
            extract_host_port(&uri("/"), &HeaderMap::new()),
            Err(ForwardError::MissingHost)
        ));
    }

    #[test]
    fn extracts_dis_order_no_from_json_body() {
        let none = HeaderMap::new();
        let trace = |body: &str| extract_trace_id(&none, &Bytes::from(body.to_string()));
        assert_eq!(
            trace(r#"{"amount":1,"dis_order_no":"DO123","items":[1,{"x":"y"}]}"#),
            "DO123"
        );
        // 前导空白与 JSON 转义。
        assert_eq!(trace("  \n{\"dis_order_no\":\"A\\u0042C\"}"), "ABC");
        // 以下情况退化为 UUID（与原先基于 serde_json::Value 的行为一致）。
        for body in [
            r#"{"dis_order_no":""}"#,
            r#"{"dis_order_no":123}"#,
            r#"{"dis_order_no":null}"#,
            r#"{"other":"x"}"#,
            r#"["DO123"]"#,
            "not json",
            "",
        ] {
            assert_eq!(trace(body).len(), 36, "{body:?} 应退化为 UUID");
        }
        // 请求头优先。
        let mut headers = HeaderMap::new();
        headers.insert(TRACE_ID_HEADER, "from-header".parse().unwrap());
        assert_eq!(
            extract_trace_id(&headers, &Bytes::from(r#"{"dis_order_no":"DO123"}"#)),
            "from-header"
        );
    }

    #[test]
    fn blocked_response_does_not_echo_resolved_address() {
        let e = ForwardError::Blocked(SecurityError::PrivateAddress("10.1.2.3".parse().unwrap()));
        assert_eq!(e.status(), StatusCode::FORBIDDEN);
        assert!(!e.to_string().contains("10.1.2.3"));
        assert!(e.to_string().contains("private_ip"));
    }
}
