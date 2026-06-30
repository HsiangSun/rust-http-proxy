//! OpenObserve 异步日志上报模块。
//!
//! 架构：
//! - 提供 [`LogSink`] 句柄给业务线程，调用 `emit()` 是 **非阻塞** 的：
//!   日志条目通过有界 mpsc 通道交付给后台 task。
//! - 通道写满时丢弃当前条目而不是阻塞代理路径——保护代理性能比保留
//!   单条日志更重要，丢弃行为会被 metrics 显式记录（可后续接入）。
//! - 后台 task 按 `batch_size` 或 `flush_interval_ms` 触发批量 POST，
//!   走 `reqwest` + rustls，对 OpenObserve 的 `_json` 入口提交。
//! - 体面降级：当 `enabled=false` 时构造一个空操作 sink，业务代码完全
//!   无需分支。

use std::time::Duration;

use base64::Engine as _;
use serde::Serialize;
use serde_json::Value;
use tokio::sync::mpsc;
use tokio::time::interval;
use tracing::{info, warn};

use crate::config::OpenObserveConfig;

/// 单条日志条目。所有自定义字段都装在 `fields` 内，便于 OpenObserve
/// 自动展开 JSON 结构。
#[derive(Debug, Clone, Serialize)]
pub struct LogEntry {
    /// 事件时间，RFC3339 字符串。
    pub timestamp: String,
    /// 关联 ID，按需取自请求体的 `dis_order_no`，否则为 uuid v4。
    pub trace_id: String,
    /// 事件等级（INFO/WARN/ERROR）。
    pub level: &'static str,
    /// 事件类别，如 `proxy.request`、`proxy.connect`、`proxy.error`。
    pub event: &'static str,
    /// 任意业务字段，最终被序列化为顶层 JSON 键。
    #[serde(flatten)]
    pub fields: Value,
}

/// LogSink 内部模式。
#[derive(Clone)]
enum Mode {
    /// 走 OpenObserve 异步批量上报。
    Remote(mpsc::Sender<LogEntry>),
    /// OpenObserve 未启用时，回退到 tracing(info!) 打到 console。
    Console,
}

/// 业务侧使用的日志句柄；克隆代价极低（Sender 引用或单字段枚举）。
#[derive(Clone)]
pub struct LogSink {
    mode: Mode,
}

impl LogSink {
    /// 构造一个 console-only 的 sink。访问日志会以 INFO 级别打到 tracing。
    pub fn console() -> Self {
        Self {
            mode: Mode::Console,
        }
    }

    /// 异步上报一条日志。非阻塞：满或关闭时只在 console 留下一条 warn。
    ///
    /// 选择 `try_send` 是为了让代理热路径永远不被日志系统阻塞。
    pub fn emit(&self, entry: LogEntry) {
        match &self.mode {
            Mode::Remote(tx) => {
                if tx.try_send(entry).is_err() {
                    warn!("OpenObserve 日志通道已满或关闭，丢弃一条日志");
                }
            }
            Mode::Console => {
                // 用结构化 tracing 输出，外部可以靠 RUST_LOG 控制。
                info!(
                    trace_id = %entry.trace_id,
                    event = entry.event,
                    level = entry.level,
                    ts = %entry.timestamp,
                    fields = %entry.fields,
                    "access"
                );
            }
        }
    }
}

/// 根据配置启动后台上报 task。
///
/// - 若 `enabled=false`：返回 console sink，访问日志直接打到 tracing。
/// - 若 `enabled=true`：起后台批量上报 task，返回 channel sink。
pub fn spawn(cfg: OpenObserveConfig) -> LogSink {
    if !cfg.enabled {
        info!("OpenObserve 未启用，访问日志回退到 console 输出");
        return LogSink::console();
    }
    let (tx, rx) = mpsc::channel::<LogEntry>(cfg.channel_capacity);
    tokio::spawn(run_forwarder(cfg, rx));
    LogSink {
        mode: Mode::Remote(tx),
    }
}

/// 后台转发任务主循环：批量收集后 POST 到 OpenObserve。
async fn run_forwarder(cfg: OpenObserveConfig, mut rx: mpsc::Receiver<LogEntry>) {
    // 构造一个支持 keep-alive、走 rustls 的客户端。
    let client = match reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .pool_idle_timeout(Duration::from_secs(60))
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            warn!(error = %e, "OpenObserve HTTP 客户端构建失败，日志上报禁用");
            return;
        }
    };

    let url = format!(
        "{}/api/{}/{}/_json",
        cfg.endpoint.trim_end_matches('/'),
        cfg.organization,
        cfg.stream
    );
    let auth_header = build_basic_auth_header(&cfg.username, &cfg.password);

    let mut buf: Vec<LogEntry> = Vec::with_capacity(cfg.batch_size);
    let mut ticker = interval(Duration::from_millis(cfg.flush_interval_ms));
    // 默认 tick 行为是 Burst，避免 task 启动时立刻 flush 空 buffer。
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    loop {
        tokio::select! {
            biased;

            // 优先消费 channel，确保 backlog 不会被 ticker 拖延。
            maybe = rx.recv() => {
                match maybe {
                    Some(item) => {
                        buf.push(item);
                        if buf.len() >= cfg.batch_size {
                            flush(&client, &url, auth_header.as_deref(), &mut buf).await;
                        }
                    }
                    None => {
                        // sender 全部释放，flush 残留后退出。
                        flush(&client, &url, auth_header.as_deref(), &mut buf).await;
                        break;
                    }
                }
            }

            _ = ticker.tick() => {
                if !buf.is_empty() {
                    flush(&client, &url, auth_header.as_deref(), &mut buf).await;
                }
            }
        }
    }
}

/// 将 buffer 内全部条目一次性 POST 到 OpenObserve。
async fn flush(
    client: &reqwest::Client,
    url: &str,
    auth_header: Option<&str>,
    buf: &mut Vec<LogEntry>,
) {
    if buf.is_empty() {
        return;
    }
    // swap 出 buffer，让 channel 在网络 IO 阶段继续接收新条目。
    let payload = std::mem::take(buf);

    let mut req = client.post(url).json(&payload);
    if let Some(h) = auth_header {
        req = req.header("Authorization", h);
    }

    match req.send().await {
        Ok(resp) if resp.status().is_success() => {}
        Ok(resp) => warn!(status = %resp.status(), "OpenObserve 返回非 2xx 状态"),
        Err(e) => warn!(error = %e, "OpenObserve 上报请求失败"),
    }
}

/// 构造 HTTP Basic Auth 头部，缺失任一字段时返回 None。
fn build_basic_auth_header(user: &str, pass: &str) -> Option<String> {
    if user.is_empty() && pass.is_empty() {
        return None;
    }
    let raw = format!("{user}:{pass}");
    let encoded = base64::engine::general_purpose::STANDARD.encode(raw);
    Some(format!("Basic {encoded}"))
}
