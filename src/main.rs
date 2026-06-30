//! rust-http-proxy 主入口。
//!
//! 流程：
//! 1. 解析配置（`config.toml` + 环境变量覆盖）。
//! 2. 初始化 tracing 日志输出。
//! 3. 构造 metrics / DNS 缓存 / 日志 sink 等共享组件。
//! 4. 启动 `/metrics` HTTP 服务。
//! 5. 按 worker 数启动 N 个绑定相同端口（SO_REUSEPORT）的 accept 循环。
//! 6. 等待 Ctrl+C 完成优雅退出。

use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use tracing::{error, info};
use tracing_subscriber::EnvFilter;

mod config;
mod dns;
mod listener;
mod logger;
mod metrics;
mod metrics_server;
mod proxy;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // 默认日志级别 info，可通过 RUST_LOG 环境变量覆盖。
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .with_target(false)
        .init();

    let cfg = config::Config::load("config.toml")?;
    info!("配置加载完成");

    // 构造共享组件。
    let metrics = Arc::new(metrics::Metrics::new()?);
    metrics::spawn_process_sampler(metrics.clone());

    let dns_cache = Arc::new(dns::DnsCache::new(
        Duration::from_secs(cfg.dns.ttl_secs),
        cfg.dns.max_entries,
        metrics.clone(),
    ));
    let log_sink = logger::spawn(cfg.openobserve.clone());

    // 启动 metrics HTTP 服务。
    let metrics_addr = SocketAddr::from_str(&cfg.metrics.listen)?;
    {
        let m = metrics.clone();
        tokio::spawn(async move {
            if let Err(e) = metrics_server::serve(metrics_addr, m).await {
                error!(error = %e, "metrics 服务异常退出");
            }
        });
    }

    // 启动 N 个共享端口的 accept 循环。
    let proxy_addr = SocketAddr::from_str(&cfg.server.listen)?;
    let workers = if cfg.server.workers == 0 {
        num_cpus_or_default()
    } else {
        cfg.server.workers
    };
    info!(%proxy_addr, workers, "代理监听启动");

    let http_client = proxy::build_http_client(&cfg.upstream);

    let ctx = Arc::new(proxy::ProxyContext {
        metrics: metrics.clone(),
        dns: dns_cache.clone(),
        log: log_sink.clone(),
        upstream: cfg.upstream.clone(),
        io_timeout: Duration::from_secs(cfg.server.io_timeout_secs),
        http_client,
    });

    for worker_id in 0..workers {
        let ctx = ctx.clone();
        tokio::spawn(async move {
            if let Err(e) = run_accept_loop(proxy_addr, ctx).await {
                error!(worker_id, error = %e, "accept 循环退出");
            }
        });
    }

    // 优雅退出：等待 Ctrl+C。
    tokio::signal::ctrl_c().await?;
    info!("收到 Ctrl+C，准备退出");
    Ok(())
}

/// 单个 worker 的 accept 循环：使用 SO_REUSEPORT 监听器接受连接，
/// 并为每个连接 spawn 一个 handler task。
async fn run_accept_loop(addr: SocketAddr, ctx: Arc<proxy::ProxyContext>) -> anyhow::Result<()> {
    let listener = listener::build_reuseport_listener(addr, 2048)?;
    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                // 接受失败通常是瞬时性的（fd 耗尽、EMFILE 等），稍等后继续。
                error!(error = %e, "accept 失败，稍后重试");
                tokio::time::sleep(Duration::from_millis(50)).await;
                continue;
            }
        };
        let ctx = ctx.clone();
        tokio::spawn(async move {
            proxy::handle_client(stream, peer, ctx).await;
        });
    }
}

/// 获取可用核数，失败时退化为 1，避免依赖 `num_cpus` crate。
fn num_cpus_or_default() -> usize {
    std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1)
}
