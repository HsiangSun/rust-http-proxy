//! Prometheus 指标定义与采集模块。
//!
//! 这里统一定义代理运行时关心的所有指标，分为三大类：
//!
//! 1. **代理常规流量**：请求总数、成功/失败计数、上下行字节、延迟直方图。
//! 2. **协议相关指标**：HTTPS CONNECT 隧道数量，以及 SOCKS 命名空间下的
//!    占位计数器，便于未来扩展 SOCKS5 支持时无需改 dashboard。
//! 3. **进程资源指标**：CPU 使用率与常驻内存，由后台采样任务定期写入。
//!
//! 所有指标均通过全局 `Registry` 暴露，`render()` 输出 Prometheus 文本。

use std::sync::Arc;
use std::time::Duration;

use once_cell::sync::Lazy;
use prometheus::{
    Encoder, Histogram, HistogramOpts, HistogramVec, IntCounter, IntCounterVec, IntGauge, Opts,
    Registry, TextEncoder,
};
use sysinfo::{Pid, ProcessRefreshKind, System};

/// 全局 Prometheus Registry 单例。
pub static REGISTRY: Lazy<Registry> = Lazy::new(Registry::new);

/// 集中持有所有指标句柄，便于在请求处理路径中以 `Arc<Metrics>` 形式共享。
#[derive(Clone)]
pub struct Metrics {
    /// 代理收到的请求总数（含 HTTP 与 HTTPS CONNECT）。
    pub requests_total: IntCounter,
    /// 处理成功的请求计数（按协议维度区分）。
    pub requests_success: IntCounterVec,
    /// 处理失败的请求计数（按失败原因区分）。
    pub requests_failure: IntCounterVec,
    /// 当前活跃的客户端连接数。
    pub active_connections: IntGauge,
    /// HTTPS CONNECT 隧道总数。
    pub https_tunnels_total: IntCounter,
    /// 上行字节数（客户端 → 上游）。
    pub bytes_up: IntCounter,
    /// 下行字节数（上游 → 客户端）。
    pub bytes_down: IntCounter,
    /// 请求耗时直方图（秒），覆盖从受理到关闭的完整生命周期（全局视图）。
    pub request_duration: Histogram,
    /// 按 (host, status) 分桶的请求耗时直方图。
    ///
    /// - `host`：上游 `host:port`，由配置约束基数（业务场景 < 50）。
    /// - `status`：响应状态分类，取值 `2xx`/`3xx`/`4xx`/`5xx`/`error`/`tunnel`。
    ///   `tunnel` 用于 HTTPS CONNECT 隧道（无 HTTP 状态码）；`error` 用于
    ///   代理自身失败、未拿到上游响应的情形。
    pub request_duration_by_host: HistogramVec,
    /// 上游建连耗时直方图（秒）。
    pub upstream_connect_duration: Histogram,
    /// DNS 缓存命中计数。
    pub dns_cache_hits: IntCounter,
    /// DNS 缓存未命中计数。
    pub dns_cache_misses: IntCounter,
    /// SOCKS 命名空间占位计数器（保留扩展位）。
    #[allow(dead_code)]
    pub socks_requests_total: IntCounter,
    /// SOCKS 失败计数（按原因维度）。
    #[allow(dead_code)]
    pub socks_failures: IntCounterVec,
    /// SOCKS 活跃会话数。
    #[allow(dead_code)]
    pub socks_active_sessions: IntGauge,
    /// 进程 CPU 使用率（百分比，单位为 0~100*核心数）。
    pub process_cpu_percent: IntGauge,
    /// 进程常驻内存（字节）。
    pub process_memory_bytes: IntGauge,
}

impl Metrics {
    /// 构造并向全局 Registry 注册所有指标。
    pub fn new() -> anyhow::Result<Self> {
        let requests_total = IntCounter::new("proxy_requests_total", "代理收到的请求总数")?;
        let requests_success = IntCounterVec::new(
            Opts::new("proxy_requests_success_total", "处理成功的请求计数"),
            &["protocol"],
        )?;
        let requests_failure = IntCounterVec::new(
            Opts::new("proxy_requests_failure_total", "处理失败的请求计数"),
            &["reason"],
        )?;
        let active_connections =
            IntGauge::new("proxy_active_connections", "当前活跃的客户端连接数")?;
        let https_tunnels_total =
            IntCounter::new("proxy_https_tunnels_total", "HTTPS CONNECT 隧道总数")?;
        let bytes_up = IntCounter::new("proxy_bytes_up_total", "上行字节数（客户端→上游）")?;
        let bytes_down = IntCounter::new("proxy_bytes_down_total", "下行字节数（上游→客户端）")?;
        let duration_buckets = vec![
            0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0,
        ];
        let request_duration = Histogram::with_opts(
            HistogramOpts::new("proxy_request_duration_seconds", "请求总耗时（秒）")
                .buckets(duration_buckets.clone()),
        )?;
        let request_duration_by_host = HistogramVec::new(
            HistogramOpts::new(
                "proxy_request_duration_by_host_seconds",
                "按上游 host 与状态分类的请求耗时（秒）",
            )
            .buckets(duration_buckets),
            &["host", "status"],
        )?;
        let upstream_connect_duration = Histogram::with_opts(
            HistogramOpts::new("proxy_upstream_connect_seconds", "上游 TCP 建连耗时（秒）")
                .buckets(vec![
                    0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0,
                ]),
        )?;
        let dns_cache_hits = IntCounter::new("proxy_dns_cache_hits_total", "DNS 缓存命中次数")?;
        let dns_cache_misses =
            IntCounter::new("proxy_dns_cache_misses_total", "DNS 缓存未命中次数")?;
        let socks_requests_total =
            IntCounter::new("proxy_socks_requests_total", "SOCKS 请求总数（保留扩展位）")?;
        let socks_failures = IntCounterVec::new(
            Opts::new("proxy_socks_failures_total", "SOCKS 失败次数"),
            &["reason"],
        )?;
        let socks_active_sessions =
            IntGauge::new("proxy_socks_active_sessions", "SOCKS 活跃会话数")?;
        let process_cpu_percent =
            IntGauge::new("process_cpu_percent", "代理进程 CPU 使用率（百分比 *100）")?;
        let process_memory_bytes =
            IntGauge::new("process_memory_bytes", "代理进程常驻内存（字节）")?;

        // 统一注册到全局 Registry。
        let r = &*REGISTRY;
        r.register(Box::new(requests_total.clone()))?;
        r.register(Box::new(requests_success.clone()))?;
        r.register(Box::new(requests_failure.clone()))?;
        r.register(Box::new(active_connections.clone()))?;
        r.register(Box::new(https_tunnels_total.clone()))?;
        r.register(Box::new(bytes_up.clone()))?;
        r.register(Box::new(bytes_down.clone()))?;
        r.register(Box::new(request_duration.clone()))?;
        r.register(Box::new(request_duration_by_host.clone()))?;
        r.register(Box::new(upstream_connect_duration.clone()))?;
        r.register(Box::new(dns_cache_hits.clone()))?;
        r.register(Box::new(dns_cache_misses.clone()))?;
        r.register(Box::new(socks_requests_total.clone()))?;
        r.register(Box::new(socks_failures.clone()))?;
        r.register(Box::new(socks_active_sessions.clone()))?;
        r.register(Box::new(process_cpu_percent.clone()))?;
        r.register(Box::new(process_memory_bytes.clone()))?;

        Ok(Self {
            requests_total,
            requests_success,
            requests_failure,
            active_connections,
            https_tunnels_total,
            bytes_up,
            bytes_down,
            request_duration,
            request_duration_by_host,
            upstream_connect_duration,
            dns_cache_hits,
            dns_cache_misses,
            socks_requests_total,
            socks_failures,
            socks_active_sessions,
            process_cpu_percent,
            process_memory_bytes,
        })
    }

    /// 将当前 Registry 中的所有指标渲染成 Prometheus 文本格式。
    pub fn render(&self) -> Vec<u8> {
        let encoder = TextEncoder::new();
        let metric_families = REGISTRY.gather();
        let mut buffer = Vec::with_capacity(4096);
        // encode 实现内部仅写入 Vec，理论上不会失败，但仍做容错处理。
        let _ = encoder.encode(&metric_families, &mut buffer);
        buffer
    }
}

/// 启动一个后台任务，每 5 秒采样一次进程的 CPU/内存占用并写入 gauge。
///
/// 之所以独立成 task：`sysinfo::System` 的刷新本身需要短暂阻塞读取
/// `/proc`，放在请求路径会影响延迟。
pub fn spawn_process_sampler(metrics: Arc<Metrics>) {
    tokio::spawn(async move {
        // 当前进程 PID。
        let pid = Pid::from_u32(std::process::id());
        let mut sys = System::new();
        // 首次刷新以建立 baseline；CPU 百分比需要两次采样差值才有意义。
        sys.refresh_processes_specifics(
            sysinfo::ProcessesToUpdate::Some(&[pid]),
            true,
            ProcessRefreshKind::new().with_cpu().with_memory(),
        );

        loop {
            tokio::time::sleep(Duration::from_secs(5)).await;
            sys.refresh_processes_specifics(
                sysinfo::ProcessesToUpdate::Some(&[pid]),
                true,
                ProcessRefreshKind::new().with_cpu().with_memory(),
            );
            if let Some(proc_) = sys.process(pid) {
                // CPU 百分比放大 100 倍以整数形式存储，便于 Prometheus int gauge。
                metrics
                    .process_cpu_percent
                    .set((proc_.cpu_usage() * 100.0) as i64);
                metrics.process_memory_bytes.set(proc_.memory() as i64);
            }
        }
    });
}

/// 把 HTTP 状态码折算成 Prometheus 友好的低基数类别。
///
/// 把 100~599 映射为 `1xx`..`5xx`，其它（包含 0 / 极端越界）归为 `unknown`。
/// 与 [`Metrics::request_duration_by_host`] 的 `status` 标签保持一致。
pub fn status_class(code: u16) -> &'static str {
    match code {
        100..=199 => "1xx",
        200..=299 => "2xx",
        300..=399 => "3xx",
        400..=499 => "4xx",
        500..=599 => "5xx",
        _ => "unknown",
    }
}
