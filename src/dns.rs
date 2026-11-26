//! 带 TTL 的并发安全 DNS 缓存。
//!
//! 设计要点：
//! - 使用 [`DashMap`] 做无锁分片哈希表，避免全局锁竞争。
//! - 缓存 **IP 列表**（不含端口），这样同一域名的 80/443 等不同端口可以
//!   共享同一条解析结果。
//! - 每条缓存项包含解析结果与到期时间戳；读取时惰性判定过期。
//! - 提供 `lookup_host` 异步接口，命中即返回，未命中则委托
//!   [`tokio::net::lookup_host`] 解析（其内部走 getaddrinfo，足够通用且
//!   尊重系统 `/etc/resolv.conf` 与 `/etc/hosts`）。
//! - 同一域名并发未命中时只发起一次解析，其余请求等待同一个结果
//!   （singleflight）。getaddrinfo 会占用一个阻塞线程，缓存过期瞬间的
//!   并发请求如果各自解析，会一次性拉起大量线程。
//! - 同时进行的 getaddrinfo 不超过 `max_concurrent_lookups` 个（含已提交、
//!   尚在阻塞线程池排队的），名额在 getaddrinfo 真正返回时才释放。
//! - 引入轻量 max_entries 上限，达到上限时优先清理过期条目，不够再随机
//!   驱逐，避免长尾域名打满内存。

use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use std::sync::Arc;
use std::time::{Duration, Instant};

use dashmap::DashMap;
use futures::future::BoxFuture;
use tokio::sync::{OnceCell, Semaphore};

use crate::metrics::Metrics;

/// 缓存值：解析得到的若干 IP 及到期时间。
#[derive(Clone)]
struct CacheEntry {
    ips: Arc<Vec<IpAddr>>,
    expire_at: Instant,
}

/// 解析函数：输入域名，返回其全部 IP。生产环境为系统 getaddrinfo，测试可替换。
type Resolver =
    Arc<dyn Fn(String) -> BoxFuture<'static, std::io::Result<Vec<IpAddr>>> + Send + Sync>;

/// 一次进行中的解析，结果由所有并发等待者共享。`io::Error` 不能 Clone，
/// 因此保存为 (kind, message)。
type Inflight = Arc<OnceCell<Result<Arc<Vec<IpAddr>>, (std::io::ErrorKind, String)>>>;

/// 公共 DNS 缓存。
pub struct DnsCache {
    inner: DashMap<String, CacheEntry>,
    inflight: DashMap<String, Inflight>,
    resolver: Resolver,
    ttl: Duration,
    max_entries: usize,
    timeout: Duration,
    metrics: Arc<Metrics>,
}

impl DnsCache {
    /// 构造一个新的 DNS 缓存。
    ///
    /// * `ttl` —— 单条解析结果的有效期。
    /// * `max_entries` —— 软上限；超过时按过期优先、随机兜底的方式驱逐。
    /// * `timeout` —— 单次解析的超时（含等待解析名额），避免异常 DNS 环境长时间挂起。
    /// * `max_concurrent_lookups` —— 同时进行的 getaddrinfo 上限。
    pub fn new(
        ttl: Duration,
        max_entries: usize,
        timeout: Duration,
        max_concurrent_lookups: usize,
        metrics: Arc<Metrics>,
    ) -> Self {
        let permits = Arc::new(Semaphore::new(max_concurrent_lookups.max(1)));
        Self::with_resolver(ttl, max_entries, timeout, metrics, system_resolver(permits))
    }

    fn with_resolver(
        ttl: Duration,
        max_entries: usize,
        timeout: Duration,
        metrics: Arc<Metrics>,
        resolver: Resolver,
    ) -> Self {
        Self {
            inner: DashMap::with_capacity(1024),
            inflight: DashMap::new(),
            resolver,
            ttl,
            max_entries,
            timeout,
            metrics,
        }
    }

    /// 解析域名并返回带指定端口的 SocketAddr 列表。
    ///
    /// 缓存按 `host`（不含端口）索引。域名先尝试按 IP 字面量解析，避免把
    /// IPv6 字面量交给 getaddrinfo 时出现平台差异。
    pub async fn lookup_host(&self, host: &str, port: u16) -> std::io::Result<Vec<SocketAddr>> {
        let ips = self.lookup_ips(host).await?;
        Ok(ips.iter().map(|ip| SocketAddr::new(*ip, port)).collect())
    }

    async fn lookup_ips(&self, host: &str) -> std::io::Result<Arc<Vec<IpAddr>>> {
        // 先查缓存。Instant::now 廉价，过期判定直接做。
        if let Some(entry) = self.inner.get(host) {
            if entry.expire_at > Instant::now() {
                self.metrics.dns_cache_hits.inc();
                return Ok(entry.ips.clone());
            }
        }
        self.metrics.dns_cache_misses.inc();

        // 未命中或已过期：加入（或发起）这一域名的解析。
        let cell = self
            .inflight
            .entry(host.to_string())
            .or_insert_with(|| Arc::new(OnceCell::new()))
            .clone();
        // 无论正常返回还是调用方被取消，都把这一轮从 inflight 中摘掉，
        // 避免随机域名 + 客户端断开时 inflight 表无界增长。
        let _guard = InflightGuard {
            map: &self.inflight,
            host,
            cell: &cell,
        };
        // 发起者被取消时 OnceCell 会让下一个等待者接手解析。
        let result = cell.get_or_init(|| self.resolve_and_cache(host)).await;
        match result {
            Ok(ips) => Ok(ips.clone()),
            Err((kind, msg)) => Err(std::io::Error::new(*kind, msg.clone())),
        }
    }

    async fn resolve_and_cache(
        &self,
        host: &str,
    ) -> Result<Arc<Vec<IpAddr>>, (std::io::ErrorKind, String)> {
        let mut resolved: Vec<IpAddr> = match host.parse::<IpAddr>() {
            Ok(ip) => vec![ip],
            Err(_) => tokio::time::timeout(self.timeout, (self.resolver)(host.to_string()))
                .await
                .map_err(|_| {
                    (
                        std::io::ErrorKind::TimedOut,
                        format!("DNS 解析超时: {host}"),
                    )
                })?
                .map_err(|e| (e.kind(), e.to_string()))?,
        };
        resolved.sort_unstable();
        resolved.dedup();

        if resolved.is_empty() {
            return Err((
                std::io::ErrorKind::AddrNotAvailable,
                format!("DNS 解析返回空结果: {host}"),
            ));
        }

        let entry = CacheEntry {
            ips: Arc::new(resolved),
            expire_at: Instant::now() + self.ttl,
        };

        // 软上限保护：超过容量时清理少量过期/任意条目。
        if self.inner.len() >= self.max_entries {
            self.evict_some();
        }

        let ips = entry.ips.clone();
        self.inner.insert(host.to_string(), entry);
        self.metrics.dns_cache_entries.set(self.inner.len() as i64);
        Ok(ips)
    }

    /// 简单的批量清理策略：优先删过期项，不够再随机砍。
    fn evict_some(&self) {
        let now = Instant::now();
        let target = self.max_entries / 8 + 1;
        let mut removed = 0usize;

        // 先删过期。DashMap 的 retain 会持有分片锁，所以放在独立块里。
        self.inner.retain(|_, v| {
            if removed >= target {
                return true;
            }
            if v.expire_at <= now {
                removed += 1;
                false
            } else {
                true
            }
        });

        if removed < target {
            // 仍不够：取首批 key 强制删除，作为最后兜底。
            let extra: Vec<String> = self
                .inner
                .iter()
                .take(target - removed)
                .map(|kv| kv.key().clone())
                .collect();
            for k in extra {
                self.inner.remove(&k);
            }
        }

        self.metrics.dns_cache_entries.set(self.inner.len() as i64);
    }
}

/// 离开作用域时移除本轮 inflight 条目（只移除同一个 OnceCell，不误删新一轮）。
struct InflightGuard<'a> {
    map: &'a DashMap<String, Inflight>,
    host: &'a str,
    cell: &'a Inflight,
}

impl Drop for InflightGuard<'_> {
    fn drop(&mut self) {
        self.map
            .remove_if(self.host, |_, v| Arc::ptr_eq(v, self.cell));
    }
}

/// 系统解析：在阻塞线程里调用 getaddrinfo（尊重 /etc/hosts 与 resolv.conf）。
///
/// getaddrinfo 无法取消：调用方超时返回后，阻塞线程仍要等它结束。名额随任务
/// 进入阻塞线程、在 getaddrinfo 返回时才释放，因此占用阻塞线程（含排队）的解析
/// 不超过 `permits` 个；DNS 故障时，新的解析在异步等待名额阶段就会超时，不会
/// 在阻塞线程池的队列里无限堆积。
fn system_resolver(permits: Arc<Semaphore>) -> Resolver {
    Arc::new(move |host: String| {
        let permits = permits.clone();
        Box::pin(async move {
            let permit = permits
                .acquire_owned()
                .await
                .map_err(std::io::Error::other)?;
            tokio::task::spawn_blocking(move || {
                let _permit = permit;
                // 端口传 0 即可，缓存只保存 IP。
                (host.as_str(), 0)
                    .to_socket_addrs()
                    .map(|addrs| addrs.map(|sa| sa.ip()).collect())
            })
            .await
            .map_err(std::io::Error::other)?
        })
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn cache_with(resolver: Resolver) -> Arc<DnsCache> {
        Arc::new(DnsCache::with_resolver(
            Duration::from_secs(60),
            100,
            Duration::from_secs(2),
            Arc::new(Metrics::new(16).unwrap()),
            resolver,
        ))
    }

    /// 每次调用计数并延迟返回 93.184.216.34 的假解析器。
    fn counting_resolver(calls: Arc<AtomicUsize>, delay: Duration) -> Resolver {
        Arc::new(move |_host| {
            let calls = calls.clone();
            Box::pin(async move {
                calls.fetch_add(1, Ordering::SeqCst);
                tokio::time::sleep(delay).await;
                Ok(vec![IpAddr::from([93, 184, 216, 34])])
            })
        })
    }

    #[tokio::test]
    async fn concurrent_misses_share_one_lookup() {
        let calls = Arc::new(AtomicUsize::new(0));
        let dns = cache_with(counting_resolver(calls.clone(), Duration::from_millis(50)));

        let tasks: Vec<_> = (0..64)
            .map(|_| {
                let dns = dns.clone();
                tokio::spawn(async move { dns.lookup_host("api.example.com", 443).await })
            })
            .collect();
        for t in tasks {
            let addrs = t.await.unwrap().unwrap();
            assert_eq!(addrs, vec![SocketAddr::from(([93, 184, 216, 34], 443))]);
        }
        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "64 个并发未命中只应解析一次"
        );
        assert!(dns.inflight.is_empty(), "解析结束后 inflight 应被清空");

        // 之后命中缓存，不再解析。
        dns.lookup_host("api.example.com", 80).await.unwrap();
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn cancelled_waiters_do_not_leak_inflight_entries() {
        let calls = Arc::new(AtomicUsize::new(0));
        let dns = cache_with(counting_resolver(calls.clone(), Duration::from_secs(10)));

        // 模拟客户端断开：解析尚未完成时取消全部等待者。
        for i in 0..32 {
            let host = format!("r{i}.example.com");
            let fut = dns.lookup_host(&host, 80);
            assert!(tokio::time::timeout(Duration::from_millis(10), fut)
                .await
                .is_err());
        }
        assert!(
            dns.inflight.is_empty(),
            "被取消的解析不应残留在 inflight 中"
        );
    }

    #[tokio::test]
    async fn lookup_errors_are_shared_and_not_cached() {
        let calls = Arc::new(AtomicUsize::new(0));
        let counter = calls.clone();
        let dns = cache_with(Arc::new(move |_host| {
            counter.fetch_add(1, Ordering::SeqCst);
            Box::pin(async {
                tokio::time::sleep(Duration::from_millis(30)).await;
                Err(std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    "nxdomain",
                ))
            })
        }));

        let (a, b) = tokio::join!(
            dns.lookup_host("missing.example.com", 80),
            dns.lookup_host("missing.example.com", 80)
        );
        assert_eq!(a.unwrap_err().kind(), std::io::ErrorKind::NotFound);
        assert_eq!(b.unwrap_err().kind(), std::io::ErrorKind::NotFound);
        assert_eq!(calls.load(Ordering::SeqCst), 1);

        // 失败结果不缓存：下一次请求重新解析。
        assert!(dns.lookup_host("missing.example.com", 80).await.is_err());
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn system_resolver_holds_permit_until_lookup_returns() {
        let permits = Arc::new(Semaphore::new(2));
        let resolve = system_resolver(permits.clone());
        let ips = resolve("localhost".to_string()).await.unwrap();
        assert!(!ips.is_empty() && ips.iter().all(IpAddr::is_loopback));
        assert_eq!(permits.available_permits(), 2, "解析结束后名额应归还");
    }

    #[tokio::test]
    async fn ip_literals_skip_resolver() {
        let calls = Arc::new(AtomicUsize::new(0));
        let dns = cache_with(counting_resolver(calls.clone(), Duration::ZERO));
        let addrs = dns.lookup_host("2001:db8::1", 443).await.unwrap();
        assert_eq!(addrs[0].ip(), "2001:db8::1".parse::<IpAddr>().unwrap());
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }
}
