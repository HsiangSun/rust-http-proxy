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
//! - 引入轻量 max_entries 上限，达到上限时优先清理过期条目，不够再随机
//!   驱逐，避免长尾域名打满内存。

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use dashmap::DashMap;
use tokio::net::lookup_host;

use crate::metrics::Metrics;

/// 缓存值：解析得到的若干 IP 及到期时间。
#[derive(Clone)]
struct CacheEntry {
    ips: Arc<Vec<IpAddr>>,
    expire_at: Instant,
}

/// 公共 DNS 缓存。
pub struct DnsCache {
    inner: DashMap<String, CacheEntry>,
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
    /// * `timeout` —— 单次 getaddrinfo 的超时，避免异常 DNS 环境长时间挂起。
    pub fn new(
        ttl: Duration,
        max_entries: usize,
        timeout: Duration,
        metrics: Arc<Metrics>,
    ) -> Self {
        Self {
            inner: DashMap::with_capacity(1024),
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

        // 未命中或已过期：走真实解析。
        self.metrics.dns_cache_misses.inc();
        let mut resolved: Vec<IpAddr> = match host.parse::<IpAddr>() {
            Ok(ip) => vec![ip],
            Err(_) => {
                // 端口传 0 即可，缓存只保存 IP。
                let addrs = tokio::time::timeout(self.timeout, lookup_host((host, 0)))
                    .await
                    .map_err(|_| {
                        std::io::Error::new(
                            std::io::ErrorKind::TimedOut,
                            format!("DNS 解析超时: {host}"),
                        )
                    })??;
                addrs.map(|sa| sa.ip()).collect()
            }
        };
        resolved.sort_unstable();
        resolved.dedup();

        if resolved.is_empty() {
            return Err(std::io::Error::new(
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
