//! 带 TTL 的并发安全 DNS 缓存。
//!
//! 设计要点：
//! - 使用 [`DashMap`] 做无锁分片哈希表，避免全局锁竞争。
//! - 每条缓存项包含解析结果与到期时间戳；读取时惰性判定过期。
//! - 提供 `lookup` 异步接口，命中即返回，未命中则委托
//!   [`tokio::net::lookup_host`] 解析（其内部走 getaddrinfo，足够通用且
//!   尊重系统 `/etc/resolv.conf` 与 `/etc/hosts`）。
//! - 引入轻量 max_entries 上限，达到上限时随机清理 1/8 旧条目，避免
//!   长尾域名打满内存。

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use dashmap::DashMap;
use tokio::net::lookup_host;

use crate::metrics::Metrics;

/// 缓存值：解析得到的若干 SocketAddr 及到期时间。
#[derive(Clone)]
struct CacheEntry {
    addrs: Arc<Vec<SocketAddr>>,
    expire_at: Instant,
}

/// 公共 DNS 缓存。
pub struct DnsCache {
    inner: DashMap<String, CacheEntry>,
    ttl: Duration,
    max_entries: usize,
    metrics: Arc<Metrics>,
}

impl DnsCache {
    /// 构造一个新的 DNS 缓存。
    ///
    /// * `ttl` —— 单条解析结果的有效期。
    /// * `max_entries` —— 软上限；超过时随机驱逐 1/8 条目。
    pub fn new(ttl: Duration, max_entries: usize, metrics: Arc<Metrics>) -> Self {
        Self {
            inner: DashMap::with_capacity(1024),
            ttl,
            max_entries,
            metrics,
        }
    }

    /// 解析形如 `host:port` 的目标地址，命中缓存优先返回。
    ///
    /// 返回所有解析到的 SocketAddr 列表。调用者通常使用第一个，但保留全集
    /// 以便后续做 happy-eyeballs 或失败轮询。
    pub async fn lookup(&self, host_port: &str) -> std::io::Result<Arc<Vec<SocketAddr>>> {
        // 先查缓存。Instant::now 廉价，过期判定直接做。
        if let Some(entry) = self.inner.get(host_port) {
            if entry.expire_at > Instant::now() {
                self.metrics.dns_cache_hits.inc();
                return Ok(entry.addrs.clone());
            }
        }

        // 未命中或已过期：走真实解析。
        self.metrics.dns_cache_misses.inc();
        let resolved: Vec<SocketAddr> = lookup_host(host_port).await?.collect();
        if resolved.is_empty() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::AddrNotAvailable,
                format!("DNS 解析返回空结果: {host_port}"),
            ));
        }
        let entry = CacheEntry {
            addrs: Arc::new(resolved),
            expire_at: Instant::now() + self.ttl,
        };

        // 软上限保护：超过容量时清理少量过期/任意条目。
        if self.inner.len() >= self.max_entries {
            self.evict_some();
        }

        let addrs = entry.addrs.clone();
        self.inner.insert(host_port.to_string(), entry);
        Ok(addrs)
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

        if removed >= target {
            return;
        }

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
}
