//! 目标地址安全策略（SSRF / 钓鱼域名防护）。
//!
//! 正向代理会替客户端发起任意出向连接，因此必须把"目标可达性"视为安全
//! 边界，而不是简单的转发参数。这里的策略覆盖三类风险：
//!
//! 1. **SSRF**：拒绝解析到内网、回环、链路本地、云元数据、组播、保留地址
//!    的目标；解析完成后再次过滤，避免 DNS rebinding 把公网域名切换成内网 IP。
//! 2. **端口探测**：只允许配置中的目标端口（默认 80/443），防止借代理扫描
//!    内网或公网的非 Web 服务。
//! 3. **恶意 / 钓鱼域名**：支持域名白名单与黑名单（`*.example.com` 通配），
//!    可以在网关侧统一拦截已知恶意域名，或只放行业务需要的域名。
//!
//! 策略同时作用于普通 HTTP 转发与 HTTPS CONNECT 隧道。

use std::future::Future;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use hyper_util::client::legacy::connect::dns::Name;
use tower_service::Service;

use crate::config::SecurityConfig;
use crate::dns::DnsCache;

/// 安全策略校验失败的原因。
#[derive(Debug, thiserror::Error)]
pub enum SecurityError {
    #[error("目标域名不合法: {0}")]
    InvalidHost(String),
    #[error("目标端口被禁止: {0}")]
    PortNotAllowed(u16),
    #[error("目标域名不在白名单: {0}")]
    DomainNotAllowed(String),
    #[error("目标域名被黑名单拒绝: {0}")]
    DomainBlocked(String),
    #[error("禁止直接访问 IP 地址: {0}")]
    IpLiteral(IpAddr),
    #[error("禁止访问私网/保留地址: {0}")]
    PrivateAddress(IpAddr),
    #[error("目标域名没有可用的公网地址: {0}")]
    NoPublicAddress(String),
}

impl SecurityError {
    /// 用于 metrics label 的稳定短标签。
    pub fn reason(&self) -> &'static str {
        match self {
            SecurityError::InvalidHost(_) => "invalid_host",
            SecurityError::PortNotAllowed(_) => "port",
            SecurityError::DomainNotAllowed(_) => "not_allowlisted",
            SecurityError::DomainBlocked(_) => "blocklisted",
            SecurityError::IpLiteral(_) => "ip_literal",
            SecurityError::PrivateAddress(_) => "private_ip",
            SecurityError::NoPublicAddress(_) => "no_public_ip",
        }
    }
}

/// 单条域名规则。
#[derive(Debug, Clone)]
struct DomainRule {
    /// 已归一化的小写域名（通配规则不含 `*.` 前缀）。
    value: String,
    /// `true` 表示 `*.example.com`，只匹配子域名。
    wildcard: bool,
}

impl DomainRule {
    fn parse(raw: &str) -> Option<Self> {
        let raw = raw.trim().trim_end_matches('.').to_ascii_lowercase();
        if raw.is_empty() {
            return None;
        }
        if raw == "*" {
            return Some(Self {
                value: String::new(),
                wildcard: true,
            });
        }
        if let Some(suffix) = raw.strip_prefix("*.") {
            if suffix.is_empty() {
                return None;
            }
            return Some(Self {
                value: suffix.to_string(),
                wildcard: true,
            });
        }
        Some(Self {
            value: raw,
            wildcard: false,
        })
    }

    fn matches(&self, host: &str) -> bool {
        if !self.wildcard {
            return host == self.value;
        }
        if self.value.is_empty() {
            return true;
        }
        host.len() > self.value.len()
            && host.ends_with(&self.value)
            && host.as_bytes()[host.len() - self.value.len() - 1] == b'.'
    }
}

/// 编译后的安全策略，进程生命周期内只读，可安全共享。
#[derive(Debug)]
pub struct SecurityPolicy {
    block_private_ips: bool,
    block_ip_literals: bool,
    allowed_ports: Vec<u16>,
    allowlist: Vec<DomainRule>,
    blocklist: Vec<DomainRule>,
}

impl SecurityPolicy {
    pub fn from_config(cfg: &SecurityConfig) -> Self {
        Self {
            block_private_ips: cfg.block_private_ips,
            block_ip_literals: cfg.block_ip_literals,
            allowed_ports: cfg.allowed_ports.clone(),
            allowlist: cfg
                .domain_allowlist
                .iter()
                .filter_map(|s| DomainRule::parse(s))
                .collect(),
            blocklist: cfg
                .domain_blocklist
                .iter()
                .filter_map(|s| DomainRule::parse(s))
                .collect(),
        }
    }

    /// 校验客户端指定的目标 host/port，并返回规范化后的 host（小写、无括号）。
    ///
    /// 注意：这里只做域名与端口层校验；域名是否解析到内网地址必须在
    /// [`SecurityPolicy::filter_addrs`] 中基于真实解析结果判断。
    pub fn check_target(&self, raw_host: &str, port: u16) -> Result<String, SecurityError> {
        let host = normalize_host(raw_host)?;

        if port == 0 || (!self.allowed_ports.is_empty() && !self.allowed_ports.contains(&port)) {
            return Err(SecurityError::PortNotAllowed(port));
        }

        if let Ok(ip) = host.parse::<IpAddr>() {
            if self.block_ip_literals {
                return Err(SecurityError::IpLiteral(ip));
            }
            if self.block_private_ips && is_blocked_ip(ip) {
                return Err(SecurityError::PrivateAddress(ip));
            }
        }

        if !self.allowlist.is_empty() && !self.allowlist.iter().any(|r| r.matches(&host)) {
            return Err(SecurityError::DomainNotAllowed(host));
        }
        if self.blocklist.iter().any(|r| r.matches(&host)) {
            return Err(SecurityError::DomainBlocked(host));
        }

        Ok(host)
    }

    /// 对真实 DNS 解析结果做二次过滤。
    ///
    /// 只要存在至少一个允许的地址就返回这些地址；若全部命中私网/保留地址，
    /// 则视为攻击（例如 DNS rebinding）并拒绝。
    pub fn filter_addrs<I>(&self, host: &str, addrs: I) -> Result<Vec<SocketAddr>, SecurityError>
    where
        I: IntoIterator<Item = SocketAddr>,
    {
        let mut allowed = Vec::new();
        let mut first_blocked = None;

        for addr in addrs {
            if self.block_private_ips && is_blocked_ip(addr.ip()) {
                first_blocked.get_or_insert(addr.ip());
                continue;
            }
            allowed.push(addr);
        }

        if allowed.is_empty() {
            if let Some(ip) = first_blocked {
                return Err(SecurityError::PrivateAddress(ip));
            }
            return Err(SecurityError::NoPublicAddress(host.to_string()));
        }

        Ok(allowed)
    }
}

/// 把客户端传入的 host 归一化并做字符级校验。
///
/// - 去掉 IPv6 的方括号与域名末尾的根点；
/// - 只接受 ASCII（IDN 必须由客户端转成 punycode），拒绝控制字符、空格、
///   路径/查询分隔符等，避免把非法 authority 传给 DNS 或上游；
/// - 合法 IP 字面量直接返回其规范文本。
pub fn normalize_host(raw: &str) -> Result<String, SecurityError> {
    let raw = raw.trim();
    let raw = raw
        .strip_prefix('[')
        .and_then(|s| s.strip_suffix(']'))
        .unwrap_or(raw);
    let raw = raw.trim_end_matches('.');
    if raw.is_empty() || raw.len() > 253 {
        return Err(SecurityError::InvalidHost(raw.to_string()));
    }

    if let Ok(ip) = raw.parse::<IpAddr>() {
        return Ok(ip.to_string());
    }

    if !raw.is_ascii() {
        return Err(SecurityError::InvalidHost(raw.to_string()));
    }

    for label in raw.split('.') {
        if label.is_empty() || label.len() > 63 {
            return Err(SecurityError::InvalidHost(raw.to_string()));
        }
        if label.starts_with('-') || label.ends_with('-') {
            return Err(SecurityError::InvalidHost(raw.to_string()));
        }
        if !label
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        {
            return Err(SecurityError::InvalidHost(raw.to_string()));
        }
    }

    Ok(raw.to_ascii_lowercase())
}

/// 判断一个 IP 是否属于不应由公网代理访问的地址。
///
/// 覆盖 IPv4 私网/回环/链路本地/组播/保留段，以及 IPv6 的 ULA、链路本地、
/// 文档段、IPv4-mapped/compatible/6to4/NAT64 中内嵌的内网 IPv4。
pub fn is_blocked_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_blocked_v4(v4),
        IpAddr::V6(v6) => is_blocked_v6(v6),
    }
}

fn is_blocked_v4(ip: Ipv4Addr) -> bool {
    let o = ip.octets();
    ip.is_unspecified()
        || ip.is_loopback()
        || ip.is_private()
        || ip.is_link_local()
        || ip.is_multicast()
        || ip.is_broadcast()
        || ip.is_documentation()
        // 0.0.0.0/8
        || o[0] == 0
        // 100.64.0.0/10（运营商级 NAT）
        || (o[0] == 100 && (o[1] & 0b1100_0000) == 64)
        // 198.18.0.0/15（benchmark）
        || (o[0] == 198 && (o[1] & 0b1111_1110) == 18)
        // 192.0.0.0/24（IETF protocol assignments）
        || (o[0] == 192 && o[1] == 0 && o[2] == 0)
        // 192.88.99.0/24（6to4 relay anycast，已废弃）
        || (o[0] == 192 && o[1] == 88 && o[2] == 99)
        // 240.0.0.0/4（保留）与 255.255.255.255（广播）
        || o[0] >= 240
}

fn is_blocked_v6(ip: Ipv6Addr) -> bool {
    if let Some(v4) = ip.to_ipv4_mapped() {
        return is_blocked_v4(v4);
    }
    if ip.is_unspecified() || ip.is_loopback() || ip.is_multicast() {
        return true;
    }

    let s = ip.segments();
    // fe80::/10 链路本地
    if (s[0] & 0xffc0) == 0xfe80 {
        return true;
    }
    // fc00::/7 唯一本地地址（ULA）
    if (s[0] & 0xfe00) == 0xfc00 {
        return true;
    }
    // 2001:db8::/32 文档地址
    if s[0] == 0x2001 && s[1] == 0x0db8 {
        return true;
    }
    // 64:ff9b::/96 NAT64，检查内嵌 IPv4
    if s[0] == 0x0064 && s[1] == 0xff9b {
        let o = ip.octets();
        return is_blocked_v4(Ipv4Addr::new(o[12], o[13], o[14], o[15]));
    }
    // 2002::/16 6to4，检查内嵌 IPv4
    if s[0] == 0x2002 {
        let o = ip.octets();
        return is_blocked_v4(Ipv4Addr::new(o[2], o[3], o[4], o[5]));
    }
    // ::/96 IPv4-compatible（已废弃）
    if s[..6].iter().all(|x| *x == 0) {
        let o = ip.octets();
        return is_blocked_v4(Ipv4Addr::new(o[12], o[13], o[14], o[15]));
    }
    false
}

/// 供 `hyper_util` 连接池使用的 DNS 解析器。
///
/// 把 [`DnsCache`] 与安全策略接进 `HttpConnector`，保证普通 HTTP 转发路径
/// 也使用同一份缓存、并且在真正建连前基于解析结果做私网过滤。这样即使
/// 攻击者使用 DNS rebinding，连接池拿到的也只会是策略允许的地址。
#[derive(Clone)]
pub struct SafeResolver {
    dns: Arc<DnsCache>,
    policy: Arc<SecurityPolicy>,
}

impl SafeResolver {
    pub fn new(dns: Arc<DnsCache>, policy: Arc<SecurityPolicy>) -> Self {
        Self { dns, policy }
    }
}

impl Service<Name> for SafeResolver {
    type Response = std::vec::IntoIter<SocketAddr>;
    type Error = std::io::Error;
    type Future = Pin<Box<dyn Future<Output = std::io::Result<Self::Response>> + Send>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, name: Name) -> Self::Future {
        let dns = self.dns.clone();
        let policy = self.policy.clone();
        let host = name.as_str().to_string();

        Box::pin(async move {
            // 端口在这里无关紧要：HttpConnector 会按 URI 的端口重新填充。
            let addrs = dns.lookup_host(&host, 0).await?;
            let allowed = policy.filter_addrs(&host, addrs).map_err(|e| {
                std::io::Error::new(std::io::ErrorKind::PermissionDenied, e.to_string())
            })?;
            Ok(allowed.into_iter())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy() -> SecurityPolicy {
        SecurityPolicy::from_config(&SecurityConfig::default())
    }

    #[test]
    fn normalizes_hosts() {
        assert_eq!(normalize_host("Example.COM.").unwrap(), "example.com");
        assert_eq!(normalize_host("[::1]").unwrap(), "::1");
        assert!(normalize_host("bad host").is_err());
        assert!(normalize_host("evil.com/path").is_err());
        assert!(normalize_host("").is_err());
    }

    #[test]
    fn blocks_private_destinations() {
        let p = policy();
        assert!(p.check_target("127.0.0.1", 80).is_err());
        assert!(p.check_target("10.0.0.1", 80).is_err());
        // 用户 VPC 示例：10.3.0.0/16 属于 10.0.0.0/8 私网。
        assert!(p.check_target("10.3.0.5", 80).is_err());
        assert!(p.check_target("10.3.255.254", 443).is_err());
        assert!(p.check_target("169.254.169.254", 80).is_err());
        assert!(p.check_target("[::1]", 80).is_err());
        assert!(p.check_target("example.com", 22).is_err());
        assert!(p.check_target("8.8.8.8", 443).is_ok());
    }

    #[test]
    fn filters_rebinding_addresses() {
        let p = policy();
        let addrs = vec![
            SocketAddr::from(([10, 0, 0, 1], 80)),
            SocketAddr::from(([10, 3, 0, 5], 80)),
            SocketAddr::from(([8, 8, 8, 8], 80)),
        ];
        let allowed = p.filter_addrs("example.com", addrs).unwrap();
        assert_eq!(allowed.len(), 1);
        assert_eq!(allowed[0].ip(), IpAddr::from([8, 8, 8, 8]));

        let only_private = vec![SocketAddr::from(([127, 0, 0, 1], 80))];
        assert!(p.filter_addrs("example.com", only_private).is_err());
    }

    #[test]
    fn domain_rules_match() {
        let cfg = SecurityConfig {
            domain_allowlist: vec!["*.example.com".into(), "api.test".into()],
            domain_blocklist: vec!["evil.example.com".into()],
            ..SecurityConfig::default()
        };
        let p = SecurityPolicy::from_config(&cfg);
        assert!(p.check_target("api.example.com", 443).is_ok());
        assert!(p.check_target("api.test", 443).is_ok());
        assert!(p.check_target("example.com", 443).is_err());
        assert!(p.check_target("evil.example.com", 443).is_err());
        assert!(p.check_target("other.test", 443).is_err());
    }
}
