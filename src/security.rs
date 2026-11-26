//! 目标地址安全策略（SSRF / 钓鱼域名防护）。
//!
//! 参考 OWASP *Server-Side Request Forgery Prevention Cheat Sheet*。正向代理
//! 的目标是任意外部域名 / IP，属于其中的 "Case 2"，因此采用"拒绝列表 +
//! 建连时强制校验"；配置域名白名单后则收紧为 "Case 1"。防护分为五层：
//!
//! 1. **请求形态**：普通转发只接受 `http`（HTTPS 走 CONNECT，其余 scheme 一律
//!    拒绝）；拒绝携带 userinfo（`user@host`）的 authority 与重复的 Host 头，
//!    避免不同组件对"目标是谁"读出不同答案。
//! 2. **主机名**：只接受 ASCII 主机名与标准写法的 IP 字面量。十六进制、八进制、
//!    整数、省略段等 IPv4 写法（`0x7f.1`、`2130706433`、`0177.0.0.1`）会被
//!    getaddrinfo 解释成 IP，一律拒绝；默认拒绝单标签主机名与内部专用后缀
//!    （`localhost`、`.internal`、`.local` …），它们只能由内网 DNS 或 search
//!    域补全解析。
//! 3. **地址**：IPv4-mapped / NAT64 地址先还原为内嵌 IPv4 再判断；拒绝全部
//!    非全球可路由地址，IPv6 只放行 `2000::/3` 全球单播；云元数据与链路本地
//!    地址无论配置如何都拒绝；支持额外拒绝网段 `blocked_cidrs`。
//! 4. **建连时强制**：解析结果中只要有一个地址被拒绝就拒绝整个目标；真正建连
//!    只使用校验过的地址（HTTP 经 [`SafeResolver`]，CONNECT 直接连接校验后的
//!    地址），校验与建连之间不存在第二次未经校验的解析，以此抵御 DNS rebinding。
//! 5. **端口与域名**：端口白名单（默认 80/443），域名白名单 / 黑名单
//!    （`*.example.com` 通配）。
//!
//! 拒绝原因只以短标签返回给客户端，不回显解析出的地址，避免代理沦为内网 DNS
//! 探测器；完整原因写入服务端日志。策略同时作用于普通 HTTP 转发与 HTTPS
//! CONNECT 隧道。

use std::error::Error as StdError;
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
///
/// `Display` 含完整细节（包括解析出的地址），只用于服务端日志；返回给客户端
/// 的文本见 [`SecurityError::client_message`]。
#[derive(Debug, Clone, thiserror::Error)]
pub enum SecurityError {
    #[error("目标域名不合法: {0}")]
    InvalidHost(String),
    #[error("非标准写法的 IP 地址（十六进制/八进制/整数/省略段）: {0}")]
    NonCanonicalIp(String),
    #[error("目标 authority 不允许携带 userinfo（user@host）")]
    UserInfo,
    #[error("不支持的协议: {0}（普通转发仅支持 http，HTTPS 请使用 CONNECT）")]
    SchemeNotAllowed(String),
    #[error("目标端口被禁止: {0}")]
    PortNotAllowed(u16),
    #[error("禁止访问内部域名: {0}")]
    InternalDomain(String),
    #[error("目标域名不在白名单: {0}")]
    DomainNotAllowed(String),
    #[error("目标域名被黑名单拒绝: {0}")]
    DomainBlocked(String),
    #[error("禁止直接访问 IP 地址: {0}")]
    IpLiteral(IpAddr),
    #[error("禁止访问云元数据/链路本地地址: {0}")]
    MetadataAddress(IpAddr),
    #[error("目标地址命中拒绝网段: {0}")]
    DeniedNetwork(IpAddr),
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
            SecurityError::NonCanonicalIp(_) => "ip_encoding",
            SecurityError::UserInfo => "userinfo",
            SecurityError::SchemeNotAllowed(_) => "scheme",
            SecurityError::PortNotAllowed(_) => "port",
            SecurityError::InternalDomain(_) => "internal_domain",
            SecurityError::DomainNotAllowed(_) => "not_allowlisted",
            SecurityError::DomainBlocked(_) => "blocklisted",
            SecurityError::IpLiteral(_) => "ip_literal",
            SecurityError::MetadataAddress(_) => "metadata_ip",
            SecurityError::DeniedNetwork(_) => "blocked_cidr",
            SecurityError::PrivateAddress(_) => "private_ip",
            SecurityError::NoPublicAddress(_) => "no_public_ip",
        }
    }

    /// 返回给客户端的说明：只含原因标签，不回显解析出的地址。
    ///
    /// 否则攻击者可以把代理当作内网 DNS 探测器，例如请求 `db.corp.example`
    /// 并从 403 消息里读出它解析到的内网 IP。
    pub fn client_message(&self) -> String {
        format!("目标被安全策略拒绝 (reason={})", self.reason())
    }
}

/// IPv4 / IPv6 网段，用于内置拒绝表与配置项 `blocked_cidrs`。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cidr {
    addr: IpAddr,
    prefix: u8,
}

impl Cidr {
    const fn v4(o: [u8; 4], prefix: u8) -> Self {
        Self {
            addr: IpAddr::V4(Ipv4Addr::new(o[0], o[1], o[2], o[3])),
            prefix,
        }
    }

    const fn v6(s: [u16; 8], prefix: u8) -> Self {
        Self {
            addr: IpAddr::V6(Ipv6Addr::new(
                s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7],
            )),
            prefix,
        }
    }

    /// 解析 `10.0.0.0/8`、`fd00:ec2::/32` 或单个地址（视为 /32、/128）。
    pub fn parse(raw: &str) -> Result<Self, String> {
        let raw = raw.trim();
        let (ip_part, prefix_part) = match raw.split_once('/') {
            Some((ip, prefix)) => (ip, Some(prefix)),
            None => (raw, None),
        };
        let ip: IpAddr = ip_part
            .parse()
            .map_err(|_| format!("无效的网段: {raw:?}"))?;
        let max = if ip.is_ipv4() { 32 } else { 128 };
        let prefix = match prefix_part {
            None => max,
            Some(p) => p
                .parse::<u8>()
                .ok()
                .filter(|p| *p <= max)
                .ok_or_else(|| format!("无效的前缀长度: {raw:?}"))?,
        };
        // `::ffff:a.b.c.d/96+` 转成 IPv4 网段，与地址校验前的规范化保持一致。
        if let IpAddr::V6(v6) = ip {
            if let (Some(v4), true) = (v6.to_ipv4_mapped(), prefix >= 96) {
                return Ok(Self {
                    addr: IpAddr::V4(v4),
                    prefix: prefix - 96,
                });
            }
        }
        Ok(Self { addr: ip, prefix })
    }

    /// 地址是否落在网段内；地址族不同时总是返回 `false`。
    pub fn contains(&self, ip: IpAddr) -> bool {
        match (self.addr, ip) {
            (IpAddr::V4(net), IpAddr::V4(ip)) => {
                let mask = u32::MAX
                    .checked_shl(32 - u32::from(self.prefix))
                    .unwrap_or(0);
                (u32::from(net) & mask) == (u32::from(ip) & mask)
            }
            (IpAddr::V6(net), IpAddr::V6(ip)) => {
                let mask = u128::MAX
                    .checked_shl(128 - u32::from(self.prefix))
                    .unwrap_or(0);
                (u128::from(net) & mask) == (u128::from(ip) & mask)
            }
            _ => false,
        }
    }
}

/// 非全球可路由的 IPv4 网段：IANA IPv4 Special-Purpose Address Registry，
/// 覆盖 OWASP SSRF Cheat Sheet 的最小拒绝列表。
const NON_GLOBAL_V4: &[Cidr] = &[
    Cidr::v4([0, 0, 0, 0], 8),       // "本网络"，含 0.0.0.0
    Cidr::v4([10, 0, 0, 0], 8),      // RFC 1918
    Cidr::v4([100, 64, 0, 0], 10),   // 运营商级 NAT
    Cidr::v4([127, 0, 0, 0], 8),     // 回环
    Cidr::v4([169, 254, 0, 0], 16),  // 链路本地
    Cidr::v4([172, 16, 0, 0], 12),   // RFC 1918
    Cidr::v4([192, 0, 0, 0], 24),    // IETF 协议分配
    Cidr::v4([192, 0, 2, 0], 24),    // TEST-NET-1
    Cidr::v4([192, 88, 99, 0], 24),  // 6to4 中继任播（已废弃）
    Cidr::v4([192, 168, 0, 0], 16),  // RFC 1918
    Cidr::v4([198, 18, 0, 0], 15),   // 基准测试
    Cidr::v4([198, 51, 100, 0], 24), // TEST-NET-2
    Cidr::v4([203, 0, 113, 0], 24),  // TEST-NET-3
    Cidr::v4([224, 0, 0, 0], 4),     // 组播
    Cidr::v4([240, 0, 0, 0], 4),     // 保留，含 255.255.255.255 广播
];

/// `2000::/3` 全球单播内仍不可全球路由的 IPv6 网段。`2000::/3` 之外的地址
/// （`::/8`、`64:ff9b:1::/48`、`100::/64`、`fc00::/7`、`fe80::/10`、
/// `fec0::/10`、`ff00::/8` 等）由 [`is_blocked_v6`] 整体拒绝。
const NON_GLOBAL_V6: &[Cidr] = &[
    Cidr::v6([0x2001, 0, 0, 0, 0, 0, 0, 0], 23), // IETF 协议分配：Teredo、基准测试、ORCHID…
    Cidr::v6([0x2001, 0x0db8, 0, 0, 0, 0, 0, 0], 32), // 文档
    Cidr::v6([0x2002, 0, 0, 0, 0, 0, 0, 0], 16), // 6to4（已废弃）
    Cidr::v6([0x3fff, 0, 0, 0, 0, 0, 0, 0], 20), // 文档（RFC 9637）
];

/// 云元数据 / 平台专用地址：无论 `block_private_ips` 如何配置都拒绝。
///
/// 这些端点一旦可达，攻击者即可借代理读取实例凭证。正向代理能替客户端发送
/// PUT 与任意请求头，IMDSv2 的 token 机制挡不住经代理发起的请求，只能在这里拦。
const ALWAYS_BLOCKED: &[Cidr] = &[
    // 链路本地：AWS/GCP/Azure/OCI/DigitalOcean IMDS 169.254.169.254、
    // ECS 任务元数据 169.254.170.2、EKS Pod Identity 169.254.170.23。
    Cidr::v4([169, 254, 0, 0], 16),
    Cidr::v4([100, 100, 100, 200], 32),          // 阿里云元数据
    Cidr::v4([192, 0, 0, 192], 32),              // Oracle Cloud 元数据
    Cidr::v4([168, 63, 129, 16], 32),            // Azure WireServer（公网段地址）
    Cidr::v6([0xfe80, 0, 0, 0, 0, 0, 0, 0], 10), // IPv6 链路本地
    Cidr::v6([0xfd00, 0x0ec2, 0, 0, 0, 0, 0, 0], 32), // AWS IMDS / Pod Identity IPv6（fd00:ec2::254 等）
];

/// 内部 / 特殊用途域名后缀：RFC 6761（`localhost`/`test`/`invalid`/`example`）、
/// RFC 6762（`local`）、RFC 7686（`onion`）、RFC 8375（`home.arpa`）、RFC 9476
/// （`alt`）、ICANN 保留给私网的 `internal`，以及 ICANN 决定永不授权的
/// `corp`/`home`/`mail`。这些名字只能由内网 DNS、mDNS 或 hosts 文件解析，
/// 不应出现在公网代理的目标里。
const INTERNAL_SUFFIXES: &[&str] = &[
    "localhost",
    "local",
    "internal",
    "localdomain",
    "home.arpa",
    "test",
    "invalid",
    "example",
    "onion",
    "alt",
    "corp",
    "home",
    "mail",
];

/// 单条域名规则。
#[derive(Debug, Clone)]
struct DomainRule {
    /// 规范化后的主机名（通配规则不含 `*.` 前缀）；IP 规则为规范文本。
    value: String,
    /// `true` 表示 `*.example.com`，只匹配子域名。
    wildcard: bool,
}

impl DomainRule {
    /// 解析一条规则；空白条目返回 `Ok(None)`，写错返回 `Err`。
    ///
    /// 规则与客户端输入走同一个 [`normalize_host`]，保证比较的是同一种规范
    /// 形式（例如 IPv6 规则 `2001:db8:0:0::1` 能匹配 `[2001:db8::1]`）。
    fn parse(raw: &str) -> Result<Option<Self>, String> {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            return Ok(None);
        }
        if trimmed == "*" {
            return Ok(Some(Self {
                value: String::new(),
                wildcard: true,
            }));
        }
        let (body, wildcard) = match trimmed.strip_prefix("*.") {
            Some(rest) => (rest, true),
            None => (trimmed, false),
        };
        let value = normalize_host(body).map_err(|e| format!("无效的域名规则 {raw:?}: {e}"))?;
        if wildcard && value.parse::<IpAddr>().is_ok() {
            return Err(format!("通配规则不能用于 IP 地址: {raw:?}"));
        }
        Ok(Some(Self { value, wildcard }))
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
    block_internal_domains: bool,
    allowed_ports: Vec<u16>,
    allowlist: Vec<DomainRule>,
    blocklist: Vec<DomainRule>,
    blocked_cidrs: Vec<Cidr>,
}

impl SecurityPolicy {
    /// 编译配置。
    ///
    /// 规则写错时直接报错而不是静默忽略：一条被忽略的黑名单或拒绝网段，
    /// 意味着运维以为已经拦截的目标实际仍然可以访问。
    pub fn from_config(cfg: &SecurityConfig) -> anyhow::Result<Self> {
        fn domain_rules(list: &[String], field: &str) -> anyhow::Result<Vec<DomainRule>> {
            list.iter()
                .filter_map(|raw| DomainRule::parse(raw).transpose())
                .collect::<Result<_, _>>()
                .map_err(|e| anyhow::anyhow!("[security] {field}: {e}"))
        }
        let blocked_cidrs = cfg
            .blocked_cidrs
            .iter()
            .filter(|raw| !raw.trim().is_empty())
            .map(|raw| Cidr::parse(raw))
            .collect::<Result<_, _>>()
            .map_err(|e| anyhow::anyhow!("[security] blocked_cidrs: {e}"))?;

        Ok(Self {
            block_private_ips: cfg.block_private_ips,
            block_ip_literals: cfg.block_ip_literals,
            block_internal_domains: cfg.block_internal_domains,
            allowed_ports: cfg.allowed_ports.clone(),
            allowlist: domain_rules(&cfg.domain_allowlist, "domain_allowlist")?,
            blocklist: domain_rules(&cfg.domain_blocklist, "domain_blocklist")?,
            blocked_cidrs,
        })
    }

    /// 校验客户端指定的目标 host/port，并返回规范化后的 host（小写、无括号，
    /// IPv4-mapped 字面量还原为 IPv4）。
    ///
    /// 这里只做主机名与端口层校验；域名是否解析到受限地址必须在
    /// [`SecurityPolicy::check_resolved`] 中基于真实解析结果判断。
    pub fn check_target(&self, raw_host: &str, port: u16) -> Result<String, SecurityError> {
        let host = normalize_host(raw_host)?;

        if port == 0 || (!self.allowed_ports.is_empty() && !self.allowed_ports.contains(&port)) {
            return Err(SecurityError::PortNotAllowed(port));
        }

        if let Ok(ip) = host.parse::<IpAddr>() {
            if self.block_ip_literals {
                return Err(SecurityError::IpLiteral(ip));
            }
            self.check_ip(ip)?;
        } else if self.block_internal_domains && is_internal_domain(&host) {
            return Err(SecurityError::InternalDomain(host));
        }

        if !self.allowlist.is_empty() && !self.allowlist.iter().any(|r| r.matches(&host)) {
            return Err(SecurityError::DomainNotAllowed(host));
        }
        if self.blocklist.iter().any(|r| r.matches(&host)) {
            return Err(SecurityError::DomainBlocked(host));
        }

        Ok(host)
    }

    /// 校验单个目标地址。
    ///
    /// 先按原始地址、再按还原出的内嵌 IPv4 匹配，保证 `::ffff:169.254.169.254`、
    /// `64:ff9b::a9fe:a9fe` 与 `169.254.169.254` 结果一致，同时允许运维用
    /// `64:ff9b::/96` 这类 IPv6 网段整体拒绝。
    pub fn check_ip(&self, ip: IpAddr) -> Result<(), SecurityError> {
        let canonical = canonical_ip(ip);
        let hit = |list: &[Cidr]| list.iter().any(|c| c.contains(ip) || c.contains(canonical));
        if hit(ALWAYS_BLOCKED) {
            return Err(SecurityError::MetadataAddress(ip));
        }
        if hit(&self.blocked_cidrs) {
            return Err(SecurityError::DeniedNetwork(ip));
        }
        if self.block_private_ips && is_blocked_ip(ip) {
            return Err(SecurityError::PrivateAddress(ip));
        }
        Ok(())
    }

    /// 校验真实 DNS 解析结果，返回可以建连的地址。
    ///
    /// 按 OWASP"任何一项校验失败即拒绝"的要求：只要有一个地址被拒绝就拒绝整个
    /// 目标，而不是挑出其中的公网地址继续连接。正常的公网域名不会同时解析到
    /// 内网地址，混合结果通常意味着 DNS rebinding 或解析结果被污染。
    pub fn check_resolved<I>(&self, host: &str, addrs: I) -> Result<Vec<SocketAddr>, SecurityError>
    where
        I: IntoIterator<Item = SocketAddr>,
    {
        let mut allowed = Vec::new();
        for addr in addrs {
            self.check_ip(addr.ip())?;
            // IPv4-mapped 地址按 IPv4 建连：行为等价，且不依赖 IPV6_V6ONLY 设置。
            allowed.push(SocketAddr::new(addr.ip().to_canonical(), addr.port()));
        }
        if allowed.is_empty() {
            return Err(SecurityError::NoPublicAddress(host.to_string()));
        }
        Ok(allowed)
    }
}

/// 普通 HTTP 转发只接受 `http` 绝对 URI，或不带 scheme 的 origin-form。
///
/// 代理不发起 TLS：`https://` 绝对 URI 会被明文发往 443，`ftp`/`gopher`/`file`
/// 等更不应转发（OWASP：协议白名单）。HTTPS 必须走 CONNECT 隧道。
pub fn check_forward_scheme(scheme: Option<&str>) -> Result<(), SecurityError> {
    match scheme {
        None => Ok(()),
        Some(s) if s.eq_ignore_ascii_case("http") => Ok(()),
        Some(s) => Err(SecurityError::SchemeNotAllowed(s.to_ascii_lowercase())),
    }
}

/// 拒绝带 userinfo 的 authority / Host 头。
///
/// RFC 9110 §4.2.4 要求把来自不可信来源的 userinfo 视为错误：它常被用来伪装
/// 真实目标（`http://trusted.com@evil.com/`），也是不同解析器读出不同 host 的
/// 典型来源。
pub fn check_no_userinfo(authority: &str) -> Result<(), SecurityError> {
    if authority.contains('@') {
        Err(SecurityError::UserInfo)
    } else {
        Ok(())
    }
}

/// 在错误链中查找 [`SecurityError`]。
///
/// [`SafeResolver`] 在建连阶段拒绝地址时，错误会被 hyper-util 包装成
/// `legacy::Error -> ConnectError -> io::Error(SecurityError)`；这里把它还原出来，
/// 让调用方按安全拦截（403）而不是上游故障（502）处理。
pub fn find_security_error<'a>(err: &'a (dyn StdError + 'static)) -> Option<&'a SecurityError> {
    let mut cur = Some(err);
    while let Some(e) = cur {
        if let Some(se) = e.downcast_ref::<SecurityError>() {
            return Some(se);
        }
        // io::Error::source() 会跳过自定义错误本身，必须用 get_ref() 取出。
        if let Some(se) = e
            .downcast_ref::<std::io::Error>()
            .and_then(|io| io.get_ref())
            .and_then(|inner| inner.downcast_ref::<SecurityError>())
        {
            return Some(se);
        }
        cur = e.source();
    }
    None
}

/// 把客户端传入的 host 归一化并做字符级校验。
///
/// - 去掉 IPv6 的方括号与域名末尾的根点；
/// - 标准写法的 IP 字面量返回规范文本，IPv4-mapped IPv6 还原为 IPv4；
/// - 只接受 ASCII（IDN 必须由客户端转成 punycode），拒绝控制字符、空格、
///   路径 / 查询分隔符等，避免把非法 authority 传给 DNS 或上游；
/// - 拒绝会被 getaddrinfo 解释成 IPv4 的非标准写法。
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
        return Ok(ip.to_canonical().to_string());
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

    // getaddrinfo（inet_aton）与浏览器（WHATWG URL）都会把最后一段是数字的
    // 主机名当作 IPv4：`0x7f.1`、`2130706433`、`0177.0.0.1`、`127.1` 都是
    // 127.0.0.1。std 只认标准点分十进制，这类写法走到这里时一律拒绝，避免
    // 绕过 IP 字面量策略，或让不同解析器读出不同地址。
    if ends_in_number(raw) {
        return Err(SecurityError::NonCanonicalIp(raw.to_string()));
    }

    Ok(raw.to_ascii_lowercase())
}

/// WHATWG URL 规范的 "ends in a number"：最后一个标签全是数字，或是 `0x`
/// 开头的十六进制数（`0x` 本身也算 0）。
fn ends_in_number(host: &str) -> bool {
    let last = host.rsplit('.').next().unwrap_or(host);
    if !last.is_empty() && last.bytes().all(|b| b.is_ascii_digit()) {
        return true;
    }
    match last.strip_prefix("0x").or_else(|| last.strip_prefix("0X")) {
        Some(hex) => hex.bytes().all(|b| b.is_ascii_hexdigit()),
        None => false,
    }
}

/// 是否为内部主机名（`host` 已经过 [`normalize_host`]，且不是 IP）。
fn is_internal_domain(host: &str) -> bool {
    // 单标签主机名（`localhost`、`metadata`、`instance-data`、`kubernetes`）会被
    // resolv.conf 的 search 域补全成内网名字，例如 EC2 的 `*.ec2.internal`、
    // Kubernetes 的 `*.svc.cluster.local`。
    if !host.contains('.') {
        return true;
    }
    INTERNAL_SUFFIXES.iter().any(|suffix| {
        host == *suffix
            || (host.len() > suffix.len()
                && host.ends_with(suffix)
                && host.as_bytes()[host.len() - suffix.len() - 1] == b'.')
    })
}

/// 还原 IPv4-mapped（`::ffff:a.b.c.d`）与 NAT64 知名前缀（`64:ff9b::/96`）中
/// 内嵌的 IPv4，其余地址原样返回。只用于校验，建连仍使用原始地址。
fn canonical_ip(ip: IpAddr) -> IpAddr {
    let IpAddr::V6(v6) = ip else {
        return ip;
    };
    if let Some(v4) = v6.to_ipv4_mapped() {
        return IpAddr::V4(v4);
    }
    if v6.segments()[..6] == [0x0064, 0xff9b, 0, 0, 0, 0] {
        let o = v6.octets();
        return IpAddr::V4(Ipv4Addr::new(o[12], o[13], o[14], o[15]));
    }
    ip
}

/// 判断一个 IP 是否属于不应由公网代理访问的非全球可路由地址
/// （`block_private_ips` 控制的范围，不含元数据地址与 `blocked_cidrs`）。
pub fn is_blocked_ip(ip: IpAddr) -> bool {
    match canonical_ip(ip) {
        v4 @ IpAddr::V4(_) => NON_GLOBAL_V4.iter().any(|c| c.contains(v4)),
        IpAddr::V6(v6) => is_blocked_v6(v6),
    }
}

fn is_blocked_v6(ip: Ipv6Addr) -> bool {
    // IANA 只把 2000::/3 分配为全球单播，其余前缀都是保留、私网、链路本地或
    // 组播。用"只放行 2000::/3"代替逐个列举，新出现的特殊前缀也默认拒绝。
    if (ip.segments()[0] & 0xe000) != 0x2000 {
        return true;
    }
    NON_GLOBAL_V6.iter().any(|c| c.contains(IpAddr::V6(ip)))
}

/// 供 `hyper_util` 连接池使用的 DNS 解析器。
///
/// 把 [`DnsCache`] 与安全策略接进 `HttpConnector`，保证普通 HTTP 转发路径
/// 也使用同一份缓存，并且在真正建连前基于解析结果做校验。即使预检查之后
/// DNS 结果发生变化（DNS rebinding），连接池拿到的也只会是策略允许的地址。
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
            // 保留 SecurityError 本身，调用方可经 find_security_error 还原拒绝原因。
            let allowed = policy
                .check_resolved(&host, addrs)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::PermissionDenied, e))?;
            Ok(allowed.into_iter())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fmt;

    fn policy() -> SecurityPolicy {
        SecurityPolicy::from_config(&SecurityConfig::default()).unwrap()
    }

    fn policy_with(f: impl FnOnce(&mut SecurityConfig)) -> SecurityPolicy {
        let mut cfg = SecurityConfig::default();
        f(&mut cfg);
        SecurityPolicy::from_config(&cfg).unwrap()
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn normalizes_hosts() {
        assert_eq!(normalize_host("Example.COM.").unwrap(), "example.com");
        assert_eq!(normalize_host("[::1]").unwrap(), "::1");
        assert_eq!(normalize_host("[::ffff:7f00:1]").unwrap(), "127.0.0.1");
        assert_eq!(
            normalize_host("[2001:4860:4860:0:0:0:0:8888]").unwrap(),
            "2001:4860:4860::8888"
        );
        assert!(normalize_host("bad host").is_err());
        assert!(normalize_host("evil.com/path").is_err());
        assert!(normalize_host("[fe80::1%25eth0]").is_err());
        assert!(normalize_host("").is_err());
    }

    #[test]
    fn rejects_non_canonical_ipv4() {
        // OWASP 列出的 Hex / Octal / Dword / Mixed 编码，以及 inet_aton 接受的省略段。
        for s in [
            "0x7f000001",
            "0X7F000001",
            "2130706433",
            "017700000001",
            "0177.0.0.1",
            "0x7f.0.0.1",
            "0x7f.1",
            "127.1",
            "127.0.1",
            "127.0.0.0x1",
            "010.0.0.1",
            "0",
            "0x",
            "1.2.3.4.5",
            "0x08080808",
            "134744072",
        ] {
            assert!(
                matches!(normalize_host(s), Err(SecurityError::NonCanonicalIp(_))),
                "{s} 应被识别为非标准 IP 写法"
            );
        }
        for s in [
            "1e100.net",
            "123.example.com",
            "a-1.b2",
            "0x7f.example",
            "xn--fiqs8s.xn--fiqz9s",
        ] {
            assert!(normalize_host(s).is_ok(), "{s} 是合法域名");
        }
    }

    #[test]
    fn blocks_owasp_minimum_ranges() {
        // OWASP SSRF Cheat Sheet 拒绝列表中的每一类地址。
        let p = policy();
        for s in [
            "169.254.169.254",
            "fd00:ec2::254",
            "127.0.0.1",
            "127.255.255.254",
            "0.0.0.0",
            "0.1.2.3",
            "::1",
            "10.0.0.1",
            "172.16.0.1",
            "172.31.255.255",
            "192.168.0.1",
            "169.254.170.2",
            "169.254.170.23",
            "fc00::1",
            "fd12:3456::1",
            "fe80::1",
            "224.0.0.1",
            "239.255.255.250",
            "ff02::1",
            "::ffff:169.254.169.254",
            "::ffff:127.0.0.1",
            "64:ff9b::a9fe:a9fe",
            "64:ff9b::7f00:1",
            "64:ff9b:1::808:808",
            "64:ff9b:1::a9fe:a9fe",
        ] {
            assert!(p.check_ip(ip(s)).is_err(), "{s} 应被拒绝");
        }
    }

    #[test]
    fn blocks_other_non_global_ranges() {
        let p = policy();
        for s in [
            "100.64.0.1",
            "100.127.255.254",
            "100.100.100.200",
            "192.0.0.1",
            "192.0.0.192",
            "192.0.2.1",
            "198.51.100.1",
            "203.0.113.1",
            "198.18.0.1",
            "198.19.255.255",
            "192.88.99.1",
            "240.0.0.1",
            "255.255.255.255",
            "::",
            "::a9fe:a9fe",
            "::ffff:0:a9fe:a9fe",
            "100::1",
            "fec0::1",
            "5f00::1",
            "4000::1",
            "2001::1",
            "2001:2::1",
            "2001:db8::1",
            "3fff::1",
            "2002:a9fe:a9fe::1",
            "2002:808:808::1",
        ] {
            assert!(p.check_ip(ip(s)).is_err(), "{s} 应被拒绝");
        }
    }

    #[test]
    fn allows_public_addresses() {
        let p = policy();
        for s in [
            "8.8.8.8",
            "1.1.1.1",
            "100.63.255.255",
            "100.128.0.1",
            "172.32.0.1",
            "198.20.0.1",
            "2001:4860:4860::8888",
            "2606:4700:4700::1111",
            "::ffff:8.8.8.8",
            "64:ff9b::808:808",
        ] {
            assert!(p.check_ip(ip(s)).is_ok(), "{s} 应放行");
        }
    }

    #[test]
    fn metadata_blocked_even_when_private_allowed() {
        let p = policy_with(|c| c.block_private_ips = false);
        for s in [
            "169.254.169.254",
            "169.254.170.2",
            "fd00:ec2::254",
            "fe80::1",
            "::ffff:169.254.169.254",
            "64:ff9b::a9fe:a9fe",
            "100.100.100.200",
            "192.0.0.192",
            "168.63.129.16",
        ] {
            assert!(
                matches!(p.check_ip(ip(s)), Err(SecurityError::MetadataAddress(_))),
                "{s} 应始终被拒绝"
            );
        }
        assert!(p.check_ip(ip("10.0.0.1")).is_ok());
        assert!(p.check_ip(ip("127.0.0.1")).is_ok());
    }

    #[test]
    fn blocked_cidrs_are_enforced() {
        let p = policy_with(|c| {
            c.blocked_cidrs = vec![
                "1.2.3.0/24".into(),
                "2a00:1450::/32".into(),
                "::ffff:9.9.9.9".into(),
                "64:ff9b::/96".into(),
            ]
        });
        for s in [
            "1.2.3.4",
            "::ffff:1.2.3.4",
            "2a00:1450:4001::1",
            "9.9.9.9",
            "64:ff9b::808:808",
        ] {
            assert!(
                matches!(p.check_ip(ip(s)), Err(SecurityError::DeniedNetwork(_))),
                "{s} 应命中 blocked_cidrs"
            );
        }
        assert!(p.check_ip(ip("1.2.4.1")).is_ok());
        assert!(p.check_ip(ip("8.8.8.8")).is_ok());
        assert!(p.check_target("1.2.3.4", 443).is_err());
    }

    #[test]
    fn blocked_cidrs_block_exact_ips() {
        // 单个 IP 只拦截它本身，不影响相邻地址；IPv4-mapped / NAT64 写法同样命中；
        // 不受 block_private_ips 与域名白名单影响；DNS 解析结果命中同样拒绝。
        let p = policy_with(|c| {
            c.block_private_ips = false;
            c.domain_allowlist = vec!["93.184.216.34".into(), "*.example.com".into()];
            c.blocked_cidrs = vec![
                "93.184.216.34".into(),
                "10.1.2.3".into(),
                "2606:2800:220:1::1".into(),
            ];
        });
        for s in [
            "93.184.216.34",
            "::ffff:93.184.216.34",
            "64:ff9b::5db8:d822",
            "10.1.2.3",
            "2606:2800:220:1::1",
        ] {
            assert!(
                matches!(p.check_ip(ip(s)), Err(SecurityError::DeniedNetwork(_))),
                "{s} 应被拦截"
            );
        }
        for s in ["93.184.216.35", "10.1.2.4", "2606:2800:220:1::2"] {
            assert!(p.check_ip(ip(s)).is_ok(), "{s} 不在列表中，应放行");
        }

        // 白名单里的 IP 命中拦截列表时仍被拒绝：拒绝优先。
        assert!(matches!(
            p.check_target("93.184.216.34", 443),
            Err(SecurityError::DeniedNetwork(_))
        ));
        // 域名本身合法，但解析结果里有被拦截的 IP，整个目标被拒绝。
        let resolved = vec![
            SocketAddr::from(([93, 184, 216, 35], 443)),
            SocketAddr::from(([93, 184, 216, 34], 443)),
        ];
        assert!(matches!(
            p.check_resolved("www.example.com", resolved),
            Err(SecurityError::DeniedNetwork(_))
        ));
    }

    #[test]
    fn invalid_rules_fail_fast() {
        for bad in ["10.0.0.0/33", "not-a-cidr", "10.0.0.0/", "fd00::/129"] {
            let cfg = SecurityConfig {
                blocked_cidrs: vec![bad.into()],
                ..SecurityConfig::default()
            };
            assert!(SecurityPolicy::from_config(&cfg).is_err(), "{bad}");
        }
        for bad in [
            "http://evil.example.com",
            "*evil.com",
            "evil.com/path",
            "*.1.2.3.4",
            "*.*.example.com",
            "0x7f.1",
        ] {
            let cfg = SecurityConfig {
                domain_blocklist: vec![bad.into()],
                ..SecurityConfig::default()
            };
            assert!(SecurityPolicy::from_config(&cfg).is_err(), "{bad}");
        }
        // 空白条目照旧忽略。
        let cfg = SecurityConfig {
            domain_blocklist: vec!["".into(), "  ".into()],
            blocked_cidrs: vec![" ".into()],
            ..SecurityConfig::default()
        };
        assert!(SecurityPolicy::from_config(&cfg).is_ok());
    }

    #[test]
    fn rejects_internal_domains() {
        let p = policy();
        for s in [
            "localhost",
            "LOCALHOST.",
            "metadata",
            "instance-data",
            "kubernetes",
            "app.localhost",
            "printer.local",
            "api.default.svc.cluster.local",
            "metadata.google.internal",
            "ip-10-0-0-1.ec2.internal",
            "router.home.arpa",
            "home.arpa",
            "host.localdomain",
            "x.test",
            "x.invalid",
            "x.example",
            "xyz.onion",
            "x.alt",
            "dc01.corp",
            "nas.home",
            "smtp.mail",
        ] {
            assert!(
                matches!(p.check_target(s, 80), Err(SecurityError::InternalDomain(_))),
                "{s} 应被识别为内部域名"
            );
        }
        for s in [
            "example.com",
            "local.com",
            "notlocal.io",
            "internal.example.com",
            "corp.example.com",
            "localhost.example.com",
        ] {
            assert!(p.check_target(s, 80).is_ok(), "{s} 应放行");
        }

        let relaxed = policy_with(|c| c.block_internal_domains = false);
        assert!(relaxed.check_target("localhost", 80).is_ok());
        assert!(relaxed.check_target("printer.local", 80).is_ok());
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
        assert!(p.check_target("[::ffff:127.0.0.1]", 80).is_err());
        assert!(p.check_target("0x7f.1", 80).is_err());
        assert!(p.check_target("example.com", 22).is_err());
        assert!(p.check_target("8.8.8.8", 443).is_ok());
    }

    #[test]
    fn non_canonical_ip_cannot_bypass_ip_literal_policy() {
        let p = policy_with(|c| c.block_ip_literals = true);
        assert!(matches!(
            p.check_target("8.8.8.8", 443),
            Err(SecurityError::IpLiteral(_))
        ));
        // 0x08080808 / 134744072 都会被 getaddrinfo 解析成 8.8.8.8。
        for s in ["0x08080808", "134744072", "8.8.2056"] {
            assert!(
                matches!(
                    p.check_target(s, 443),
                    Err(SecurityError::NonCanonicalIp(_))
                ),
                "{s}"
            );
        }
    }

    #[test]
    fn check_resolved_rejects_any_blocked_address() {
        let p = policy();
        let mixed = vec![
            SocketAddr::from(([8, 8, 8, 8], 80)),
            SocketAddr::from(([10, 3, 0, 5], 80)),
        ];
        assert!(matches!(
            p.check_resolved("example.com", mixed),
            Err(SecurityError::PrivateAddress(_))
        ));
        let metadata = vec![SocketAddr::from(([169, 254, 169, 254], 80))];
        assert!(matches!(
            p.check_resolved("example.com", metadata),
            Err(SecurityError::MetadataAddress(_))
        ));
        assert!(matches!(
            p.check_resolved("example.com", Vec::new()),
            Err(SecurityError::NoPublicAddress(_))
        ));

        let public = vec![
            SocketAddr::from(([8, 8, 8, 8], 443)),
            "[2001:4860:4860::8888]:443".parse().unwrap(),
            "[::ffff:1.1.1.1]:443".parse().unwrap(),
        ];
        let allowed = p.check_resolved("example.com", public).unwrap();
        assert_eq!(allowed.len(), 3);
        // IPv4-mapped 地址按 IPv4 建连。
        assert_eq!(allowed[2], SocketAddr::from(([1, 1, 1, 1], 443)));
    }

    #[test]
    fn domain_rules_match() {
        let cfg = SecurityConfig {
            domain_allowlist: vec!["*.example.com".into(), "api.partner.io".into()],
            domain_blocklist: vec!["evil.example.com".into()],
            ..SecurityConfig::default()
        };
        let p = SecurityPolicy::from_config(&cfg).unwrap();
        assert!(p.check_target("api.example.com", 443).is_ok());
        assert!(p.check_target("API.Partner.IO.", 443).is_ok());
        assert!(p.check_target("example.com", 443).is_err());
        assert!(p.check_target("evil.example.com", 443).is_err());
        assert!(p.check_target("other.partner.io", 443).is_err());
    }

    #[test]
    fn ip_rules_use_canonical_form() {
        let p = policy_with(|c| {
            c.domain_allowlist = vec![
                "2001:4860:4860:0:0:0:0:8888".into(),
                "[::ffff:1.1.1.1]".into(),
            ]
        });
        assert!(p.check_target("[2001:4860:4860::8888]", 443).is_ok());
        assert!(p.check_target("1.1.1.1", 443).is_ok());
        assert!(p.check_target("[::ffff:1.1.1.1]", 443).is_ok());
        assert!(p.check_target("8.8.8.8", 443).is_err());
    }

    #[test]
    fn scheme_and_userinfo_checks() {
        assert!(check_forward_scheme(None).is_ok());
        assert!(check_forward_scheme(Some("http")).is_ok());
        assert!(check_forward_scheme(Some("HTTP")).is_ok());
        for s in ["https", "ftp", "gopher", "file", "dict", "ws"] {
            assert!(
                matches!(
                    check_forward_scheme(Some(s)),
                    Err(SecurityError::SchemeNotAllowed(_))
                ),
                "{s}"
            );
        }
        assert!(check_no_userinfo("example.com:80").is_ok());
        assert!(check_no_userinfo("[::1]:80").is_ok());
        assert!(matches!(
            check_no_userinfo("user:pass@example.com"),
            Err(SecurityError::UserInfo)
        ));
        assert!(matches!(
            check_no_userinfo("example.com@127.0.0.1"),
            Err(SecurityError::UserInfo)
        ));
    }

    #[test]
    fn finds_security_error_in_error_chain() {
        #[derive(Debug)]
        struct Outer(std::io::Error);
        impl fmt::Display for Outer {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("outer")
            }
        }
        impl StdError for Outer {
            fn source(&self) -> Option<&(dyn StdError + 'static)> {
                Some(&self.0)
            }
        }

        let blocked = Outer(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            SecurityError::PrivateAddress(ip("10.0.0.1")),
        ));
        assert_eq!(
            find_security_error(&blocked).map(SecurityError::reason),
            Some("private_ip")
        );
        let refused = Outer(std::io::Error::new(
            std::io::ErrorKind::ConnectionRefused,
            "refused",
        ));
        assert!(find_security_error(&refused).is_none());
    }

    /// 用真实的 hyper-util `HttpConnector` + `Client` 验证：解析器在建连阶段
    /// 返回的 SecurityError 能穿过 hyper-util 的错误包装被还原出来。
    #[tokio::test]
    async fn resolver_rejection_survives_hyper_util_error_chain() {
        use bytes::Bytes;
        use http_body_util::Full;
        use hyper_util::client::legacy::connect::HttpConnector;
        use hyper_util::client::legacy::Client;
        use hyper_util::rt::TokioExecutor;

        #[derive(Clone)]
        struct DenyAll;
        impl Service<Name> for DenyAll {
            type Response = std::vec::IntoIter<SocketAddr>;
            type Error = std::io::Error;
            type Future = std::future::Ready<std::io::Result<Self::Response>>;

            fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
                Poll::Ready(Ok(()))
            }

            fn call(&mut self, _name: Name) -> Self::Future {
                std::future::ready(Err(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    SecurityError::PrivateAddress(ip("10.0.0.1")),
                )))
            }
        }

        let client = Client::builder(TokioExecutor::new())
            .build::<_, Full<Bytes>>(HttpConnector::new_with_resolver(DenyAll));
        let req = hyper::Request::get("http://rebound.example.com/")
            .body(Full::new(Bytes::new()))
            .unwrap();
        let err = client.request(req).await.unwrap_err();
        assert_eq!(
            find_security_error(&err).map(SecurityError::reason),
            Some("private_ip")
        );
    }

    #[test]
    fn client_message_hides_resolved_addresses() {
        let e = SecurityError::PrivateAddress(ip("10.1.2.3"));
        // 服务端日志保留细节，客户端只拿到原因标签。
        assert!(e.to_string().contains("10.1.2.3"));
        assert!(!e.client_message().contains("10.1.2.3"));
        assert!(e.client_message().contains("private_ip"));
    }

    #[test]
    fn cidr_contains() {
        let c = Cidr::parse("10.3.0.0/16").unwrap();
        assert!(c.contains(ip("10.3.255.1")));
        assert!(!c.contains(ip("10.4.0.1")));
        // 地址族不同不匹配；调用方负责先规范化。
        assert!(!c.contains(ip("::ffff:10.3.0.1")));
        assert!(Cidr::parse("10.3.1.5/16").unwrap().contains(ip("10.3.9.9")));
        assert!(Cidr::parse("0.0.0.0/0").unwrap().contains(ip("8.8.8.8")));
        assert!(Cidr::parse("::/0").unwrap().contains(ip("2001:db8::1")));
        assert!(Cidr::parse("8.8.8.8").unwrap().contains(ip("8.8.8.8")));
        assert!(!Cidr::parse("8.8.8.8").unwrap().contains(ip("8.8.8.9")));
        assert_eq!(
            Cidr::parse("::ffff:10.0.0.0/104").unwrap(),
            Cidr::parse("10.0.0.0/8").unwrap()
        );
    }
}
