//! 配置加载模块。
//!
//! 该模块负责从 `config.toml` 文件以及环境变量中读取配置，并提供给
//! 其它模块只读访问。所有字段均使用 `serde` 反序列化，且对常用字段
//! 提供合理的默认值，方便在容器环境中以最小配置启动。

use std::path::Path;

use serde::Deserialize;

/// 顶层配置结构，对应 `config.toml` 文件的全部内容。
#[derive(Debug, Clone, Default, Deserialize)]
pub struct Config {
    /// 代理服务端相关配置。
    #[serde(default)]
    pub server: ServerConfig,
    /// Prometheus 指标暴露配置。
    #[serde(default)]
    pub metrics: MetricsConfig,
    /// DNS 缓存相关配置。
    #[serde(default)]
    pub dns: DnsConfig,
    /// 上游连接池配置。
    #[serde(default)]
    pub upstream: UpstreamConfig,
    /// OpenObserve 日志上报配置。
    #[serde(default)]
    pub openobserve: OpenObserveConfig,
}

/// 代理监听与 worker 行为配置。
#[derive(Debug, Clone, Deserialize)]
pub struct ServerConfig {
    /// 代理监听地址，例如 `0.0.0.0:8080`。
    pub listen: String,
    /// 启动多少个使用 SO_REUSEPORT 共享监听端口的 worker；0 表示 CPU 核数。
    pub workers: usize,
    /// 单条连接的整体读写超时（秒）。
    pub io_timeout_secs: u64,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            listen: "0.0.0.0:8080".to_string(),
            workers: 0,
            io_timeout_secs: 60,
        }
    }
}

/// Prometheus 指标接口监听配置。
#[derive(Debug, Clone, Deserialize)]
pub struct MetricsConfig {
    /// `/metrics` HTTP 接口监听地址。
    pub listen: String,
}

impl Default for MetricsConfig {
    fn default() -> Self {
        Self {
            listen: "0.0.0.0:9090".to_string(),
        }
    }
}

/// DNS 缓存配置。
#[derive(Debug, Clone, Deserialize)]
pub struct DnsConfig {
    /// 缓存生存时间（秒）。
    pub ttl_secs: u64,
    /// 最大缓存条目数，防止解析极多域名时内存膨胀。
    pub max_entries: usize,
}

impl Default for DnsConfig {
    fn default() -> Self {
        Self {
            ttl_secs: 60,
            max_entries: 10_000,
        }
    }
}

/// 上游连接池配置。
///
/// 池容量字段为后续接入 `hyper_util::client::legacy::Client` 预留，
/// 当前转发路径每请求建连，故暂未使用。
#[derive(Debug, Clone, Deserialize)]
pub struct UpstreamConfig {
    /// 每个 host 的最大空闲连接数。
    #[allow(dead_code)]
    pub pool_max_idle_per_host: usize,
    /// 空闲连接最长保持时长（秒）。
    #[allow(dead_code)]
    pub pool_idle_timeout_secs: u64,
    /// 建连超时（秒）。
    pub connect_timeout_secs: u64,
}

impl Default for UpstreamConfig {
    fn default() -> Self {
        Self {
            pool_max_idle_per_host: 64,
            pool_idle_timeout_secs: 90,
            connect_timeout_secs: 10,
        }
    }
}

/// OpenObserve 日志上报配置。
#[derive(Debug, Clone, Deserialize)]
pub struct OpenObserveConfig {
    /// 是否启用日志上报。
    pub enabled: bool,
    /// OpenObserve API 入口，例如 `https://api.openobserve.ai`。
    pub endpoint: String,
    /// 组织（org）名称。
    pub organization: String,
    /// 日志流（stream）名称。
    pub stream: String,
    /// HTTP Basic Auth 用户名。
    pub username: String,
    /// HTTP Basic Auth 密码或 API Token。
    pub password: String,
    /// 单批上报的最大日志条数。
    pub batch_size: usize,
    /// 强制刷新的最大间隔（毫秒）。
    pub flush_interval_ms: u64,
    /// 内部 channel 容量；满后将丢弃最旧日志。
    pub channel_capacity: usize,
}

impl Default for OpenObserveConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            endpoint: "http://127.0.0.1:5080".to_string(),
            organization: "default".to_string(),
            stream: "proxy_logs".to_string(),
            username: String::new(),
            password: String::new(),
            batch_size: 200,
            flush_interval_ms: 1000,
            channel_capacity: 10_000,
        }
    }
}

impl Config {
    /// 从指定路径加载 TOML 配置文件，并应用环境变量覆盖。
    ///
    /// 找不到文件时使用全部默认值；这样在容器化部署中可以只通过
    /// 环境变量来配置。
    pub fn load<P: AsRef<Path>>(path: P) -> anyhow::Result<Self> {
        let mut cfg = if path.as_ref().exists() {
            let content = std::fs::read_to_string(path.as_ref())?;
            toml::from_str::<Config>(&content)?
        } else {
            Config::default()
        };
        cfg.apply_env_overrides();
        Ok(cfg)
    }

    /// 将常用敏感字段以环境变量形式覆盖到配置中。
    ///
    /// 这样做的好处是：配置文件可入版本库，密钥仅注入容器环境。
    fn apply_env_overrides(&mut self) {
        if let Ok(v) = std::env::var("PROXY_LISTEN") {
            self.server.listen = v;
        }
        if let Ok(v) = std::env::var("METRICS_LISTEN") {
            self.metrics.listen = v;
        }
        if let Ok(v) = std::env::var("OO_ENDPOINT") {
            self.openobserve.endpoint = v;
        }
        if let Ok(v) = std::env::var("OO_ORG") {
            self.openobserve.organization = v;
        }
        if let Ok(v) = std::env::var("OO_STREAM") {
            self.openobserve.stream = v;
        }
        if let Ok(v) = std::env::var("OO_USERNAME") {
            self.openobserve.username = v;
        }
        if let Ok(v) = std::env::var("OO_PASSWORD") {
            self.openobserve.password = v;
        }
        if let Ok(v) = std::env::var("OO_ENABLED") {
            self.openobserve.enabled = matches!(v.as_str(), "1" | "true" | "TRUE" | "yes");
        }
    }
}
