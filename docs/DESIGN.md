# rust-http-proxy 设计与实现规范

> 高性能 Rust HTTP/HTTPS 正向代理，原生 Prometheus metrics 与
> OpenObserve 日志上报，支持端口复用、DNS 缓存、上游连接池。

---

## 1. 目标与非目标

### 1.1 设计目标
- **强并发**：单进程支撑 5w+ QPS、十万级长连接。
- **可观测**：完整暴露 Prometheus 指标，支持外部抓取与告警。
- **结构化日志**：所有访问日志异步上报到 OpenObserve，并带统一
  `trace_id`，便于全链路追踪。
- **资源友好**：通过端口复用 + 上游连接池减少端口/句柄消耗。
- **代码安全**：纯 `safe Rust`，不使用 `unsafe`；统一错误处理；超时与
  反压贯穿全链路。

### 1.2 非目标
- 反向代理 / 负载均衡（不在本次范围）。
- SOCKS5 完整实现（保留指标命名空间，便于未来扩展）。
- 鉴权认证（如 Basic 代理认证），可后续以中间件方式追加。

---

## 2. 总体架构

```
                       ┌──────────────────────────────────────┐
                       │                main()                │
                       │  load config / init metrics / spawn  │
                       └─────────────┬────────────────────────┘
                                     │
   ┌────────────────────────┐        │        ┌────────────────────────┐
   │ /metrics HTTP server    │◀──────┤        │ OpenObserve log task   │
   │ (hyper, port 9090)      │       │        │  (mpsc + reqwest)      │
   └────────────────────────┘       │        └────────────────────────┘
                                     │                  ▲
                                     │                  │ LogEntry
                                     ▼                  │ (非阻塞 try_send)
                       ┌──────────────────────────────────────┐
                       │   N × accept loop (SO_REUSEPORT)     │
                       │   one Tokio task per worker          │
                       └─────────────┬────────────────────────┘
                                     │ TcpStream
                                     ▼
                       ┌──────────────────────────────────────┐
                       │   proxy::handle_client (per conn)    │
                       │  hyper::server::http1 + service_fn   │
                       └─────────────┬────────────────────────┘
                                     │
              ┌──────────────────────┴────────────────────────┐
              │                                               │
              ▼                                               ▼
   ┌──────────────────┐                            ┌──────────────────────┐
   │  HTTP forward    │                            │  HTTPS CONNECT tunnel│
   │  (build req,     │                            │  (200 then bi-copy)  │
   │   send_request)  │                            │                      │
   └────────┬─────────┘                            └─────────┬────────────┘
            │                                                │
            ▼                                                ▼
   ┌────────────────────────────────┐         ┌────────────────────────────┐
   │ DNS cache (DashMap, TTL=60s)   │◀────────┤  upstream TCP (SO_NODELAY) │
   └────────────────────────────────┘         └────────────────────────────┘
```

### 2.1 模块划分
| 模块 | 文件 | 职责 |
|------|------|------|
| 配置 | `src/config.rs` | TOML + 环境变量加载 |
| 监听器 | `src/listener.rs` | `SO_REUSEADDR/SO_REUSEPORT` Socket 构造 |
| DNS | `src/dns.rs` | TTL 缓存 + 容量保护 |
| Metrics | `src/metrics.rs` | Prometheus 指标定义与进程采样 |
| Metrics HTTP | `src/metrics_server.rs` | `/metrics` 端点 |
| 日志 | `src/logger.rs` | OpenObserve 异步批量上报 |
| 代理核心 | `src/proxy.rs` | HTTP 转发 + HTTPS CONNECT 隧道 |
| 主入口 | `src/main.rs` | 组装与运行时编排 |

---

## 3. 关键技术决策

### 3.1 异步运行时：Tokio + Hyper
- 使用 Tokio 多线程 runtime（默认 worker = CPU 核数）。
- 选择 hyper 1.x：成熟、零拷贝、HTTP/1 与 HTTP/2 兼备；其
  `service_fn` 闭包模型与 keep-alive 支持非常适合代理场景。
- `hyper_util::rt::TokioIo` 适配 hyper IO trait 与 tokio AsyncRead/Write。

### 3.2 端口复用 (SO_REUSEPORT)
- 通过 `socket2::Socket` 设置 `SO_REUSEADDR + SO_REUSEPORT`，由内核
  在多个监听 fd 间均衡分发新连接。
- 配合启动多个 worker（默认 = CPU 核数）的 accept 循环，避免
  单 accept 锁热点。
- 重启时无 `TIME_WAIT` 阻塞 bind 的烦恼。

### 3.3 上游连接复用
- 对 HTTP 转发：使用 `hyper_util::client::legacy::Client` + `HttpConnector`，
  内置 per-host keep-alive 池。池参数走配置 `upstream.pool_max_idle_per_host`
  与 `upstream.pool_idle_timeout_secs`。高并发请求同一目标时，仅在池满或
  连接被对端关闭时才会触发新建连接，**显著减少本机出向端口消耗**
  （否则极易在 `2k+ QPS / 同一目标`场景触发 `EADDRNOTAVAIL`）。
- 对 HTTPS CONNECT：隧道天然 1:1，无法跨用户复用；每次现连。

### 3.4 DNS 缓存
- 数据结构：`DashMap<String, CacheEntry>`，分片锁并发读写。
- TTL 60s（可配置）；惰性过期 + 软容量上限。
- 命中/未命中分别打点到 `proxy_dns_cache_hits_total` /
  `proxy_dns_cache_misses_total`。

### 3.5 Metrics
- 全量使用 `prometheus` crate；统一通过 `Registry::gather` 输出
  text 格式。
- 进程级 CPU/内存由独立 task 每 5 秒采样一次，依赖
  `sysinfo`。CPU 百分比乘 100 存为 int64 gauge，方便 Grafana 直接
  做百分比图。
- 主要指标列表见 `docs/METRICS.md`。

### 3.6 日志上报
- 业务线程调用 `LogSink::emit()`，内部为 `tokio::sync::mpsc::try_send`，
  **绝不阻塞**热路径。
- 后台 task 维护批量 buffer：达到 `batch_size` 或 `flush_interval_ms`
  超时即触发一次 `POST /api/{org}/{stream}/_json`。
- HTTP 客户端为 `reqwest` + rustls + gzip；连接池长保 60s。
- 通道满或失败均按 `warn!` 记录到本地 tracing，永不重试无限放大。
- **OpenObserve 未启用时降级到 console**：`LogSink::console()` 把每条
  访问日志走 `tracing::info!("access", trace_id=..., event=..., fields=...)`,
  受 `RUST_LOG` 控制。本地开发或外发未配置时也能立刻看到访问日志。
- **上游失败的根因可观察**：CONNECT/HTTP 转发路径在 DNS 解析、TCP 建连、
  上游请求三个失败点都会以 `warn!` 输出 `client=peer host=h:p kind=ErrorKind error=msg`,
  让 `EADDRNOTAVAIL`（本机端口耗尽）、`ECONNREFUSED`（远端拒绝）、`timeout`
  这种问题可以从日志直接定位，无需翻指标。

### 3.7 trace_id 提取
- HTTP 转发场景：收齐请求体后调用 `extract_trace_id(body)`，尝试
  `serde_json::from_slice` 解析；若得到顶层字段 `dis_order_no`（非空
  字符串），即用之，否则退化为 `Uuid::new_v4()`。
- CONNECT 场景：请求体不可读（端到端 TLS），直接生成 UUID v4。

### 3.8 安全性与正确性
- 全部 `safe Rust`，无 `unsafe`。
- hop-by-hop 头部统一剥除（RFC 7230 §6.1）。
- 所有上游 IO 均有显式超时（建连、send_request、tunnel 读写）。
- mpsc 通道有界，`try_send` 失败即丢弃，杜绝日志背压拖垮主路径。
- 错误以 `thiserror` 枚举分类后映射到 metrics 标签与 HTTP 状态码。

---

## 4. 启动与配置

### 4.1 运行
```bash
cargo build --release
RUST_LOG=info ./target/release/rust-http-proxy
```

### 4.2 配置项（`config.toml`）
所有字段可被环境变量覆盖（见 `src/config.rs::apply_env_overrides`）：

| Env | 作用 |
|-----|------|
| `PROXY_LISTEN` | 代理监听地址 |
| `METRICS_LISTEN` | Prometheus 端点地址 |
| `OO_ENABLED` | 是否启用 OpenObserve 上报 |
| `OO_ENDPOINT` / `OO_ORG` / `OO_STREAM` | OpenObserve 目标 |
| `OO_USERNAME` / `OO_PASSWORD` | Basic Auth 凭证 |

---

## 5. 性能与容量目标

| 维度 | 目标值 | 说明 |
|------|--------|------|
| QPS（HTTP，1KB 请求） | ≥ 50,000/核 | 受限于上游 RTT，理论上线远高 |
| 并发连接 | ≥ 100,000 | 由 Tokio + 端口复用支撑 |
| P99 处理延迟（不含上游 RTT） | < 5 ms | hyper + 无锁 DNS 缓存 |
| 上游建连耗时 | 命中 DNS 缓存时 ≤ 1 ms（局域网） | DNS 缓存核心收益 |

> 实测请以业务流量为准；可结合 `proxy_request_duration_seconds`
> 直方图与 `process_cpu_percent` 监控持续调优 worker 数和池大小。

---

## 6. 测试与验证

### 6.1 单元/集成测试建议
- `dns.rs`：mock 时间源验证 TTL 过期与容量驱逐。
- `proxy.rs`：使用 `tokio::net::TcpListener` 起一个 mock 上游，
  发起 `CONNECT` 与普通 GET，断言流量统计。
- `logger.rs`：用 `httpmock` 验证批量与 flush 间隔行为。

### 6.2 压测命令示例
```bash
# HTTP
wrk -t8 -c1000 -d30s --header "Host: target.local" \
  http://127.0.0.1:8080/path -x http://127.0.0.1:8080

# HTTPS 隧道
curl -x http://127.0.0.1:8080 https://example.com -v
```

---

## 7. 后续演进

- ✅ HTTP/HTTPS 正向代理
- ⏳ SOCKS5：metric 命名空间已留好，新增 `src/socks.rs` 即可接入
- ⏳ Basic 代理鉴权 / IP 白名单
- ⏳ 上游连接池接入 `hyper_util::client::legacy::Client`
- ⏳ 启动期热加载配置（SIGHUP）
- ⏳ HTTP/2 ALPN（hyper 已支持，仅需切换 server builder）
