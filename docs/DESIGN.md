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
| DNS | `src/dns.rs` | TTL 缓存 + 容量保护（按域名缓存 IP） |
| 安全策略 | `src/security.rs` | SSRF 防护、端口/域名黑白名单、DNS resolver |
| Metrics | `src/metrics.rs` | Prometheus 指标定义、有界 host 基数与进程采样 |
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
- 设置 `pool_timer` 后空闲连接由后台任务按 `pool_idle_timeout_secs` 主动回收；
  不设置时 hyper-util 只在复用时检查过期，长期不再访问的上游连接会一直占着内存与 fd。
- 对 HTTPS CONNECT：隧道天然 1:1，无法跨用户复用；每次现连。

### 3.4 DNS 缓存
- 数据结构：`DashMap<String, CacheEntry>`，分片锁并发读写。
- 缓存按域名保存 **IP 列表**（不含端口），HTTP 与 CONNECT 共用同一份缓存；
  同一域名的 80/443 等端口共享解析结果。
- TTL 60s（可配置）；惰性过期 + 软容量上限（优先清过期，其次随机驱逐）。
- 命中/未命中分别打点到 `proxy_dns_cache_hits_total` /
  `proxy_dns_cache_misses_total`；当前条目数暴露为 `proxy_dns_cache_entries`。
- **singleflight**：同一域名并发未命中时只发起一次 getaddrinfo，其余请求等待同一结果；
  缓存过期瞬间的并发请求不会各自占用一个阻塞线程。
- **解析并发上限**：同时进行的 getaddrinfo 不超过 `dns.max_concurrent_lookups`，名额在
  getaddrinfo 真正返回时才释放（它无法取消），tokio 阻塞线程池按同一数值封顶。DNS 故障时
  新的解析在异步等待名额阶段超时，不会在阻塞线程池队列中堆积。

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
- **访问日志在响应体传完时上报**：`proxy.request` 的 `bytes_down` 为实际转发字节；
  响应体没有完整送达（上游出错、空闲超时、客户端提前断开）时 level 为 WARN 并带 `error` 字段。
- **失败与客户端放弃的请求同样有访问日志**：返回错误响应时上报 level=WARN 的
  `proxy.request` / `proxy.connect`（含 `status`、`reason`、`error`、`duration_ms`）。客户端在
  代理给出响应前断开时，hyper 直接丢弃请求处理的 future，由 `PendingRequest` 的 Drop 补记
  `reason=client_closed`；进程退出时被运行时丢弃的请求不计。
- **上游失败的根因可观察**：CONNECT/HTTP 转发路径在 DNS 解析、TCP 建连、
  上游请求三个失败点都会以 `warn!` 输出 `client=peer host=h:p kind=ErrorKind error=msg`,
  让 `EADDRNOTAVAIL`（本机端口耗尽）、`ECONNREFUSED`（远端拒绝）、`timeout`
  这种问题可以从日志直接定位，无需翻指标。

### 3.7 trace_id 提取
- HTTP 转发场景：请求体不超过 `server.max_buffered_body_bytes`（默认 256 KiB）时整体缓冲，
  用只含 `dis_order_no` 一个字段的结构体反序列化（其余字段跳过，不构建 JSON 树），取顶层的
  非空字符串；更大的请求体流式转发，trace_id 取 `X-PROXY-TRACE-ID` 请求头，否则退化为
  `Uuid::new_v4()`。
- CONNECT 场景：请求体不可读（端到端 TLS），直接生成 UUID v4。

### 3.8 安全性与正确性
- 全部 `safe Rust`，无 `unsafe`。
- hop-by-hop 头部统一剥除（RFC 7230 §6.1）。
- 所有 IO 均有显式超时：建连超时；上游 IO 空闲超时（请求体上传、等待响应头、
  响应体下载、隧道读写，持续有数据流动就不会触发）；客户端请求头超时（含 keep-alive 空闲）。
- mpsc 通道有界，`try_send` 失败即丢弃，杜绝日志背压拖垮主路径。
- 错误以 `thiserror` 枚举分类后映射到 metrics 标签与 HTTP 状态码。

### 3.9 目标地址安全策略（SSRF / 钓鱼域名）
正向代理是天然的 SSRF 放大器，因此把"目标可达性"作为安全边界，设计参考 OWASP
*Server-Side Request Forgery Prevention Cheat Sheet*。代理的目标是任意外部域名/IP，
对应其中的 "Case 2"（拒绝列表 + 建连时强制校验）；配置 `domain_allowlist` 后收紧为
"Case 1"（白名单）。

| OWASP 建议 | 实现 |
|-----------|------|
| 只允许 HTTP/HTTPS | 普通转发只接受 `http` 绝对 URI；`https://`、`ftp://`、`gopher://`、`file://` 等返回 403（`reason=scheme`）。HTTPS 走 CONNECT |
| 用库校验 IP，防 Hex/Octal/Dword/Mixed 编码绕过 | `std::net::IpAddr` 只接受标准写法；最后一段是数字的主机名（WHATWG "ends in a number"）一律拒绝（`ip_encoding`），否则 getaddrinfo 会把 `0x7f.1` 解析成 127.0.0.1 |
| 比对拒绝列表前先规范化 | IPv4-mapped、NAT64 `64:ff9b::/96` 先还原为内嵌 IPv4；配置规则与客户端输入走同一个 `normalize_host` |
| 最小拒绝列表（IMDS、回环、RFC1918、链路本地、ULA、组播、NAT64…） | IPv4 按 IANA 特殊用途地址表全部拒绝；IPv6 只放行 `2000::/3` 全球单播，再排除其中的 Teredo/6to4/文档段；云元数据地址单独成表，`block_private_ips=false` 时仍拒绝（`metadata_ip`） |
| 防 DNS rebinding：只连接校验过的地址，校验与建连之间不能有未校验的解析 | HTTP：`SafeResolver` 接入 `HttpConnector`，连接池建连前对实际使用的地址校验；CONNECT：直接连接校验后的地址。解析结果中任一地址受限即拒绝整个目标 |
| 重试与回退连接同样校验 | Happy Eyeballs 回退与连接池重试都只从 `SafeResolver` 校验后的地址里选 |
| 禁止跟随重定向 | 代理不跟随上游 3xx（原样返回，客户端的下一跳请求重新校验）；OpenObserve 上报客户端设置 `redirect::Policy::none()` |
| 解析器读法不一致时直接拒绝 | 拒绝 userinfo（`trusted.com@evil.com`，RFC 9110 §4.2.4）与重复 Host 头；绝对 URI 优先并覆盖 Host 头 |
| 维护内部域名列表，避免把内部名发给外部 DNS | 解析前拒绝单标签主机名与 `.internal`/`.local`/`.localhost`/`.home.arpa` 等内部后缀（`internal_domain`）；公司自有内网域名加入 `domain_blocklist` |
| 网络层隔离 | systemd `IPAddressDeny=` 丢弃与元数据端点之间的报文；FreeBSD 提供按用户限制出站的 PF 规则示例；入站由 PF / 安全组限制为 VPC |

补充说明：
- 拦截响应只返回 `reason=<标签>`，不回显解析出的地址，避免代理沦为内网 DNS 探测器；
  完整原因（含地址）写入 `warn!` 日志与 `proxy.blocked` 访问日志事件。
- 预检查之后 DNS 结果发生变化时，`SafeResolver` 在建连阶段拒绝；错误经
  `find_security_error` 从 hyper-util 错误链中还原，仍按 403 与
  `proxy_security_blocked_total` 统计，而不是记成上游 502。
- `blocked_cidrs` 用于补充"公网地址但信任本代理出口 IP"的目标；网段或域名规则写错时
  启动失败，避免以为已拦截的目标实际可达。
- 不通过给目标名追加根点（`example.com.`）来绕开 resolv.conf 的 search 域：实测 glibc
  会因此跳过 `/etc/hosts`，破坏 hosts 覆盖与基于 hosts 的拦截。单标签主机名已在解析前
  被拒绝，经 search 域补全出的内网名字仍会被地址校验拦下。
- `allowed_ports` 默认只放行 80/443，降低借代理做端口探测的风险；`domain_allowlist` /
  `domain_blocklist` 支持精确域名与 `*.example.com` 通配，可在网关侧拦截已知钓鱼/恶意域名。
- host 维度指标基数由 `[metrics] max_host_labels` 限制；达到上限后新 host
  折叠为 `other`，避免攻击者用海量随机域名制造 Prometheus label 内存膨胀。
- 被拦截目标通过 `proxy_security_blocked_total{reason}` 观测。

---

### 3.10 内存与连接资源
目标是让单个请求的内存与 body 大小无关、总内存只随并发连接数线性增长，以便在 2 核
512 MB 的机器上稳定运行（推荐配置见 README「小内存机器调优」）。

| 资源 | 控制方式 |
|------|---------|
| 响应体 | 流式转发（`body::ResponseBody`），每帧累加 `proxy_bytes_down_total`；等待上游数据超过 `io_timeout_secs` 即中断 |
| 请求体 | 不超过 `max_buffered_body_bytes` 时整体缓冲（提取 `dis_order_no`），超过则"已读前缀 + 剩余部分"流式上传（`body::buffer_or_stream`） |
| 单连接缓冲 | 客户端侧与上游侧的 hyper 读写缓冲上限均为 64 KiB（默认约 400 KiB），同时也是请求头 / 响应头的大小上限 |
| 空闲 / 慢速客户端 | hyper 设置 timer 后 `header_read_timeout`（= `client_idle_timeout_secs`）生效，覆盖 keep-alive 空闲期与 slowloris |
| 并发连接 | `max_connections`：达到上限后暂停 accept，新连接在内核 backlog 排队；计数见 `proxy_connections_throttled_total` |
| 阻塞线程 | `dns.max_concurrent_lookups` 同时限制 getaddrinfo 并发与阻塞线程池大小，并配合 singleflight |
| 上游空闲连接 | `pool_timer` 主动回收，`pool_max_idle_per_host` 限制每个上游的空闲连接数 |
| 其他有界结构 | DNS 缓存 `max_entries`、host 指标标签 `max_host_labels`、日志通道 `channel_capacity` |

超时按"空闲"而非"总时长"计算（`body::Activity` / `body::idle_timeout`）：只要请求体还在
上传或响应体还在下载就不会被中断；请求体传完后，"空闲"就是等待上游响应头的时间。
响应体的空闲计时只在等待上游数据时进行，客户端读得慢（背压）不算上游空闲。

Linux 实测（release 构建，绑定 2 核）：

| 场景 | 改动前峰值 RSS | 改动后峰值 RSS |
|------|---------------|---------------|
| 经代理下载 200 MiB | 208 MiB | 6.3 MiB |
| 4 路 50 MiB 并发下载 | 224.5 MiB | 6.7 MiB |
| 上传 100 MiB | 233.9 MiB | 6.9 MiB |
| 300 个并发 DNS 未命中 | 约 300 个线程 | 70 个线程（64 + 基础线程）|
| 2000 条 slowloris 连接（35 s 后） | 全部仍在 | 全部被回收 |

`tests/resource_e2e.rs` 以端到端测试固定了上述行为（大文件上传 / 下载峰值内存上限、
空闲与慢速连接回收、并发连接上限）。

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
| `PROXY_CONFIG` | 配置文件路径（默认 `config.toml`） |

`[security]` 与 `[metrics] max_host_labels` 的说明见 `config.toml` 注释。

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
