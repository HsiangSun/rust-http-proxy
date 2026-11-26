# 指标手册

> Prometheus 端点：`GET http://<METRICS_LISTEN>/metrics`，文本格式
> （`text/plain; version=0.0.4`）。

## 1. 代理通用指标
| 指标名 | 类型 | 维度 | 说明 |
|--------|------|------|------|
| `proxy_requests_total` | counter | — | 收到的请求总数（HTTP + CONNECT）|
| `proxy_requests_success_total` | counter | `protocol`={http,https} | 处理成功的请求 |
| `proxy_requests_failure_total` | counter | `reason`={missing_host,dns,blocked,connect,handshake,upstream,body,timeout,client_closed} | 失败计数；`client_closed` 为客户端在代理返回响应前断开（多为客户端自身超时先到，如 Go `http.Client.Timeout`）|
| `proxy_active_connections` | gauge | — | 当前活跃客户端连接数，含已建立的 CONNECT 隧道（此前隧道建立后即不再计入）|
| `proxy_connections_throttled_total` | counter | — | 达到 `server.max_connections` 而暂停 accept 的次数；持续增长说明上限偏小 |
| `proxy_https_tunnels_total` | counter | — | HTTPS CONNECT 隧道总数 |
| `proxy_bytes_up_total` | counter | — | 客户端 → 上游 总字节数 |
| `proxy_bytes_down_total` | counter | — | 上游 → 客户端 总字节数（随流式转发实时累加）|
| `proxy_request_duration_seconds` | histogram | — | 请求生命周期耗时（秒，全局视图）；HTTP 转发计到响应体传完为止 |
| `proxy_request_duration_by_host_seconds` | histogram | `host`, `status` | 按上游 host 分维的耗时；host 基数受 `[metrics] max_host_labels` 限制，超出后记为 `other`；status 取 `2xx`/`3xx`/`4xx`/`5xx`/`tunnel`/`error`/`unknown` |
| `proxy_upstream_connect_seconds` | histogram | — | 上游 TCP 建连耗时（秒）|

## 2. DNS 指标
| 指标名 | 类型 | 说明 |
|--------|------|------|
| `proxy_dns_cache_hits_total` | counter | DNS 缓存命中 |
| `proxy_dns_cache_misses_total` | counter | DNS 缓存未命中（触发系统解析）|
| `proxy_dns_cache_entries` | gauge | 当前 DNS 缓存条目数 |

## 2.1 安全指标
| 指标名 | 类型 | 维度 | 说明 |
|--------|------|------|------|
| `proxy_security_blocked_total` | counter | `reason`，取值见下表 | 被目标安全策略拦截的请求数 |
| `proxy_metrics_host_label_overflow_total` | counter | — | host 维度标签达到上限后折叠为 `other` 的次数 |

`proxy_security_blocked_total` 的 `reason` 取值（与 403 响应体中的 `reason=` 一致）：

| reason | 含义 |
|--------|------|
| `scheme` | 普通转发使用了 `http` 以外的协议（`https://` 绝对 URI、`ftp://`、`gopher://` 等）|
| `userinfo` | 目标 authority 或 Host 头携带 `user@` |
| `invalid_host` | 主机名格式非法，或出现多个 Host 头 |
| `ip_encoding` | 十六进制/八进制/整数/省略段等非标准 IP 写法（如 `0x7f.1`、`2130706433`）|
| `port` | 目标端口不在 `allowed_ports` |
| `internal_domain` | 单标签主机名或 `.internal`/`.local`/`.localhost` 等内部后缀 |
| `ip_literal` | `block_ip_literals=true` 时直接使用 IP |
| `not_allowlisted` / `blocklisted` | 不在域名白名单 / 命中域名黑名单 |
| `metadata_ip` | 云元数据或链路本地地址（始终拒绝），**建议单独告警** |
| `blocked_cidr` | 命中 `blocked_cidrs` |
| `private_ip` | 私网/回环/保留等非全球可路由地址（IP 字面量或 DNS 解析结果）|
| `no_public_ip` | DNS 没有返回任何可用地址 |

告警示例：`increase(proxy_security_blocked_total{reason="metadata_ip"}[5m]) > 0`。
对应的 `proxy.blocked` 访问日志事件带有 `client` / `host` / `reason` / `error`，用于反查来源。

## 3. SOCKS 命名空间（保留扩展位）
| 指标名 | 类型 | 维度 | 说明 |
|--------|------|------|------|
| `proxy_socks_requests_total` | counter | — | SOCKS 请求计数 |
| `proxy_socks_failures_total` | counter | `reason` | SOCKS 失败计数 |
| `proxy_socks_active_sessions` | gauge | — | SOCKS 活跃会话数 |

## 4. 进程资源
| 指标名 | 类型 | 说明 |
|--------|------|------|
| `process_cpu_percent` | gauge | CPU 使用率（×100 整数；单核 100% 时为 10000）|
| `process_memory_bytes` | gauge | 常驻物理内存（字节） |

## 5. 推荐 Grafana 面板
1. **总览**：QPS（`rate(proxy_requests_total[1m])`）、成功率（**排除客户端错误口径**，见下方注解）：
   ```promql
   sum(rate(proxy_requests_success_total[5m]))
   / (sum(rate(proxy_requests_success_total[5m]))
      + sum(rate(proxy_requests_failure_total{reason!~"dns|missing_host"}[5m])))
   ```
2. **延迟**：`histogram_quantile(0.99, sum by (le) (rate(proxy_request_duration_seconds_bucket[5m])))`
3. **资源**：`process_cpu_percent / 100`、`process_memory_bytes / 1024 / 1024`
4. **DNS 命中率**：`rate(proxy_dns_cache_hits_total[1m]) / (rate(proxy_dns_cache_hits_total[1m]) + rate(proxy_dns_cache_misses_total[1m]))`

> **成功率口径说明**：分母排除 `reason=dns` 与 `reason=missing_host`。这两类是客户端错误
> （请求了不存在的域名、请求缺 Host 头），代理本身工作正常，不应拉低 SLI。若客户端在
> 长期请求死域名，会导致此类失败 counter 持续增长，用 `rate()` 也无法完全消掉（只要还在
> 打），因此从分母剔除。要定位具体是谁在打死域名，看 `proxy_request_duration_by_host_seconds`
> 里 `status="error"` 的 host 分布，再结合 openobserve 日志 (`event=proxy.request` + `host=...`)
> 反查客户端 IP。`client_closed` 保留在分母里：它通常说明上游（或代理）慢于客户端的超时，
> 请求对客户端而言确实失败了。
