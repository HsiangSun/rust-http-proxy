# 指标手册

> Prometheus 端点：`GET http://<METRICS_LISTEN>/metrics`，文本格式
> （`text/plain; version=0.0.4`）。

## 1. 代理通用指标
| 指标名 | 类型 | 维度 | 说明 |
|--------|------|------|------|
| `proxy_requests_total` | counter | — | 收到的请求总数（HTTP + CONNECT）|
| `proxy_requests_success_total` | counter | `protocol`={http,https} | 处理成功的请求 |
| `proxy_requests_failure_total` | counter | `reason`={missing_host,dns,connect,handshake,upstream,body,timeout} | 失败计数 |
| `proxy_active_connections` | gauge | — | 当前活跃客户端连接数 |
| `proxy_https_tunnels_total` | counter | — | HTTPS CONNECT 隧道总数 |
| `proxy_bytes_up_total` | counter | — | 客户端 → 上游 总字节数 |
| `proxy_bytes_down_total` | counter | — | 上游 → 客户端 总字节数 |
| `proxy_request_duration_seconds` | histogram | — | 请求生命周期耗时（秒，全局视图）|
| `proxy_request_duration_by_host_seconds` | histogram | `host`, `status` | 按上游 host 分维的耗时；status 取 `2xx`/`3xx`/`4xx`/`5xx`/`tunnel`/`error`/`unknown` |
| `proxy_upstream_connect_seconds` | histogram | — | 上游 TCP 建连耗时（秒）|

## 2. DNS 指标
| 指标名 | 类型 | 说明 |
|--------|------|------|
| `proxy_dns_cache_hits_total` | counter | DNS 缓存命中 |
| `proxy_dns_cache_misses_total` | counter | DNS 缓存未命中（触发系统解析）|

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
1. **总览**：QPS（`rate(proxy_requests_total[1m])`）、成功率
   （`sum(rate(proxy_requests_success_total[1m]))/sum(rate(proxy_requests_total[1m]))`）
2. **延迟**：`histogram_quantile(0.99, sum by (le) (rate(proxy_request_duration_seconds_bucket[5m])))`
3. **资源**：`process_cpu_percent / 100`、`process_memory_bytes / 1024 / 1024`
4. **DNS 命中率**：`rate(proxy_dns_cache_hits_total[1m]) / (rate(proxy_dns_cache_hits_total[1m]) + rate(proxy_dns_cache_misses_total[1m]))`
