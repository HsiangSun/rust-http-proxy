# 压测工具

`proxy_bench.py` 是一个只用 Python 标准库实现的 HTTP/HTTPS 正向代理压测脚本，
支持 Linux / FreeBSD（FreeBSD 上先 `pkg install python3`）。

它覆盖两条真实代理路径：

- **HTTP**：客户端发送 absolute-form 请求（`GET http://host/...`），代理做普通转发。
- **HTTPS**：客户端先发 `CONNECT` 建隧道，再做 TLS 握手，代理只做字节透传。

以及两种连接方式：

- **keepalive**：每个并发 worker 复用一条连接/隧道，测代理热路径。
- **new**：每个请求新建连接；HTTPS 还会重新做 CONNECT + TLS 握手。

## 快速开始

```bash
# HTTP keep-alive：2000 请求，100 并发
python3 deploy/bench/proxy_bench.py \
  --proxy 127.0.0.1:8080 --mode http -n 2000 -c 100

# HTTPS CONNECT + TLS keep-alive
python3 deploy/bench/proxy_bench.py \
  --proxy 127.0.0.1:8080 --mode https -n 2000 -c 100

# 每请求新建 HTTPS 隧道（包含 CONNECT + TLS 握手）
python3 deploy/bench/proxy_bench.py \
  --proxy 127.0.0.1:8080 --mode https --connection new -n 200 -c 50

# 指定上游端口 / 路径 / 超时
python3 deploy/bench/proxy_bench.py \
  --proxy 127.0.0.1:8080 --target example.com --target-port 443 \
  --mode https --path / -n 500 -c 50 --timeout 10

# 自签名证书的上游
python3 deploy/bench/proxy_bench.py --mode https --insecure ...
```

## 验证安全策略

默认 `block_private_ips = true` 时，访问私网目标应返回 403。可以把
`--expect-status` 设为 403 来压拦截路径：

```bash
python3 deploy/bench/proxy_bench.py \
  --proxy 127.0.0.1:8080 --mode http -n 5000 -c 200 \
  --target 10.3.0.5 --expect-status 403
```

## 大文件吞吐

```bash
# 5MB 下载，5 路并发（请确认 allowed_ports 放行 443）
python3 deploy/bench/proxy_bench.py \
  --proxy 127.0.0.1:8080 --mode https \
  --target speed.cloudflare.com --path '/__down?bytes=5000000' \
  -n 20 -c 5
```

输出里的 `received` / `throughput` 就是实际下行字节和聚合吞吐。

## 输出说明

```text
mode=https connection=keepalive proxy=127.0.0.1:8080 target=example.com:443/
requests=2000 concurrency=100 ok=2000 status_mismatch=0 errors=0
elapsed=5.80s rps=344.8 received=... throughput=...
latency_ms min=... p50=... p90=... p95=... p99=... max=...
setup_ms(count=100) avg=... max=...
status_codes: 200=2000
```

- `latency_ms`：keepalive 模式是单次请求耗时；new 模式包含建连/CONNECT/TLS。
- `setup_ms`：keepalive 模式的连接建立耗时（HTTP 为 TCP，HTTPS 为 CONNECT + TLS）。
- `status_mismatch`：状态码不等于 `--expect-status` 的数量。
- `errors`：连接/解析错误数量。
- 退出码：有错误、有状态码不匹配或没有任何成功请求时为 1。

## 注意事项

- **跨公网压测看到的是 RTT 上限，不是代理 CPU 上限。** 例如客户端到代理
  单程/往返 RTT 为 230ms 时，keepalive 的 p50 基本就在 240ms 左右。
- 要测代理真实容量，建议：
  - 在代理所在机器/同 region 机器上运行压测；
  - 使用同 region 的上游目标；
  - `--proxy 127.0.0.1:8080`。
- 如果使用私网上游做同机压测，需要临时调整 `[security]`（例如
  `block_private_ips = false`），压测完成后务必恢复。
- 默认只放行 80/443；测试其他端口时请先改 `[security] allowed_ports`。

## ab 快速对比（仅 HTTP）

```bash
# Linux/FreeBSD 安装 ab 后
ab -n 2000 -c 100 -k -X 127.0.0.1:8080 http://example.com/
```

`ab` 的 `-X` 走普通 HTTP 代理，适合快速对比 HTTP 路径；HTTPS CONNECT 请使用
本目录的 Python 脚本。
