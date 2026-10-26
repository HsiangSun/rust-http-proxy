#!/usr/bin/env python3
"""rust-http-proxy 压测工具。

支持两种代理路径：
  * HTTP  : 客户端发送绝对 URI（`GET http://host/...`），代理做普通转发。
  * HTTPS : 客户端先 CONNECT 建隧道，再做 TLS 握手（端到端加密）。

支持两种连接方式：
  * keepalive : 每个并发 worker 复用一条连接/隧道，测代理热路径。
  * new       : 每个请求新建连接（HTTPS 还包含 CONNECT + TLS 握手）。

只用 Python 标准库，Linux / FreeBSD 均可运行（FreeBSD: pkg install python3）。

示例：
  # HTTP keep-alive
  python3 deploy/bench/proxy_bench.py -n 2000 -c 100 --mode http

  # HTTPS CONNECT + TLS keep-alive
  python3 deploy/bench/proxy_bench.py -n 2000 -c 100 --mode https

  # 每请求新建 HTTPS 隧道
  python3 deploy/bench/proxy_bench.py -n 200 -c 50 --mode https --connection new

  # 验证安全策略拦截性能（目标为私网 IP，期望 403）
  python3 deploy/bench/proxy_bench.py -n 5000 -c 200 --target 10.3.0.5 --expect-status 403

  # 大文件下载吞吐
  python3 deploy/bench/proxy_bench.py -n 20 -c 5 --mode https \
      --target speed.cloudflare.com --path '/__down?bytes=5000000'
"""

import argparse
import http.client
import math
import ssl
import sys
import time
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed


def split_host_port(value: str, default_port: int):
    """解析 host:port，兼容 [IPv6]:port 写法。"""
    value = value.strip()
    if value.startswith("["):
        host, _, rest = value[1:].partition("]")
        port = int(rest[1:]) if rest.startswith(":") else default_port
        return host, port
    if value.count(":") == 1:
        host, port = value.rsplit(":", 1)
        return host, int(port)
    # 无端口，或未加方括号的 IPv6 地址
    return value, default_port


def fmt_authority(host: str, port: int, default_port: int) -> str:
    """生成 Host 头 / 绝对 URI 使用的 authority。"""
    h = f"[{host}]" if ":" in host and not host.startswith("[") else host
    return h if port == default_port else f"{h}:{port}"


def default_target_port(mode: str) -> int:
    return 443 if mode == "https" else 80


def make_connection(args, tls_context):
    proxy_host, proxy_port = split_host_port(args.proxy, 8080)
    if args.mode == "https":
        conn = http.client.HTTPSConnection(
            proxy_host,
            proxy_port,
            timeout=args.timeout,
            context=tls_context,
        )
        # 关键：HTTPSConnection 先连 HTTP 代理，set_tunnel 内部发 CONNECT，
        # 然后只用目标域名做 SNI/TLS，正好复现真实 HTTPS 代理路径。
        conn.set_tunnel(args.target, args.target_port)
        return conn
    return http.client.HTTPConnection(proxy_host, proxy_port, timeout=args.timeout)


def do_request(conn, args):
    """发送一次 GET，读完响应体，返回 (状态码, 字节数, 连接是否会被对端关闭)。"""
    keep_alive = args.connection == "keepalive"
    connection_header = "keep-alive" if keep_alive else "close"
    authority = fmt_authority(
        args.target,
        args.target_port,
        default_target_port(args.mode),
    )
    headers = {
        "Host": authority,
        "Accept": "*/*",
        "Connection": connection_header,
    }

    if args.mode == "http":
        # 普通 HTTP 正向代理要求 absolute-form URI。
        url = f"http://{authority}{args.path}"
        conn.request("GET", url, headers=headers)
    else:
        # CONNECT 隧道内是普通 origin-form 请求。
        conn.request("GET", args.path, headers=headers)

    resp = conn.getresponse()
    status = resp.status
    will_close = resp.will_close
    total = 0
    while True:
        chunk = resp.read(65536)
        if not chunk:
            break
        total += len(chunk)
    return status, total, will_close


def run_one(args, tls_context):
    """一个独立请求：包含建连（HTTP）或 CONNECT + TLS（HTTPS）耗时。"""
    t0 = time.perf_counter()
    conn = make_connection(args, tls_context)
    try:
        # 显式建连：HTTP 是到代理的 TCP；HTTPS 还包含 CONNECT + TLS 握手。
        conn.connect()
        status, nbytes, _ = do_request(conn, args)
    finally:
        conn.close()
    return time.perf_counter() - t0, status, nbytes


def run_keepalive_worker(args, tls_context, count):
    """在一条连接/隧道上连续发 count 个请求。"""
    latencies = []
    statuses = Counter()
    errors = []
    setup_times = []
    total_bytes = 0
    conn = None
    consecutive_errors = 0

    try:
        for _ in range(count):
            try:
                if conn is None:
                    t_setup = time.perf_counter()
                    conn = make_connection(args, tls_context)
                    conn.connect()
                    setup_times.append(time.perf_counter() - t_setup)

                t0 = time.perf_counter()
                status, nbytes, will_close = do_request(conn, args)
                latencies.append(time.perf_counter() - t0)
                statuses[status] += 1
                total_bytes += nbytes
                consecutive_errors = 0

                if will_close:
                    conn.close()
                    conn = None
            except Exception as exc:  # noqa: BLE001 - 压测工具需要收集所有连接错误
                errors.append(f"{type(exc).__name__}: {exc}")
                if conn is not None:
                    try:
                        conn.close()
                    except Exception:
                        pass
                    conn = None
                consecutive_errors += 1
                if consecutive_errors >= args.max_consecutive_errors:
                    errors.append(
                        f"aborted after {consecutive_errors} consecutive errors"
                    )
                    break
    finally:
        if conn is not None:
            try:
                conn.close()
            except Exception:
                pass

    return latencies, statuses, errors, setup_times, total_bytes


def percentile(sorted_values, p):
    if not sorted_values:
        return 0.0
    idx = math.ceil((p / 100.0) * len(sorted_values)) - 1
    return sorted_values[max(0, min(idx, len(sorted_values) - 1))]


def parse_args(argv):
    parser = argparse.ArgumentParser(
        description="HTTP/HTTPS forward proxy benchmark (rust-http-proxy)",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("--proxy", default="127.0.0.1:8080", help="代理地址 host:port")
    parser.add_argument("--target", default="example.com", help="上游目标域名或 IP")
    parser.add_argument("--target-port", type=int, default=0, help="上游端口；0 表示按 mode 取默认值")
    parser.add_argument("--path", default="/", help="请求路径（可带 query）")
    parser.add_argument("--mode", choices=("http", "https"), default="http", help="代理路径类型")
    parser.add_argument(
        "--connection",
        choices=("keepalive", "new"),
        default="keepalive",
        help="keepalive=每个 worker 复用连接；new=每请求新建连接",
    )
    parser.add_argument("-n", "--requests", type=int, default=2000, help="总请求数")
    parser.add_argument("-c", "--concurrency", type=int, default=100, help="并发 worker 数")
    parser.add_argument("--timeout", type=float, default=20.0, help="socket 超时（秒）")
    parser.add_argument("--expect-status", type=int, default=200, help="期望的 HTTP 状态码")
    parser.add_argument("--insecure", action="store_true", help="HTTPS 时不校验上游证书")
    parser.add_argument(
        "--max-consecutive-errors",
        type=int,
        default=3,
        help="keepalive worker 连续错误达到该值后退出（避免代理不可用时长时间挂起）",
    )
    return parser.parse_args(argv)


def main(argv=None):
    args = parse_args(argv)
    if args.target_port == 0:
        args.target_port = default_target_port(args.mode)
    if args.requests <= 0 or args.concurrency <= 0:
        print("ERROR: --requests 和 --concurrency 必须大于 0", file=sys.stderr)
        return 2

    tls_context = ssl.create_default_context()
    if args.insecure:
        tls_context.check_hostname = False
        tls_context.verify_mode = ssl.CERT_NONE
    # 本脚本只实现 HTTP/1.1；显式禁用 h2，避免服务端协商到 h2 后 response 解析不上。
    tls_context.set_alpn_protocols(["http/1.1"])

    started = time.perf_counter()
    latencies = []
    setup_times = []
    statuses = Counter()
    errors = []
    total_bytes = 0

    if args.connection == "new":
        with ThreadPoolExecutor(max_workers=args.concurrency) as pool:
            futures = [pool.submit(run_one, args, tls_context) for _ in range(args.requests)]
            for future in as_completed(futures):
                try:
                    latency, status, nbytes = future.result()
                    latencies.append(latency)
                    statuses[status] += 1
                    total_bytes += nbytes
                except Exception as exc:  # noqa: BLE001
                    errors.append(f"{type(exc).__name__}: {exc}")
    else:
        pool_size = min(args.concurrency, args.requests)
        base, extra = divmod(args.requests, pool_size)
        counts = [base + (1 if i < extra else 0) for i in range(pool_size)]
        counts = [c for c in counts if c > 0]

        with ThreadPoolExecutor(max_workers=len(counts)) as pool:
            futures = [
                pool.submit(run_keepalive_worker, args, tls_context, count)
                for count in counts
            ]
            for future in as_completed(futures):
                try:
                    w_lat, w_status, w_errors, w_setup, w_bytes = future.result()
                    latencies.extend(w_lat)
                    statuses.update(w_status)
                    errors.extend(w_errors)
                    setup_times.extend(w_setup)
                    total_bytes += w_bytes
                except Exception as exc:  # noqa: BLE001
                    errors.append(f"{type(exc).__name__}: {exc}")

    elapsed = time.perf_counter() - started
    latencies.sort()
    ok = len(latencies)
    mismatched = ok - statuses.get(args.expect_status, 0)

    print(
        f"mode={args.mode} connection={args.connection} "
        f"proxy={args.proxy} target={args.target}:{args.target_port}{args.path}"
    )
    print(
        f"requests={args.requests} concurrency={args.concurrency} "
        f"ok={ok} status_mismatch={mismatched} errors={len(errors)}"
    )
    if ok:
        mib = total_bytes / (1024 * 1024)
        print(
            f"elapsed={elapsed:.2f}s rps={ok / elapsed:.1f} "
            f"received={total_bytes} bytes ({mib:.2f} MiB) "
            f"throughput={mib / elapsed:.2f} MiB/s"
        )
        print(
            f"latency_ms min={latencies[0] * 1000:.1f} "
            f"p50={percentile(latencies, 50) * 1000:.1f} "
            f"p90={percentile(latencies, 90) * 1000:.1f} "
            f"p95={percentile(latencies, 95) * 1000:.1f} "
            f"p99={percentile(latencies, 99) * 1000:.1f} "
            f"max={latencies[-1] * 1000:.1f}"
        )
    if setup_times:
        setup_times.sort()
        print(
            f"setup_ms(count={len(setup_times)}) "
            f"avg={sum(setup_times) / len(setup_times) * 1000:.1f} "
            f"max={setup_times[-1] * 1000:.1f}"
        )
    print("status_codes: " + ", ".join(f"{k}={v}" for k, v in sorted(statuses.items())))
    if errors:
        print("sample_errors:")
        for err in errors[:5]:
            print(f"  - {err}")

    if not ok or errors or mismatched:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
