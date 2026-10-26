# rust-http-proxy

一个用 Rust 写的高性能 HTTP / HTTPS 正向代理：

- ⚡ Tokio + Hyper 1.x，多 worker SO_REUSEPORT 共享监听
- 📈 原生 Prometheus 指标 `/metrics`（含 CPU/内存、SOCKS 预留命名空间）
- 📝 OpenObserve 异步批量日志上报，自动以请求体 `dis_order_no` 作为 trace_id
- 🧠 DashMap + TTL 的 DNS 缓存（默认 60s），HTTP 与 CONNECT 共用
- 🔁 端口复用 + 上游连接复用，缓解端口耗尽
- 🛡️ SSRF 防护：默认阻断私网/回环/云元数据地址、限制目标端口、支持域名黑白名单
- 📉 有界 metrics 基数：随机域名不会造成 Prometheus label series 无界增长
- 🐧🐡 支持 Linux 与 FreeBSD
- 🧵 纯 safe Rust，全链路超时与有界反压

## 快速开始

```bash
cargo build --release
# 可选：编辑 config.toml 或注入环境变量
RUST_LOG=info ./target/release/rust-http-proxy
```

启动后：
- 代理监听 `0.0.0.0:8080`
- 指标暴露 `http://0.0.0.0:9090/metrics`

测试：

```bash
# HTTP
curl -x http://127.0.0.1:8080 http://httpbin.org/get
# HTTPS
curl -x http://127.0.0.1:8080 https://httpbin.org/get
```

## 部署到 AWS Graviton (Amazon Linux 2023)

打 `v*` tag 时 GitHub Actions 会自动产出 `rust-http-proxy-<tag>-aarch64-linux-gnu.tar.gz`
并发布到 Release 页。服务器上：

```bash
# 1. 下载并校验
curl -fLO https://github.com/<owner>/<repo>/releases/download/v0.1.0/rust-http-proxy-v0.1.0-aarch64-linux-gnu.tar.gz
curl -fLO https://github.com/<owner>/<repo>/releases/download/v0.1.0/rust-http-proxy-v0.1.0-aarch64-linux-gnu.tar.gz.sha256
sha256sum -c rust-http-proxy-v0.1.0-aarch64-linux-gnu.tar.gz.sha256

# 2. 解压并启动
tar -xzf rust-http-proxy-v0.1.0-aarch64-linux-gnu.tar.gz
cd rust-http-proxy-v0.1.0-aarch64-linux-gnu
RUST_LOG=info ./rust-http-proxy
```

构建在 GitHub Runner 上跑（Ubuntu 22.04），通过 `cargo-zigbuild` 把
glibc 下限锁定为 **2.34**，与 AL2023 完全兼容。

## 作为 systemd 服务运行

仓库的 `deploy/` 目录提供了 unit 与一键安装脚本。把 tar.gz 解压到任意临时目录后：

```bash
# 把 deploy/ 一并拷过来（仓库 release tar.gz 已含 docs 与 config.toml）
sudo bash deploy/install.sh
```

脚本会：

1. 创建系统用户 `rust-proxy`（最小权限运行）
2. 将二进制 + `config.toml` 拷贝到 `/opt/rust-http-proxy/`
3. 安装 `rust-http-proxy.service` 到 `/etc/systemd/system/`
4. 安装 `deploy/sysctl.d/99-rust-http-proxy.conf` 到 `/etc/sysctl.d/` 并 `sysctl --system` 生效
   （放开 `somaxconn` / `ip_local_port_range` / TCP 缓冲区 / BBR / TIME\_WAIT 复用 等，
   与 unit 里的 `LimitNOFILE=1048576` 配套；不需要时用 `SKIP_SYSCTL=1 sudo ./install.sh` 跳过）
5. `systemctl enable + restart`，并打印状态

内核调优效果自检：

```bash
sysctl net.core.somaxconn net.ipv4.ip_local_port_range net.ipv4.tcp_congestion_control
cat /proc/$(pidof rust-http-proxy)/limits | grep -E "open files|processes"
# 期望：somaxconn=65535；port_range=1024 65535；congestion_control=bbr；open files=1048576
```

常用操作：

```bash
systemctl status rust-http-proxy
journalctl -u rust-http-proxy -f          # 实时日志
sudo systemctl restart rust-http-proxy
sudo systemctl stop rust-http-proxy
```

修改 `/opt/rust-http-proxy/config.toml` 后需 `restart` 才生效。

## 安全加固

`config.toml` 的 `[security]` 段控制目标地址策略，默认配置已经开启基础防护：

```toml
[security]
block_private_ips = true          # 拒绝 127.0.0.1 / 10.x / 169.254.169.254 / ULA 等
block_ip_literals = false         # 是否连公网 IP 字面量也拒绝
allowed_ports = [80, 443]         # 目标端口白名单，空数组表示不限制
domain_allowlist = []             # 非空时只放行匹配域名，支持 *.example.com
domain_blocklist = []             # 统一拦截已知恶意/钓鱼域名，支持 *.example.com
```

- 校验同时覆盖普通 HTTP 与 HTTPS CONNECT。
- DNS 解析完成后会再次过滤地址，防止 DNS rebinding 把公网域名切换为内网 IP。
- `[metrics] max_host_labels` 限制 host 维度指标基数；随机域名/不存在的域名会被折叠为 `other`。

## FreeBSD

代码与依赖已兼容 FreeBSD（移除了 Linux 专属的 procfs process collector）。

打 `v*` tag 时 GitHub Actions 会在 FreeBSD 15.1 **aarch64** VM 中额外构建
`rust-http-proxy-<tag>-aarch64-unknown-freebsd.tar.gz`，与 Linux 包一起发布。
aarch64 通过 QEMU 模拟编译，CI 中使用 thin LTO 以控制构建时间；该包面向
FreeBSD 15.1+，x86_64 FreeBSD 可直接按下面步骤在目标机上构建。

```bash
# 也可以直接在 FreeBSD 上构建
pkg install rust
cargo build --release

# 安装为 rc.d 服务（二进制与 config.toml 放在 release 包根目录）
sudo sh deploy/freebsd/install.sh
```

服务管理：

```bash
service rust-http-proxy status
service rust-http-proxy stop
service rust-http-proxy start
service rust-http-proxy restart
tail -f /var/log/messages | grep rust-http-proxy
```

内核调优参考 `deploy/freebsd/sysctl.conf.sample`（默认不自动修改系统配置）。
可通过 `PROXY_CONFIG=/path/to/config.toml` 或 rc.conf 的
`rust_http_proxy_config` 指定配置文件（rc.conf 变量名仍使用下划线）。

镜像部署时，可统一使用 `server.listen = "0.0.0.0:8080"` 和
`metrics.listen = "0.0.0.0:9090"`，通过 PF 将这两个端口限制为 VPC 内访问。
`deploy/freebsd/pf.conf.sample` 默认允许来源 `10.3.0.0/16`，保留本机回环访问，
拒绝其他 IPv4 来源以及 IPv6 对这两个端口的访问；其他端口和出站流量继续放行。
该配置不包含固定的本机 IP 或网卡名称，可以随镜像复制。

以下命令适用于尚未配置 PF 的主机；已有防火墙时应将端口限制合并到原规则中，
不能用示例覆盖原有的访问限制。以 root 执行：

```sh
kldload -n pf
pfctl -nf deploy/freebsd/pf.conf.sample
install -m 0600 deploy/freebsd/pf.conf.sample /etc/pf.conf
sysrc pf_enable=YES pf_rules=/etc/pf.conf pflog_enable=YES
service pflog start
service pf start
service rust-http-proxy restart
```

规则中的 `log` 记录被阻断的访问。实时查看：

```sh
tcpdump -nn -e -tttt -i pflog0
```

历史日志使用 `tcpdump -nn -e -tttt -r /var/log/pflog` 读取。
如果提示 `pflog0: No such device exists`，先执行 `service pflog start`；
服务会加载 `pflog` 模块并自动创建接口。

制作镜像前确认 `pf_enable="YES"`、`pflog_enable="YES"` 与 `rust_http_proxy_enable="YES"`。
如果新机器位于不同 VPC，应修改 PF 中的 `vpc_net` 并执行 `service pf reload`。

## 文档

- [设计与实现规范](docs/DESIGN.md)
- [指标手册](docs/METRICS.md)
- [可观测：VictoriaMetrics 抓取 + Grafana Dashboard](docs/OBSERVABILITY.md)
- [Grafana Dashboard JSON](docs/grafana-dashboard.json)
- [压测工具](deploy/bench/README.md)
