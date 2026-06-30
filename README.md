# rust-http-proxy

一个用 Rust 写的高性能 HTTP / HTTPS 正向代理：

- ⚡ Tokio + Hyper 1.x，多 worker SO_REUSEPORT 共享监听
- 📈 原生 Prometheus 指标 `/metrics`（含 CPU/内存、SOCKS 预留命名空间）
- 📝 OpenObserve 异步批量日志上报，自动以请求体 `dis_order_no` 作为 trace_id
- 🧠 DashMap + TTL 的 DNS 缓存（默认 60s）
- 🔁 端口复用 + 上游连接复用，缓解端口耗尽
- 🛡️ 纯 safe Rust，全链路超时与有界反压

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
4. `systemctl enable + restart`，并打印状态

常用操作：

```bash
systemctl status rust-http-proxy
journalctl -u rust-http-proxy -f          # 实时日志
sudo systemctl restart rust-http-proxy
sudo systemctl stop rust-http-proxy
```

修改 `/opt/rust-http-proxy/config.toml` 后需 `restart` 才生效。

## 文档

- [设计与实现规范](docs/DESIGN.md)
- [指标手册](docs/METRICS.md)
