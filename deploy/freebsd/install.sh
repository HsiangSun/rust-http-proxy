#!/bin/sh
#
# rust-http-proxy FreeBSD 安装脚本
#
# 用法：
#   sudo sh deploy/freebsd/install.sh
#   sudo BIN=/path/to/rust-http-proxy sh deploy/freebsd/install.sh
#
# 行为：
#   1. 创建系统用户 rust-proxy
#   2. 安装二进制/配置到 /usr/local/rust-http-proxy
#   3. 安装 rc.d 服务到 /usr/local/etc/rc.d/rust_http_proxy
#   4. 在 /etc/rc.conf 中启用并启动服务
#
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
APP_USER="rust-proxy"
APP_GROUP="rust-proxy"
APP_DIR="/usr/local/rust-http-proxy"
RC_NAME="rust_http_proxy"
RC_SRC="${SCRIPT_DIR}/${RC_NAME}"
RC_DST="/usr/local/etc/rc.d/${RC_NAME}"

if [ "$(id -u)" -ne 0 ]; then
    echo "ERROR: 请用 root / sudo 运行" >&2
    exit 1
fi

# ── 查找二进制 ────────────────────────────────────────────────────────────
BIN_SRC=""
for c in "${BIN:-}" \
         "${SCRIPT_DIR}/rust-http-proxy" \
         "${SCRIPT_DIR}/../../rust-http-proxy" \
         "${SCRIPT_DIR}/../../../rust-http-proxy"; do
    if [ -n "$c" ] && [ -f "$c" ]; then
        BIN_SRC="$c"
        break
    fi
done
if [ -z "$BIN_SRC" ]; then
    echo "ERROR: 找不到 rust-http-proxy 二进制，请用 BIN=路径 指定" >&2
    exit 1
fi

# ── 查找配置 ──────────────────────────────────────────────────────────────
CFG_SRC=""
for c in "${CFG:-}" \
         "${SCRIPT_DIR}/config.toml" \
         "${SCRIPT_DIR}/../../config.toml" \
         "${SCRIPT_DIR}/../../../config.toml"; do
    if [ -n "$c" ] && [ -f "$c" ]; then
        CFG_SRC="$c"
        break
    fi
done

# ── 创建用户/组 ───────────────────────────────────────────────────────────
if ! pw groupshow "$APP_GROUP" >/dev/null 2>&1; then
    pw groupadd "$APP_GROUP"
    echo "[+] 创建用户组 $APP_GROUP"
fi
if ! pw usershow "$APP_USER" >/dev/null 2>&1; then
    pw useradd "$APP_USER" \
        -g "$APP_GROUP" \
        -d /nonexistent \
        -s /usr/sbin/nologin \
        -c "rust-http-proxy"
    echo "[+] 创建系统用户 $APP_USER"
fi

# ── 安装文件 ──────────────────────────────────────────────────────────────
install -d -m 0755 "$APP_DIR"
install -m 0755 "$BIN_SRC" "$APP_DIR/rust-http-proxy"
echo "[+] 二进制部署到 $APP_DIR/rust-http-proxy"

if [ -n "$CFG_SRC" ]; then
    if [ -f "$APP_DIR/config.toml" ]; then
        echo "[i] $APP_DIR/config.toml 已存在，跳过覆盖"
    else
        install -m 0640 -o root -g "$APP_GROUP" "$CFG_SRC" "$APP_DIR/config.toml"
        echo "[+] 配置文件部署到 $APP_DIR/config.toml"
    fi
else
    echo "[i] 未找到 config.toml，代理将使用内置默认配置"
fi

install -d -m 0755 /usr/local/etc/rc.d
install -m 0755 "$RC_SRC" "$RC_DST"
echo "[+] rc.d 服务安装到 $RC_DST"

# ── 启用并启动 ────────────────────────────────────────────────────────────
sysrc "${RC_NAME}_enable=YES" >/dev/null
sysrc "${RC_NAME}_config=${APP_DIR}/config.toml" >/dev/null
if service "$RC_NAME" status >/dev/null 2>&1; then
    service "$RC_NAME" restart
else
    service "$RC_NAME" start
fi

echo
echo "===== 安装完成 ====="
service "$RC_NAME" status || true
echo
echo "查看日志： tail -f /var/log/messages | grep rust-http-proxy"
echo "重启服务： service $RC_NAME restart"
echo "停止服务： service $RC_NAME stop"
echo
echo "可选内核调优（参考 deploy/freebsd/sysctl.conf.sample，追加到 /etc/sysctl.conf）"
