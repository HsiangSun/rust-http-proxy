#!/usr/bin/env bash
#
# rust-http-proxy 部署脚本（Amazon Linux 2023 / 任意 systemd 发行版）
#
# 行为：
#   1. 创建系统用户/用户组 rust-proxy（已存在则跳过）
#   2. 把当前目录的二进制 & config.toml 拷到 /opt/rust-http-proxy/
#   3. 安装 systemd unit 到 /etc/systemd/system/
#   4. enable + restart 服务，并打印状态
#
# 用法：
#   sudo ./install.sh                                 # 用脚本所在目录的文件
#   sudo BIN=/path/to/rust-http-proxy ./install.sh    # 显式指定二进制
#
set -euo pipefail

# ── 解析路径 ──────────────────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
APP_USER="rust-proxy"
APP_GROUP="rust-proxy"
APP_DIR="/opt/rust-http-proxy"
UNIT_NAME="rust-http-proxy.service"
UNIT_SRC="${SCRIPT_DIR}/${UNIT_NAME}"
UNIT_DST="/etc/systemd/system/${UNIT_NAME}"
SYSCTL_NAME="99-rust-http-proxy.conf"
SYSCTL_SRC="${SCRIPT_DIR}/sysctl.d/${SYSCTL_NAME}"
SYSCTL_DST="/etc/sysctl.d/${SYSCTL_NAME}"

# 二进制查找顺序：环境变量 BIN > 脚本同级 > 上级目录
BIN_DEFAULT_CANDIDATES=(
  "${BIN:-}"
  "${SCRIPT_DIR}/rust-http-proxy"
  "${SCRIPT_DIR}/../rust-http-proxy"
)
BIN_SRC=""
for c in "${BIN_DEFAULT_CANDIDATES[@]}"; do
  if [[ -n "$c" && -f "$c" ]]; then BIN_SRC="$c"; break; fi
done
if [[ -z "$BIN_SRC" ]]; then
  echo "ERROR: 找不到二进制文件，请把 rust-http-proxy 放到脚本同级，或用 BIN=路径 ./install.sh" >&2
  exit 1
fi

# config.toml 查找
CFG_DEFAULT_CANDIDATES=(
  "${CFG:-}"
  "${SCRIPT_DIR}/config.toml"
  "${SCRIPT_DIR}/../config.toml"
)
CFG_SRC=""
for c in "${CFG_DEFAULT_CANDIDATES[@]}"; do
  if [[ -n "$c" && -f "$c" ]]; then CFG_SRC="$c"; break; fi
done

# ── 必须 root ─────────────────────────────────────────────────────────────
if [[ $EUID -ne 0 ]]; then
  echo "ERROR: 请用 sudo 运行" >&2
  exit 1
fi

# ── 1. 创建用户/用户组 ────────────────────────────────────────────────────
if ! getent group "$APP_GROUP" >/dev/null; then
  groupadd --system "$APP_GROUP"
  echo "[+] 创建用户组 $APP_GROUP"
fi
if ! id -u "$APP_USER" >/dev/null 2>&1; then
  useradd --system \
          --gid "$APP_GROUP" \
          --home-dir "$APP_DIR" \
          --no-create-home \
          --shell /usr/sbin/nologin \
          "$APP_USER"
  echo "[+] 创建系统用户 $APP_USER"
fi

# ── 2. 部署文件 ───────────────────────────────────────────────────────────
mkdir -p "$APP_DIR"
BIN_DST="$APP_DIR/rust-http-proxy"

# 用 inode 比较来判断 src 与 dst 是不是同一文件，避免 `install` 拒绝同源覆盖。
same_file() {
  [[ -e "$1" && -e "$2" ]] || return 1
  local a b
  a="$(stat -c '%d:%i' -- "$1" 2>/dev/null || echo "")"
  b="$(stat -c '%d:%i' -- "$2" 2>/dev/null || echo "")"
  [[ -n "$a" && "$a" == "$b" ]]
}

if same_file "$BIN_SRC" "$BIN_DST"; then
  # 文件已经在目标位置，只更新属主与权限。
  chown "$APP_USER:$APP_GROUP" "$BIN_DST"
  chmod 0755 "$BIN_DST"
  echo "[i] 二进制已在 $BIN_DST，仅刷新属主与权限"
else
  install -m 0755 -o "$APP_USER" -g "$APP_GROUP" "$BIN_SRC" "$BIN_DST"
  echo "[+] 二进制部署到 $BIN_DST"
fi

if [[ -n "$CFG_SRC" ]]; then
  CFG_DST="$APP_DIR/config.toml"
  if same_file "$CFG_SRC" "$CFG_DST"; then
    chown "$APP_USER:$APP_GROUP" "$CFG_DST"
    chmod 0640 "$CFG_DST"
    echo "[i] 配置已在 $CFG_DST，仅刷新属主与权限"
  elif [[ -f "$CFG_DST" ]]; then
    # 已存在的配置不覆盖，避免运维改过的配置被刷掉。
    echo "[i] $CFG_DST 已存在，跳过覆盖（如需更新请手动 diff）"
  else
    install -m 0640 -o "$APP_USER" -g "$APP_GROUP" "$CFG_SRC" "$CFG_DST"
    echo "[+] 配置文件部署到 $CFG_DST"
  fi
else
  echo "[i] 未找到 config.toml，代理将使用内置默认配置"
fi

# ── 3. 安装 systemd unit ──────────────────────────────────────────────────
if [[ ! -f "$UNIT_SRC" ]]; then
  echo "ERROR: 找不到 unit 文件: $UNIT_SRC" >&2
  exit 1
fi
install -m 0644 "$UNIT_SRC" "$UNIT_DST"
echo "[+] systemd unit 安装到 $UNIT_DST"

# ── 3.5 安装内核调优 sysctl（可用 SKIP_SYSCTL=1 跳过） ────────────────────
# 高并发代理必备：放开 fd、backlog、TIME_WAIT、临时端口、BBR 等。
# 与 unit 的 LimitNOFILE 配套；不装的话进程会被内核上限倒挂。
if [[ "${SKIP_SYSCTL:-0}" != "1" && -f "$SYSCTL_SRC" ]]; then
  install -m 0644 "$SYSCTL_SRC" "$SYSCTL_DST"
  echo "[+] 内核调优参数安装到 $SYSCTL_DST"
  # 立即生效；conntrack 缺模块时 sysctl 会打印警告，忽略即可。
  sysctl --system >/dev/null 2>&1 || sysctl -p "$SYSCTL_DST" >/dev/null 2>&1 || true
  echo "[+] sysctl 已应用（校验：sysctl net.core.somaxconn net.ipv4.tcp_congestion_control）"
elif [[ "${SKIP_SYSCTL:-0}" == "1" ]]; then
  echo "[i] SKIP_SYSCTL=1，跳过内核调优安装"
fi

# ── 4. 启动服务 ───────────────────────────────────────────────────────────
systemctl daemon-reload
systemctl enable "$UNIT_NAME"
# 用 try-restart 兼容首次安装（无活跃实例时不会报错）。
systemctl restart "$UNIT_NAME"

echo
echo "===== 部署完成 ====="
systemctl --no-pager --full status "$UNIT_NAME" || true
echo
echo "查看实时日志：  journalctl -u $UNIT_NAME -f"
echo "重启服务：      sudo systemctl restart $UNIT_NAME"
echo "停止服务：      sudo systemctl stop $UNIT_NAME"
