#!/bin/sh
# 配置代理独立日志、UTF-8 与轮转；可重复执行，不清空现有日志。
set -eu
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)

if [ "$(id -u)" -ne 0 ]; then
    echo "ERROR: 日志配置需要 root 权限" >&2
    exit 1
fi
for file in exclude-proxy-syslog.awk syslog-rust-http-proxy.conf \
    newsyslog-rust-http-proxy.conf cron-rust-http-proxy-logs; do
    if [ ! -f "$SCRIPT_DIR/$file" ]; then
        echo "ERROR: 缺少日志配置文件 $SCRIPT_DIR/$file" >&2
        exit 1
    fi
done

BACKUP_DIR=$(mktemp -d /var/backups/rust-http-proxy-logging.XXXXXXXX)
cp -p /etc/syslog.conf "$BACKUP_DIR/syslog.conf"
cp -p /etc/rc.conf "$BACKUP_DIR/rc.conf"
for file in /usr/local/etc/syslog.d/rust-http-proxy.conf \
    /usr/local/etc/newsyslog.conf.d/rust-http-proxy.conf \
    /etc/cron.d/rust-http-proxy-logs; do
    if [ -f "$file" ]; then
        # 上级目录名区分两个同名的 rust-http-proxy.conf。
        label=$(basename "$(dirname "$file")")
        cp -p "$file" "$BACKUP_DIR/$label-$(basename "$file")"
    fi
done

awk -f "$SCRIPT_DIR/exclude-proxy-syslog.awk" /etc/syslog.conf > "$BACKUP_DIR/syslog.conf.new"
if ! grep -Eq '^include[[:space:]]+/usr/local/etc/syslog\.d[[:space:]]*$' "$BACKUP_DIR/syslog.conf.new"; then
    printf '\n!*\ninclude /usr/local/etc/syslog.d\n' >> "$BACKUP_DIR/syslog.conf.new"
fi
install -d -m 0755 /usr/local/etc/syslog.d /usr/local/etc/newsyslog.conf.d /etc/cron.d
touch /var/log/rust-http-proxy.log
chown root:wheel /var/log/rust-http-proxy.log
chmod 0640 /var/log/rust-http-proxy.log
install -m 0644 "$SCRIPT_DIR/syslog-rust-http-proxy.conf" /usr/local/etc/syslog.d/rust-http-proxy.conf
install -m 0644 "$SCRIPT_DIR/newsyslog-rust-http-proxy.conf" /usr/local/etc/newsyslog.conf.d/rust-http-proxy.conf
install -m 0644 "$SCRIPT_DIR/cron-rust-http-proxy-logs" /etc/cron.d/rust-http-proxy-logs
install -m 0644 "$BACKUP_DIR/syslog.conf.new" /etc/syslog.conf
newsyslog -n /var/log/rust-http-proxy.log

flags_changed=NO
syslog_flags=$(sysrc -n syslogd_flags)
case " $syslog_flags " in
    *' -8 '*) ;;
    *)
        sysrc "syslogd_flags=$syslog_flags -8" >/dev/null
        flags_changed=YES
        ;;
esac
sysrc syslogd_enable=YES cron_enable=YES >/dev/null
if service syslogd status >/dev/null 2>&1; then
    if [ "$flags_changed" = YES ]; then
        service syslogd restart
    else
        service syslogd reload
    fi
else
    service syslogd start
fi
if ! service cron status >/dev/null 2>&1; then
    service cron start
fi

echo "[+] 日志配置完成：/var/log/rust-http-proxy.log（5 MiB/每天轮转，保留 5 份压缩备份）"
echo "[i] 原日志配置已备份到 $BACKUP_DIR"
