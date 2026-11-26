//! SSRF 防护端到端测试：启动真实的代理二进制，用原始 HTTP 请求验证拦截行为。
//!
//! 全部只访问 127.0.0.1：被拦截的目标在建连前就被拒绝，放行路径使用本地
//! mock 上游，不依赖外网，可以在 CI 中稳定运行。

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;
use std::thread;
use std::time::{Duration, Instant};

/// 串行化"选端口 → 代理完成 bind"这段窗口。代理监听带 SO_REUSEPORT，
/// 两个并行测试若拿到同一个空闲端口会同时 bind 成功、互相抢连接。
static START_LOCK: Mutex<()> = Mutex::new(());
static NEXT_ID: AtomicUsize = AtomicUsize::new(0);

const IO_TIMEOUT: Duration = Duration::from_secs(10);

/// 运行中的代理进程；drop 时结束进程并清理临时配置。
struct Proxy {
    child: Child,
    port: u16,
    dir: PathBuf,
}

impl Proxy {
    /// 用给定的 `[security]` 段启动代理，并等到端口可连接。
    fn start(security: &str) -> Self {
        let _guard = START_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let (child, port, dir) = spawn_proxy(security, Stdio::null());
        let mut proxy = Self { child, port, dir };
        let deadline = Instant::now() + IO_TIMEOUT;
        while TcpStream::connect(("127.0.0.1", proxy.port)).is_err() {
            if let Some(status) = proxy.child.try_wait().unwrap() {
                panic!("代理启动失败: {status}");
            }
            assert!(Instant::now() < deadline, "代理启动超时");
            thread::sleep(Duration::from_millis(20));
        }
        proxy
    }

    fn send(&self, raw: &str) -> (u16, String) {
        let mut stream = self.connect();
        stream.write_all(raw.as_bytes()).expect("发送请求");
        read_response(&mut stream)
    }

    fn connect(&self) -> TcpStream {
        let stream = TcpStream::connect(("127.0.0.1", self.port)).expect("连接代理");
        stream.set_read_timeout(Some(IO_TIMEOUT)).unwrap();
        stream.set_write_timeout(Some(IO_TIMEOUT)).unwrap();
        stream
    }

    /// 断言请求被拦截：403，且响应体带有指定的原因标签。
    fn assert_blocked(&self, raw: &str, reason: &str) {
        let (status, body) = self.send(raw);
        assert_eq!(status, 403, "{raw:?} -> {body}");
        assert!(
            body.contains(&format!("reason={reason}")),
            "{raw:?} 期望 reason={reason}，实际: {body}"
        );
    }
}

impl Drop for Proxy {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// 写入临时配置并启动代理进程，返回 (进程, 代理端口, 临时目录)。
fn spawn_proxy(security: &str, stderr: Stdio) -> (Child, u16, PathBuf) {
    let port = free_port();
    let metrics_port = free_port();
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!(
        "ssrf-e2e-{}-{}",
        std::process::id(),
        NEXT_ID.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let config = dir.join("config.toml");
    std::fs::write(
        &config,
        format!(
            "[server]\nlisten = \"127.0.0.1:{port}\"\nworkers = 1\nio_timeout_secs = 5\n\
             [metrics]\nlisten = \"127.0.0.1:{metrics_port}\"\n\
             [upstream]\npool_max_idle_per_host = 4\npool_idle_timeout_secs = 30\n\
             connect_timeout_secs = 2\n\
             [security]\n{security}\n"
        ),
    )
    .unwrap();

    let child = Command::new(env!("CARGO_BIN_EXE_rust-http-proxy"))
        .env("PROXY_CONFIG", &config)
        .env("RUST_LOG", "warn")
        .env("NO_COLOR", "1")
        // 避免外部环境变量覆盖测试配置。
        .env_remove("PROXY_LISTEN")
        .env_remove("METRICS_LISTEN")
        .env_remove("OO_ENABLED")
        .stdout(Stdio::null())
        .stderr(stderr)
        .spawn()
        .expect("启动代理进程");
    (child, port, dir)
}

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// 读取一个 HTTP/1.1 响应：按 Content-Length 读响应体，没有则视为无响应体
///（CONNECT 的 200 响应即如此）。
fn read_response(stream: &mut TcpStream) -> (u16, String) {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    let header_end = loop {
        if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break pos + 4;
        }
        let n = stream.read(&mut chunk).expect("读取响应头");
        assert!(
            n > 0,
            "连接在响应头结束前关闭: {:?}",
            String::from_utf8_lossy(&buf)
        );
        buf.extend_from_slice(&chunk[..n]);
    };
    let head = String::from_utf8_lossy(&buf[..header_end]).into_owned();
    let status = head
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .expect("解析状态码");
    let content_length = head
        .lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            if name.eq_ignore_ascii_case("content-length") {
                value.trim().parse::<usize>().ok()
            } else {
                None
            }
        })
        .unwrap_or(0);
    let mut body = buf[header_end..].to_vec();
    while body.len() < content_length {
        let n = stream.read(&mut chunk).expect("读取响应体");
        if n == 0 {
            break;
        }
        body.extend_from_slice(&chunk[..n]);
    }
    (status, String::from_utf8_lossy(&body).into_owned())
}

/// 本地 mock 上游：每个连接读完请求头后返回固定响应 `upstream-ok`。
fn spawn_upstream() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    thread::spawn(move || {
        for mut stream in listener.incoming().flatten() {
            thread::spawn(move || {
                let mut buf = Vec::new();
                let mut chunk = [0u8; 1024];
                while !buf.windows(4).any(|w| w == b"\r\n\r\n") {
                    match stream.read(&mut chunk) {
                        Ok(0) | Err(_) => return,
                        Ok(n) => buf.extend_from_slice(&chunk[..n]),
                    }
                }
                let _ = stream.write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 11\r\nConnection: close\r\n\r\nupstream-ok",
                );
            });
        }
    });
    port
}

fn get(uri: &str) -> String {
    format!("GET {uri} HTTP/1.1\r\nHost: x\r\n\r\n")
}

fn tunnel(authority: &str) -> String {
    format!("CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n\r\n")
}

#[test]
fn blocks_ssrf_payloads_with_default_policy() {
    let proxy = Proxy::start("");
    let cases = [
        // 回环 / 私网
        (get("http://127.0.0.1/"), "private_ip"),
        (get("http://10.0.0.1/"), "private_ip"),
        (get("http://[::1]/"), "private_ip"),
        // 云元数据及其 IPv6 / mapped / NAT64 写法
        (
            get("http://169.254.169.254/latest/meta-data/"),
            "metadata_ip",
        ),
        (get("http://[::ffff:169.254.169.254]/"), "metadata_ip"),
        (get("http://[64:ff9b::a9fe:a9fe]/"), "metadata_ip"),
        (get("http://[fd00:ec2::254]/"), "metadata_ip"),
        // 非标准 IP 写法（getaddrinfo 会把它们解析成 127.0.0.1）
        (get("http://0x7f.1/"), "ip_encoding"),
        (get("http://2130706433/"), "ip_encoding"),
        (get("http://0177.0.0.1/"), "ip_encoding"),
        // 内部域名
        (get("http://localhost/"), "internal_domain"),
        (get("http://metadata.google.internal/"), "internal_domain"),
        // 请求形态
        (get("http://user:pass@example.com/"), "userinfo"),
        (get("http://example.com@127.0.0.1/"), "userinfo"),
        (get("https://example.com/"), "scheme"),
        (get("gopher://example.com:70/_x"), "scheme"),
        (get("http://example.com:22/"), "port"),
        (
            "GET / HTTP/1.1\r\nHost: a.example.com\r\nHost: b.example.com\r\n\r\n".to_string(),
            "invalid_host",
        ),
        // CONNECT 隧道
        (tunnel("127.0.0.1:443"), "private_ip"),
        (tunnel("[::1]:443"), "private_ip"),
        (tunnel("169.254.169.254:443"), "metadata_ip"),
        (tunnel("user@example.com:443"), "userinfo"),
        (tunnel("kubernetes:443"), "internal_domain"),
        (tunnel("example.com:22"), "port"),
    ];
    for (raw, reason) in &cases {
        proxy.assert_blocked(raw, reason);
    }
}

#[test]
fn dns_result_block_does_not_leak_address() {
    // 关闭内部域名检查，让 localhost 真正经系统解析（hosts 文件）得到回环地址。
    let proxy = Proxy::start("block_internal_domains = false");
    for raw in [get("http://localhost/"), tunnel("localhost:443")] {
        let (status, body) = proxy.send(&raw);
        assert_eq!(status, 403, "{raw:?} -> {body}");
        assert!(body.contains("reason=private_ip"), "{raw:?} -> {body}");
        assert!(
            !body.contains("127.0.0.1") && !body.contains("::1"),
            "响应不应回显解析出的地址: {body}"
        );
    }
}

#[test]
fn blocked_cidrs_block_specific_ips() {
    let upstream = spawn_upstream();
    // 放开私网，只用 blocked_cidrs 精确拦截指定 IP / 网段；mock 上游在 127.0.0.1。
    let proxy = Proxy::start(
        r#"block_private_ips = false
allowed_ports = []
blocked_cidrs = ["127.0.0.2", "127.0.1.0/24", "::1"]"#,
    );

    // 不在列表里的地址正常转发。
    let (status, body) = proxy.send(&get(&format!("http://127.0.0.1:{upstream}/")));
    assert_eq!((status, body.as_str()), (200, "upstream-ok"));

    // 列表中的单个 IP、网段内的地址、IPv4-mapped 写法、IPv6 地址都被拦截，
    // 普通转发与 CONNECT 隧道一致。
    for authority in [
        format!("127.0.0.2:{upstream}"),
        format!("127.0.1.7:{upstream}"),
        format!("[::ffff:127.0.0.2]:{upstream}"),
        format!("[::1]:{upstream}"),
    ] {
        proxy.assert_blocked(&get(&format!("http://{authority}/")), "blocked_cidr");
        proxy.assert_blocked(&tunnel(&authority), "blocked_cidr");
    }

    // CONNECT 到未拦截的地址：隧道建立后可以正常与上游通信。
    let mut stream = proxy.connect();
    stream
        .write_all(tunnel(&format!("127.0.0.1:{upstream}")).as_bytes())
        .unwrap();
    assert_eq!(read_response(&mut stream).0, 200);
    stream
        .write_all(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
        .unwrap();
    let (status, body) = read_response(&mut stream);
    assert_eq!((status, body.as_str()), (200, "upstream-ok"));

    // 关闭 block_private_ips 后，云元数据地址仍然始终拦截。
    proxy.assert_blocked(&get("http://169.254.169.254/"), "metadata_ip");
}

#[test]
fn blocked_cidrs_apply_to_dns_results() {
    // 域名本身合法，但解析出的地址命中 blocked_cidrs，同样拦截。
    let proxy = Proxy::start(
        r#"block_private_ips = false
block_internal_domains = false
blocked_cidrs = ["127.0.0.0/8", "::1"]"#,
    );
    proxy.assert_blocked(&get("http://localhost/"), "blocked_cidr");
    proxy.assert_blocked(&tunnel("localhost:443"), "blocked_cidr");
}

#[test]
fn invalid_rules_abort_startup() {
    for (rule, field) in [
        (r#"blocked_cidrs = ["10.0.0.0/33"]"#, "blocked_cidrs"),
        (r#"blocked_cidrs = ["not-an-ip"]"#, "blocked_cidrs"),
        (
            r#"domain_blocklist = ["http://evil.example"]"#,
            "domain_blocklist",
        ),
    ] {
        let (status, stderr) = run_until_exit(rule);
        assert!(!status.success(), "{rule}: 写错的规则应导致启动失败");
        assert!(
            stderr.contains(field),
            "{rule}: 错误信息应指明字段: {stderr}"
        );
    }
}

/// 启动代理并等待其自行退出（用于验证启动失败的场景），返回退出码与 stderr。
fn run_until_exit(security: &str) -> (ExitStatus, String) {
    let (mut child, _port, dir) = spawn_proxy(security, Stdio::piped());
    let deadline = Instant::now() + IO_TIMEOUT;
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break status;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            let _ = std::fs::remove_dir_all(&dir);
            panic!("{security}: 代理应当启动失败，却一直在运行");
        }
        thread::sleep(Duration::from_millis(20));
    };
    let mut stderr = String::new();
    child
        .stderr
        .take()
        .unwrap()
        .read_to_string(&mut stderr)
        .unwrap();
    let _ = std::fs::remove_dir_all(&dir);
    (status, stderr)
}
