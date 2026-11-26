//! 端到端测试共用的工具：启动真实的代理二进制、收发原始 HTTP 报文、
//! 本地 mock 上游。全部只访问 127.0.0.1，不依赖外网。
#![allow(dead_code)] // 各测试文件只用到其中一部分。

use std::io::{BufRead, BufReader, Read, Write};
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

pub const IO_TIMEOUT: Duration = Duration::from_secs(10);

/// 运行中的代理进程；drop 时结束进程并清理临时配置。
pub struct Proxy {
    child: Child,
    pub port: u16,
    metrics_port: u16,
    dir: PathBuf,
}

impl Proxy {
    /// 用给定的 `[security]` 段启动代理，并等到端口可连接。
    pub fn start(security: &str) -> Self {
        Self::start_with("", security)
    }

    /// 额外追加 `[server]` 配置行后启动代理。
    pub fn start_with(server: &str, security: &str) -> Self {
        Self::launch(server, security, false)
    }

    /// 同 [`Proxy::start_with`]，另把 info 级别日志写进临时文件，供 [`Proxy::logs`]
    /// 读取。未启用 OpenObserve 时访问日志事件也打在这里。
    pub fn start_logged(server: &str, security: &str) -> Self {
        Self::launch(server, security, true)
    }

    fn launch(server: &str, security: &str, logged: bool) -> Self {
        let _guard = START_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let (child, port, metrics_port, dir) = spawn_proxy(server, security, Stdio::null(), logged);
        let mut proxy = Self {
            child,
            port,
            metrics_port,
            dir,
        };
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

    pub fn pid(&self) -> u32 {
        self.child.id()
    }

    /// 代理至今输出的日志；只有 [`Proxy::start_logged`] 启动时才有内容。
    pub fn logs(&self) -> String {
        std::fs::read_to_string(self.dir.join(LOG_FILE)).unwrap_or_default()
    }

    pub fn send(&self, raw: &str) -> (u16, String) {
        let mut stream = self.connect();
        stream.write_all(raw.as_bytes()).expect("发送请求");
        read_response(&mut stream)
    }

    pub fn connect(&self) -> TcpStream {
        let stream = TcpStream::connect(("127.0.0.1", self.port)).expect("连接代理");
        stream.set_read_timeout(Some(IO_TIMEOUT)).unwrap();
        stream.set_write_timeout(Some(IO_TIMEOUT)).unwrap();
        stream
    }

    /// 断言请求被拦截：403，且响应体带有指定的原因标签。
    pub fn assert_blocked(&self, raw: &str, reason: &str) {
        let (status, body) = self.send(raw);
        assert_eq!(status, 403, "{raw:?} -> {body}");
        assert!(
            body.contains(&format!("reason={reason}")),
            "{raw:?} 期望 reason={reason}，实际: {body}"
        );
    }

    /// 读取 `/metrics` 中某个不带标签的指标值。
    pub fn metric(&self, name: &str) -> Option<f64> {
        let mut stream = TcpStream::connect(("127.0.0.1", self.metrics_port)).ok()?;
        stream.set_read_timeout(Some(IO_TIMEOUT)).ok()?;
        stream
            .write_all(b"GET /metrics HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
            .ok()?;
        let (_, body) = read_response(&mut stream);
        body.lines()
            .find(|line| line.split_whitespace().next() == Some(name))
            .and_then(|line| line.split_whitespace().nth(1)?.parse().ok())
    }
}

impl Drop for Proxy {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// [`Proxy::start_logged`] 的日志文件名（在代理的临时目录下）。
const LOG_FILE: &str = "proxy.log";

/// 写入临时配置并启动代理进程，返回 (进程, 代理端口, 指标端口, 临时目录)。
/// `logged` 时 stdout 写入 [`LOG_FILE`]，日志级别为 info。
fn spawn_proxy(
    server: &str,
    security: &str,
    stderr: Stdio,
    logged: bool,
) -> (Child, u16, u16, PathBuf) {
    let port = free_port();
    let metrics_port = free_port();
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!(
        "e2e-{}-{}",
        std::process::id(),
        NEXT_ID.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let config = dir.join("config.toml");
    std::fs::write(
        &config,
        format!(
            "[server]\nlisten = \"127.0.0.1:{port}\"\nworkers = 1\nio_timeout_secs = 5\n{server}\n\
             [metrics]\nlisten = \"127.0.0.1:{metrics_port}\"\n\
             [upstream]\npool_max_idle_per_host = 4\npool_idle_timeout_secs = 30\n\
             connect_timeout_secs = 2\n\
             [security]\n{security}\n"
        ),
    )
    .unwrap();

    let (stdout, level) = if logged {
        let file = std::fs::File::create(dir.join(LOG_FILE)).unwrap();
        (Stdio::from(file), "info")
    } else {
        (Stdio::null(), "warn")
    };
    let child = Command::new(env!("CARGO_BIN_EXE_rust-http-proxy"))
        .env("PROXY_CONFIG", &config)
        .env("RUST_LOG", level)
        .env("NO_COLOR", "1")
        // 避免外部环境变量覆盖测试配置。
        .env_remove("PROXY_LISTEN")
        .env_remove("METRICS_LISTEN")
        .env_remove("OO_ENABLED")
        .stdout(stdout)
        .stderr(stderr)
        .spawn()
        .expect("启动代理进程");
    (child, port, metrics_port, dir)
}

/// 轮询直到条件成立；`within` 内一直不成立返回 false。
pub fn eventually(within: Duration, mut cond: impl FnMut() -> bool) -> bool {
    let deadline = Instant::now() + within;
    loop {
        if cond() {
            return true;
        }
        if Instant::now() >= deadline {
            return false;
        }
        thread::sleep(Duration::from_millis(20));
    }
}

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// 启动代理并等待其自行退出（用于验证启动失败的场景），返回退出码与 stderr。
pub fn run_until_exit(security: &str) -> (ExitStatus, String) {
    let (mut child, _port, _metrics_port, dir) = spawn_proxy("", security, Stdio::piped(), false);
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

/// 读取响应头，返回 (状态码, Content-Length, 头部之后已读到的数据)。
fn read_head(stream: &mut TcpStream) -> (u16, Option<u64>, Vec<u8>) {
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
    let content_length = head.lines().find_map(|line| {
        let (name, value) = line.split_once(':')?;
        if name.eq_ignore_ascii_case("content-length") {
            value.trim().parse().ok()
        } else {
            None
        }
    });
    (status, content_length, buf[header_end..].to_vec())
}

/// 读取一个 HTTP/1.1 响应：按 Content-Length 读响应体，没有则视为无响应体
/// （CONNECT 的 200 响应即如此）。
pub fn read_response(stream: &mut TcpStream) -> (u16, String) {
    let (status, content_length, mut body) = read_head(stream);
    let len = content_length.unwrap_or(0) as usize;
    let mut chunk = [0u8; 4096];
    while body.len() < len {
        let n = stream.read(&mut chunk).expect("读取响应体");
        if n == 0 {
            break;
        }
        body.extend_from_slice(&chunk[..n]);
    }
    (status, String::from_utf8_lossy(&body).into_owned())
}

/// 读取响应但只统计响应体字节数，不在测试进程里缓存大响应。
pub fn read_response_len(stream: &mut TcpStream) -> (u16, u64) {
    let (status, content_length, already) = read_head(stream);
    let expected = content_length.expect("大响应应带 Content-Length");
    let mut total = already.len() as u64;
    let mut chunk = vec![0u8; 64 * 1024];
    while total < expected {
        let n = stream.read(&mut chunk).expect("读取响应体");
        if n == 0 {
            break;
        }
        total += n as u64;
    }
    (status, total)
}

/// 本地 mock 上游，每个连接处理一个请求后关闭：
/// - `GET /big/<n>`：流式返回 n 字节；
/// - 带请求体（Content-Length 或 chunked）：读完后返回 `received=<字节数>`；
/// - 其他：返回 `upstream-ok`。
pub fn spawn_upstream() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            thread::spawn(move || {
                let _ = serve_one(stream);
            });
        }
    });
    port
}

fn serve_one(stream: TcpStream) -> std::io::Result<()> {
    let mut reader = BufReader::new(stream.try_clone()?);
    let mut writer = stream;
    let mut request_line = String::new();
    reader.read_line(&mut request_line)?;
    let (mut content_length, mut chunked) = (None, false);
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line)? == 0 {
            return Ok(());
        }
        let line = line.trim_end();
        if line.is_empty() {
            break;
        }
        if let Some((name, value)) = line.split_once(':') {
            if name.eq_ignore_ascii_case("content-length") {
                content_length = value.trim().parse::<u64>().ok();
            }
            if name.eq_ignore_ascii_case("transfer-encoding")
                && value.to_ascii_lowercase().contains("chunked")
            {
                chunked = true;
            }
        }
    }
    let received = if chunked {
        drain_chunked(&mut reader)?
    } else if let Some(n) = content_length {
        std::io::copy(&mut reader.by_ref().take(n), &mut std::io::sink())?
    } else {
        0
    };

    let path = request_line.split_whitespace().nth(1).unwrap_or("/");
    if let Some(n) = path
        .strip_prefix("/big/")
        .and_then(|n| n.parse::<u64>().ok())
    {
        write!(
            writer,
            "HTTP/1.1 200 OK\r\nContent-Length: {n}\r\nConnection: close\r\n\r\n"
        )?;
        let chunk = [0u8; 64 * 1024];
        let mut left = n;
        while left > 0 {
            let k = left.min(chunk.len() as u64) as usize;
            writer.write_all(&chunk[..k])?;
            left -= k as u64;
        }
        return Ok(());
    }
    let body = if chunked || content_length.is_some() {
        format!("received={received}")
    } else {
        "upstream-ok".to_string()
    };
    write!(
        writer,
        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
}

fn drain_chunked(reader: &mut impl BufRead) -> std::io::Result<u64> {
    let mut total = 0;
    loop {
        let mut size_line = String::new();
        reader.read_line(&mut size_line)?;
        let size_hex = size_line.trim().split(';').next().unwrap_or("0");
        let size = u64::from_str_radix(size_hex, 16).unwrap_or(0);
        if size == 0 {
            // 跳过 trailers，直到空行。
            loop {
                let mut line = String::new();
                if reader.read_line(&mut line)? == 0 || line.trim_end().is_empty() {
                    return Ok(total);
                }
            }
        }
        std::io::copy(&mut reader.by_ref().take(size), &mut std::io::sink())?;
        total += size;
        let mut crlf = String::new();
        reader.read_line(&mut crlf)?;
    }
}

pub fn get(uri: &str) -> String {
    format!("GET {uri} HTTP/1.1\r\nHost: x\r\n\r\n")
}

pub fn tunnel(authority: &str) -> String {
    format!("CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n\r\n")
}

/// 进程的峰值常驻内存（KiB，来自 /proc 的 VmHWM）。
#[cfg(target_os = "linux")]
pub fn peak_rss_kib(pid: u32) -> u64 {
    let status = std::fs::read_to_string(format!("/proc/{pid}/status")).unwrap();
    status
        .lines()
        .find_map(|line| line.strip_prefix("VmHWM:"))
        .and_then(|v| v.trim().trim_end_matches("kB").trim().parse().ok())
        .expect("读取 VmHWM")
}
