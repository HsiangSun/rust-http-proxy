//! 访问日志端到端测试：返回错误响应的请求、客户端在代理响应前断开的请求，都要
//! 留下 WARN 访问日志事件与失败计数。全部只访问 127.0.0.1。

mod common;

use std::io::{Read, Write};
use std::net::TcpListener;
#[cfg(target_os = "linux")]
use std::net::TcpStream;
use std::sync::mpsc;
use std::thread;
#[cfg(target_os = "linux")]
use std::time::Duration;

use common::{eventually, spawn_upstream, Proxy, IO_TIMEOUT};

/// 放开私网以访问本地 mock 上游。
const LOCAL_UPSTREAM: &str = "block_private_ips = false\nallowed_ports = []";

const CLIENT_CLOSED: &str = r#"proxy_requests_failure_total{reason="client_closed"}"#;
const CONNECT_FAILED: &str = r#"proxy_requests_failure_total{reason="connect"}"#;

/// 等到带指定 trace_id 的访问日志事件出现，并检查它包含所有 `expected` 子串。
fn assert_event(proxy: &Proxy, trace_id: &str, expected: &[&str]) {
    let mut found = None;
    eventually(IO_TIMEOUT, || {
        found = proxy
            .logs()
            .lines()
            .find(|line| line.contains(" access") && line.contains(trace_id))
            .map(str::to_string);
        found.is_some()
    });
    let line =
        found.unwrap_or_else(|| panic!("缺少 trace_id={trace_id} 的访问日志:\n{}", proxy.logs()));
    for s in expected {
        assert!(line.contains(s), "期望包含 {s}: {line}");
    }
}

/// 收下请求但始终不回响应的上游；每收到一个请求就从返回的 channel 通知一次。
fn spawn_silent_upstream() -> (u16, mpsc::Receiver<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        for mut stream in listener.incoming().flatten() {
            let tx = tx.clone();
            thread::spawn(move || {
                let mut buf = [0u8; 4096];
                let mut notified = false;
                // 一直读到对端关闭，期间不回任何数据。
                while let Ok(n) = stream.read(&mut buf) {
                    if n == 0 {
                        break;
                    }
                    if !notified {
                        notified = true;
                        let _ = tx.send(());
                    }
                }
            });
        }
    });
    (port, rx)
}

/// 客户端发出请求后、上游响应前放弃（例如 Go 的 `http.Client.Timeout` 先到期）：
/// hyper 会丢弃请求处理的 future，必须仍然记一次 client_closed，trace_id 取自请求体。
#[test]
fn client_gone_before_response_is_logged() {
    let (upstream, received) = spawn_silent_upstream();
    let proxy = Proxy::start_logged("", LOCAL_UPSTREAM);

    let body = r#"{"dis_order_no":"ORDER-GONE-1"}"#;
    let mut client = proxy.connect();
    write!(
        client,
        "POST http://127.0.0.1:{upstream}/pay HTTP/1.1\r\nHost: 127.0.0.1:{upstream}\r\n\
         Content-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    )
    .unwrap();
    received.recv_timeout(IO_TIMEOUT).expect("上游应收到请求");
    drop(client);

    // 测试配置的 io_timeout 是 5s：若没识别出客户端断开，会在那时记成 timeout。
    assert!(
        eventually(IO_TIMEOUT, || proxy.metric(CLIENT_CLOSED) == Some(1.0)),
        "应计入一次 client_closed，日志:\n{}",
        proxy.logs()
    );
    let host = format!(r#""host":"127.0.0.1:{upstream}""#);
    assert_event(
        &proxy,
        "ORDER-GONE-1",
        &[
            "proxy.request",
            r#""reason":"client_closed""#,
            r#""method":"POST""#,
            &host,
        ],
    );
    assert!(eventually(IO_TIMEOUT, || proxy
        .metric("proxy_active_connections")
        == Some(0.0)));
}

/// 建连会一直挂起的端口：backlog=1 且从不 accept，先用两个连接占满全连接队列，
/// 之后新来的 SYN 会被内核丢弃。返回值需要保持存活。
#[cfg(target_os = "linux")]
fn blackhole_port() -> (socket2::Socket, Vec<TcpStream>, u16) {
    use socket2::{Domain, Socket, Type};
    use std::io::ErrorKind;
    use std::net::SocketAddr;

    let socket = Socket::new(Domain::IPV4, Type::STREAM, None).unwrap();
    socket
        .bind(&SocketAddr::from(([127, 0, 0, 1], 0)).into())
        .unwrap();
    socket.listen(1).unwrap();
    let addr = socket.local_addr().unwrap().as_socket().unwrap();
    let fill = (0..2)
        .filter_map(|_| TcpStream::connect_timeout(&addr, Duration::from_millis(500)).ok())
        .collect();
    let probe = TcpStream::connect_timeout(&addr, Duration::from_millis(300));
    assert!(
        matches!(&probe, Err(e) if e.kind() == ErrorKind::TimedOut),
        "前提：新连接应当挂起，实际 {probe:?}"
    );
    (socket, fill, addr.port())
}

/// CONNECT 在代理连上游期间客户端放弃：同样记一次 client_closed（proxy.connect）。
#[cfg(target_os = "linux")]
#[test]
fn client_gone_while_tunnel_connecting_is_logged() {
    let (_listener, _fill, port) = blackhole_port();
    let proxy = Proxy::start_logged("", LOCAL_UPSTREAM);

    let mut client = proxy.connect();
    write!(
        client,
        "CONNECT 127.0.0.1:{port} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n\
         X-PROXY-TRACE-ID: TUNNEL-GONE-1\r\n\r\n"
    )
    .unwrap();
    // 测试配置的建连超时是 2s，此时代理还在等上游的 SYN-ACK。
    thread::sleep(Duration::from_millis(300));
    drop(client);

    // 若没识别出客户端断开，会在建连超时后记成 timeout，而不是 client_closed。
    assert!(
        eventually(IO_TIMEOUT, || proxy.metric(CLIENT_CLOSED) == Some(1.0)),
        "应计入一次 client_closed，日志:\n{}",
        proxy.logs()
    );
    assert_event(
        &proxy,
        "TUNNEL-GONE-1",
        &["proxy.connect", r#""reason":"client_closed""#],
    );
}

/// 返回错误响应的请求也要有访问日志事件，带状态码、原因与根因。
#[test]
fn failed_requests_are_logged() {
    let ok_upstream = spawn_upstream();
    // 监听后立即关闭，得到一个会拒绝连接的端口。
    let refused = TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let proxy = Proxy::start_logged("", LOCAL_UPSTREAM);

    let (status, _) = proxy.send(&format!(
        "GET http://127.0.0.1:{ok_upstream}/ HTTP/1.1\r\nHost: 127.0.0.1:{ok_upstream}\r\n\
         Connection: close\r\n\r\n"
    ));
    assert_eq!(status, 200);

    let body = r#"{"dis_order_no":"ORDER-502"}"#;
    let (status, _) = proxy.send(&format!(
        "POST http://127.0.0.1:{refused}/pay HTTP/1.1\r\nHost: 127.0.0.1:{refused}\r\n\
         Content-Length: {}\r\n\r\n{body}",
        body.len()
    ));
    assert_eq!(status, 502);
    assert_event(
        &proxy,
        "ORDER-502",
        &[
            "proxy.request",
            r#""status":502"#,
            r#""reason":"connect""#,
            "Connection refused",
        ],
    );

    let (status, _) = proxy.send(&format!(
        "CONNECT 127.0.0.1:{refused} HTTP/1.1\r\nHost: 127.0.0.1:{refused}\r\n\
         X-PROXY-TRACE-ID: TUNNEL-502\r\n\r\n"
    ));
    assert_eq!(status, 502);
    assert_event(
        &proxy,
        "TUNNEL-502",
        &["proxy.connect", r#""status":502"#, r#""reason":"connect""#],
    );

    assert_eq!(proxy.metric(CONNECT_FAILED), Some(2.0));
    assert_eq!(
        proxy.metric(CLIENT_CLOSED),
        None,
        "正常与失败的请求都不应记成 client_closed"
    );
}
