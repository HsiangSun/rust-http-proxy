//! 资源占用端到端测试：流式转发让内存与 body 大小无关、空闲 / 慢速连接被回收、
//! 并发连接数上限生效。全部只访问 127.0.0.1。

mod common;

use std::io::{ErrorKind, Read, Write};
use std::net::TcpStream;
use std::time::{Duration, Instant};

use common::{get, read_response, read_response_len, spawn_upstream, tunnel, Proxy};

/// 放开私网以访问本地 mock 上游。
const LOCAL_UPSTREAM: &str = "block_private_ips = false\nallowed_ports = []";

/// 大 body 的大小：旧实现会把它整个读进内存。
const BIG: u64 = 256 * 1024 * 1024;

/// 流式转发时代理峰值内存的上限（KiB）。整体缓冲 256 MiB 时远超这个值。
#[cfg(target_os = "linux")]
const STREAMING_PEAK_RSS_LIMIT_KIB: u64 = 64 * 1024;

#[test]
fn large_download_is_streamed() {
    let upstream = spawn_upstream();
    let proxy = Proxy::start(LOCAL_UPSTREAM);

    let mut stream = proxy.connect();
    stream
        .write_all(get(&format!("http://127.0.0.1:{upstream}/big/{BIG}")).as_bytes())
        .unwrap();
    let (status, received) = read_response_len(&mut stream);
    assert_eq!((status, received), (200, BIG));

    #[cfg(target_os = "linux")]
    {
        let peak = common::peak_rss_kib(proxy.pid());
        assert!(
            peak < STREAMING_PEAK_RSS_LIMIT_KIB,
            "下载 {} MiB 时代理峰值内存 {} MiB，应流式转发而不是整体缓冲",
            BIG >> 20,
            peak >> 10
        );
    }
}

#[test]
fn large_upload_is_streamed() {
    let upstream = spawn_upstream();
    let proxy = Proxy::start(LOCAL_UPSTREAM);

    // chunked 上传（没有 Content-Length）。
    let mut stream = proxy.connect();
    write!(
        stream,
        "PUT http://127.0.0.1:{upstream}/upload HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n"
    )
    .unwrap();
    let chunk = vec![0u8; 64 * 1024];
    for _ in 0..BIG / chunk.len() as u64 {
        write!(stream, "{:x}\r\n", chunk.len()).unwrap();
        stream.write_all(&chunk).unwrap();
        stream.write_all(b"\r\n").unwrap();
    }
    stream.write_all(b"0\r\n\r\n").unwrap();
    let (status, body) = read_response(&mut stream);
    assert_eq!((status, body), (200, format!("received={BIG}")));

    // 带 Content-Length、超过缓冲上限的请求体同样完整送达。
    let len = 3 * 1024 * 1024;
    let mut stream = proxy.connect();
    write!(
        stream,
        "POST http://127.0.0.1:{upstream}/upload HTTP/1.1\r\nHost: x\r\nContent-Length: {len}\r\n\r\n"
    )
    .unwrap();
    stream.write_all(&vec![b'x'; len]).unwrap();
    let (status, body) = read_response(&mut stream);
    assert_eq!((status, body), (200, format!("received={len}")));

    #[cfg(target_os = "linux")]
    {
        let peak = common::peak_rss_kib(proxy.pid());
        assert!(
            peak < STREAMING_PEAK_RSS_LIMIT_KIB,
            "上传 {} MiB 时代理峰值内存 {} MiB，应流式转发而不是整体缓冲",
            BIG >> 20,
            peak >> 10
        );
    }
}

/// 等待对端关闭连接：读到 EOF 或连接被重置返回 true，在 `within` 内一直没关返回 false。
/// 期间收到的数据（例如 408 响应）忽略。
fn closed_by_peer(stream: &mut TcpStream, within: Duration) -> bool {
    stream.set_read_timeout(Some(within)).unwrap();
    let mut buf = [0u8; 1024];
    loop {
        match stream.read(&mut buf) {
            Ok(0) => return true,
            Ok(_) => continue,
            Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {
                return false
            }
            Err(_) => return true,
        }
    }
}

#[test]
fn idle_and_slow_clients_are_disconnected() {
    let upstream = spawn_upstream();
    let proxy = Proxy::start_with("client_idle_timeout_secs = 1", LOCAL_UPSTREAM);

    // 连上后什么都不发。
    let mut idle = proxy.connect();
    // slowloris：只发半个请求头。
    let mut slow = proxy.connect();
    slow.write_all(b"GET http://127.0.0.1/ HTTP/1.1\r\nX-Slow: ")
        .unwrap();
    // keep-alive：完成一个请求后保持空闲。
    let mut keep_alive = proxy.connect();
    keep_alive
        .write_all(get(&format!("http://127.0.0.1:{upstream}/")).as_bytes())
        .unwrap();
    assert_eq!(read_response(&mut keep_alive).0, 200);

    let started = Instant::now();
    for (name, stream) in [
        ("空闲", &mut idle),
        ("slowloris", &mut slow),
        ("keep-alive 空闲", &mut keep_alive),
    ] {
        assert!(
            closed_by_peer(stream, Duration::from_secs(5)),
            "{name}连接应在 client_idle_timeout_secs 后被关闭"
        );
    }
    assert!(started.elapsed() < Duration::from_secs(5));
}

#[test]
fn max_connections_queues_extra_clients() {
    let upstream = spawn_upstream();
    let proxy = Proxy::start_with(
        "max_connections = 2\nclient_idle_timeout_secs = 0",
        LOCAL_UPSTREAM,
    );
    let request = get(&format!("http://127.0.0.1:{upstream}/"));

    // 占满两个名额：各完成一个请求，确认已被 accept，然后保持 keep-alive。
    let mut held: Vec<TcpStream> = (0..2)
        .map(|_| {
            let mut s = proxy.connect();
            s.write_all(request.as_bytes()).unwrap();
            assert_eq!(read_response(&mut s).0, 200);
            s
        })
        .collect();

    // 第三个连接停在内核 backlog 里，暂时得不到响应。
    let mut third = proxy.connect();
    third.write_all(request.as_bytes()).unwrap();
    third
        .set_read_timeout(Some(Duration::from_millis(700)))
        .unwrap();
    let mut probe = [0u8; 1];
    let err = third.read(&mut probe).expect_err("达到上限时不应被服务");
    assert!(matches!(
        err.kind(),
        ErrorKind::WouldBlock | ErrorKind::TimedOut
    ));
    assert!(
        proxy
            .metric("proxy_connections_throttled_total")
            .unwrap_or(0.0)
            >= 1.0
    );

    // 释放一个名额后，排队的连接被正常服务。
    drop(held.pop());
    third.set_read_timeout(Some(common::IO_TIMEOUT)).unwrap();
    let (status, body) = read_response(&mut third);
    assert_eq!((status, body.as_str()), (200, "upstream-ok"));
}

#[test]
fn connect_tunnels_count_toward_limits() {
    let upstream = spawn_upstream();
    let proxy = Proxy::start_with(
        "max_connections = 1\nclient_idle_timeout_secs = 0",
        LOCAL_UPSTREAM,
    );

    // 建立一条隧道并保持打开（mock 上游在等请求头，隧道一直存活）。
    let mut held = proxy.connect();
    held.write_all(tunnel(&format!("127.0.0.1:{upstream}")).as_bytes())
        .unwrap();
    assert_eq!(read_response(&mut held).0, 200);
    assert_eq!(
        proxy.metric("proxy_active_connections"),
        Some(1.0),
        "隧道应计入活跃连接数"
    );

    // 隧道占着唯一的名额：新连接排队。
    let mut second = proxy.connect();
    second
        .write_all(get(&format!("http://127.0.0.1:{upstream}/")).as_bytes())
        .unwrap();
    second
        .set_read_timeout(Some(Duration::from_millis(700)))
        .unwrap();
    let mut probe = [0u8; 1];
    assert!(
        second.read(&mut probe).is_err(),
        "隧道仍占用名额时新连接不应被服务"
    );

    // 关闭隧道后名额归还，排队的连接被服务。
    drop(held);
    second.set_read_timeout(Some(common::IO_TIMEOUT)).unwrap();
    assert_eq!(read_response(&mut second).0, 200);
}
