//! 监听器工具：通过 `socket2` 创建带 `SO_REUSEADDR` + `SO_REUSEPORT`
//! 的 TCP 监听器。
//!
//! 启用 `SO_REUSEPORT` 后，多个 worker task（甚至多进程）可以同时
//! 绑定到同一 `host:port`，由内核做连接级别的均衡，从而：
//!
//! 1. 降低跨核 accept 锁竞争，显著提升高并发短连接吞吐。
//! 2. 在 `TIME_WAIT` 大量堆积时仍能正常 bind，避免端口耗尽导致重启失败。

use std::net::SocketAddr;

use socket2::{Domain, Protocol, Socket, Type};
use tokio::net::TcpListener;

/// 创建一个启用了端口复用的 [`TcpListener`]。
///
/// * `addr` —— 待绑定的地址。
/// * `backlog` —— accept 队列长度，建议 1024+。
pub fn build_reuseport_listener(addr: SocketAddr, backlog: i32) -> std::io::Result<TcpListener> {
    let domain = if addr.is_ipv6() {
        Domain::IPV6
    } else {
        Domain::IPV4
    };
    let socket = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))?;

    // SO_REUSEADDR：允许 TIME_WAIT 状态的端口被复用，避免重启不可用。
    socket.set_reuse_address(true)?;

    // SO_REUSEPORT：允许多 worker 同时 bind 同一端口（Linux/BSD 特性）。
    // 在非 Unix 平台上 socket2 不暴露此 API，因此用 cfg 包裹。
    #[cfg(unix)]
    socket.set_reuse_port(true)?;

    // 非阻塞 + bind + listen。
    socket.set_nonblocking(true)?;
    socket.bind(&addr.into())?;
    socket.listen(backlog)?;

    let std_listener: std::net::TcpListener = socket.into();
    TcpListener::from_std(std_listener)
}
