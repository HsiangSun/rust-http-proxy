//! SSRF 防护端到端测试：启动真实的代理二进制，用原始 HTTP 请求验证拦截行为。
//!
//! 全部只访问 127.0.0.1：被拦截的目标在建连前就被拒绝，放行路径使用本地
//! mock 上游，不依赖外网，可以在 CI 中稳定运行。

mod common;

use std::io::Write;

use common::{get, read_response, run_until_exit, spawn_upstream, tunnel, Proxy};

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
