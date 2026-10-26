# 仅排除 messages/daemon.log 中的代理日志，保留其他程序和路由规则。
BEGIN { program = "*" }

/^(#!|!)/ {
    program = $0
    sub(/^#!/, "!", program)
    sub(/^![ \t]*/, "", program)
    sub(/[ \t]*#.*$/, "", program)
    sub(/[ \t]+$/, "", program)
    print
    next
}

$2 ~ /^-?\/var\/log\/(messages|daemon\.log)$/ && $0 !~ /^[ \t]*#/ {
    updated = ""
    if (program == "*") {
        updated = "-rust-http-proxy"
    } else {
        list = program
        negative = substr(list, 1, 1) == "-"
        sub(/^[+-]/, "", list)
        count = split(list, names, ",")
        found = 0
        kept = ""
        for (i = 1; i <= count; i++) {
            if (names[i] == "rust-http-proxy") {
                found = 1
            } else {
                kept = kept (kept == "" ? "" : ",") names[i]
            }
        }
        if (negative && !found) {
            updated = program ",rust-http-proxy"
        } else if (!negative && found) {
            if (kept == "") {
                print "# rust-http-proxy uses its own log: " $0
                next
            }
            updated = kept
        }
    }
    if (updated != "") {
        print "!" updated
        print
        print "!" program
        next
    }
}

{ print }
