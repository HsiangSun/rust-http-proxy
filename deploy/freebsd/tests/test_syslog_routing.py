"""Run with python3 -m unittest discover -s deploy/freebsd/tests."""
import pathlib
import subprocess
import unittest

FREEBSD = pathlib.Path(__file__).resolve().parents[1]


def rewrite(config):
    return subprocess.run(
        ["awk", "-f", str(FREEBSD / "exclude-proxy-syslog.awk")],
        input=config, text=True, capture_output=True, check=True,
    ).stdout


def destinations(config, program):
    """Evaluate program selectors for fixtures using the *.* priority selector."""
    selector = "*"
    result = set()
    for line in config.splitlines():
        line = line.strip()
        if line.startswith("#!"):
            line = line[1:]
        if line.startswith("!"):
            selector = line[1:].strip()
        elif line and not line.startswith("#"):
            if selector == "*":
                matches = True
            elif selector.startswith("-"):
                matches = program not in selector[1:].split(",")
            else:
                matches = program in selector.lstrip("+").split(",")
            if matches:
                result.add(line.split()[1])
    return result


class SyslogRoutingTests(unittest.TestCase):
    def test_proxy_is_removed_from_shared_logs_without_changing_other_programs(self):
        original = """*.* /var/log/messages
!-devd
*.* /var/log/daemon.log
*.* /var/log/custom.log
!sshd
*.* /var/log/auth-extra.log
!*
"""
        updated = rewrite(original)
        self.assertEqual(destinations(updated, "rust-http-proxy"), {"/var/log/custom.log"})
        self.assertEqual(destinations(updated, "sshd"), {
            "/var/log/messages", "/var/log/daemon.log", "/var/log/custom.log", "/var/log/auth-extra.log",
        })
        self.assertEqual(destinations(updated, "devd"), {"/var/log/messages"})

    def test_repeated_setup_does_not_add_duplicate_filters(self):
        original = "*.* /var/log/messages\n!-devd\n*.* /var/log/daemon.log\n!*\n"
        updated = rewrite(original)
        self.assertEqual(rewrite(updated), updated)

    def test_positive_program_filters_keep_other_programs_and_other_files(self):
        original = "!rust-http-proxy,sshd\n*.* /var/log/messages\n*.* /var/log/custom.log\n!*\n"
        updated = rewrite(original)
        self.assertEqual(destinations(updated, "rust-http-proxy"), {"/var/log/custom.log"})
        self.assertEqual(destinations(updated, "sshd"), {"/var/log/messages", "/var/log/custom.log"})

    def test_proxy_only_rule_is_removed_without_enabling_other_programs(self):
        original = "!rust-http-proxy\n*.* /var/log/messages\n*.* /var/log/custom.log\n!*\n"
        updated = rewrite(original)
        self.assertEqual(destinations(updated, "rust-http-proxy"), {"/var/log/custom.log"})
        self.assertEqual(destinations(updated, "sshd"), set())


if __name__ == "__main__":
    unittest.main()
