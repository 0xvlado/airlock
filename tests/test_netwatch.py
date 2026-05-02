import os
import subprocess
import sys
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from netwatch import (
    ALLOWED_HOSTS_DURING_INSTALL,
    SUSPICIOUS_PORTS,
    NetEvent,
    NetWatchResult,
    _is_private_ip,
    diff_connections,
    run_with_network_monitor,
    snapshot_connections,
)


class TestIsPrivateIP(unittest.TestCase):
    def test_10_range(self):
        self.assertTrue(_is_private_ip("10.0.0.1"))

    def test_172_range(self):
        self.assertTrue(_is_private_ip("172.16.0.1"))

    def test_192_range(self):
        self.assertTrue(_is_private_ip("192.168.1.1"))

    def test_localhost(self):
        self.assertTrue(_is_private_ip("127.0.0.1"))

    def test_zero_addr(self):
        self.assertTrue(_is_private_ip("0.0.0.0"))

    def test_public_ip(self):
        self.assertFalse(_is_private_ip("8.8.8.8"))

    def test_ipv6_loopback(self):
        self.assertTrue(_is_private_ip("::1"))

    def test_ipv6_mapped_private(self):
        self.assertTrue(_is_private_ip("::ffff:192.168.1.1"))

    def test_link_local_ipv6(self):
        self.assertTrue(_is_private_ip("fe80::1"))

    def test_public_ipv6(self):
        self.assertFalse(_is_private_ip("2001:db8::1"))

    def test_fd_prefix(self):
        self.assertTrue(_is_private_ip("fd00::1"))


class TestNetEventDataclass(unittest.TestCase):
    def test_to_dict_basic(self):
        e = NetEvent(timestamp=1.0, pid=100, ip="1.2.3.4", port=443)
        d = e.to_dict()
        self.assertEqual(d["remote"], "1.2.3.4:443")
        self.assertEqual(d["pid"], 100)
        self.assertNotIn("hostname", d)
        self.assertNotIn("suspicious", d)

    def test_to_dict_with_hostname(self):
        e = NetEvent(timestamp=1.0, pid=0, ip="1.2.3.4", port=443, hostname="example.com")
        d = e.to_dict()
        self.assertEqual(d["hostname"], "example.com")

    def test_to_dict_suspicious(self):
        e = NetEvent(timestamp=1.0, pid=0, ip="1.2.3.4", port=4444, suspicious=True, reason="bad port")
        d = e.to_dict()
        self.assertTrue(d["suspicious"])
        self.assertEqual(d["reason"], "bad port")


class TestNetWatchResultDataclass(unittest.TestCase):
    def test_to_dict(self):
        r = NetWatchResult(blocked=True, summary="test")
        d = r.to_dict()
        self.assertEqual(d["total_connections"], 0)
        self.assertTrue(d["blocked"])
        self.assertEqual(d["summary"], "test")


class TestSnapshotConnections(unittest.TestCase):
    MOCK_TCP = """  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0100007F:0050 0100007F:C000 01 00000000:00000000 00:00000000 00000000     0        0 12345 1 0000000000000000 100 0 0 10 0
   1: 0100007F:0050 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 12346 1 0000000000000000 100 0 0 10 0"""

    @patch("netwatch.Path")
    def test_parses_established_tcp4(self, mock_path_cls):
        mock_proc = MagicMock()
        mock_proc.exists.return_value = True
        mock_proc.read_text.return_value = self.MOCK_TCP

        def path_side_effect(p):
            if p in ("/proc/net/tcp", "/proc/net/tcp6"):
                m = MagicMock()
                m.exists.return_value = (p == "/proc/net/tcp")
                m.read_text.return_value = self.MOCK_TCP if p == "/proc/net/tcp" else ""
                return m
            return MagicMock(exists=MagicMock(return_value=False))

        mock_path_cls.side_effect = path_side_effect
        conns = snapshot_connections()
        self.assertTrue(len(conns) >= 1)

    @patch("netwatch.Path")
    def test_no_proc_net(self, mock_path_cls):
        mock_path_cls.return_value.exists.return_value = False
        mock_path_cls.side_effect = lambda p: MagicMock(exists=MagicMock(return_value=False))
        conns = snapshot_connections()
        self.assertEqual(conns, set())


class TestDiffConnections(unittest.TestCase):
    @patch("netwatch.socket.getfqdn")
    def test_new_connection_detected(self, mock_fqdn):
        mock_fqdn.return_value = "registry.npmjs.org"
        before = set()
        after = {("93.184.216.34", 443)}
        events = diff_connections(before, after)
        self.assertEqual(len(events), 1)

    def test_no_new_connections(self):
        conns = {("192.168.1.1", 80)}
        events = diff_connections(conns, conns)
        self.assertEqual(events, [])

    @patch("netwatch.socket.getfqdn")
    def test_private_ip_not_suspicious(self, mock_fqdn):
        before = set()
        after = {("192.168.1.100", 80)}
        events = diff_connections(before, after)
        self.assertFalse(any(e.suspicious for e in events))

    @patch("netwatch.socket.getfqdn")
    def test_suspicious_port(self, mock_fqdn):
        mock_fqdn.return_value = "evil.com"
        before = set()
        after = {("8.8.8.8", 4444)}
        events = diff_connections(before, after)
        self.assertTrue(events[0].suspicious)
        self.assertIn("suspicious port", events[0].reason)

    @patch("netwatch.socket.getfqdn")
    def test_allowed_host_not_suspicious(self, mock_fqdn):
        mock_fqdn.return_value = "registry.npmjs.org"
        before = set()
        after = {("104.16.0.1", 443)}
        events = diff_connections(before, after)
        self.assertFalse(any(e.suspicious for e in events))

    @patch("netwatch.socket.getfqdn")
    def test_unexpected_host(self, mock_fqdn):
        mock_fqdn.return_value = "evil.example.com"
        before = set()
        after = {("1.2.3.4", 443)}
        events = diff_connections(before, after)
        self.assertTrue(events[0].suspicious)
        self.assertIn("unexpected", events[0].reason)

    @patch("netwatch.socket.getfqdn")
    def test_unresolvable_ip(self, mock_fqdn):
        mock_fqdn.return_value = "1.2.3.4"
        before = set()
        after = {("1.2.3.4", 443)}
        events = diff_connections(before, after)
        self.assertTrue(events[0].suspicious)
        self.assertIn("unresolvable", events[0].reason)

    @patch("netwatch.socket.getfqdn")
    def test_fqdn_raises(self, mock_fqdn):
        mock_fqdn.side_effect = OSError("lookup failed")
        before = set()
        after = {("1.2.3.4", 443)}
        events = diff_connections(before, after)
        self.assertTrue(events[0].suspicious)

    @patch("netwatch.socket.getfqdn")
    def test_all_suspicious_ports(self, mock_fqdn):
        mock_fqdn.return_value = "something.com"
        for port in SUSPICIOUS_PORTS:
            before = set()
            after = {("8.8.8.8", port)}
            events = diff_connections(before, after)
            self.assertTrue(events[0].suspicious, f"Port {port} not flagged")


class TestWatchWithStrace(unittest.TestCase):
    @patch("netwatch.subprocess.run")
    @patch("netwatch.Path")
    @patch("netwatch.os.unlink")
    @patch("netwatch.tempfile.NamedTemporaryFile")
    def test_timeout_handling(self, mock_tmp, mock_unlink, mock_path, mock_run):
        mock_tmp.return_value.__enter__ = MagicMock()
        mock_tmp.return_value.name = "/tmp/test.log"
        mock_tmp.return_value.close = MagicMock()
        mock_run.side_effect = subprocess.TimeoutExpired(cmd="test", timeout=300)

        from netwatch import watch_with_strace
        result = watch_with_strace(["echo"], timeout=1)
        self.assertIn("timed out", result.summary)

    @patch("netwatch.subprocess.run")
    @patch("netwatch.tempfile.NamedTemporaryFile")
    def test_strace_not_found(self, mock_tmp, mock_run):
        mock_tmp.return_value.name = "/tmp/test.log"
        mock_tmp.return_value.close = MagicMock()
        mock_run.side_effect = FileNotFoundError()

        from netwatch import watch_with_strace
        result = watch_with_strace(["echo"])
        self.assertIn("strace not found", result.summary)


class TestRunWithNetworkMonitor(unittest.TestCase):
    @patch("netwatch.run_sandboxed")
    def test_sandbox_mode(self, mock_sandbox):
        mock_sandbox.return_value = NetWatchResult(summary="sandboxed")
        result = run_with_network_monitor(["echo"], sandbox=True)
        mock_sandbox.assert_called_once()
        self.assertEqual(result.summary, "sandboxed")

    @patch("netwatch.Path")
    @patch("netwatch.watch_with_strace")
    def test_strace_mode(self, mock_strace, mock_path):
        mock_path.return_value.exists.return_value = True
        mock_strace.return_value = NetWatchResult(summary="straced")
        result = run_with_network_monitor(["echo"], use_strace=True)
        mock_strace.assert_called_once()

    @patch("netwatch.diff_connections")
    @patch("netwatch.snapshot_connections")
    @patch("netwatch.subprocess.run")
    @patch("netwatch.Path")
    def test_fallback_to_diff(self, mock_path, mock_run, mock_snap, mock_diff):
        mock_path.return_value.exists.return_value = False
        mock_snap.return_value = set()
        mock_diff.return_value = []
        mock_run.return_value = MagicMock(returncode=0)

        result = run_with_network_monitor(["echo"], use_strace=True)
        self.assertEqual(mock_snap.call_count, 2)

    @patch("netwatch.diff_connections")
    @patch("netwatch.snapshot_connections")
    @patch("netwatch.subprocess.run")
    @patch("netwatch.Path")
    def test_fallback_timeout(self, mock_path, mock_run, mock_snap, mock_diff):
        mock_path.return_value.exists.return_value = False
        mock_snap.return_value = set()
        mock_diff.return_value = []
        mock_run.side_effect = subprocess.TimeoutExpired(cmd="test", timeout=300)

        result = run_with_network_monitor(["echo"], use_strace=True)
        self.assertIsNotNone(result)

    @patch("netwatch.diff_connections")
    @patch("netwatch.snapshot_connections")
    @patch("netwatch.subprocess.run")
    @patch("netwatch.Path")
    def test_fallback_file_not_found(self, mock_path, mock_run, mock_snap, mock_diff):
        mock_path.return_value.exists.return_value = False
        mock_snap.return_value = set()
        mock_diff.return_value = []
        mock_run.side_effect = FileNotFoundError()

        result = run_with_network_monitor(["echo"], use_strace=True)
        self.assertIsNotNone(result)


class TestRunSandboxed(unittest.TestCase):
    @patch("netwatch.Path")
    def test_bwrap_not_found(self, mock_path):
        mock_path.return_value.exists.return_value = False
        mock_path.side_effect = lambda p: MagicMock(exists=MagicMock(return_value=False))

        from netwatch import run_sandboxed
        result = run_sandboxed(["echo"])
        self.assertFalse(result.blocked)
        self.assertIn("bwrap not found", result.summary)


class TestBuildBwrapCmd(unittest.TestCase):
    @patch.dict(os.environ, {"HOME": "/home/test"})
    @patch("netwatch.os.path.isdir", return_value=False)
    @patch("netwatch.os.getcwd", return_value="/tmp/project")
    def test_basic_command(self, mock_cwd, mock_isdir):
        from netwatch import _build_bwrap_cmd
        cmd = _build_bwrap_cmd(["node", "script.js"])
        self.assertIn("--unshare-net", cmd)
        self.assertIn("node", cmd)
        self.assertIn("script.js", cmd)

    @patch.dict(os.environ, {"HOME": "/home/test"})
    @patch("netwatch.os.path.isdir", return_value=False)
    @patch("netwatch.os.getcwd", return_value="/tmp/project")
    def test_with_project_dir(self, mock_cwd, mock_isdir):
        from netwatch import _build_bwrap_cmd
        cmd = _build_bwrap_cmd(["node"], project_dir="/my/project")
        bind_pairs = list(zip(cmd, cmd[1:]))
        self.assertTrue(any(a == "--bind" and b == "/my/project" for a, b in bind_pairs))

    @patch.dict(os.environ, {"HOME": "/home/test"})
    @patch("netwatch.os.path.isdir", return_value=True)
    @patch("netwatch.os.getcwd", return_value="/tmp/project")
    def test_node_modules_bind(self, mock_cwd, mock_isdir):
        from netwatch import _build_bwrap_cmd
        cmd = _build_bwrap_cmd(["node"])
        self.assertIn("/tmp/project/node_modules", cmd)


if __name__ == "__main__":
    unittest.main()
