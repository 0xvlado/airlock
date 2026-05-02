import json
import os
import re
import signal
import socket
import struct
import subprocess
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path

PRIVATE_IP_PREFIXES = (
    "10.", "172.16.", "172.17.", "172.18.", "172.19.",
    "172.20.", "172.21.", "172.22.", "172.23.", "172.24.",
    "172.25.", "172.26.", "172.27.", "172.28.", "172.29.",
    "172.30.", "172.31.", "192.168.", "127.", "0.0.0.0",
    "::1", "::ffff:127.", "::ffff:10.", "::ffff:192.168.",
    "::ffff:172.", "fe80:", "fd",
)


def _is_private_ip(ip: str) -> bool:
    return any(ip.startswith(p) for p in PRIVATE_IP_PREFIXES)


@dataclass
class NetEvent:
    timestamp: float
    pid: int
    ip: str
    port: int
    hostname: str = ""
    suspicious: bool = False
    reason: str = ""

    def to_dict(self) -> dict:
        d = {
            "timestamp": self.timestamp,
            "pid": self.pid,
            "remote": f"{self.ip}:{self.port}",
        }
        if self.hostname:
            d["hostname"] = self.hostname
        if self.suspicious:
            d["suspicious"] = True
            d["reason"] = self.reason
        return d


@dataclass
class NetWatchResult:
    events: list[NetEvent] = field(default_factory=list)
    suspicious_events: list[NetEvent] = field(default_factory=list)
    dns_lookups: list[dict] = field(default_factory=list)
    blocked: bool = False
    summary: str = ""

    def to_dict(self) -> dict:
        return {
            "total_connections": len(self.events),
            "suspicious_connections": [e.to_dict() for e in self.suspicious_events],
            "dns_lookups": self.dns_lookups,
            "blocked": self.blocked,
            "summary": self.summary,
        }


ALLOWED_HOSTS_DURING_INSTALL = {
    "registry.npmjs.org",
    "registry.yarnpkg.com",
    "registry.npmmirror.com",
    "nodejs.org",
    "github.com",
    "api.github.com",
    "raw.githubusercontent.com",
    "objects.githubusercontent.com",
    "codeload.github.com",
}

KNOWN_DNS_RESOLVERS = {
    "1.1.1.1", "1.0.0.1",
    "8.8.8.8", "8.8.4.4",
    "9.9.9.9", "149.112.112.112",
    "208.67.222.222", "208.67.220.220",
    "127.0.0.53",
}

SUSPICIOUS_PORTS = {
    4444, 5555, 6666, 6667, 6697,
    8888, 9001, 9050, 9150,
    31337, 12345, 27374,
    25, 587, 465,
    6379,
    27017,
    3306,
}


def snapshot_connections() -> set[tuple[str, int]]:
    conns = set()
    for proc_path in ["/proc/net/tcp", "/proc/net/tcp6"]:
        p = Path(proc_path)
        if not p.exists():
            continue
        try:
            for line in p.read_text().splitlines()[1:]:
                parts = line.split()
                if len(parts) < 4 or parts[3] != "01":
                    continue
                addr_hex, port_hex = parts[2].split(":")
                port = int(port_hex, 16)
                if len(addr_hex) == 8:
                    addr_int = int(addr_hex, 16)
                    ip = socket.inet_ntoa(struct.pack("<I", addr_int))
                else:
                    chunks = [addr_hex[i:i+8] for i in range(0, 32, 8)]
                    packed = b""
                    for chunk in chunks:
                        packed += struct.pack("<I", int(chunk, 16))
                    ip = socket.inet_ntop(socket.AF_INET6, packed)
                conns.add((ip, port))
        except (PermissionError, OSError, ValueError):
            pass
    return conns


def diff_connections(before: set, after: set) -> list[NetEvent]:
    events = []
    new_conns = after - before
    for ip, port in new_conns:
        event = NetEvent(timestamp=time.time(), pid=0, ip=ip, port=port)

        if not _is_private_ip(ip):
            try:
                hostname = socket.getfqdn(ip)
                if hostname != ip:
                    event.hostname = hostname
            except (socket.herror, socket.gaierror, OSError):
                pass

        if port in SUSPICIOUS_PORTS:
            event.suspicious = True
            event.reason = f"suspicious port {port}"
        elif not _is_private_ip(ip):
            if event.hostname:
                if not any(event.hostname.endswith(h) for h in ALLOWED_HOSTS_DURING_INSTALL):
                    event.suspicious = True
                    event.reason = f"unexpected external host: {event.hostname}"
            else:
                event.suspicious = True
                event.reason = "unresolvable external IP"

        events.append(event)
    return events


def watch_with_strace(cmd: list[str], timeout: int = 300) -> NetWatchResult:
    result = NetWatchResult()
    strace_log = tempfile.NamedTemporaryFile(
        prefix="airlock_strace_", suffix=".log", delete=False,
        dir=os.environ.get("TMPDIR", "/tmp"),
    )
    strace_log.close()

    strace_cmd = [
        "/usr/bin/strace", "-f",
        "-e", "trace=connect,sendto",
        "-e", "signal=none",
        "-o", strace_log.name,
    ] + cmd

    try:
        proc = subprocess.run(
            strace_cmd, timeout=timeout,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    except subprocess.TimeoutExpired:
        result.summary = "Install timed out"
        return result
    except FileNotFoundError:
        result.summary = "strace not found — install strace for network tracing"
        return result

    try:
        log_content = Path(strace_log.name).read_text(errors="replace")
    except OSError:
        result.summary = "Could not read strace log"
        return result
    finally:
        try:
            os.unlink(strace_log.name)
        except OSError:
            pass

    connect_v4 = re.compile(
        r"(?:\[pid\s+(\d+)\])?\s*connect\(\d+,\s*\{sa_family=AF_INET,\s*"
        r"sin_port=htons\((\d+)\),\s*sin_addr=inet_addr\(\"([^\"]+)\"\)"
    )

    connect_v6 = re.compile(
        r"(?:\[pid\s+(\d+)\])?\s*connect\(\d+,\s*\{sa_family=AF_INET6,\s*"
        r"sin6_port=htons\((\d+)\),\s*sin6_flowinfo=\S+,\s*"
        r"inet_pton\(AF_INET6,\s*\"([^\"]+)\""
    )

    dns_pattern = re.compile(
        r"sendto\(\d+,.*\"([a-zA-Z0-9][\w\-\.]+\.[a-zA-Z]{2,})"
    )

    seen_ips = set()
    seen_dns = set()

    for line in log_content.splitlines():
        for pattern in [connect_v4, connect_v6]:
            m = pattern.search(line)
            if m:
                groups = m.groups()
                pid = int(groups[0]) if groups[0] else 0
                port = int(groups[1])
                ip = groups[2] or (groups[3] if len(groups) > 3 else "")
                if not ip or ip in seen_ips:
                    continue
                if port == 0:
                    continue
                if port == 53 and (ip in KNOWN_DNS_RESOLVERS or _is_private_ip(ip)):
                    seen_ips.add(ip)
                    result.dns_lookups.append({"resolver": ip})
                    continue
                seen_ips.add(ip)

                event = NetEvent(timestamp=time.time(), pid=pid, ip=ip, port=port)

                if not _is_private_ip(ip):
                    try:
                        hostname = socket.getfqdn(ip)
                        if hostname != ip:
                            event.hostname = hostname
                    except (socket.herror, socket.gaierror, OSError):
                        pass

                    if port in SUSPICIOUS_PORTS:
                        event.suspicious = True
                        event.reason = f"suspicious port {port}"
                    elif event.hostname:
                        if not any(event.hostname.endswith(h) for h in ALLOWED_HOSTS_DURING_INSTALL):
                            event.suspicious = True
                            event.reason = f"unexpected host: {event.hostname}"
                    else:
                        event.suspicious = True
                        event.reason = "unknown external IP"

                result.events.append(event)
                if event.suspicious:
                    result.suspicious_events.append(event)
                break

        m = dns_pattern.search(line)
        if m:
            domain = m.group(1)
            if domain not in seen_dns:
                seen_dns.add(domain)
                result.dns_lookups.append({"domain": domain})

    if result.suspicious_events:
        result.summary = f"{len(result.suspicious_events)} suspicious connection(s) during install"
    else:
        result.summary = f"{len(result.events)} connection(s), none suspicious"

    return result


def _build_bwrap_cmd(cmd: list[str], project_dir: str | None = None) -> list[str]:
    bwrap = [
        "/usr/bin/bwrap",
        "--unshare-net",
        "--ro-bind", "/usr", "/usr",
        "--ro-bind", "/lib", "/lib",
        "--ro-bind", "/lib64", "/lib64",
        "--ro-bind", "/bin", "/bin",
        "--ro-bind", "/sbin", "/sbin",
        "--ro-bind", "/etc/resolv.conf", "/etc/resolv.conf",
        "--ro-bind", "/etc/ssl", "/etc/ssl",
        "--ro-bind", "/etc/ca-certificates", "/etc/ca-certificates",
        "--proc", "/proc",
        "--dev", "/dev",
        "--tmpfs", "/tmp",
        "--symlink", "usr/lib", "/lib",
    ]
    home = os.environ.get("HOME", "/home/vs")
    bwrap.extend(["--ro-bind", home, home])
    if project_dir:
        bwrap.extend(["--bind", project_dir, project_dir])
    node_modules = os.path.join(os.getcwd(), "node_modules")
    if os.path.isdir(node_modules):
        bwrap.extend(["--bind", node_modules, node_modules])
    bwrap.extend(["--setenv", "HOME", home])
    bwrap.extend(["--chdir", os.getcwd()])
    bwrap.extend(["--die-with-parent"])
    bwrap.extend(cmd)
    return bwrap


def run_sandboxed(
    cmd: list[str],
    timeout: int = 300,
    project_dir: str | None = None,
) -> NetWatchResult:
    result = NetWatchResult()
    result.blocked = True

    if not Path("/usr/bin/bwrap").exists():
        result.summary = "bwrap not found — install bubblewrap for sandbox mode"
        result.blocked = False
        return result

    bwrap_cmd = _build_bwrap_cmd(cmd, project_dir)

    strace_log = None
    if Path("/usr/bin/strace").exists():
        strace_log = tempfile.NamedTemporaryFile(
            prefix="airlock_sandbox_", suffix=".log", delete=False,
            dir=os.environ.get("TMPDIR", "/tmp"),
        )
        strace_log.close()
        bwrap_cmd = [
            "/usr/bin/strace", "-f",
            "-e", "trace=connect,sendto",
            "-e", "signal=none",
            "-o", strace_log.name,
        ] + bwrap_cmd

    try:
        proc = subprocess.run(
            bwrap_cmd, timeout=timeout,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        exit_code = proc.returncode
    except subprocess.TimeoutExpired:
        result.summary = "Sandboxed script timed out"
        return result
    except FileNotFoundError:
        result.summary = "Failed to start sandbox"
        return result

    if strace_log:
        try:
            log_content = Path(strace_log.name).read_text(errors="replace")
            blocked_conns = []
            connect_re = re.compile(
                r"connect\(\d+.*?htons\((\d+)\).*?"
                r"(?:inet_addr\(\"([^\"]+)\"\)|inet_pton\([^,]+,\s*\"([^\"]+)\")"
            )
            for line in log_content.splitlines():
                if "ENETUNREACH" in line or "ECONNREFUSED" in line or "ENETDOWN" in line:
                    m = connect_re.search(line)
                    if m:
                        port = int(m.group(1))
                        ip = m.group(2) or m.group(3) or ""
                        if port == 0 or not ip:
                            continue
                        if port == 53:
                            continue
                        if _is_private_ip(ip):
                            continue
                        event = NetEvent(
                            timestamp=time.time(), pid=0,
                            ip=ip, port=port,
                            suspicious=True,
                            reason="BLOCKED by sandbox \u2014 attempted external connection",
                        )
                        try:
                            hostname = socket.getfqdn(ip)
                            if hostname != ip:
                                event.hostname = hostname
                        except (socket.herror, socket.gaierror, OSError):
                            pass
                        blocked_conns.append(event)

            result.events = blocked_conns
            result.suspicious_events = blocked_conns
        except OSError:
            pass
        finally:
            try:
                os.unlink(strace_log.name)
            except OSError:
                pass

    if result.suspicious_events:
        result.summary = f"BLOCKED {len(result.suspicious_events)} outbound connection(s)"
    else:
        result.summary = "Script ran in sandbox \u2014 no outbound attempts detected"

    return result


def run_with_network_monitor(
    cmd: list[str],
    use_strace: bool = True,
    sandbox: bool = False,
    timeout: int = 300,
    project_dir: str | None = None,
) -> NetWatchResult:
    if sandbox:
        return run_sandboxed(cmd, timeout, project_dir)

    if use_strace and Path("/usr/bin/strace").exists():
        return watch_with_strace(cmd, timeout)

    before = snapshot_connections()
    try:
        subprocess.run(cmd, timeout=timeout, capture_output=True, text=True)
    except (subprocess.TimeoutExpired, FileNotFoundError):
        pass
    after = snapshot_connections()

    events = diff_connections(before, after)
    suspicious = [e for e in events if e.suspicious]

    return NetWatchResult(
        events=events,
        suspicious_events=suspicious,
        summary=f"{len(suspicious)} suspicious of {len(events)} new connection(s)",
    )
