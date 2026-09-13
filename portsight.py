#!/usr/bin/env python3
"""portsight - see WHO really holds a network port on Linux.

Single file, standard library only. No lsof/ss/netstat required: sockets are
resolved straight from /proc, so it works in bare containers and minimal VPS
images. Ownership is attributed all the way up: systemd unit, docker
container, socket-activated services (the "why is systemd holding :22" case).

Exit codes:
  0  no matching sockets found (or --kill succeeded)
  1  matching sockets found (useful in scripts: `portsight 8080 && free!`)
  2  usage/IO error
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import signal
import subprocess
import sys

__version__ = "0.1.2"

# single seam for tests: point this at a fake tree to avoid touching the
# real /proc (and accidentally killing things)
PROC_ROOT = "/proc"

# /proc/net/tcp state codes we care about
TCP_STATES = {
    "0A": "LISTEN",
    "01": "ESTABLISHED",
    "06": "TIME_WAIT",
    "07": "CLOSE",
}
TCP_LISTEN = "0A"

HEX_RE = re.compile(r"^[0-9A-Fa-f]+$")
CONTAINER_ID_RE = re.compile(r"([0-9a-f]{64})")
DOCKER_PREFIX_RE = re.compile(r"^docker-([0-9a-f]{64})\.scope$")
DOCKER_PROXY_RE = re.compile(r"-container-ip (\S+) -container-port (\d+)")

# lazily-built {container-ip: (short_id, name, image, via)} for docker-proxy
_IP_MAP: dict | None = None


def container_ip_map() -> dict:
    """Map container IPs to container metadata via the docker/podman CLI.

    docker-proxy is a host-side process: the container's cgroup is not in its
    own /proc/PID/cgroup, so the port must be attributed through the
    -container-ip argument from its cmdline instead.
    """
    global _IP_MAP
    if _IP_MAP is not None:
        return _IP_MAP
    _IP_MAP = {}
    for binary in ("docker", "podman"):
        exe = shutil.which(binary)
        if not exe:
            continue
        try:
            out = subprocess.run([exe, "ps", "-q"], capture_output=True,
                                 text=True, timeout=3)
        except (OSError, subprocess.SubprocessError):
            continue
        if out.returncode != 0:
            continue
        ids = out.stdout.split()
        if not ids:
            continue
        try:
            out = subprocess.run(
                [exe, "inspect", "--format",
                 "{{range .NetworkSettings.Networks}}{{.IPAddress}},{{end}} {{.Name}} {{.Config.Image}}",
                 *ids],
                capture_output=True, text=True, timeout=3)
        except (OSError, subprocess.SubprocessError):
            continue
        if out.returncode != 0:
            continue
        for line in out.stdout.splitlines():
            ip_field, _, rest = line.partition(" ")
            if not rest:  # line had no metadata part (no networks at all)
                continue
            name, _, image = rest.partition(" ")
            for ip in ip_field.rstrip(",").split(","):
                if ip:
                    _IP_MAP[ip] = {"name": name.lstrip("/"), "image": image,
                                   "via": binary}
        # one runtime is enough; keep the first that answered
        if _IP_MAP:
            break
    return _IP_MAP


def container_from_proxy_cmdline(cmdline: str) -> dict:
    """docker-proxy keeps the target container-ip in its argv.

    Returns {} unless both the ip is parseable and the runtime map resolves it.
    """
    m = DOCKER_PROXY_RE.search(cmdline or "")
    if not m:
        return {}
    meta = container_ip_map().get(m.group(1))
    if not meta:
        return {}
    return {"unit": "", "container": meta["name"], "image": meta["image"],
            "runtime": meta["via"]}


class PortsightError(Exception):
    """Fatal, user-facing error."""


class Palette:
    def __init__(self, enabled: bool):
        self.enabled = enabled

    def wrap(self, code: str, text: str) -> str:
        if not self.enabled:
            return text
        return f"\033[{code}m{text}\033[0m"

    def port(self, text): return self.wrap("1;36", text)
    def bold(self, text): return self.wrap("1", text)
    def pid(self, text): return self.wrap("1", text)
    def unit(self, text): return self.wrap("35", text)
    def container(self, text): return self.wrap("38;5;75", text)
    def warn(self, text): return self.wrap("33", text)
    def dim(self, text): return self.wrap("2", text)
    def ok(self, text): return self.wrap("32", text)


# --------------------------------------------------------------------------- #
# Address helpers
# --------------------------------------------------------------------------- #

def parse_hex_addr(hex_addr: str) -> tuple[str, int]:
    """'0100007F:22B8' -> ('127.0.0.1', 8888). Supports v4 (8 hex) and v6 (32)."""
    addr_hex, _, port_hex = hex_addr.rpartition(":")
    if not HEX_RE.match(port_hex):
        raise ValueError(f"bad port field: {hex_addr!r}")
    port = int(port_hex, 16)
    if len(addr_hex) == 8:
        raw = bytes.fromhex(addr_hex)
        return ".".join(str(b) for b in reversed(raw)), port
    if len(addr_hex) == 32:
        # four little-endian 32-bit words
        words = [addr_hex[i:i + 8] for i in range(0, 32, 8)]
        octets = b"".join(bytes.fromhex(w)[::-1] for w in words)
        groups = [octets[i:i + 2].hex().lstrip("0") or "0" for i in range(0, 16, 2)]
        if all(g == "0" for g in groups):
            return "::", port
        best_start, best_len, start = 0, 0, None
        for i, g in enumerate(groups + ["x"]):
            if g == "0":
                if start is None:
                    start = i
            else:
                if start is not None and i - start > best_len:
                    best_start, best_len = start, i - start
                start = None
        if best_len >= 2:
            head = ":".join(groups[:best_start])
            tail = ":".join(groups[best_start + best_len:])
            return f"{head}::{tail}" if head or tail else "::", port
        return ":".join(groups), port
    raise ValueError(f"bad address field: {hex_addr!r}")


def fmt_bind(addr: str, port: int, proto: str) -> str:
    wildcard = addr in ("0.0.0.0", "::")
    if ":" in addr:
        return f"[{addr}]:{port}" if not wildcard else f"[{addr}]:{port}"
    return f"{addr}:{port}" if not wildcard else f"*:{port}"


# --------------------------------------------------------------------------- #
# Socket inventory (/proc/net/{tcp,tcp6,udp,udp6})
# --------------------------------------------------------------------------- #

def read_socket_table(proto: str) -> list[dict]:
    """One entry per socket inode with its local address/state."""
    fname = f"{PROC_ROOT}/net/{proto}"
    rows = []
    try:
        with open(fname, "r") as fh:
            lines = fh.readlines()[1:]
    except OSError:
        return rows
    for line in lines:
        parts = line.split()
        if len(parts) < 10:
            continue
        local = parts[1]
        state = parts[3]
        try:
            addr, port = parse_hex_addr(local)
        except ValueError:
            continue
        inode = int(parts[9])
        if inode == 0:
            continue  # kernel-owned (TIME_WAIT etc.)
        rows.append({"proto": proto, "addr": addr, "port": port,
                     "state": state, "inode": inode,
                     "uid": int(parts[7])})
    return rows


def collect_sockets(want_tcp: bool, want_udp: bool, show_established: bool) -> list[dict]:
    socks: list[dict] = []
    wanted = {"tcp": want_tcp, "tcp6": want_tcp, "udp": want_udp, "udp6": want_udp}
    for proto, want in wanted.items():
        if not want:
            continue
        for row in read_socket_table(proto):
            if row["proto"].startswith("tcp"):
                if row["state"] != TCP_LISTEN and not (show_established and row["state"] == "01"):
                    continue
            else:
                # udp has no LISTEN: 07 = unconnected bound socket, 01 = connected peer
                if row["state"] not in ("07", "01"):
                    continue
                row["state"] = TCP_LISTEN  # display as LISTEN
            socks.append(row)
    return socks


# --------------------------------------------------------------------------- #
# inode -> pid map (scan /proc/*/fd)
# --------------------------------------------------------------------------- #

def scan_proc_fds() -> dict[int, list[int]]:
    """socket inode -> list of pids holding it (sorted)."""
    inode_to_pids: dict[int, list[int]] = {}
    for pid_dir in os.listdir(PROC_ROOT):
        if not pid_dir.isdigit():
            continue
        pid = int(pid_dir)
        fd_dir = f"{PROC_ROOT}/{pid}/fd"
        try:
            fds = os.listdir(fd_dir)
        except OSError:
            continue  # gone, or EACCES without root
        for fd in fds:
            try:
                link = os.readlink(f"{fd_dir}/{fd}")
            except OSError:
                continue
            if link.startswith("socket:["):
                try:
                    inode = int(link[8:-1])
                except ValueError:
                    continue
                inode_to_pids.setdefault(inode, []).append(pid)
    for pids in inode_to_pids.values():
        pids.sort()
    return inode_to_pids


# --------------------------------------------------------------------------- #
# Process facts
# --------------------------------------------------------------------------- #

def proc_info(pid: int) -> dict:
    info = {"pid": pid, "comm": "?", "ppid": 0, "uid": -1, "cmdline": "",
            "is_kernel_thread": False}
    try:
        with open(f"{PROC_ROOT}/{pid}/comm") as fh:
            info["comm"] = fh.read().strip() or "?"
    except OSError:
        return info
    info["exe"] = safe_readlink(f"{PROC_ROOT}/{pid}/exe")
    try:
        with open(f"{PROC_ROOT}/{pid}/cmdline", "rb") as fh:
            raw = fh.read()
        info["cmdline"] = raw.replace(b"\0", b" ").decode("utf-8", "replace").strip()
        info["is_kernel_thread"] = (raw == b"")
    except OSError:
        pass
    try:
        with open(f"{PROC_ROOT}/{pid}/status") as fh:
            for line in fh:
                if line.startswith("PPid:"):
                    info["ppid"] = int(line.split()[1])
                elif line.startswith("Uid:"):
                    info["uid"] = int(line.split()[1])
                elif line.startswith("Threads:"):
                    info["threads"] = int(line.split()[1])
                if "ppid" in info and info.get("uid", -1) >= 0 and "threads" in info:
                    break
    except OSError:
        pass
    return info


def safe_readlink(path: str) -> str:
    try:
        return os.readlink(path)
    except OSError:
        return ""


def uid_name(uid: int) -> str:
    if uid == 0:
        return "root"
    try:
        import pwd
        return pwd.getpwuid(uid).pw_name
    except Exception:
        return str(uid)


# --------------------------------------------------------------------------- #
# Ownership: cgroup -> systemd unit / docker container
# --------------------------------------------------------------------------- #

def read_cgroups(pid: int) -> list[str]:
    """Paths from /proc/PID/cgroup (both v1 and v2 layouts)."""
    paths = []
    try:
        with open(f"{PROC_ROOT}/{pid}/cgroup") as fh:
            for line in fh:
                parts = line.strip().split(":", 2)
                if len(parts) == 3 and parts[2] and parts[2] != "/":
                    paths.append(parts[2])
    except OSError:
        pass
    return paths


def unit_from_cgroup(paths: list[str]) -> str:
    for p in paths:
        seg = [s for s in p.split("/") if s]
        if not seg:
            continue
        last = seg[-1]
        if last == "init.scope":
            continue  # pid 1 / host root scope — not a real unit
        if last.endswith((".service", ".scope", ".slice", ".timer", ".socket")):
            if DOCKER_PREFIX_RE.match(last) or CONTAINER_ID_RE.search(p):
                continue  # container scope, handled separately
            if last.endswith(".service"):
                return last
            return last
    return ""


def container_id_from_cgroup(paths: list[str]) -> str:
    for p in paths:
        m = CONTAINER_ID_RE.search(p)
        if m:
            return m.group(1)
    return ""


def docker_inspect(cid: str) -> dict:
    """Best effort: ask docker/podman CLI if it exists and we can reach it."""
    for binary in ("docker", "podman"):
        exe = shutil.which(binary)
        if not exe:
            continue
        try:
            out = subprocess.run(
                [exe, "inspect", "--format", "{{.Name}}|{{.Config.Image}}", cid[:12]],
                capture_output=True, text=True, timeout=3)
            if out.returncode == 0 and "|" in out.stdout:
                name, _, image = out.stdout.strip().partition("|")
                return {"name": name.lstrip("/"), "image": image, "via": binary}
        except (OSError, subprocess.TimeoutExpired):
            continue
    return {}


def owner_of(pid: int) -> dict:
    """Attribute a pid: systemd unit and/or container."""
    owner = {"unit": "", "container": "", "image": "", "runtime": ""}
    paths = read_cgroups(pid)
    owner["unit"] = unit_from_cgroup(paths)
    cid = container_id_from_cgroup(paths)
    if cid:
        meta = docker_inspect(cid)
        owner["container"] = meta.get("name", "") or cid[:12]
        owner["image"] = meta.get("image", "")
        owner["runtime"] = meta.get("via", "")
        # in containers, /proc/1/cgroup path is often the real id even w/o CLI
        if not meta:
            owner["container"] = cid[:12]
        return owner
    # host-side proxy process: its own cgroup names docker.service, not the
    # container it forwards to. Resolve through -container-ip in argv.
    info = proc_info(pid)
    if info.get("comm") == "docker-proxy":
        proxy = container_from_proxy_cmdline(info.get("cmdline", ""))
        if proxy:
            proxy["unit"] = owner["unit"]
            owner.update({k: v for k, v in proxy.items() if v})
    return owner


# --------------------------------------------------------------------------- #
# Process tree
# --------------------------------------------------------------------------- #

def ancestry(pid: int, max_depth: int = 6) -> list[dict]:
    chain = []
    seen = set()
    cur = pid
    while cur and cur > 1 and cur not in seen and len(chain) < max_depth:
        seen.add(cur)
        info = proc_info(cur)
        if info["comm"] == "?":
            break
        chain.append(info)
        cur = info["ppid"]
    return chain


# --------------------------------------------------------------------------- #
# The port conflicts with 'systemd' itself: socket activation detection
# --------------------------------------------------------------------------- #

def refine_socket_activation(entry: dict) -> None:
    """If systemd (pid 1) holds the listen fd alongside the service, the port
    was opened by a .socket unit. Ask systemctl which one, if possible."""
    entry["socket_activated"] = False
    holders = entry.get("pids", [])
    if not holders or 1 not in holders:
        return
    entry["socket_activated"] = True
    exe = shutil.which("systemctl")
    if not exe:
        return
    try:
        out = subprocess.run(
            [exe, "list-sockets", "--no-legend", "--plain", "--all"],
            capture_output=True, text=True, timeout=3)
    except (OSError, subprocess.TimeoutExpired):
        return
    for line in out.stdout.splitlines():
        # --plain --no-legend:  ADDRESS  SOCKET-UNIT  [SERVICE-UNIT]
        cols = line.split()
        if len(cols) < 2:
            continue
        addr = cols[0]
        host_part = addr.rpartition(":")[0]
        if not addr.endswith(f":{entry['port']}"):
            continue
        # match address family: our proto carries it (tcp/tcp6)
        entry_is_v6 = entry["proto"].endswith("6")
        line_is_v6 = addr.startswith("[") or ":" in host_part
        if entry_is_v6 != line_is_v6:
            continue
        unit = next((c for c in cols[1:] if c.endswith(".socket")), "")
        if not unit:
            unit = cols[1] if cols[1].endswith(".service") else ""
        if unit:
            entry["activation_unit"] = unit
            break


# --------------------------------------------------------------------------- #
# macOS fallback (lsof-based)
# --------------------------------------------------------------------------- #

def resolve_macos(ports: list[int], proto_filter: str) -> list[dict]:
    if not shutil.which("lsof"):
        raise PortsightError("on macOS portsight needs `lsof` (usually preinstalled)")
    args = ["lsof", "-nP", "-iTCP" if proto_filter != "udp" else "-iUDP", "-sTCP:LISTEN"]
    try:
        out = subprocess.run(args, capture_output=True, text=True, timeout=15)
    except subprocess.TimeoutExpired:
        raise PortsightError("lsof timed out")
    entries = []
    for line in out.stdout.splitlines()[1:]:
        cols = line.split(None, 8)
        if len(cols) < 9:
            continue
        # COMMAND PID USER FD TYPE DEVICE SIZE/OFF NODE NAME
        name = cols[8]
        m = re.search(r"\(LISTEN\)\s*$", name) or cols[3].endswith("u")
        addr_port = name.split("->")[0]
        pm = re.search(r":(\d+)$", addr_port)
        if not pm:
            continue
        port = int(pm.group(1))
        if ports and port not in ports:
            continue
        proto = "tcp" if "TCP" in cols[4].upper() or cols[7].isdigit() and "(LISTEN" in name else "udp"
        pid = int(cols[1])
        entries.append({"port": port, "addr": addr_port.rpartition(":")[0].strip("[]") or "*",
                        "proto": cols[4].lower(), "state": "LISTEN" if "(LISTEN" in name else "BOUND",
                        "pids": [pid], "procs": [proc_info(pid)],
                        "owners": [owner_of(pid)], "inode": 0})
    return entries


# --------------------------------------------------------------------------- #
# Core resolution
# --------------------------------------------------------------------------- #

def resolve(ports: list[int], proto: str, show_established: bool,
            with_owners: bool = True) -> list[dict]:
    socks = collect_sockets(proto in ("tcp", "all"), proto in ("udp", "all"),
                            show_established)
    if ports:
        socks = [s for s in socks if s["port"] in ports]
    if not socks:
        return []

    inode_map = scan_proc_fds() if with_owners else {}

    grouped: dict[tuple, dict] = {}
    for s in socks:
        key = (s["port"], s["proto"], s["addr"], s["state"])
        ent = grouped.setdefault(key, {
            "port": s["port"], "proto": s["proto"], "addr": s["addr"],
            "state": TCP_STATES.get(s["state"], s["state"]),
            "inode": s["inode"], "uid": s["uid"], "pids": []})
        for pid in inode_map.get(s["inode"], []):
            if pid not in ent["pids"]:
                ent["pids"].append(pid)

    for ent in grouped.values():
        ent["pids"].sort()
        procs = [proc_info(p) for p in ent["pids"]] if ent["pids"] else []
        ent["procs"] = procs
        ent["owners"] = [owner_of(p) for p in ent["pids"]] if ent["pids"] else []
        refine_socket_activation(ent)
        # socket activation: attribute the .socket unit that opened the port
        act = ent.get("activation_unit")
        if ent.get("socket_activated") and act:
            for pid, o in zip(ent.get("pids", []), ent.get("owners", [])):
                if pid == 1 and not o.get("unit"):
                    o["unit"] = act
                    o["socket_activated"] = True
    return sorted(grouped.values(), key=lambda e: (e["port"], e["proto"], e["addr"]))


# --------------------------------------------------------------------------- #
# Rendering
# --------------------------------------------------------------------------- #

def owner_label(ent: dict, pal: Palette) -> str:
    bits = []
    for o in (ent.get("owners") or []):
        if o.get("container"):
            tag = f"container:{o['container']}"
            if o.get("image"):
                tag += f" ({o['image']})"
            bits.append(pal.container(tag))
        if o.get("unit"):
            suffix = pal.warn(" [socket-activated]") if o.get("socket_activated") else ""
            bits.append(pal.unit(f"unit:{o['unit']}{suffix}"))
    return "  ".join(dict.fromkeys(bits)) if bits else pal.dim("—")


def render_tree(ent: dict, pal: Palette) -> str:
    lines = []
    procs = ent.get("procs") or []
    if not procs:
        lines.append(pal.dim("   (owner not visible — run with sudo to map inode→pid)"))
        return "\n".join(lines)
    by_pid = {p["pid"]: p for p in procs}
    for p in procs:
        chain = ancestry(p["pid"])
        for depth, node in enumerate(chain):
            prefix = "   " + ("  └─ " if depth else "     ")
            tag = pal.pid(f"{node['pid']} {node['comm']}")
            users = uid_name(node["uid"])
            cmd = node["cmdline"] or "[kernel thread]"
            if len(cmd) > 78:
                cmd = cmd[:75] + "..."
            lines.append(f"{prefix}{tag} {pal.dim('('+users+')')} {pal.dim(cmd)}")
            if node["pid"] != p["pid"] and node["pid"] in by_pid:
                break
            if node["ppid"] == 1 or node["pid"] == 1:
                break
    return "\n".join(lines)


_ANSI_RE = re.compile(r"\033\[[0-9;]*m")


def plain_len(s: str) -> int:
    """Visible width of a possibly-colored string."""
    return len(_ANSI_RE.sub("", s))


COLUMNS = ("PORT", "PROTO", "STATE", "PIDS", "OWNER")


def render(entries: list[dict], pal: Palette, show_tree: bool) -> str:
    rows = []
    for ent in entries:
        head = fmt_bind(ent["addr"], ent["port"], ent["proto"])
        pid_txt = ", ".join(f"{p['pid']}/{p['comm']}"
                            for p in (ent.get("procs") or [])) or "?"
        rows.append([
            pal.port(head),
            pal.dim(ent["proto"]),
            pal.dim(ent["state"]),
            pal.pid(pid_txt),
            owner_label(ent, pal),
        ])
    widths = [max(len(COLUMNS[i]), *(plain_len(r[i]) for r in rows))
              for i in range(len(COLUMNS))] if rows else \
             [len(c) for c in COLUMNS]
    header = "  ".join(pal.bold(COLUMNS[i].ljust(widths[i]))
                       for i in range(len(COLUMNS)))
    out = [header]
    for r, ent in zip(rows, entries):
        line = "  ".join(cell.ljust(widths[i] + len(cell) - plain_len(cell))
                         for i, cell in enumerate(r))
        out.append(line.rstrip())
        if show_tree:
            out.append(render_tree(ent, pal))
    return "\n".join(out)


def summary(entries: list[dict]) -> str:
    ports = sorted({e["port"] for e in entries})
    return f"{len(entries)} socket(s) on port(s): " + ", ".join(map(str, ports))


# --------------------------------------------------------------------------- #
# Kill
# --------------------------------------------------------------------------- #

PROTECTED_COMMS = {"systemd", "init", "sshd", "dockerd", "containerd", "kubelet"}


def do_kill(entries: list[dict], escalate_after: float, assume_yes: bool,
            pal: Palette) -> int:
    targets: list[int] = []
    for ent in entries:
        for p in ent.get("procs", []):
            if p["pid"] <= 1:
                print(f"portsight: refusing to signal pid {p['pid']} "
                      f"({p['comm']}) on port {ent['port']}", file=sys.stderr)
                continue
            if p.get("is_kernel_thread"):
                continue
            targets.append(p["pid"])
    targets = sorted(set(targets))
    if not targets:
        print("portsight: no killable process owners found", file=sys.stderr)
        return 2

    risky = [p for p in targets
             if proc_info(p)["comm"] in PROTECTED_COMMS]
    print("portsight: about to kill:", ", ".join(
        f"{p} ({proc_info(p)['comm']})" for p in targets), file=sys.stderr)
    if risky:
        print(f"portsight: warning: {risky} look like critical services",
              file=sys.stderr)
    if not assume_yes:
        if not sys.stdin.isatty():
            print("portsight: not a tty — pass --yes to kill non-interactively",
                  file=sys.stderr)
            return 2
        try:
            answer = input(f"Kill {len(targets)} process(es)? [y/N] ")
        except (EOFError, KeyboardInterrupt):
            print()
            return 2
        if answer.strip().lower() not in ("y", "yes"):
            print("portsight: aborted", file=sys.stderr)
            return 2
    for pid in targets:
        try:
            os.kill(pid, signal.SIGTERM)
        except OSError as exc:
            print(f"portsight: kill {pid}: {exc}", file=sys.stderr)
    import time
    deadline = time.monotonic() + escalate_after
    remaining = set(targets)
    while remaining and time.monotonic() < deadline:
        time.sleep(0.2)
        for pid in list(remaining):
            try:
                os.kill(pid, 0)
            except OSError:
                remaining.discard(pid)
    for pid in sorted(remaining):
        try:
            os.kill(pid, signal.SIGKILL)
            print(f"portsight: {pid} ignored SIGTERM, sent SIGKILL", file=sys.stderr)
        except OSError:
            pass
    print(pal.ok("portsight: done"), file=sys.stderr)
    return 0


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="portsight",
        description="Show exactly who holds a network port: process tree, "
                    "systemd unit, docker container. Reads /proc directly — "
                    "no lsof/ss needed on Linux.",
        epilog="""\
examples:
  portsight                # all listening sockets, attributed
  portsight 8080           # who owns :8080 (and :8080 on every address)
  portsight 53 443         # several ports at once
  portsight --udp 38341    # UDP (wireguard, dns, game servers)
  portsight 8080 --kill    # confirm, SIGTERM, SIGKILL after 3s
  portsight 3000 --json | jq '.[].pids'
  portsight --established 5432   # also show connected peers

exit codes:
  0  nothing found / killed ok   1  socket(s) found   2  error
""",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("ports", nargs="*", type=int,
                        help="port numbers (default: show all listening)")
    parser.add_argument("-p", "--proto", choices=["tcp", "udp", "all"],
                        default="tcp",
                        help="protocol filter: tcp (default), udp, all")
    parser.add_argument("-u", "--udp", action="store_true",
                        help="shortcut for --proto udp")
    parser.add_argument("-a", "--all", action="store_true",
                        help="all protocols (tcp+udp)")
    parser.add_argument("-t", "--tree", action="store_true", dest="show_tree",
                        default=None,
                        help="show parent process chain under each hit "
                             "(default: on when stdout is a terminal)")
    parser.add_argument("-T", "--no-tree", action="store_false", dest="show_tree",
                        help="table lines only")
    parser.add_argument("-e", "--established", action="store_true",
                        help="include ESTABLISHED/connected sockets, not just listeners")
    parser.add_argument("-k", "--kill", action="store_true",
                        help="kill the owning processes (asks to confirm)")
    parser.add_argument("-y", "--yes", action="store_true",
                        help="no confirmation prompt (for scripts, use carefully)")
    parser.add_argument("--escalate-after", type=float, default=3.0, metavar="SEC",
                        help="seconds to wait after SIGTERM before SIGKILL (default: 3)")
    parser.add_argument("-j", "--json", action="store_true",
                        help="machine-readable JSON output")
    parser.add_argument("-q", "--quiet", action="store_true",
                        help="print nothing, rely on the exit code only")
    parser.add_argument("--no-owner", action="store_true",
                        help="skip /proc/*/fd scan (faster, no pid attribution)")
    parser.add_argument("--color", choices=["auto", "always", "never"],
                        default="auto", help="colorize output (default: auto)")
    parser.add_argument("-V", "--version", action="version",
                        version=f"portsight {__version__}")
    return parser


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if any(p < 1 or p > 65535 for p in args.ports):
        print("portsight: error: ports must be 1..65535", file=sys.stderr)
        return 2

    proto = args.proto
    if args.udp:
        proto = "udp"
    if args.all:
        proto = "all"

    try:
        if sys.platform == "darwin":
            entries = resolve_macos(args.ports, proto)
        else:
            entries = resolve(args.ports, proto, args.established,
                              with_owners=not args.no_owner)
    except PortsightError as exc:
        print(f"portsight: error: {exc}", file=sys.stderr)
        return 2

    color = args.color == "always" or (args.color == "auto" and sys.stdout.isatty())
    pal = Palette(color)

    if args.quiet and not args.kill:
        return 1 if entries else 0

    if args.json:
        payload = []
        for e in entries:
            payload.append({
                "port": e["port"], "proto": e["proto"], "addr": e["addr"],
                "state": e["state"], "inode": e["inode"],
                "pids": e.get("pids", []),
                "procs": [{"pid": p["pid"], "comm": p["comm"], "uid": uid_name(p["uid"]),
                           "cmdline": p["cmdline"]} for p in e.get("procs", [])],
                "owners": e.get("owners", []),
                "socket_activated": e.get("socket_activated", False),
            })
        json.dump(payload, sys.stdout, indent=2)
        sys.stdout.write("\n")
    elif not entries:
        if args.ports:
            wanted = ", ".join(
                f"{p}{'/'+proto if proto != 'all' else ''}" for p in args.ports)
            print(f"portsight: {wanted} — free ✓" if color else
                  f"portsight: {wanted} — free")
    else:
        show_tree = args.show_tree if args.show_tree is not None else bool(sys.stdout.isatty())
        print(render(entries, pal, show_tree))
        print(pal.dim(summary(entries)))

    if args.kill and entries:
        return do_kill(entries, args.escalate_after, args.yes, pal)
    return 1 if entries else 0


if __name__ == "__main__":
    sys.exit(main())
