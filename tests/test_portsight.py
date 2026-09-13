"""Tests for portsight — run against a FAKE /proc tree, never the real one."""
import io
import json
import contextlib
import importlib
import os
import shutil
import tempfile
import unittest

import portsight


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #

def h4(ip: str, port: int) -> str:
    """Encode ipv4+port the way /proc/net/tcp does (little-endian hex)."""
    octets = ip.split(".")
    addr = "".join(f"{int(o):02X}" for o in reversed(octets))
    return f"{addr}:{port:04X}"


def make_proc(root: str, sockets: dict, procs: dict) -> None:
    """sockets: {'tcp': [lines...], 'udp': [...]}. procs: {pid: {...}}"""
    net = os.path.join(root, "net")
    os.makedirs(net, exist_ok=True)
    header = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode"
    for fam, lines in sockets.items():
        with open(os.path.join(net, fam), "w") as fh:
            fh.write(header + "\n")
            for i, line in enumerate(lines):
                fh.write(f"{i:4}: {line}\n")
    for pid, spec in procs.items():
        pdir = os.path.join(root, str(pid))
        os.makedirs(os.path.join(pdir, "fd"), exist_ok=True)
        with open(os.path.join(pdir, "comm"), "w") as fh:
            fh.write(spec.get("comm", "test") + "\n")
        with open(os.path.join(pdir, "cmdline"), "w") as fh:
            fh.write(" ".join(spec.get("cmd", ["test"])) + "\x00")
        with open(os.path.join(pdir, "status"), "w") as fh:
            fh.write(f"Name:\t{spec.get('comm','test')}\n"
                     f"State:\tS (sleeping)\n"
                     f"Tgid:\t{pid}\n"
                     f"PPid:\t{spec.get('ppid', 1)}\n"
                     f"Uid:\t{spec.get('uid', 0)}\t0\t0\t0\n"
                     f"Threads:\t1\n")
        with open(os.path.join(pdir, "cgroup"), "w") as fh:
            fh.write(spec.get("cgroup", "0::/system.slice/x.service\n"))
        for link_name, target in spec.get("fds", {}).items():
            os.symlink(target, os.path.join(pdir, "fd", link_name))


class ProcTestCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="portsight-test-")
        self._orig_root = portsight.PROC_ROOT
        portsight.PROC_ROOT = self.tmp

    def tearDown(self):
        portsight.PROC_ROOT = self._orig_root
        shutil.rmtree(self.tmp, ignore_errors=True)

    def run_cli(self, argv):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = portsight.main(argv)
        return code, out.getvalue(), err.getvalue()


# --------------------------------------------------------------------------- #
# address parsing
# --------------------------------------------------------------------------- #

class AddrTests(unittest.TestCase):
    def test_ipv4_wildcard(self):
        self.assertEqual(portsight.parse_hex_addr("00000000:22B8"), ("0.0.0.0", 8888))

    def test_ipv4_loopback(self):
        self.assertEqual(portsight.parse_hex_addr("0100007F:1F90"), ("127.0.0.1", 8080))

    def test_ipv6_any(self):
        self.assertEqual(portsight.parse_hex_addr(
            "00000000000000000000000000000000:0016"), ("::", 22))

    def test_ipv6_loopback(self):
        self.assertEqual(portsight.parse_hex_addr(
            "00000000000000000000000001000000:1F90"), ("::1", 8080))

    def test_ipv6_full_compress(self):
        addr, port = portsight.parse_hex_addr(
            "0000000000000000FFFF00000100007F:0050")
        self.assertEqual(port, 80)
        self.assertIn("::", addr)

    def test_bad_input(self):
        with self.assertRaises(ValueError):
            portsight.parse_hex_addr("XYZ:1")
        with self.assertRaises(ValueError):
            portsight.parse_hex_addr("0102:1")

    def test_fmt_bind(self):
        self.assertEqual(portsight.fmt_bind("0.0.0.0", 22, "tcp"), "*:22")
        self.assertEqual(portsight.fmt_bind("127.0.0.1", 8080, "tcp"), "127.0.0.1:8080")
        self.assertEqual(portsight.fmt_bind("::", 22, "tcp6"), "[::]:22")


# --------------------------------------------------------------------------- #
# socket tables + inode->pid + owners
# --------------------------------------------------------------------------- #

class ResolveTests(ProcTestCase):
    def _fixture(self):
        # hermes-like service on 8644 (pid 100), socket-activated ssh on 22
        # (pid 1 + pid 200), a docker-ish container app on 8080 (pid 300)
        make_proc(
            self.tmp,
            {
                "tcp": [
                    f"{h4('0.0.0.0', 8644)} {h4('0.0.0.0', 0)} 0A 00000000:00000000 00:00000000 00000000     0        0 1111 1",
                    f"{h4('0.0.0.0', 22)} {h4('0.0.0.0', 0)} 0A 00000000:00000000 00:00000000 00000000     0        0 2222 1",
                    f"{h4('0.0.0.0', 8080)} {h4('0.0.0.0', 0)} 0A 00000000:00000000 00:00000000 00000000  1000        0 3333 1",
                    f"{h4('127.0.0.1', 8644)} {h4('127.0.0.1', 5000)} 01 00000000:00000000 00:00000000 00000000     0        0 1111 1",
                ],
                "udp": [
                    f"{h4('127.0.0.53', 53)} {h4('0.0.0.0', 0)} 07 00000000:00000000 00:00000000 00000000   996        0 4444 1",
                ],
            },
            {
                1: {"comm": "systemd", "ppid": 0,
                    "cgroup": "0::/init.scope\n",
                    "fds": {"15": "socket:[2222]"}},
                100: {"comm": "hermes", "ppid": 773,
                      "cgroup": "0::/user.slice/user-0.slice/service/hermes-gateway.service\n",
                      "fds": {"21": "socket:[1111]"}},
                200: {"comm": "sshd", "ppid": 1,
                      "cgroup": "0::/system.slice/ssh.service\n",
                      "fds": {"3": "socket:[2222]"}},
                300: {"comm": "java", "ppid": 1, "uid": 1000,
                      "cgroup": ("0::/system.slice/docker-"
                                 + "a" * 64 + ".scope\n"),
                      "fds": {"7": "socket:[3333]"}},
                400: {"comm": "resolved", "ppid": 1,
                      "cgroup": "0::/system.slice/systemd-resolved.service\n",
                      "fds": {"15": "socket:[4444]"}},
            },
        )

    def test_tcp_listen_only_by_default(self):
        self._fixture()
        entries = portsight.resolve([], "tcp", show_established=False)
        ports = {(e["port"], e["addr"]) for e in entries}
        self.assertEqual(ports, {(8644, "0.0.0.0"), (22, "0.0.0.0"), (8080, "0.0.0.0")})

    def test_established_included_on_demand(self):
        self._fixture()
        entries = portsight.resolve([8644], "tcp", show_established=True)
        states = {e["state"] for e in entries}
        self.assertEqual(states, {"LISTEN", "ESTABLISHED"})

    def test_inode_to_pid_mapping(self):
        self._fixture()
        entries = portsight.resolve([8644], "tcp", False)
        self.assertEqual(entries[0]["pids"], [100])
        self.assertEqual(entries[0]["procs"][0]["comm"], "hermes")

    def test_dual_holder_port_22(self):
        self._fixture()
        # systemctl is not available against fake data; socket_activated flag
        # still lights up because pid 1 holds the fd
        entries = portsight.resolve([22], "tcp", False)
        self.assertIn(1, entries[0]["pids"])
        self.assertIn(200, entries[0]["pids"])
        self.assertTrue(entries[0]["socket_activated"])

    def test_container_owner_no_cli(self):
        self._fixture()
        entries = portsight.resolve([8080], "tcp", False)
        owner = entries[0]["owners"][0]
        self.assertEqual(owner["container"], "a" * 12)  # falls back to short id
        self.assertEqual(owner["image"], "")            # no docker CLI in test env

    def test_udp(self):
        self._fixture()
        entries = portsight.resolve([53], "udp", False)
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0]["state"], "LISTEN")
        self.assertEqual(entries[0]["pids"], [400])

    def test_proto_all(self):
        self._fixture()
        entries = portsight.resolve([], "all", False)
        protos = {e["proto"] for e in entries}
        self.assertEqual(protos, {"tcp", "udp"})

    def test_no_owner_scan(self):
        self._fixture()
        entries = portsight.resolve([8644], "tcp", False, with_owners=False)
        self.assertEqual(entries[0]["pids"], [])

    def test_kernel_sockets_skipped(self):
        self._fixture()
        entries = portsight.resolve([8644], "tcp", True)
        self.assertTrue(all(e["inode"] != 0 for e in entries))


# --------------------------------------------------------------------------- #
# CLI behavior
# --------------------------------------------------------------------------- #

class CliTests(ResolveTests):
    def test_exit_1_when_found(self):
        self._fixture()
        code, out, _ = self.run_cli(["8644", "--no-tree", "--color", "never"])
        self.assertEqual(code, 1)
        self.assertIn("8644", out)
        self.assertIn("hermes", out)

    def test_free_port_exit_0(self):
        self._fixture()
        code, out, _ = self.run_cli(["44444"])
        self.assertEqual(code, 0)
        self.assertIn("free", out)

    def test_json_shape(self):
        self._fixture()
        code, out, _ = self.run_cli(["8080", "--json"])
        payload = json.loads(out)
        self.assertEqual(code, 1)
        self.assertEqual(payload[0]["port"], 8080)
        self.assertEqual(payload[0]["pids"], [300])
        self.assertIn("owners", payload[0])

    def test_bad_port(self):
        code, _, err = self.run_cli(["70000"])
        self.assertEqual(code, 2)
        self.assertIn("1..65535", err)

    def test_udp_flag(self):
        self._fixture()
        code, out, _ = self.run_cli(["--udp", "53", "--no-tree"])
        self.assertEqual(code, 1)
        self.assertIn("udp LISTEN", out)

    def test_summary_line(self):
        self._fixture()
        _, out, _ = self.run_cli(["--no-tree", "--color", "never"])
        self.assertIn("socket(s) on port(s):", out.strip().splitlines()[-1])

    def test_quiet_exit_codes(self):
        self._fixture()
        code, out, _ = self.run_cli(["8644", "--quiet"])
        self.assertEqual((code, out), (1, ""))
        code, out, _ = self.run_cli(["44444", "--quiet"])
        self.assertEqual((code, out), (0, ""))


# --------------------------------------------------------------------------- #
# kill safety (pure logic: build fake entries, check target selection)
# --------------------------------------------------------------------------- #

class KillSafetyTests(ProcTestCase):
    def test_protected_pid1_and_kernel_threads_never_targeted(self):
        make_proc(self.tmp, {}, {
            1: {"comm": "systemd", "ppid": 0, "fds": {}},
            2: {"comm": "kthreadd", "ppid": 0, "fds": {}},
            999999: {"comm": "app", "ppid": 1, "fds": {}},
        })
        entries = [{
            "port": 8080, "proto": "tcp", "addr": "0.0.0.0", "state": "LISTEN",
            "pids": [1, 2, 999999], "socket_activated": True,
            "procs": [{"pid": 1, "comm": "systemd", "cmdline": "/sbin/init",
                       "ppid": 0, "uid": 0, "is_kernel_thread": False},
                      {"pid": 2, "comm": "kthreadd", "cmdline": "",
                       "ppid": 0, "uid": 0, "is_kernel_thread": True},
                      {"pid": 999999, "comm": "app", "cmdline": "app",
                       "ppid": 1, "uid": 0, "is_kernel_thread": False}],
            "owners": [],
        }]
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            # pid 999999 surely does not exist -> os.kill gives ESRCH which the
            # tool treats as 'already gone'; pid 1 must be refused, pid 2 skipped
            code = portsight.do_kill(entries, escalate_after=0.1,
                                     assume_yes=True, pal=portsight.Palette(False))
        self.assertEqual(code, 0)
        self.assertIn("refusing to signal pid 1", err.getvalue())
        self.assertNotIn("2 (kthreadd)", err.getvalue())  # kernel thread not even listed


if __name__ == "__main__":
    unittest.main()
