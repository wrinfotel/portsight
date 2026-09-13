# portsight

**Who really holds this port?** Not just the PID — the whole story: process tree, systemd unit, docker container, socket activation.

Reads `/proc` directly on Linux. **No `lsof`, no `ss`, no `netstat` required** — works in bare containers and minimal VPS images where those tools are missing. Single Python file, standard library only, Python 3.8+.

```
$ portsight 22 --tree
*:22  tcp LISTEN  1/systemd, 452960/sshd  unit:ssh.socket [socket-activated]  unit:ssh.service
        452960 sshd (root) sshd: /usr/sbin/sshd -D [listener] 5 of 10-100 startups
```

## Why

`kill-port`-style tools answer *"which PID"*. You usually want to know **what it actually is**:

- `systemd` holds `:22` — is SSH broken? No: it's **socket activation**, the listening fd belongs to `ssh.socket` and was handed to `sshd`. portsight detects fd-sharing with pid 1 and names the unit.
- `:8080` is held by `docker-proxy` — which container? portsight walks the cgroup path to the container id and (if the `docker`/`podman` CLI is reachable) prints the container name and image.
- A containerized Java app's port: portsight attributes it through `docker-<id>.scope` even with **no docker CLI installed** in the namespace it runs in.
- `EADDRINUSE` on a dev port at 2 a.m.: `portsight 3000 --kill` finds it, asks once, SIGTERMs, escalates to SIGKILL after 3 s.

## Install

```sh
# one file, no dependencies
curl -fsSL https://raw.githubusercontent.com/wrinfotel/portsight/main/portsight.py -o /usr/local/bin/portsight
chmod +x /usr/local/bin/portsight
```

Or with [pipx](https://pipx.pypa.io/) once a tagged wheel exists — until then, curl-and-run is the whole story. Root sees every process; unrooted runs degrade gracefully (ports are listed, owners marked "not visible — run with sudo").

## Usage

```
portsight                  # every listening socket, attributed
portsight 8080             # who owns :8080 (all addresses, tcp)
portsight 53 443           # several ports
portsight --udp 38341      # UDP (WireGuard, DNS, game servers)
portsight --all            # tcp + udp
portsight 8080 --kill      # confirm interactively, then SIGTERM→SIGKILL
portsight 5432 --established   # include connected peers, not just listeners
portsight --json           # machine-readable, jq-friendly
portsight -T               # table only (no process tree) — default when piped
```

Exit codes are scriptable:

| code | meaning |
|---|---|
| 0 | port free (or `--kill` succeeded) |
| 1 | socket(s) found |
| 2 | usage / IO error |

```sh
portsight 8080 --quiet && echo "free, starting server"   # exit 0 = free
portsight 8080 --json | jq '.[].owners[].container'
```

## What the columns mean

```
[::]:8644  tcp6 LISTEN  468079/hermes  unit:hermes-gateway.service
    │         │     │        │                │
    │         │     │        │                └ cgroup attribution (systemd/docker)
    │         │     │        └ pid/comm of every process holding the fd
    │         │     └ state (UDP has no LISTEN; bound sockets show as LISTEN)
    │         └ protocol + address family
    └ bound address (* = wildcard)
```

- **`unit:x.socket [socket-activated]`** — the fd was opened by systemd on behalf of `x.service`. Killing `x.service` won't free the port; the fd lives in the socket unit.
- **`container:<name> (<image>)`** — resolved via cgroup id; name/image need a working `docker`/`podman` CLI, short id always works.
- Process tree (`--tree`) walks parents so you see *who started whom*.

## Platform support

- **Linux** — full feature set, zero external tools. Needs `/proc` mounted; root (or `sudo`) to map sockets of other users' processes.
- **macOS** — fallback via `lsof` (preinstalled); attribution limited to PID/uid (no cgroups).
- Windows — not supported (patches welcome, PRs gated on tests).

## How it works (one paragraph)

`/proc/net/{tcp,tcp6,udp,udp6}` gives every socket's local address and inode. Scanning `/proc/*/fd` maps inode → PIDs (the same trick `lsof` does, without its startup cost). Each PID's `/proc/PID/cgroup` names its systemd unit or container scope; UDP states are normalized since UDP has no `LISTEN`. The port is "yours" only when you can name its holder.

## Tests

```sh
python3 -m unittest discover tests   # 32 tests, fake /proc tree — never touches your live system
```

## Ideas for later

- `--watch` mode: alert when a port changes owner
- reverse DNS / service name for remote addresses in `--established`
- show the exact `fd=` numbers per holder
- Windows named-pipe mode

## License

MIT
