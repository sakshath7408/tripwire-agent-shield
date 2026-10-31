"""Who is answering on the daemon port? The hook's check that a verdict came from the real daemon.

At startup the daemon makes a random per-boot key (held in its memory) and writes it, with its PID and start
time, to TRIPWIRE_HOME/daemon.json (0600), one entry per port. For each PreToolUse the hook sends a fresh nonce;
the daemon answers with HMAC-SHA256(key, nonce | decision | sha256(request body)) in `X-Tripwire-Mac`. The hook
denies when the MAC is missing or wrong, or when the PID that published the key is gone (or, on Linux, was
reused by another process).

What this does and does not buy (be honest about it): an impostor started after `pkill` must now also read
daemon.json, and the engine blocks agent reads of TRIPWIRE_HOME; the PID check catches a replaced daemon even
if the key leaked. But a program running as the same OS user can read that file outside the agent's tool calls,
so this raises the bar, it is not a boundary. `tripwire harden` (daemon as another user) is the real fix.

Kept tiny and import-light (os, json, the builtin SHA-256): the hook runs on every tool call.
"""

from __future__ import annotations

import json
import os
import time

try:  # the builtin SHA-256: `hashlib` loads OpenSSL, which costs milliseconds on every hook call
    from _sha2 import sha256 as _sha256  # Python 3.12+
except ImportError:  # pragma: no cover
    try:
        from _sha256 import sha256 as _sha256  # type: ignore[no-redef]  # Python 3.11
    except ImportError:
        from hashlib import sha256 as _sha256  # type: ignore[no-redef]

FILE = "daemon.json"
NONCE_HEADER = "X-Tripwire-Nonce"
MAC_HEADER = "X-Tripwire-Mac"


def mac(key: bytes, nonce: str, decision: str, body: bytes) -> str:
    """HMAC-SHA256 (RFC 2104) over nonce, decision and the request body's digest. Written out with hashlib so the
    hook does not pay for importing `hmac`."""
    msg = f"{nonce}\n{decision}\n{_sha256(body).hexdigest()}".encode()
    k = key if len(key) <= 64 else _sha256(key).digest()
    k = k.ljust(64, b"\0")
    inner = _sha256(bytes(b ^ 0x36 for b in k) + msg).digest()
    return _sha256(bytes(b ^ 0x5C for b in k) + inner).hexdigest()


def same(a: str, b: str) -> bool:
    """Constant-time compare without importing hmac."""
    if len(a) != len(b):
        return False
    r = 0
    for x, y in zip(a.encode(), b.encode()):
        r |= x ^ y
    return r == 0


def _start_ticks(pid: int) -> str | None:
    """Linux only: the process start time in clock ticks since boot (field 22 of /proc/<pid>/stat)."""
    try:
        with open(f"/proc/{pid}/stat") as f:
            s = f.read()
        return s.rsplit(")", 1)[1].split()[19]
    except (OSError, IndexError):
        return None


def home_dir() -> str:
    return os.environ.get("TRIPWIRE_HOME") or os.path.join(os.path.expanduser("~"), ".tripwire")


def publish(home: str, port: int, key: bytes) -> str:
    """Daemon side: record this process as the one serving `port`. 0600, written atomically."""
    path = os.path.join(home, FILE)
    try:
        with open(path) as f:
            data = json.load(f)
        if not isinstance(data, dict) or not isinstance(data.get("ports"), dict):
            data = {"ports": {}}
    except (OSError, ValueError):
        data = {"ports": {}}
    pid = os.getpid()
    data["ports"][str(int(port))] = {"pid": pid, "started": time.time(), "ticks": _start_ticks(pid), "key": key.hex()}
    os.makedirs(home, exist_ok=True)
    tmp = f"{path}.{pid}.tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump(data, f)
    os.chmod(tmp, 0o600)
    os.replace(tmp, path)
    return path


def lookup(port: int, home: str | None = None) -> dict | None:
    """Hook side: the entry the real daemon published for `port`, or None (older daemon, hardened home we can't
    read, or a URL that isn't a local port)."""
    try:
        with open(os.path.join(home or home_dir(), FILE)) as f:
            e = json.load(f)["ports"][str(int(port))]
        return e if isinstance(e, dict) and e.get("key") and e.get("pid") else None
    except (OSError, ValueError, KeyError, TypeError):
        return None


def alive(entry: dict) -> bool:
    """Is the process that published this entry still running (and, on Linux, the same process)?"""
    pid = int(entry["pid"])
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        pass  # exists, owned by another user
    except OSError:
        return False
    want = entry.get("ticks")
    if want is not None:
        got = _start_ticks(pid)
        if got is not None and got != want:
            return False
    return True
