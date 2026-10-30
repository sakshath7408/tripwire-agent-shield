"""Who may change the daemon's mind.

The guarded agent usually runs as the same OS user as the daemon, so the localhost API is a control plane it would
love to use: reset sessions, rewrite its own task, switch autonomy, approve its own ASKs. Tripwire's rule: no file
the agent can read gives it any of that.

* The hook token, ~/.tripwire/token (0600). The Claude Code hook, the MCP proxy and the demo read it, so assume the
  agent can too. It can only send a task, tool outputs and actions to check: POST /v1/task, /v1/observe,
  /v1/evaluate (plus asking to pair, which a person still has to approve). Every other endpoint answers 403.
* The dashboard cookie: a random value per paired browser, HttpOnly and SameSite=Strict. The daemon keeps only its
  SHA-256 (dashboards.json), so reading that file gives nothing usable. It is the only credential that can answer
  an ASK, change settings, delete rules, reset, read the feed or approve a new browser.
* There is no admin key on disk. Older versions wrote ~/.tripwire/admin.key; the daemon deletes it on start.

A browser gets the cookie only by swapping a one-time pairing code (POST /v1/pair, single use, 10 minutes). Codes
are minted only where a person is:

1. `tripwire serve` prints one link at startup, to its own terminal only (never to a log), and another each time
   you press Enter there. Not while a live session has seen hidden instructions.
2. `tripwire open` asks the daemon to pair (POST /v1/pair/request) and shows a 6-digit code. A person approves it by
   typing those digits into the `tripwire serve` terminal, or by clicking Approve in a dashboard that is already
   paired after checking the digits match. Then `open` receives the link. Nothing the agent can read or call
   approves it.
3. Hardened mode only (`serve --hardened`, daemon running as its own OS user): `sudo -u _tripwire tripwire open`
   reads console.key from the daemon's private folder.

Honest limit: a process running as your OS user can still do what you can. It can read your browser's cookie
store, attach a debugger to the daemon (ptrace), stop the daemon and start its own copy in a terminal it controls,
or edit Tripwire's files. Tripwire blocks the agent's known routes to these, but only running the daemon as a
separate OS user (`tripwire harden`, docs/HARDENING.md) is a real boundary.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import time
from pathlib import Path

HEADER = "X-Tripwire-Token"
CONSOLE_HEADER = "X-Tripwire-Console"  # hardened mode only: console.key lives in the daemon user's 0700 folder
DEMO_HEADER = "X-Tripwire-Demo-Admin"  # `serve --demo-admin` only: a throwaway stage/test daemon, never by default
COOKIE = "tripwire_dash"
PAIR_TTL = 600  # seconds a pairing code stays valid
REQUEST_TTL = 300  # seconds a `tripwire open` request waits for a person
COOKIE_DAYS = 30
MAX_DASHBOARDS = 20
LOCAL_HOSTS = {"127.0.0.1", "localhost", "[::1]", "::1"}
NO_LOGIN_SHELLS = {"/usr/bin/false", "/bin/false", "/sbin/nologin", "/usr/sbin/nologin", "/usr/bin/nologin"}


def home() -> Path:
    return Path(os.environ.get("TRIPWIRE_HOME") or Path.home() / ".tripwire")


def token_path(base: Path | None = None) -> Path:
    return (base or home()) / "token"


def legacy_admin_path(base: Path | None = None) -> Path:
    return (base or home()) / "admin.key"


def console_key_path(base: Path | None = None) -> Path:
    return (base or home()) / "console.key"


def demo_admin_path(base: Path | None = None) -> Path:
    return (base or home()) / "demo-admin.key"


def remove_legacy_admin(base: Path | None = None) -> bool:
    """Migration: admin.key was readable by the agent, so it must not survive. True if one was deleted."""
    p = legacy_admin_path(base)
    try:
        p.unlink()
        return True
    except FileNotFoundError:
        return False


def _write_secret(p: Path, value: str) -> None:
    p.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(str(p), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(value + "\n")
    os.chmod(p, 0o600)


def load_or_create(base: Path | None = None, p: Path | None = None) -> str:
    p = p or token_path(base)
    try:
        tok = p.read_text().strip()
        if len(tok) >= 32:
            return tok
    except OSError:
        pass
    tok = secrets.token_urlsafe(32)
    _write_secret(p, tok)
    return tok


def write_secret(p: Path, value: str) -> None:
    _write_secret(p, value)


def read_token() -> str | None:
    """For clients (hooks, proxy, demo). $TRIPWIRE_TOKEN wins, then ~/.tripwire/token."""
    env = os.environ.get("TRIPWIRE_TOKEN")
    if env:
        return env.strip()
    try:
        return token_path().read_text().strip() or None
    except OSError:
        return None


def headers() -> dict[str, str]:
    tok = read_token()
    return {HEADER: tok} if tok else {}


def read_console_key() -> str | None:
    """Hardened mode: only the daemon's own OS user can read this file (its folder is 0700)."""
    try:
        return console_key_path().read_text().strip() or None
    except OSError:
        return None


def hardened_problem(base: Path, uid: int | None = None) -> str | None:
    """Why this process may not run in hardened mode, or None. Hardened mode writes console.key, which is only
    safe when the agent cannot read the folder: the daemon runs as a user with no login shell and owns a 0700
    TRIPWIRE_HOME. Your own account always has a login shell, so an agent can't switch this on as you."""
    import pwd
    uid = os.getuid() if uid is None else uid
    try:
        shell = pwd.getpwuid(uid).pw_shell
    except KeyError:
        return "this user is not in the user database"
    if shell not in NO_LOGIN_SHELLS:
        return (f"the daemon must run as its own OS user with no login shell (this user's shell is {shell}). "
                "See `tripwire harden`.")
    try:
        st = base.stat()
    except OSError:
        return f"{base} does not exist"
    if st.st_uid != uid or st.st_mode & 0o077:
        return f"{base} must be owned by the daemon user and have mode 0700"
    return None


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


class DashboardStore:
    """Paired browsers. Only SHA-256 digests are stored, so the file is useless to a reader: the cookie itself
    lives only in the browser. Pairings survive a daemon restart."""

    def __init__(self, path: Path | None) -> None:
        self.path = path
        self.entries: dict[str, float] = {}  # digest -> expiry
        if path:
            try:
                data = json.loads(path.read_text())
                now = time.time()
                self.entries = {d: float(exp) for d, exp in data.get("dashboards", {}).items()
                                if isinstance(d, str) and len(d) == 64 and float(exp) > now}
            except (OSError, ValueError, AttributeError, TypeError):
                self.entries = {}

    def _save(self) -> None:
        if not self.path:
            return
        tmp = self.path.with_suffix(".tmp")
        fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            json.dump({"note": "SHA-256 of paired dashboard cookies. The cookies themselves are only in your browser.",
                       "dashboards": self.entries}, f)
        os.replace(tmp, self.path)

    def add(self) -> str:
        """A new browser: returns the cookie value (shown to nobody but that browser)."""
        value = secrets.token_urlsafe(32)
        self.entries[_digest(value)] = time.time() + COOKIE_DAYS * 86400
        while len(self.entries) > MAX_DASHBOARDS:
            self.entries.pop(min(self.entries, key=self.entries.get))
        try:
            self._save()
        except OSError:
            pass  # still paired until the daemon restarts
        return value

    def check(self, value: str | None) -> bool:
        if not value or not isinstance(value, str) or len(value) > 200:
            return False
        exp = self.entries.get(_digest(value))
        return exp is not None and exp > time.time()

    def count(self) -> int:
        now = time.time()
        return sum(1 for exp in self.entries.values() if exp > now)


def new_pair_code() -> str:
    return secrets.token_urlsafe(18)


def new_digits() -> str:
    return f"{secrets.randbelow(10 ** 6):06d}"


def same(a: str | None, b: str | None) -> bool:
    return bool(a and b) and hmac.compare_digest(a.encode(), b.encode())


def host_only(host_header: str) -> str:
    h = (host_header or "").strip().lower()
    if h.startswith("["):
        return h[: h.find("]") + 1] if "]" in h else h
    return h.rsplit(":", 1)[0] if h.count(":") == 1 else h


def is_local_host(host_header: str | None) -> bool:
    return host_only(host_header or "") in LOCAL_HOSTS


def is_local_origin(origin: str | None) -> bool:
    if not origin:
        return True  # non-browser clients send none; a credential still has to match
    if "://" not in origin:
        return False
    return is_local_host(origin.split("://", 1)[1].split("/", 1)[0])
