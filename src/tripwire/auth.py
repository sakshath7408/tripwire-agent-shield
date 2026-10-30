"""Who may change the daemon's mind.

The guarded agent runs as the same OS user as the daemon, so the localhost API is a control plane it would love to
use: reset sessions, rewrite its own task, switch autonomy, approve its own ASKs. Tripwire splits the credentials:

* The hook token, ~/.tripwire/token (0600). The Claude Code hook, the MCP proxy and the demo read it. It can only
  send a task (before hidden instructions are seen), tool outputs and actions to check: POST /v1/task,
  /v1/observe, /v1/evaluate. Every other endpoint answers 403 to it.
* The admin secret, ~/.tripwire/admin.key (0600). Only the CLI's admin commands (`tripwire open`) and your own
  stage scripts read it. No adapter or hook code loads it. It can do everything, including minting pairing codes.
* The dashboard cookie: an HttpOnly, SameSite=Strict key derived from the admin secret (not from the hook token),
  earned only by swapping a one-time pairing code (POST /v1/pair, single use, 10 minutes). No request header earns
  it. `tripwire open` mints the code only from an interactive terminal, after you type a confirmation word, and the
  code is never written to a log.

On top of that the engine blocks the agent's known routes to these: reading ~/.tripwire (globs and variables
expanded), any call to the daemon's port (also through names like lvh.me that lead back here, --resolve, a Host
header, or rot13), importing or running Tripwire's own code (`from tripwire ...`, `python -m tripwire`, the
`tripwire` program), and switching Claude Code's hooks off. A session that saw hidden instructions can't be re-tasked
over the API at all, and a reset never forgets that it saw them.

The audit log records the credential actually used: "hook-token", "admin" or "dashboard".

Honest limit: a process running as your OS user can, in principle, read any file you can, including admin.key.
Tripwire raises the bar and blocks the agent's known routes, but it is not an OS security boundary. For a hard
boundary, run the daemon as a separate OS user (docs/HARDENING.md), so the agent cannot read its secrets at all.
"""

from __future__ import annotations

import hmac
import os
import secrets
from pathlib import Path

HEADER = "X-Tripwire-Token"
ADMIN_HEADER = "X-Tripwire-Admin"
COOKIE = "tripwire_dash"
PAIR_TTL = 600  # seconds a pairing code stays valid
LOCAL_HOSTS = {"127.0.0.1", "localhost", "[::1]", "::1"}


def home() -> Path:
    return Path(os.environ.get("TRIPWIRE_HOME") or Path.home() / ".tripwire")


def token_path(base: Path | None = None) -> Path:
    return (base or home()) / "token"


def admin_path(base: Path | None = None) -> Path:
    return (base or home()) / "admin.key"


def load_or_create_admin(base: Path | None = None) -> str:
    """The daemon's admin secret. Separate from the hook token: the hook and adapters never read this file."""
    return load_or_create(base, admin_path(base))


def read_admin() -> str | None:
    """For the CLI's admin commands only. There is deliberately no environment variable: the agent inherits your
    shell's environment."""
    try:
        return admin_path().read_text().strip() or None
    except OSError:
        return None


def admin_headers() -> dict[str, str]:
    a = read_admin()
    return {ADMIN_HEADER: a} if a else {}


def load_or_create(base: Path | None = None, p: Path | None = None) -> str:
    p = p or token_path(base)
    try:
        tok = p.read_text().strip()
        if len(tok) >= 32:
            return tok
    except OSError:
        pass
    p.parent.mkdir(parents=True, exist_ok=True)
    tok = secrets.token_urlsafe(32)
    fd = os.open(str(p), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(tok + "\n")
    os.chmod(p, 0o600)
    return tok


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


def dash_key(admin: str) -> str:
    """The dashboard cookie's value: derived from the admin secret (never from the hook token, which an agent could
    reach more easily), so it survives restarts, but it is not the secret itself."""
    return hmac.new(admin.encode(), b"tripwire-dashboard-v2", "sha256").hexdigest()


def new_pair_code() -> str:
    return secrets.token_urlsafe(18)


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
        return True  # non-browser clients send none; the token still has to match
    if "://" not in origin:
        return False
    return is_local_host(origin.split("://", 1)[1].split("/", 1)[0])
