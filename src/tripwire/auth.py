"""Who may change the daemon's mind.

The guarded agent runs as the same user as the daemon, so an open localhost API is a control plane it could use
to reset sessions, rewrite the trusted task or approve its own ASKs. Every mutating endpoint therefore needs a
per-install token from ~/.tripwire/token (0600). Adapters (Claude Code hook, MCP proxy, demo) read the file; the
dashboard gets it as a SameSite=Strict, HttpOnly cookie when a browser opens the page. The engine also blocks any
agent action aimed at the daemon or at ~/.tripwire, so the agent cannot read the token or call the API.

Honest limit: code running as your user can always read your files. For real isolation, run the daemon as a
separate OS user so the token and audit key are not readable by the agent at all.
"""

from __future__ import annotations

import hmac
import os
import secrets
from pathlib import Path

HEADER = "X-Tripwire-Token"
COOKIE = "tripwire_token"
LOCAL_HOSTS = {"127.0.0.1", "localhost", "[::1]", "::1"}


def home() -> Path:
    return Path(os.environ.get("TRIPWIRE_HOME") or Path.home() / ".tripwire")


def token_path(base: Path | None = None) -> Path:
    return (base or home()) / "token"


def load_or_create(base: Path | None = None) -> str:
    p = token_path(base)
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
