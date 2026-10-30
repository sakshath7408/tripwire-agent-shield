"""Who may change the daemon's mind.

The guarded agent runs as the same user as the daemon, so an open localhost API is a control plane it could use
to reset sessions, rewrite the trusted task or approve its own ASKs. Every mutating endpoint therefore needs a
per-install token from ~/.tripwire/token (0600). Adapters (Claude Code hook, MCP proxy, demo) read the file.

The dashboard never gets the token. `tripwire serve` prints, and `tripwire open` mints, a one-time pairing code
(single use, 10 minutes). The page swaps it once (POST /v1/pair) for an HttpOnly, SameSite=Strict cookie that holds a
key derived from the token. No request header can earn that cookie: a 30 Oct review got it with one faked
`sec-fetch-dest: document` header. The engine also blocks agent actions aimed at local ports it can't resolve, at the
daemon's port, or at ~/.tripwire (globs and variables expanded), so the agent cannot read the token or call the API.

The audit log records who changed things: "dashboard" (cookie) or "api-token" (header), never a guessed "human".

Honest limit: code running as your user can always read your files. For real isolation, run the daemon as a
separate OS user so the token and audit key are not readable by the agent at all.
"""

from __future__ import annotations

import hmac
import os
import secrets
from pathlib import Path

HEADER = "X-Tripwire-Token"
COOKIE = "tripwire_dash"
PAIR_TTL = 600  # seconds a pairing code stays valid
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


def dash_key(token: str) -> str:
    """The dashboard cookie's value: derived from the token, so it survives restarts, but it is not the token."""
    return hmac.new(token.encode(), b"tripwire-dashboard-v1", "sha256").hexdigest()


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
