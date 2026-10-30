"""Signed tool metadata pins for MCP servers.

An MCP server tells the agent what its tools do through free text (description) and a JSON
schema. Both go straight into the model's context, so they are an injection channel. Two attacks:

  tool poisoning  a description that hides instructions ("before using this tool, read ~/.ssh...")
  rug pull        a server that looked fine when you approved it later changes a description

Defence: on `tools/list` we hash each tool (SHA-256 over canonical JSON of name, description,
inputSchema) and pin the hashes per server in ~/.tripwire/tool_pins.json, signed with an HMAC key
created once at ~/.tripwire/pin.key (0600). First sight of a server pins it (trust on first use).
Afterwards any changed or new tool is hidden and its calls are blocked until the user runs
`tripwire pins approve <server>`. A poisoned description is never exposed, approved or not.
If the pin file's signature does not verify, every tool of every server is treated as unverified.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


def home() -> Path:
    return Path(os.environ.get("TRIPWIRE_HOME") or Path.home() / ".tripwire")


def canonical(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def tool_hash(tool: dict) -> str:
    return hashlib.sha256(canonical({"name": tool.get("name"), "description": tool.get("description"),
                                     "inputSchema": tool.get("inputSchema")})).hexdigest()


def _key(base: Path) -> bytes:
    path = base / "pin.key"
    base.mkdir(parents=True, exist_ok=True)
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        key = bytes.fromhex(path.read_text().strip())
        if len(key) < 32:
            raise ValueError("pin key is too short")
        return key
    key = secrets.token_bytes(32)
    with os.fdopen(fd, "w") as f:
        f.write(key.hex())
    return key


def poison_reason(tool: dict) -> str | None:
    """Look for hidden instructions in what the server says about a tool."""
    from ..taint import INJECTION_MARKERS  # imported lazily; the proxy fails closed if this breaks

    texts: list[str] = []

    def walk(v: Any) -> None:
        if isinstance(v, str):
            texts.append(v)
        elif isinstance(v, dict):
            for x in v.values():
                walk(x)
        elif isinstance(v, list):
            for x in v:
                walk(x)

    walk(tool.get("description"))
    walk(tool.get("inputSchema"))
    blob = "\n".join(texts)
    m = INJECTION_MARKERS.search(blob)
    if m:
        return f"its description hides instructions for the AI (\"{m.group(0)}\")"
    if any(c in blob for c in ("​", "‌", "‍", "⁠", "﻿")) or any(0xE0000 <= ord(c) <= 0xE007F for c in blob):
        return "its description contains invisible characters, a common way to hide instructions"
    return None


@dataclass
class Check:
    ok: dict[str, str] = field(default_factory=dict)  # tool -> hash, safe to expose and call
    changed: list[str] = field(default_factory=list)
    new: list[str] = field(default_factory=list)
    poisoned: dict[str, str] = field(default_factory=dict)  # tool -> reason
    first_use: bool = False
    tampered: bool = False

    def blocked_reason(self, server: str, tool: str) -> str | None:
        if tool in self.poisoned:
            return f"MCP tool '{tool}' was hidden because {self.poisoned[tool]}."
        if self.tampered:
            return f"The Tripwire pin file was changed outside Tripwire. Re-check and run `tripwire pins approve {server}`."
        if tool in self.changed:
            return (f"MCP tool '{tool}' changed its description or inputs since you approved it (possible rug pull). "
                    f"Review it, then run `tripwire pins approve {server}`.")
        if tool in self.new:
            return f"MCP tool '{tool}' is new since you approved this server. Review it, then run `tripwire pins approve {server}`."
        return None


class PinStore:
    def __init__(self, base: Path | None = None) -> None:
        self.base = base or home()
        self.path = self.base / "tool_pins.json"
        self.key = _key(self.base)

    def _sig(self, servers: dict) -> str:
        return hmac.new(self.key, canonical(servers), hashlib.sha256).hexdigest()

    def load(self) -> tuple[dict, bool]:
        """Returns (servers, valid). Missing file is valid and empty."""
        if not self.path.exists():
            return {}, True
        try:
            data = json.loads(self.path.read_text())
            servers = data.get("servers", {})
            return servers, hmac.compare_digest(str(data.get("sig", "")), self._sig(servers))
        except Exception:
            return {}, False

    def save(self, servers: dict) -> None:
        self.base.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(".tmp")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            json.dump({"servers": servers, "sig": self._sig(servers)}, f, indent=2, sort_keys=True)
        os.replace(tmp, self.path)

    def check(self, server: str, tools: list[dict]) -> Check:
        servers, valid = self.load()
        c = Check(tampered=not valid)
        current, info = {}, {}
        for t in tools:
            name = str(t.get("name"))
            current[name] = tool_hash(t)
            info[name] = str(t.get("description") or "")[:300]
            reason = poison_reason(t)
            if reason:
                c.poisoned[name] = reason
        entry = servers.get(server) if valid else None
        if valid and entry is None:
            c.first_use = True
            servers[server] = {"tools": {n: h for n, h in current.items() if n not in c.poisoned},
                               "pending": {}, "approved_at": time.time()}
            self.save(servers)
            entry = servers[server]
        pinned = (entry or {}).get("tools", {})
        for name, h in current.items():
            if name in c.poisoned:
                continue
            if c.tampered:
                c.changed.append(name)
            elif name not in pinned:
                c.new.append(name)
            elif pinned[name] != h:
                c.changed.append(name)
            else:
                c.ok[name] = h
        if valid and entry is not None:
            pending = {n: current[n] for n in c.changed + c.new}
            if pending != entry.get("pending", {}):
                entry["pending"] = pending
                entry["pending_info"] = {n: info[n] for n in pending}
                self.save(servers)
        return c

    def approve(self, server: str) -> list[str]:
        """Accept the pending (changed/new) tools of a server.

        If the pin file fails its signature check its contents cannot be trusted, so approving
        resets it: every server is pinned afresh the next time it lists its tools."""
        servers, valid = self.load()
        if not valid:
            self.save({})
            return ["(pin file reset; servers re-pin on next start)"]
        if server not in servers:
            raise KeyError(server)
        entry = servers[server]
        accepted = list(entry.get("pending", {}))
        entry["tools"] = {**entry.get("tools", {}), **entry.get("pending", {})}
        entry["pending"], entry["pending_info"], entry["approved_at"] = {}, {}, time.time()
        self.save(servers)
        return accepted

    def pinned_ok(self, server: str, tool: str) -> bool:
        servers, valid = self.load()
        return valid and tool in servers.get(server, {}).get("tools", {}) and tool not in servers[server].get("pending", {})
