"""Signed tool metadata pins for MCP servers.

An MCP server tells the agent what its tools do through free text (description) and a JSON
schema. Both go straight into the model's context, so they are an injection channel. Two attacks:

  tool poisoning  a description that hides instructions ("before using this tool, read ~/.ssh...")
  rug pull        a server that looked fine when you approved it later changes a description

Defence: on `tools/list` we hash each tool (SHA-256 over canonical JSON of name, description,
inputSchema) and pin the hashes per server in ~/.tripwire/tool_pins.json, signed with an HMAC key
created once at ~/.tripwire/pin.key (0600). First sight of a server pins it (trust on first use).
Afterwards any changed or new tool is hidden and its calls are blocked until the user runs
`tripwire pins approve <server>`. A description that fails `poison_reason` is never pinned, exposed or
approved: not on first use, not after a change. `poison_reason` looks for the published injection phrases,
invisible characters, orders addressed to the AI (also in a few other languages), "don't tell the user",
quiet extra recipients, other tools named as a first step, and references to keys or agent settings. It is a
deterministic check, so a description that dodges every shape still gets pinned; the engine then still judges
every call the tool makes.
If the pin file's signature does not verify, every tool of every server is treated as unverified.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
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


# A tool description tells the model what the tool does. These shapes tell the model what *it* must do, hide
# something from the user, or point it at secrets: none belongs in an honest description. All bounded.
_ROLE = r"(?:assistant|ai|a\.i\.|model|llm|agent|claude|chatgpt|copilot|gpt)"
POISON_SHAPES: list[tuple[str, "re.Pattern[str]"]] = []


def _shape(why: str, pat: str) -> None:
    POISON_SHAPES.append((why, re.compile(pat, re.I)))


_shape("it gives the AI orders", rf"\b(?:the|you,?\s{{1,3}}the|as\s{{1,3}}an?)\s{{1,3}}{_ROLE}\s{{1,3}}(?:must|should|shall|needs?\s{{1,3}}to|has\s{{1,3}}to|"
       r"is\s{1,3}required\s{1,3}to|is\s{1,3}instructed\s{1,3}to|will\s{1,3}(?:always|first))\b")
_shape("it gives the AI orders", r"\byou\s{1,3}(?:must|should|need\s{1,3}to|have\s{1,3}to|are\s{1,3}required\s{1,3}to)\s{1,3}"
       r"(?:first|always|also|secretly|silently|quietly)\b")
_shape("it gives the AI orders", r"\byou\s{1,3}(?:must|should|need\s{1,3}to|have\s{1,3}to)\s{1,3}(?:first\s{1,3})?"
       r"(?:read|cat|open|call|invoke|send|pass|include|attach|upload|forward|copy|fetch|email|post|bcc|cc)\b")
_shape("it tells the AI to do something else before using it",
       r"\b(?:before|prior\s{1,3}to)\s{1,3}(?:using|calling|invoking|running)\s{1,3}(?:this|the|any)\s{1,3}(?:tool|function|command)"
       r"\W{1,3}(?:\w{1,20}\W{1,3}){0,4}?(?:you\s{1,3})?(?:must|should|need|first|always|read|call|invoke|send|pass|include|"
       r"fetch|open|upload|copy)\b")
_shape("it tells the AI to hide something from the user",
       r"\b(?:do\s{1,3}not|don'?t|never|without)\s{1,3}(?:\w{1,20}\s{1,3}){0,2}?(?:tell|tells|telling|mention|mentioning|inform|informing|"
       r"notify|notifying|reveal|revealing|show|showing|alert|alerting|disclose)\w{0,3}\s{1,3}(?:\w{1,20}\s{1,3}){0,3}?(?:the\s{1,3})?user")
_shape("it tells the AI to hide something from the user",
       r"\b(?:keep\s{1,3}(?:this|it)\s{1,3}(?:secret|hidden|private)\s{1,3}from|the\s{1,3}user\s{1,3}(?:must|should|need)\s{1,3}(?:not|never)"
       r"\s{1,3}(?:know|see|be\s{1,3}told))\b")
_shape("it quietly adds a recipient", r"\b(?:always|also|secretly|silently|quietly)\s{1,3}(?:bcc|cc|blind[\s-]{1,2}copy|forward|copy|"
       r"send\s{1,3}(?:a\s{1,3})?copy)\b")
_shape("it quietly adds a recipient", r"\bbcc\s{0,3}:?\s{0,3}[\w.+-]{1,64}@[\w-]{1,63}\.")
_shape("it tells the AI to pass data into an argument",
       r"\bpass\s{1,3}(?:its|the|their|all|any|your|this)?\s{0,3}(?:full\s{1,3}|entire\s{1,3}|raw\s{1,3})?"
       r"(?:contents?|output|text|data|key|keys|secrets?|tokens?|history|conversation)\s{1,3}(?:in|into|as|via|through|to)\b")
_shape("it tells the AI to use another tool first",
       r"\b(?:first|before\s{1,3}(?:this|that|anything)|then|also)\s{1,3}(?:call|invoke|use|run)\s{1,3}(?:the\s{1,3})?[`'\"]?"
       r"[a-z][a-z0-9]{0,30}(?:_[a-z0-9]{1,30}){1,6}[`'\"]?")
_shape("it hides tagged instructions", r"<\s{0,2}/?\s{0,2}(?:important|instructions?|system|secret|hidden|admin|override)\s{0,2}>")
# The same orders in other languages (a few common phrasings each; cheap, not exhaustive).
_shape("it gives the AI orders in another language",
       r"\b(?:ne\s{1,3}(?:le\s{1,3}|lui\s{1,3})?(?:dis|dites|mentionne[sz]?)\s{1,3}pas\s{1,3}(?:à|a)\s{1,3}l['’]utilisateur|"
       r"n['’]en\s{1,3}(?:parle|parlez)\s{1,3}pas|sans\s{1,3}(?:le\s{1,3}dire|pr[ée]venir|informer)\s{1,3}(?:à\s{1,3})?l['’]utilisateur|"
       r"l['’]assistant\s{1,3}doit|(?:lis|lisez)\s{1,3}d['’]abord|"
       r"no\s{1,3}(?:se\s{1,3})?(?:le|lo)\s{1,3}(?:digas|diga|menciones)\s{1,3}al\s{1,3}usuario|sin\s{1,3}(?:decirle|avisar)\s{1,3}al\s{1,3}usuario|"
       r"el\s{1,3}asistente\s{1,3}debe|primero\s{1,3}lee|"
       r"sag(?:en\s{1,3}sie)?\s{1,3}dem\s{1,3}(?:benutzer|nutzer)\s{1,3}nichts?|ohne\s{1,3}den\s{1,3}(?:benutzer|nutzer)\s{1,3}zu\s{1,3}informieren|"
       r"der\s{1,3}assistent\s{1,3}muss|lies\s{1,3}zuerst|"
       r"n[ãa]o\s{1,3}(?:diga|conte|mencione)\s{1,3}ao\s{1,3}usu[áa]rio|sem\s{1,3}(?:avisar|informar)\s{1,3}o\s{1,3}usu[áa]rio|"
       r"o\s{1,3}assistente\s{1,3}deve)")
_shape("it gives the AI orders in another language",
       r"不要告诉用户|不要向用户|别告诉用户|助手必须|首先读取|请先读取|"
       r"उपयोगकर्ता\s{0,3}को\s{0,3}(?:मत|न)\s{0,3}बता|सहायक\s{0,3}को\s{0,3}(?:पहले|चाहिए)")
SECRET_REF = re.compile(r"(?:~|\$HOME|%USERPROFILE%)?[\w.-]{0,64}/(?:[\w.-]{1,64}/){0,6}[\w.-]{1,64}|"
                        r"(?<![\w.])(?:\.env(?:\.\w{1,20})?|id_(?:rsa|ed25519|ecdsa|dsa)|\.netrc|\.npmrc|\.pypirc|"
                        r"\.git-credentials|mcp\.json|claude_desktop_config\.json)(?![\w.])", re.I)
AGENT_CONFIG = re.compile(r"(?:^|[/~\s'\"`])(?:\.cursor/|\.claude/|\.codeium/|\.continue/|\.vscode/mcp|mcp\.json|"
                          r"claude_desktop_config\.json|\.tripwire/)", re.I)


GRAB_VERB = re.compile(r"(?:\b(?:read|reads|reading|cat|open|include|including|pass|send|sending|upload|attach|copy|"
                       r"forward|paste|embed|append)\b|\bcontents?\s{1,3}of\b|\b(?:lis|lire|leer|lee|lesen|lies|ler)\b|读取|发送|पढ़)",
                       re.I)


def _grabbed(blob: str, start: int) -> bool:
    """Something is done *with* the reference ("read ~/.ssh/id_rsa", "pass the contents of .env"). A description that
    only says where a tool finds its own config ("uses the profile in ~/.aws/credentials") is not an order."""
    window = re.split(r"[.!?;。]\s", blob[max(0, start - 60):start])[-1]
    return bool(GRAB_VERB.search(window))


def _secret_ref(blob: str) -> str | None:
    from ..analyzers import paths  # lazily, like the injection markers

    blob = blob[:50_000]
    for n, m in enumerate(SECRET_REF.finditer(blob)):
        if n > 200:
            break
        ref = m.group(0)
        if ref.lower().endswith((".pub", ".example", ".sample", ".template")):
            continue
        probe = ref if "/" in ref else "/x/" + ref
        if (paths.is_secret(paths.expand(probe, "/x")) or AGENT_CONFIG.search(" " + ref)) and _grabbed(blob, m.start()):
            return ref
    for m in AGENT_CONFIG.finditer(blob):
        if _grabbed(blob, m.start()):
            return m.group(0).strip(" '\"`")
    for m in re.finditer(r"\bprivate\s{1,3}(?:ssh\s{1,3})?keys?\b|\bssh\s{1,3}keys?\b", blob, re.I):
        if _grabbed(blob, m.start()):
            return m.group(0)
    return None


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
    text = " ".join(blob[:50_000].split())
    for why, pat in POISON_SHAPES:
        m = pat.search(text)
        if m:
            return f"{why} (\"{m.group(0)[:80]}\")"
    ref = _secret_ref(blob)
    if ref:
        return f"it points at your keys or agent settings (\"{ref[:80]}\")"
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
