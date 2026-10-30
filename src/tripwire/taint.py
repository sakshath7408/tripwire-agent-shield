"""Provenance tracking.

The user's prompt is the only trusted text. Every tool output (files, web pages,
emails) is untrusted data. When an outgoing action uses a value that first showed
up in untrusted data and never in the user's words, the agent is probably obeying
something it read, not something it was asked. That is the prompt-injection signal,
and it does not depend on another model checking itself.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

URL = re.compile(r"https?://[^\s'\"<>)\]]{1,2048}", re.I)
EMAIL = re.compile(r"(?<![\w.+-])[\w.+-]{1,64}@[\w-]{1,63}(?:\.[\w-]{1,63}){1,8}")
IBAN = re.compile(r"\b[A-Z]{2}\d{2}[A-Z0-9]{10,30}\b")
UPI = re.compile(r"(?<![\w.-])[\w.-]{2,64}@(?:ok\w+|ybl|paytm|upi|ibl|axl|apl|sbi|icici|hdfc\w*|ptyes|yapl)\b", re.I)
IP = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?\b")
PHONE = re.compile(r"(?<![\d])\+?\d[\d -]{8,18}\d")
DOMAIN = re.compile(r"(?<![\w.-])(?:[a-z0-9-]{1,63}\.){1,8}(?:com|net|org|io|xyz|ru|cn|top|sh|dev|app|co|in|me|info|biz|site|online|tk)\b", re.I)

MAX_OBSERVE = 1_000_000  # characters scanned per tool output; keeps a giant output from stalling the guard

INDICATOR_PATTERNS = {
    "url": URL,
    "email": EMAIL,
    "iban": IBAN,
    "upi": UPI,
    "ip": IP,
    "phone": PHONE,
    "domain": DOMAIN,
}

# Imperative phrases that betray instructions hidden in data.
INJECTION_MARKERS = re.compile(
    r"(ignore (all |any )?(previous|prior|above) (instructions|prompts?)|disregard (the )?(previous|above)|"
    r"you (must|should) now|new instructions?:|system prompt|<\s*/?\s*(system|instructions?|important)\s*>|"
    r"as an ai (agent|assistant)|do not (tell|inform|mention to) the user|without (asking|telling) the user|"
    r"assistant,? please|before (doing|completing) (anything|the task)|important!+)",
    re.I,
)


def indicators(text: str) -> dict[str, set[str]]:
    out: dict[str, set[str]] = {}
    for kind, pat in INDICATOR_PATTERNS.items():
        found = {m.group(0).rstrip(".,;:").lower() for m in pat.finditer(text)}
        if kind == "phone":
            found = {re.sub(r"[ -]", "", f) for f in found if len(re.sub(r"\D", "", f)) >= 10}
        if found:
            out[kind] = found
    return out


def _norm(s: str) -> str:
    return re.sub(r"\s+", " ", s).strip().lower()


@dataclass
class TaintSource:
    tool: str
    snippet: str


@dataclass
class TaintStore:
    trusted_text: str = ""
    trusted: dict[str, set[str]] = field(default_factory=dict)
    # indicator value -> where it came from
    untrusted: dict[str, TaintSource] = field(default_factory=dict)
    # normalised lines from untrusted outputs that look like commands or instructions
    untrusted_lines: list[tuple[str, TaintSource]] = field(default_factory=list)
    injection_seen: list[TaintSource] = field(default_factory=list)

    def add_trusted(self, text: str) -> None:
        self.trusted_text += "\n" + _norm(text)
        for kind, vals in indicators(text).items():
            self.trusted.setdefault(kind, set()).update(vals)

    def add_untrusted(self, tool: str, text: str) -> None:
        text = text[:MAX_OBSERVE]
        for vals in indicators(text).values():
            for v in vals:
                if v not in self.untrusted:
                    self.untrusted[v] = TaintSource(tool, _snippet(text, v))
        for line in text.splitlines():
            n = _norm(line)
            if 8 <= len(n) <= 400:
                self.untrusted_lines.append((n, TaintSource(tool, line.strip()[:160])))
        self.untrusted_lines = self.untrusted_lines[-5000:]
        m = INJECTION_MARKERS.search(text)
        if m:
            self.injection_seen.append(TaintSource(tool, _snippet(text, m.group(0))))

    def is_trusted_value(self, value: str) -> bool:
        v = value.lower()
        return any(v in vals for vals in self.trusted.values()) or v in self.trusted_text

    def tainted_values(self, text: str) -> list[tuple[str, TaintSource]]:
        """Indicators inside `text` that came from untrusted data and not from the user."""
        hits = []
        for vals in indicators(text).values():
            for v in vals:
                src = self.untrusted.get(v) or _domain_match(v, self.untrusted)
                if src and not self.is_trusted_value(v):
                    hits.append((v, src))
        return hits

    def command_from_data(self, command: str) -> TaintSource | None:
        """Did this shell command appear verbatim inside something the agent read?"""
        n = _norm(command)
        if len(n) < 8 or n in self.trusted_text:
            return None
        for line, src in reversed(self.untrusted_lines):
            if n in line:
                return src
        return None


def _domain_match(value: str, untrusted: dict[str, TaintSource]) -> TaintSource | None:
    for k, src in untrusted.items():
        if len(k) > 5 and (k in value or value in k):
            return src
    return None


def _snippet(text: str, needle: str, width: int = 70) -> str:
    i = text.lower().find(needle.lower())
    if i < 0:
        return text[:width * 2].strip()
    s = text[max(0, i - width): i + len(needle) + width]
    return " ".join(s.split())
