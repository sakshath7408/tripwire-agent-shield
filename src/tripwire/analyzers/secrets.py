"""Spot secret material inside arguments that are about to leave the machine."""

from __future__ import annotations

import re

SECRET_CONTENT = [
    ("private_key", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    ("aws_key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("github_token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b")),
    ("anthropic_key", re.compile(r"\bsk-ant-[A-Za-z0-9_-]{20,}")),
    ("openai_key", re.compile(r"\bsk-(proj-)?[A-Za-z0-9]{20,}")),
    ("slack_token", re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}")),
    ("google_key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")),
    ("stripe_key", re.compile(r"\b[sr]k_live_[0-9a-zA-Z]{20,}")),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}")),
    # Bounded on purpose: with `*` here, 800 KB of "X_SECRET" repeated took 287 s (one huge output froze the guard).
    ("env_assignment", re.compile(r"(?<![A-Za-z0-9_])[A-Z][A-Z0-9_]{0,48}(SECRET|TOKEN|PASSWORD|API_KEY|PRIVATE_KEY|ACCESS_KEY|_PASS(?:WD)?(?![A-Z])|_PWD(?![A-Z]))[A-Z0-9_]{0,48}[ \t]{0,4}=[ \t]{0,4}[^\s=]\S{7,4096}")),
]


def find_secrets(text: str) -> list[str]:
    return [name for name, pat in SECRET_CONTENT if pat.search(text)]


def redact(text: str) -> str:
    for _, pat in SECRET_CONTENT:
        text = pat.sub(lambda m: m.group(0)[:6] + "…[redacted]", text)
    return text
