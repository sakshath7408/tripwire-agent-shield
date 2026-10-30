"""Core data types shared by every part of Tripwire."""

from __future__ import annotations

import re
import time
import uuid
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field, field_validator, model_validator


_SURROGATE = re.compile("[\ud800-\udfff]")


def scrub(v: Any, depth: int = 0) -> Any:
    """Replace lone UTF-16 surrogates ("\\udc80", which JSON allows and a non-UTF-8 byte in tool output turns into)
    with U+FFFD. Left in, they crashed the verdict's JSON encoding and the daemon answered HTTP 500.
    Deep values are left alone; the engine already treats very deep args as uncheckable."""
    if isinstance(v, str):
        try:
            v.encode("utf-8")
            return v
        except UnicodeEncodeError:
            return _SURROGATE.sub("\ufffd", v)
    if depth > 64:
        return v
    if isinstance(v, dict):
        return {scrub(k, depth + 1): scrub(x, depth + 1) for k, x in v.items()}
    if isinstance(v, list):
        return [scrub(x, depth + 1) for x in v]
    return v


class _Clean(BaseModel):
    @model_validator(mode="before")
    @classmethod
    def _scrub(cls, data: Any) -> Any:
        return scrub(data)


class Decision(str, Enum):
    ALLOW = "allow"
    ASK = "ask"
    BLOCK = "block"


class Capability(str, Enum):
    """What a tool call can do to the world. Drives which checks run."""

    READ = "read"  # reads local data (files, search)
    FETCH = "fetch"  # pulls outside content in (web, email inbox)
    WRITE = "write"  # changes local files
    EXEC = "exec"  # runs a shell command
    SEND = "send"  # sends data out (email, message, http post)
    MONEY = "money"  # moves money
    DELETE = "delete"  # destroys data
    AGENT = "agent"  # spawns another agent
    CREDENTIAL = "credential"  # changes passwords, keys, 2FA, recovery settings
    UNKNOWN = "unknown"


# Severity scale. Risk score of a verdict is the max finding severity (plus small boosts).
INFO, LOW, MEDIUM, HIGH, CRITICAL = 0, 20, 50, 80, 100


class Action(_Clean):
    """One tool call an agent wants to make."""

    session_id: str = "default"
    tool: str
    args: dict[str, Any] = Field(default_factory=dict)
    source: str = "sdk"  # claude-code | mcp | sdk | bench
    cwd: str | None = None
    # Cross-agent trail. agent: who is acting (defaults to the session id). parent: the agent that
    # spawned this one (a Claude Code sub-agent's parent is the main agent of its session).
    agent: str | None = None
    parent: str | None = None


class Finding(BaseModel):
    rule: str  # stable id, e.g. "shell.rm_root"
    severity: int

    @field_validator("severity")
    @classmethod
    def _clamp(cls, v: int) -> int:  # boosts can push past 100; the scale is 0-100
        return max(0, min(100, v))
    message: str  # one plain-English line a non-expert understands
    category: str = "general"  # destructive | exfiltration | injection | scope | secrets | obfuscation | persistence | privilege | network
    evidence: str | None = None


class Verdict(BaseModel):
    id: str = Field(default_factory=lambda: uuid.uuid4().hex[:12])
    ts: float = Field(default_factory=time.time)
    action: Action
    capability: Capability
    decision: Decision
    risk: int
    summary: str
    findings: list[Finding] = Field(default_factory=list)
    judge: dict[str, Any] | None = None
    elapsed_ms: float = 0.0
    resolved_by: str | None = None  # "human" when a person approved/denied an ASK
    trace: str | None = None  # root agent of the agent tree this action belongs to (set by the daemon)
    autonomy: str | None = None  # autonomy level in force when this was decided: strict | balanced | autonomous
    auto: bool = False  # True when the autonomy layer or a learned rule decided it instead of asking you
    rule_id: str | None = None  # the learned rule that decided it, if any


class Observation(_Clean):
    """Output a tool returned. Everything here is untrusted data, never instructions."""

    session_id: str = "default"
    tool: str
    output: str
    source: str = "sdk"
    agent: str | None = None
    parent: str | None = None


class TaskSpec(_Clean):
    """What the human actually asked for. The only trusted text in a session."""

    session_id: str = "default"
    prompt: str
    cwd: str | None = None
    profile: str | None = None  # permission profile name from policy YAML
    agent: str | None = None
    parent: str | None = None
