"""Map a tool name to what it can do. Works for Claude Code tools and arbitrary MCP tools."""

from __future__ import annotations

import re

from .models import Capability

# Exact names first (Claude Code built-ins and common MCP servers).
EXACT: dict[str, Capability] = {
    "bash": Capability.EXEC,
    "shell": Capability.EXEC,
    "run_command": Capability.EXEC,
    "execute_command": Capability.EXEC,
    "read": Capability.READ,
    "glob": Capability.READ,
    "grep": Capability.READ,
    "ls": Capability.READ,
    "read_file": Capability.READ,
    "list_directory": Capability.READ,
    "write": Capability.WRITE,
    "edit": Capability.WRITE,
    "multiedit": Capability.WRITE,
    "notebookedit": Capability.WRITE,
    "write_file": Capability.WRITE,
    "edit_file": Capability.WRITE,
    "webfetch": Capability.FETCH,
    "websearch": Capability.FETCH,
    "fetch": Capability.FETCH,
    "task": Capability.AGENT,
    "agent": Capability.AGENT,
}

# Then keyword patterns over the normalised name. Order matters: most dangerous first.
PATTERNS: list[tuple[re.Pattern[str], Capability]] = [
    (re.compile(r"(send_money|transfer|payment|pay_|_pay\b|upi|wire|refund|withdraw|schedule_transaction|update_scheduled_transaction)"), Capability.MONEY),
    (re.compile(r"(delete|remove|drop|purge|destroy|wipe|truncate|rm_)"), Capability.DELETE),
    (re.compile(r"(exec|run_|shell|terminal|command|eval)"), Capability.EXEC),
    (re.compile(r"(send|email|mail|message|post_|post\b|publish|share|invite|reply|forward|upload|webhook|http_post|create_issue|comment|tweet|slack)"), Capability.SEND),
    (re.compile(r"(write|edit|create|update|append|insert|set_|save|rename|move|patch|commit|push)"), Capability.WRITE),
    (re.compile(r"(fetch|browse|web|url|http|download|search_web|get_webpage|inbox|read_email|get_unread|read_channel|get_messages)"), Capability.FETCH),
    (re.compile(r"(?:^|_)(read|get|list|search|find|query|show|view|cat|describe)"), Capability.READ),
]


def normalise(tool: str) -> str:
    # MCP tools from Claude Code arrive as mcp__server__tool. Keep the tool part.
    name = tool.split("__")[-1] if tool.startswith("mcp__") else tool
    name = re.sub(r"([a-z])([A-Z])", r"\1_\2", name)
    return name.lower().replace("-", "_")


READ_PREFIX = re.compile(r"^(get|list|search|read|check|find|fetch|count|lookup)_")
OUTSIDE_DATA = re.compile(r"(inbox|email|mail|message|channel|web|url|page|feed|post|review|comment)")
VERB_RULES: list[tuple[re.Pattern[str], Capability]] = [
    (re.compile(r"(password|passwd|credential|2fa|mfa|api_key|access_key|recovery|security_question)"), Capability.CREDENTIAL),
    (re.compile(r"^(reserve|book|purchase|buy|order|checkout)_"), Capability.MONEY),
    (re.compile(r"^cancel_"), Capability.DELETE),
    (re.compile(r"(invite|^add_\w*(participant|user|member|guest|collaborator)s?)"), Capability.SEND),
]


def classify(tool: str, overrides: dict[str, str] | None = None) -> Capability:
    if overrides and tool in overrides:
        return Capability(overrides[tool])
    name = normalise(tool)
    if name in EXACT:
        return EXACT[name]
    for pattern, cap in VERB_RULES:
        if pattern.search(name):
            return cap
    # Getters never change anything. What they return is outside data when it comes from mail, chat or the web.
    if READ_PREFIX.match(name):
        return Capability.FETCH if OUTSIDE_DATA.search(name) else Capability.READ
    for pattern, cap in PATTERNS:
        if pattern.search(name):
            return cap
    return Capability.UNKNOWN
