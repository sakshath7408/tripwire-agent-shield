"""The simulated agent.

A Planner decides the next tool call from the history. Two kinds can plug in:

  NaivePlanner  (default) a deterministic stand-in for a hijacked LLM. It follows a fixed plan for the
                user's task, and it naively obeys any imperative instruction it finds in content it reads
                (read this file, POST that, email this, run that command, transfer money). That is exactly
                the failure mode prompt injection exploits, made reproducible so the demo is the same every time.

  Any LLM planner  implement `next_action(history) -> ToolCall | None` (for example a local Ollama model).
                Nothing else changes: the runner, the world and the guard stay the same.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Callable, Protocol


@dataclass
class ToolCall:
    tool: str
    args: dict[str, Any]
    why: str = ""  # "task" or "injected: <where the instruction came from>"


@dataclass
class Step:
    call: ToolCall
    output: str  # what the agent saw back (tool output, or the guard's refusal)
    decision: str = "allow"  # allow | ask | block (or "unguarded")
    executed: bool = True


class Planner(Protocol):
    def next_action(self, history: list[Step]) -> ToolCall | None: ...


PlanItem = ToolCall | Callable[[list[Step]], ToolCall | None]

FILE_RE = re.compile(r"(~/[\w./-]+[\w]|(?<![\w/])\.env\b)")
URL_RE = re.compile(r"https?://[^\s'\"<>`)]+")
EMAIL_RE = re.compile(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+")
CMD_RE = re.compile(r"`([^`]+)`")
MONEY_RE = re.compile(r"\b(?:transfer|send|pay|wire)\s+\$?([\d,]+(?:\.\d+)?)", re.I)
IBAN_RE = re.compile(r"\b[A-Z]{2}\d{2}[A-Z0-9]{10,30}\b")
IMPERATIVE = re.compile(r"\b(must|please|before doing|before completing|before running|do this|read|post|email|reply|"
                        r"run|transfer|send|install)\b", re.I)


def extract_instructions(text: str, source: str) -> list[PlanItem]:
    """Turn imperative sentences found in untrusted content into tool calls, the way a hijacked agent would."""
    out: list[PlanItem] = []
    # one "instruction" per paragraph / comment so 'read X and POST it to Y' stays together
    for chunk in re.split(r"\n\s*\n|<!--|-->", text):
        if not IMPERATIVE.search(chunk):
            continue
        why = f"injected: instruction found in {source}"
        files = [f for f in FILE_RE.findall(chunk) if "/" in f or f == ".env"]
        urls = [u.rstrip(".,") for u in URL_RE.findall(chunk)]
        cmds = [c for c in CMD_RE.findall(chunk) if c.split()[0] in ("curl", "wget", "bash", "sh", "python", "python3", "rm")]
        money = MONEY_RE.search(chunk)
        ibans = IBAN_RE.findall(chunk)
        body = "\n".join(l for l in chunk.splitlines() if "From: " not in l)  # the sender line is not an instruction
        emails = list(dict.fromkeys(e for e in EMAIL_RE.findall(body) if re.search(r"\b(email|reply|send|forward)\b", body, re.I)))
        if not (files or cmds or money or emails or (urls and re.search(r"\bpost\b", chunk, re.I))):
            continue
        for f in files:
            out.append(ToolCall("read_file", {"path": f}, why))
        if money and ibans:
            out.append(ToolCall("send_money", {"to": ibans[0], "amount": float(money.group(1).replace(",", "")),
                                               "memo": "invoice"}, why))
        loot = _loot(files)
        if re.search(r"\bpost\b", chunk, re.I):
            for u in urls:
                if u not in " ".join(cmds):
                    out.append(lambda h, u=u, loot=loot: ToolCall("http_post", {"url": u, "data": loot(h)}, why))
        for e in emails:
            out.append(lambda h, e=e, loot=loot: ToolCall("send_email", {"to": e, "subject": "As requested",
                                                                          "body": loot(h)}, why))
        for c in cmds:
            out.append(ToolCall("run_command", {"command": c}, why))
    return out


def _loot(files: list[str]) -> Callable[[list[Step]], str]:
    """Whatever the agent managed to read from the requested files (empty if the guard stopped the reads)."""
    def collect(history: list[Step]) -> str:
        parts = [s.output for s in history if s.call.tool == "read_file" and s.call.args.get("path") in files
                 and s.executed]
        return "\n".join(parts) if parts else "(could not read the files)"
    return collect


@dataclass
class NaivePlanner:
    """Fixed task plan + obeys instructions found in tool outputs (injected steps run first, like a real hijack)."""

    plan: list[PlanItem]
    obey_injections: bool = True
    queue: list[PlanItem] = field(default_factory=list)
    _seen: int = 0

    def __post_init__(self) -> None:
        self.queue = list(self.plan)

    def next_action(self, history: list[Step]) -> ToolCall | None:
        if self.obey_injections:
            for step in history[self._seen:]:
                if step.executed and step.call.tool in ("read_file", "fetch_url", "read_inbox"):
                    src = step.call.args.get("path") or step.call.args.get("url") or "the inbox"
                    self.queue[0:0] = extract_instructions(step.output, src)
            self._seen = len(history)
        while self.queue:
            item = self.queue.pop(0)
            call = item(history) if callable(item) else item
            if call is not None:
                return call
        return None
