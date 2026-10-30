"""Autonomy: decide an ASK on its own when the answer is obvious, and learn from the user's answers.

Three levels (a setting, see server.py):
- strict: today's behaviour. Every ASK goes to a human.
- balanced (default): an ASK becomes ALLOW when nothing suspicious was read, the task plainly asked for this kind
  of action, every target came from the user (or clean content), and it is not money, credentials, deleting outside
  the project or a risky shell command. An ASK becomes BLOCK when hidden instructions were seen and the task never
  asked for this action. Everything else still asks.
- autonomous: like balanced, plus routine sends to people the user named (even if the task never said "send") and
  reads of the user's own non-secret files outside the project. Money and credential changes always ask; anything
  after hidden instructions never gets auto-allowed.

Learned rules: when the user answers an ASK with "remember", Tripwire stores a narrow rule (same tool, same
capability, same normalised target) and applies it to the next matching ASK. A learned ALLOW is never created for
money, credentials, deletes outside the project or anything with injection findings, and is never applied once
hidden instructions were seen. A learned BLOCK is always fine.

Neither layer ever touches a BLOCK. It only ever turns an ASK into a decision, so the hard floor (profile deny,
secrets egress, injected targets, the shell analyzer's HIGH findings) is unchanged.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shlex
import threading
import time
import uuid
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any

import yaml

from .analyzers import paths
from .models import INFO, Action, Capability, Decision, Finding, Verdict
from .taint import indicators

if TYPE_CHECKING:  # pragma: no cover
    from .session import Session

LEVELS = ("strict", "balanced", "autonomous")
DEFAULT_LEVEL = "balanced"
NEVER_AUTO_ALLOW = {Capability.MONEY, Capability.CREDENTIAL, Capability.UNKNOWN}

# Extra intent words for capabilities Session.intends does not cover (it only knows the high-impact ones).
EXTRA_INTENT: dict[Capability, re.Pattern[str]] = {
    Capability.WRITE: re.compile(r"\b(write|save|edit|fix|update|change|create|add|modify|refactor|implement|rename|"
                                 r"note|draft|record|append|patch|generate|make|format|bump|correct|replace|move|copy)\w*", re.I),
    Capability.READ: re.compile(r"\b(read|check|look|open|show|find|review|summar|list|search|inspect|see|explain|"
                                r"analy|what|which|how|compare|count|fix|debug|test)\w*", re.I),
    Capability.AGENT: re.compile(r"\b(agent|delegate|parallel|subagent|sub-agent|helper|explore)\w*", re.I),
}

# Findings an autonomy level may look past. Every ASK-level finding on the action must be in this set, or it asks.
# Everything not listed (unknown tools, too-big inputs, secret files, exfil patterns, money, credentials, risky shell,
# unrequested high-impact actions, anything about injection) always goes to a human.
WAIVABLE = {
    "balanced": {"profile.ask", "scope.outside_workspace"},
    "autonomous": {"profile.ask", "scope.outside_workspace", "intent.unrequested_send", "taint.url_template"},
}
RISKY_DELETE_RULES = {"shell.rm_outside", "shell.rm_home", "shell.rm_root", "shell.rm_system", "shell.rm_home_child",
                      "shell.rm_ws_parent", "shell.rm_secrets", "shell.find_delete", "shell.mv_away", "shell.mv_destroy"}
UNSAFE_CATEGORIES = {"injection", "exfiltration", "secrets"}

ASK_AT, BLOCK_AT = 50, 80


def normalise_level(level: str | None) -> str:
    level = (level or os.environ.get("TRIPWIRE_AUTONOMY") or DEFAULT_LEVEL).strip().lower()
    if level not in LEVELS:
        raise ValueError(f"autonomy must be one of {', '.join(LEVELS)}")
    return level


def asked_for(s: "Session", cap: Capability) -> bool:
    """Did the user's own words plainly ask for this kind of action?"""
    if cap in NEVER_AUTO_ALLOW or not s.task:
        return False
    pat = EXTRA_INTENT.get(cap)
    if pat is not None:
        return bool(pat.search(s.task))
    return s.intends(cap)


def requested(s: "Session", cap: Capability) -> bool:
    """Like asked_for, but money and password changes count too: an injected session must not auto-block the
    payment or booking you asked for. Those stay a question for you (they are never auto-allowed either)."""
    if cap in (Capability.MONEY, Capability.CREDENTIAL):
        return s.intends(cap)
    return asked_for(s, cap)


# ---------------------------------------------------------------- targets
RECIPIENT_KEY = re.compile(r"^(to|cc|bcc|recipients?|emails?|email_address(es)?|address(es)?|participants?|attendees?|"
                           r"invitees?|users?|user|members?|phone|phone_number|number|iban|account|payee|beneficiary|"
                           r"channel|reply_to|recipient_id|user_id)$", re.I)
URL_KEY = re.compile(r"(?:^|_)(url|uri|link|endpoint|href|webhook|host)s?$", re.I)
PATH_KEY = re.compile(r"(?:^|_)(path|file|dir|folder|target|dest|source|src|location|filename)s?$", re.I)
CMD_KEYS = ("command", "cmd", "script", "code")


def _key(k: Any) -> str:
    return re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", str(k)[:64]).lower().replace("-", "_")


def _keyed(value: Any, key_re: re.Pattern[str], depth: int = 0, hit: bool = False) -> list[str]:
    if depth > 16:
        return []
    if isinstance(value, str):
        return [value] if hit else []
    if isinstance(value, (int, float)) and hit and not isinstance(value, bool):
        return [str(value)]
    if isinstance(value, dict):
        return [s for k, v in value.items() for s in _keyed(v, key_re, depth + 1, hit or bool(key_re.search(_key(k))))]
    if isinstance(value, (list, tuple)):
        return [s for v in value for s in _keyed(v, key_re, depth + 1, hit)]
    return []


def _host(u: str) -> str:
    m = re.match(r"^(?:[a-z][\w+.-]{0,20}://)?(?:[^@/\s]{0,256}@)?([^/:?#\s]{1,256})", u.strip(), re.I)
    return m.group(1).lower() if m else u.lower()


def recipients(args: dict) -> list[str]:
    raw = _keyed(args, RECIPIENT_KEY)
    found = indicators("\n".join(raw))
    vals = sorted({v for k in ("email", "phone", "iban", "upi") for v in found.get(k, ())})
    if vals:
        return vals
    return sorted({r.strip().lower() for r in raw if r.strip() and len(r) <= 200})


def command_shape(cmd: str) -> str:
    """`git push origin main` -> `git push origin *`. Program, up to two sub-command words and every flag are kept;
    other arguments become `*`. Anything compound (pipes, `;`, `$(...)`, redirects) is only ever matched exactly."""
    cmd = cmd.strip()
    if re.search(r"[|;&`$<>()\n\\]", cmd):
        return "exact:" + " ".join(cmd.split())
    try:
        toks = shlex.split(cmd)
    except ValueError:
        return "exact:" + " ".join(cmd.split())
    if not toks:
        return "exact:"
    out, words = [os.path.basename(toks[0])], 0
    for t in toks[1:]:
        if t.startswith("-"):
            out.append(t.split("=", 1)[0])
        elif words < 2 and re.fullmatch(r"[a-z][a-z0-9_.:-]{0,40}", t) and "/" not in t:
            out.append(t)
            words += 1
        else:
            words = 2  # positional arguments after the first free-form one are never sub-commands
            if out[-1] != "*":
                out.append("*")
    return " ".join(out)


def _paths(args: dict, cwd: str | None) -> list[str]:
    out = []
    for v in _keyed(args, PATH_KEY):
        if not v or len(v) > 4096 or "\n" in v or ("://" in v and not v.lower().startswith("file://")):
            continue
        v = v[7:] if v.lower().startswith("file://") else v
        out.append(os.path.normpath(paths.expand(v, cwd)))
    return out


def target_of(action: Action, cap: Capability, cwd: str | None) -> str:
    """The narrow, normalised thing this action points at: who, which host, which folder, which command shape."""
    args = action.args or {}
    if cap in (Capability.SEND, Capability.MONEY, Capability.CREDENTIAL):
        r = recipients(args)
        if r:
            return "to:" + ",".join(r)
    if cap == Capability.EXEC:
        cmd = next((args[k] for k in CMD_KEYS if isinstance(args.get(k), str)), None)
        argv = next((args[k] for k in ("argv", "args", "arguments") if isinstance(args.get(k), list)), None)
        if cmd is None and argv:
            cmd = shlex.join(str(x) for x in argv)
        if cmd is not None:
            return "cmd:" + command_shape(cmd)
    urls = [u for u in _keyed(args, URL_KEY) if "://" in u or "." in u]
    if cap in (Capability.FETCH, Capability.SEND) and urls:
        return "host:" + ",".join(sorted({_host(u) for u in urls}))
    if cap in (Capability.READ, Capability.WRITE, Capability.DELETE):
        ps = _paths(args, cwd)
        if ps:
            dirs = sorted({os.path.dirname(p).rstrip("/") + "/" for p in ps})
            if len(dirs) == 1:
                return "path:" + dirs[0]
    blob = json.dumps(args, sort_keys=True, default=str)
    return "exact:" + hashlib.sha256(blob.encode()).hexdigest()[:16]


def target_matches(rule_target: str, target: str) -> bool:
    if rule_target.startswith("path:") and target.startswith("path:"):
        return target[5:].startswith(rule_target[5:])
    if rule_target.startswith("cmd:") and target.startswith("cmd:"):
        r, t = rule_target[4:], target[4:]
        if r.startswith("exact:") or t.startswith("exact:"):
            return r == t
        rt, tt = r.split(), t.split()
        return len(rt) == len(tt) and all(a == b or a == "*" for a, b in zip(rt, tt))
    return rule_target == target


def describe_target(cap: Capability, target: str) -> str:
    kind, _, val = target.partition(":")
    if kind == "to":
        return f"to {val.replace(',', ', ')}"
    if kind == "host":
        return f"on {val.replace(',', ', ')}"
    if kind == "path":
        verb = {Capability.READ: "reading", Capability.WRITE: "changing", Capability.DELETE: "deleting"}.get(cap, "using")
        return f"{verb} files in {val}"
    if kind == "cmd":
        return f"running `{val.removeprefix('exact:')}`"
    return "with exactly these details"


# ---------------------------------------------------------------- learned rules
@dataclass
class LearnedRule:
    id: str
    decision: str  # allow | block
    tool: str
    capability: str
    target: str
    scope: str  # session | always
    created: float
    description: str
    session: str | None = None  # only for scope == "session"

    def public(self) -> dict:
        d = asdict(self)
        d.pop("session", None)
        return d


class LearnRefused(ValueError):
    """Plain-English reason a remembered ALLOW was not stored."""


def unsafe_to_learn_allow(v: Verdict, s: "Session | None") -> str | None:
    cap = v.capability
    if cap == Capability.MONEY:
        return "Tripwire never remembers an allow for moving money. It will ask each time."
    if cap == Capability.CREDENTIAL:
        return "Tripwire never remembers an allow for password or key changes. It will ask each time."
    if cap == Capability.UNKNOWN:
        return "Tripwire doesn't know what this tool does, so it won't remember an allow for it."
    bad = [f for f in v.findings if f.category in UNSAFE_CATEGORIES]
    if bad:
        return f"Not remembered: this action had a warning that matters every time ({bad[0].message})"
    if s is not None and s.taint.injection_seen:
        return "Not remembered: hidden instructions were found in this session."
    if any(f.rule in RISKY_DELETE_RULES for f in v.findings):
        return "Tripwire never remembers an allow for deleting outside your project. It will ask each time."
    if cap == Capability.DELETE and s is not None and any(not s.in_workspace(p) for p in _paths(v.action.args or {}, s.cwd)):
        return "Tripwire never remembers an allow for deleting outside your project. It will ask each time."
    return None


class LearnedStore:
    """Session rules live in memory. "always" rules live in learned.yaml (only you write it; agents may not:
    the never-touch-tripwire policy rule blocks writes to ~/.tripwire)."""

    def __init__(self, path: Path | None = None) -> None:
        self.path = path
        self.rules: list[LearnedRule] = []
        self._lock = threading.Lock()
        if path is not None and path.exists():
            try:
                data = yaml.safe_load(path.read_text()) or {}
                self.rules = [LearnedRule(**{k: r[k] for k in LearnedRule.__dataclass_fields__ if k in r})
                              for r in data.get("rules") or [] if r.get("decision") in ("allow", "block")]
                # A hand-edited file must not smuggle in an allow Tripwire would never learn.
                self.rules = [r for r in self.rules if r.scope == "always" and not
                              (r.decision == "allow" and r.capability in ("money", "credential", "unknown"))]
            except Exception:  # noqa: BLE001 - a broken file means no learned rules, never a crash
                self.rules = []

    def _save(self) -> None:
        if self.path is None:
            return
        self.path.parent.mkdir(parents=True, exist_ok=True)
        keep = [r.public() for r in self.rules if r.scope == "always"]
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text("# Rules Tripwire learned from your answers. Delete one with DELETE /v1/rules/{id} "
                       "or by removing it here.\n" + yaml.safe_dump({"rules": keep}, sort_keys=False))
        os.replace(tmp, self.path)

    def list(self, session: str | None = None) -> list[LearnedRule]:
        return [r for r in self.rules if r.scope == "always" or session is None or r.session == session]

    def get(self, rid: str) -> LearnedRule | None:
        return next((r for r in self.rules if r.id == rid), None)

    def add(self, v: Verdict, decision: Decision, scope: str, s: "Session | None") -> LearnedRule:
        if scope not in ("session", "always"):
            raise LearnRefused("remember must be 'session' or 'always'.")
        if decision == Decision.ALLOW:
            why = unsafe_to_learn_allow(v, s)
            if why:
                raise LearnRefused(why)
        cap = v.capability
        target = target_of(v.action, cap, s.cwd if s else v.action.cwd)
        session = v.action.session_id if scope == "session" else None
        when = "Always" if scope == "always" else "For this session,"
        desc = (f"{when} {decision.value} {v.action.tool} {describe_target(cap, target)}"
                f"{'' if scope == 'always' else ' without asking'}.")
        if scope == "always":
            desc = desc.replace("Always allow", "Always allow, without asking,", 1)
        with self._lock:
            # one rule per (tool, capability, target, scope, session): a new answer replaces the old one
            self.rules = [r for r in self.rules if not (r.tool == v.action.tool and r.capability == cap.value and
                                                        r.target == target and r.scope == scope and r.session == session)]
            rule = LearnedRule(id="r-" + uuid.uuid4().hex[:8], decision=decision.value, tool=v.action.tool,
                               capability=cap.value, target=target, scope=scope, created=round(time.time(), 3),
                               description=desc, session=session)
            self.rules.append(rule)
            self._save()
        return rule

    def delete(self, rid: str) -> LearnedRule | None:
        with self._lock:
            r = self.get(rid)
            if r is None:
                return None
            self.rules.remove(r)
            self._save()
            return r

    def match(self, action: Action, cap: Capability, cwd: str | None) -> LearnedRule | None:
        if not self.rules:
            return None
        target = target_of(action, cap, cwd)
        hits = [r for r in self.rules if r.tool == action.tool and r.capability == cap.value
                and (r.scope == "always" or r.session == action.session_id) and target_matches(r.target, target)]
        if not hits:
            return None
        # A block beats an allow; a session answer beats an older "always" one.
        return sorted(hits, key=lambda r: (r.decision == "block", r.scope == "session", r.created))[-1]


# ---------------------------------------------------------------- the autonomy layer
@dataclass
class AutoResult:
    decision: Decision
    finding: Finding
    rule_id: str | None = None


@dataclass
class Context:
    """What the engine already worked out about the action, so the autonomy layer doesn't redo it."""
    command_src_injected: bool = False
    extra: dict = field(default_factory=dict)


def _ask_findings(findings: list[Finding]) -> list[Finding]:
    return [f for f in findings if f.severity >= ASK_AT]


def _named(s: "Session", value: str) -> bool:
    return s.taint.is_trusted_value(value)


def _what(cap: Capability, action: Action, s: "Session") -> str:
    args = action.args or {}
    if cap == Capability.SEND:
        r = recipients(args)
        return f"message {', '.join(r[:3])}" if r else "send this message"
    if cap == Capability.EXEC:
        t = target_of(action, cap, s.cwd)[4:].removeprefix("exact:")
        return f"run `{t[:60]}`"
    if cap == Capability.FETCH:
        urls = _keyed(args, URL_KEY)
        return f"open {_host(urls[0])}" if urls else "fetch this"
    if cap in (Capability.WRITE, Capability.READ, Capability.DELETE):
        ps = _paths(args, s.cwd)
        verb = {Capability.WRITE: "change", Capability.READ: "read", Capability.DELETE: "delete"}[cap]
        if ps:
            p = ps[0]
            if s.cwd and p.startswith(os.path.realpath(s.cwd) + os.sep):
                p = os.path.relpath(p, os.path.realpath(s.cwd))
            return f"{verb} {p}"
        return f"{verb} files"
    if cap == Capability.AGENT:
        return "start a helper agent"
    return "do this"


def _clean_read_note(s: "Session") -> str:
    return "nothing it read had hidden instructions" if s.taint.untrusted_lines or s.taint.untrusted else \
        "nothing suspicious was read"


def decide(level: str, s: "Session", action: Action, cap: Capability, findings: list[Finding],
           ctx: Context | None = None) -> AutoResult | None:
    """Turn an ASK into ALLOW or BLOCK when the answer is obvious. None means: still ask the human."""
    if level == "strict":
        return None
    ctx = ctx or Context()
    asks = _ask_findings(findings)
    args = action.args or {}

    # ---- auto-block: hidden instructions were seen and the user never asked for this
    if s.taint.injection_seen:
        src = s.taint.injection_seen[-1]
        secret_read = any(f.rule in ("secrets.read", "shell.secret_read") for f in findings)
        if secret_read or not requested(s, cap) or ctx.command_src_injected:
            why = ("read a credential file you never mentioned" if secret_read else
                   "run a command copied from that content" if ctx.command_src_injected and requested(s, cap) else
                   f"{_cap_verb(cap)}")
            return AutoResult(Decision.BLOCK, Finding(
                rule="autonomy.blocked", severity=BLOCK_AT, category="injection", evidence=src.snippet,
                message=f"Blocked on its own: hidden instructions were found in {src.where}, and you never asked it to {why}."))
        return None  # after hidden instructions, anything left still needs a human

    # ---- auto-allow
    if cap in NEVER_AUTO_ALLOW:
        return None
    waivable = WAIVABLE[level]
    if any(f.rule not in waivable for f in asks):
        return None
    if any((f.rule.startswith("shell.") or f.rule == "write.risky_code") and f.severity >= ASK_AT for f in findings):
        return None
    if any(f.category in ("injection", "exfiltration", "secrets") and f.rule != "taint.url_template" for f in asks):
        return None
    if any(f.rule == "taint.url_template" for f in asks) and (cap != Capability.SEND or level != "autonomous"):
        return None  # a link filled in with data: only in a message to people you named, and only when autonomous
    # every value that came from outside must come from content without hidden instructions
    blob = json.dumps(args, default=str)
    if any(src.injected for _, src in s.taint.tainted_values(blob)):
        return None

    named_people = False
    if cap == Capability.SEND:
        who = recipients(args)
        found = indicators("\n".join(_keyed(args, RECIPIENT_KEY)))
        people = sorted({v for k in ("email", "phone", "iban", "upi") for v in found.get(k, ())})
        # Sends must go only to people you named yourself; a recipient taken from a document stays an ask.
        if not people or len(people) != len(who) or not all(_named(s, p) for p in people):
            return None
        named_people = True
    if cap == Capability.FETCH:
        hosts = {_host(u) for u in _keyed(args, URL_KEY)}
        if any(not (_named(s, h) or h in s.taint.untrusted or any(h in k for k in s.taint.untrusted if k.startswith("http")))
               for h in hosts):
            return None

    plainly_asked = asked_for(s, cap)
    if cap == Capability.SEND and level == "autonomous" and named_people:
        plainly_asked = True  # a routine message to someone you named
    if not plainly_asked:
        return None

    if cap in (Capability.WRITE, Capability.DELETE, Capability.READ):
        ps = _paths(args, s.cwd)
        outside = [p for p in ps if not s.in_workspace(p)]
        if outside:
            if cap == Capability.DELETE:
                return None  # never delete outside the project on its own
            if cap == Capability.READ:
                if level != "autonomous" or any(paths.is_secret(p) or paths.is_system(p) for p in outside):
                    return None
                home = os.path.realpath(os.path.expanduser("~"))
                if not all(os.path.realpath(p).startswith(home + os.sep) for p in outside):
                    return None
            elif not all(_named(s, raw) for raw in _raw_paths(args, outside, s.cwd)):
                return None  # writing outside the project only where you said so
    elif any(f.rule == "scope.outside_workspace" for f in asks):
        return None

    what = _what(cap, action, s)
    return AutoResult(Decision.ALLOW, Finding(
        rule="autonomy.allowed", severity=INFO, category="autonomy",
        message=f"Allowed on its own: you asked to {what} and {_clean_read_note(s)}."))


def _raw_paths(args: dict, wanted: list[str], cwd: str | None) -> list[str]:
    """The path strings as written in the args, for the ones in `wanted` (expanded)."""
    out = []
    for v in _keyed(args, PATH_KEY):
        vv = v[7:] if v.lower().startswith("file://") else v
        if os.path.normpath(paths.expand(vv, cwd)) in wanted:
            out.append(vv)
    return out or wanted


def _cap_verb(cap: Capability) -> str:
    return {Capability.SEND: "send messages", Capability.MONEY: "move money", Capability.DELETE: "delete anything",
            Capability.EXEC: "run commands", Capability.WRITE: "change files", Capability.READ: "read files",
            Capability.FETCH: "fetch outside content", Capability.AGENT: "start other agents",
            Capability.CREDENTIAL: "change passwords or keys"}.get(cap, "use this tool")


def apply_learned(rule: LearnedRule, s: "Session", cap: Capability, findings: list[Finding]) -> AutoResult | None:
    """A remembered answer. A learned BLOCK always applies; a learned ALLOW loses to anything unsafe."""
    if rule.decision == "block":
        return AutoResult(Decision.BLOCK, Finding(
            rule="learned.block", severity=BLOCK_AT, category="policy",
            message=f"Blocked on its own: you said no to this before ({rule.description})"), rule.id)
    if cap in NEVER_AUTO_ALLOW or s.taint.injection_seen:
        return None
    if any(f.category in UNSAFE_CATEGORIES for f in findings) or any(f.rule in RISKY_DELETE_RULES for f in findings):
        return None
    return AutoResult(Decision.ALLOW, Finding(
        rule="learned.allow", severity=INFO, category="autonomy",
        message=f"Allowed on its own: you said yes to this before ({rule.description})"), rule.id)


# ---------------------------------------------------------------- settings
def settings_path(home: Path) -> Path:
    return home / "settings.json"


def load_settings(home: Path) -> dict:
    try:
        data = json.loads(settings_path(home).read_text())
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def save_settings(home: Path, data: dict) -> None:
    home.mkdir(parents=True, exist_ok=True)
    p = settings_path(home)
    tmp = p.with_suffix(".tmp")
    tmp.write_text(json.dumps(data, indent=1))
    os.replace(tmp, p)
