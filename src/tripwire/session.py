"""Per-session state: the trusted task, taint, and a short history of actions."""

from __future__ import annotations

import json
import logging
import os
import re
import time
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path

from .models import Capability, Verdict
from .taint import TaintSource, TaintStore

log = logging.getLogger("tripwire.session")

# Words in the user's own prompt that make a capability expected rather than suspicious.
INTENT_WORDS: dict[Capability, re.Pattern[str]] = {
    # Only unambiguous send verbs count on their own. "add", "email", "post", "share"... also name things
    # ("Add a unit test", "Summarise my email"), so they count only next to a recipient (see SEND_WEAK below).
    Capability.SEND: re.compile(r"\b(send|sends|sending|sent|reply|replies|replying|respond|forward\w*|notify|notifies|"
                                r"invite\w*|tell|dm|ping|cc)\b", re.I),
    Capability.MONEY: re.compile(r"\b(pay|send money|transfer|refund|upi|invoice|bill|rent|book|reserve|order|purchase|buy)\w*", re.I),
    Capability.CREDENTIAL: re.compile(r"\b(password|passcode|credential|2fa|mfa|login|recovery)\w*", re.I),
    Capability.DELETE: re.compile(r"\b(delete|remove|clean|clear|wipe|drop|purge|uninstall|rm)\w*", re.I),
    Capability.FETCH: re.compile(r"\b(web|url|http|download|fetch|browse|search online|look up|docs)\w*", re.I),
    Capability.EXEC: re.compile(r"\b(run|test|build|install|deploy|compile|lint|start|execute|script|npm|pip|make)\w*", re.I),
}


REPLY_WORDS = re.compile(r"\b(reply|replies|replying|respond\w*|answer\w*|write back|get back to)\b", re.I)
# A weak send verb followed, in the same clause, by someone to send to: "email the notes to bob@x.com",
# "add Dora to the general channel", "share the doc with Alice", "post it in #eng".
SEND_WEAK = re.compile(
    r"\b(email|e-mail|mail|message|text|post|share|slack|add|include|introduce|write back)\w*\b(?:[^.!?\n;]|[.](?=\S)){0,80}?"
    r"(\bto\s+(the\s+)?([\w.+-]{1,64}@|[@#]|(['\"]?[\w-]+['\"]?\s+){0,3}(channel|team|group|chat|thread|everyone|slack|workspace|"
    r"inbox|list|meeting|call)\b|me\b|him\b|her\b|them\b|us\b)|\bwith\s+([\w.+-]{1,64}@|[@#]|me\b|him\b|her\b|them\b|"
    r"us\b|everyone\b|the\s+team\b)|\bin\s+[#@]|[\w.+-]{1,64}@[\w-]{1,63}\.|(?<![\w-])[@#][\w-]{2,})", re.I)
# "write them a message", "to each user write the message: ...": writing a message is sending one.
SEND_WRITE_MSG = re.compile(r"\bwrite\w*\s+(?:back\b|(?:to\s+)?(?:them|him|her|each\s+\w+|everyone|\w+)\s+(?:a|an|the|this)(?:\s+(?!commit\b)\w+){0,2}\s+"
                            r"(?:message|note|dm|email|reply)\b|(?:a|an|the|this)\s+(?:message|dm|email|reply)\b)", re.I)
SEND_TO_NAME = re.compile(r"\b(?:[Ee]mail|[Mm]essage|[Tt]ext|[Ss]lack|DM|[Ww]rite to|[Ss]hare\b[^.!?\n;]{0,60}?\bwith|[Ss]end\b[^.!?\n;]{0,60}?\bto)\s+(?!The\b|A\b|An\b|My\b)[A-Z][a-z]{1,30}\b")


@dataclass
class Session:
    id: str
    cwd: str | None = None
    task: str = ""
    profile: str | None = None
    taint: TaintStore = field(default_factory=TaintStore)
    history: deque[Verdict] = field(default_factory=lambda: deque(maxlen=200))
    secrets_read: list[str] = field(default_factory=list)  # sensitive paths actually read this session
    # secret reads awaiting a human answer: verdict id -> (tool, path). Only count once approved or observed.
    pending_secrets: dict[str, tuple[str, str]] = field(default_factory=dict)
    last_verdict_id: str | None = None  # the call whose output we expect next
    # files that now hold a copy of a secret (cp .env notes.txt, or a Write of key material); a later publish leaks them
    tainted_files: set[str] = field(default_factory=set)
    staged_secrets: list[str] = field(default_factory=list)  # secret files added to git, waiting for a push
    # secret values seen in outputs (the right-hand side of KEY=value lines from a credential file), so an encoded
    # copy (base64 in a commit message) is still recognised
    secret_values: set[str] = field(default_factory=set)
    # code files the agent wrote that would do something risky when run: path -> (severity, category, message)
    risky_written: dict[str, tuple[int, str, str]] = field(default_factory=dict)
    # every file the agent wrote this session (normalised paths); feeding one to an interpreter after hidden
    # instructions is the attacker's code running
    agent_written: set[str] = field(default_factory=set)
    last_seen: float = field(default_factory=time.time)

    def set_task(self, prompt: str, cwd: str | None = None, profile: str | None = None, verified: bool = True) -> None:
        """verified=False: the prompt came in over the API after hidden instructions were seen. It still counts as
        your words, except that it can't vouch for any value those hidden instructions supplied."""
        if profile:
            self.profile = profile
        if prompt.strip() and self.task.endswith(prompt.strip()):
            prompt = ""  # the same prompt sent twice (a retried hook) is one prompt, not two
        self.task = (self.task + "\n" + prompt).strip()
        self.taint.add_trusted(prompt, exclude_injected=not verified)
        if cwd:
            self.cwd = cwd

    def intends(self, cap: Capability) -> bool:
        pat = INTENT_WORDS.get(cap)
        if not (pat and self.task):
            return False
        if pat.search(self.task):
            return True
        return cap == Capability.SEND and bool(SEND_WEAK.search(self.task) or SEND_TO_NAME.search(self.task)
                                               or SEND_WRITE_MSG.search(self.task))

    def asked_to_reply(self) -> bool:
        return bool(self.task and REPLY_WORDS.search(self.task))

    def in_workspace(self, path: str) -> bool:
        if not self.cwd:
            return True
        p = os.path.realpath(os.path.expanduser(path if os.path.isabs(os.path.expanduser(path)) else os.path.join(self.cwd, path)))
        root = os.path.realpath(self.cwd)
        return p == root or p.startswith(root + os.sep)


SNAPSHOT_VERSION = 1
KEEP_FOR_S = 24 * 3600  # a saved session older than this is not restored
MAX_SESSIONS = 2000  # in memory; beyond this the least recently used sessions without hidden instructions go first


def _src(t: TaintSource, secrets: set[str] = frozenset()) -> list:
    return [t.tool, _mask(t.snippet, secrets), t.injected, t.label, t.seq]


def _mask(text: str, secrets: set[str]) -> str:
    from .analyzers.secrets import redact
    for v in secrets:
        if v and v in text:
            text = text.replace(v, "[secret]")
    return redact(text)


def _clean(text: str, secrets: set[str]) -> bool:
    """True if the text holds no secret we know of (a known secret value or a key pattern)."""
    low = text.lower()
    return _mask(text, secrets) == text and not any(v and v.lower() in low for v in secrets)


def _unsrc(x: list) -> TaintSource:
    return TaintSource(str(x[0]), str(x[1]), bool(x[2]), str(x[3]), int(x[4]))


def session_to_dict(s: Session) -> dict:
    """What a daemon restart must not forget: the task, everything learned from tool outputs (above all that hidden
    instructions were seen) and which secrets were read. Secret values themselves are never written to disk."""
    t = s.taint
    sv = s.secret_values
    return {
        "id": s.id, "cwd": s.cwd, "task": s.task, "profile": s.profile, "last_seen": s.last_seen,
        "history": [v.model_dump(mode="json") for v in list(s.history)[-50:]],
        "secrets_read": s.secrets_read[-200:], "pending_secrets": {k: list(v) for k, v in s.pending_secrets.items()},
        "last_verdict_id": s.last_verdict_id, "tainted_files": sorted(s.tainted_files),
        "staged_secrets": s.staged_secrets, "risky_written": {k: list(v) for k, v in s.risky_written.items()},
        "agent_written": sorted(s.agent_written)[:5000],
        "taint": {"trusted_text": t.trusted_text, "trusted": {k: sorted(v) for k, v in t.trusted.items()},
                  "untrusted": {k: _src(v, sv) for k, v in t.untrusted.items() if _clean(k, sv)},
                  "untrusted_lines": [[n, _src(src, sv)] for n, src in t.untrusted_lines[-1000:] if _clean(n, sv)],
                  "injection_seen": [_src(x, sv) for x in t.injection_seen[-50:]], "seen": t.seen,
                  "senders": t.senders, "listed": t.listed, "unverified": sorted(t.unverified)[:500]},
    }


def session_from_dict(d: dict) -> Session:
    t = d.get("taint") or {}
    taint = TaintStore(
        trusted_text=t.get("trusted_text", ""), trusted={k: set(v) for k, v in (t.get("trusted") or {}).items()},
        untrusted={k: _unsrc(v) for k, v in (t.get("untrusted") or {}).items()},
        untrusted_lines=[(n, _unsrc(src)) for n, src in t.get("untrusted_lines") or []],
        injection_seen=[_unsrc(x) for x in t.get("injection_seen") or []], seen=int(t.get("seen") or 0),
        senders=dict(t.get("senders") or {}), listed=dict(t.get("listed") or {}),
        unverified=set(t.get("unverified") or []))
    s = Session(id=d["id"], cwd=d.get("cwd"), task=d.get("task") or "", profile=d.get("profile"), taint=taint,
                secrets_read=list(d.get("secrets_read") or []),
                pending_secrets={k: (v[0], v[1]) for k, v in (d.get("pending_secrets") or {}).items()},
                last_verdict_id=d.get("last_verdict_id"), tainted_files=set(d.get("tainted_files") or []),
                staged_secrets=list(d.get("staged_secrets") or []),
                risky_written={k: (int(v[0]), v[1], v[2]) for k, v in (d.get("risky_written") or {}).items()},
                agent_written=set(d.get("agent_written") or []),
                last_seen=float(d.get("last_seen") or time.time()))
    for v in d.get("history") or []:
        s.history.append(Verdict.model_validate(v))
    return s


MAX_TOMBSTONES = 5000


class SessionStore:
    def __init__(self) -> None:
        self._s: dict[str, Session] = {}
        self.changes = 0  # bumped on every access; the daemon saves a snapshot when it moves
        # Session id -> the hidden instructions it saw. A reset or eviction forgets the session but never that:
        # a session that comes back under the same id starts out knowing it was attacked (review 3: a reset wiped
        # the injection memory, then the attacker's blocked send was allowed).
        self.tombstones: dict[str, list[TaintSource]] = {}

    def _bury(self, s: Session) -> None:
        if s.taint.injection_seen:
            self.tombstones[s.id] = list(s.taint.injection_seen[-5:])
            while len(self.tombstones) > MAX_TOMBSTONES:
                self.tombstones.pop(next(iter(self.tombstones)))

    def was_injected(self, sid: str) -> bool:
        s = self._s.get(sid)
        return bool(s and s.taint.injection_seen) or sid in self.tombstones

    def get(self, sid: str, cwd: str | None = None) -> Session:
        s = self._s.get(sid)
        if s is None:
            if len(self._s) >= MAX_SESSIONS:
                self._evict()
            s = self._s[sid] = Session(id=sid, cwd=cwd)
            if sid in self.tombstones:
                s.taint.injection_seen = list(self.tombstones[sid])
        elif cwd and not s.cwd:
            s.cwd = cwd
        s.last_seen = time.time()
        self.changes += 1
        return s

    def _evict(self) -> None:
        """Forget the least recently used sessions, keeping any that saw hidden instructions while we can."""
        order = sorted(self._s.values(), key=lambda x: (bool(x.taint.injection_seen), x.last_seen))
        for s in order[: max(1, len(order) // 10)]:
            self._bury(s)
            self._s.pop(s.id, None)

    def all(self) -> list[Session]:
        return list(self._s.values())

    def reset(self, keep_injected: bool = False) -> int:
        """Forget sessions. keep_injected: keep the ones that saw hidden instructions. Returns how many were kept."""
        self.changes += 1
        for s in self._s.values():
            self._bury(s)
        if not keep_injected:
            self._s.clear()
            return 0
        self._s = {k: s for k, s in self._s.items() if s.taint.injection_seen}
        return len(self._s)

    # ---- surviving a daemon restart ----------------------------------------------
    def save(self, path: Path) -> int:
        """Write every recent session to `path` (0600, atomic). Returns how many were saved."""
        now = time.time()
        rows = [session_to_dict(s) for s in list(self._s.values()) if now - s.last_seen < KEEP_FOR_S]
        graves = {k: [_src(x) for x in v] for k, v in list(self.tombstones.items())}
        data = json.dumps({"version": SNAPSHOT_VERSION, "saved": now, "sessions": rows, "tombstones": graves},
                          separators=(",", ":"))
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_name(path.name + ".tmp")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(data)
        os.replace(tmp, path)
        return len(rows)

    def load(self, path: Path) -> int:
        """Restore sessions saved by an earlier daemon. A missing file is normal; a broken one is logged loudly."""
        try:
            raw = path.read_text()
        except FileNotFoundError:
            return 0
        try:
            data = json.loads(raw)
            now = time.time()
            n = 0
            for k, v in (data.get("tombstones") or {}).items():
                self.tombstones.setdefault(k, [_unsrc(x) for x in v])
            for d in data.get("sessions") or []:
                if now - float(d.get("last_seen") or 0) < KEEP_FOR_S and d.get("id") not in self._s:
                    self._s[d["id"]] = session_from_dict(d)
                    n += 1
            return n
        except Exception as e:  # noqa: BLE001
            log.error("Could not restore sessions from %s (%s: %s). Starting without them.", path, type(e).__name__, e)
            return 0
