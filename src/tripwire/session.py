"""Per-session state: the trusted task, taint, and a short history of actions."""

from __future__ import annotations

import os
import re
from collections import deque
from dataclasses import dataclass, field

from .models import Capability, Verdict
from .taint import TaintStore

# Words in the user's own prompt that make a capability expected rather than suspicious.
INTENT_WORDS: dict[Capability, re.Pattern[str]] = {
    Capability.SEND: re.compile(r"\b(send|email|mail|message|reply|post|share|notify|tell|invite|forward|slack|add|include|introduce)\w*", re.I),
    Capability.MONEY: re.compile(r"\b(pay|send money|transfer|refund|upi|invoice|bill|rent|book|reserve|order|purchase|buy)\w*", re.I),
    Capability.CREDENTIAL: re.compile(r"\b(password|passcode|credential|2fa|mfa|login|recovery)\w*", re.I),
    Capability.DELETE: re.compile(r"\b(delete|remove|clean|clear|wipe|drop|purge|uninstall|rm)\w*", re.I),
    Capability.FETCH: re.compile(r"\b(web|url|http|download|fetch|browse|search online|look up|docs)\w*", re.I),
    Capability.EXEC: re.compile(r"\b(run|test|build|install|deploy|compile|lint|start|execute|script|npm|pip|make)\w*", re.I),
}


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

    def set_task(self, prompt: str, cwd: str | None = None, profile: str | None = None) -> None:
        if profile:
            self.profile = profile
        self.task = (self.task + "\n" + prompt).strip()
        self.taint.add_trusted(prompt)
        if cwd:
            self.cwd = cwd

    def intends(self, cap: Capability) -> bool:
        pat = INTENT_WORDS.get(cap)
        return bool(pat and self.task and pat.search(self.task))

    def in_workspace(self, path: str) -> bool:
        if not self.cwd:
            return True
        p = os.path.realpath(os.path.expanduser(path if os.path.isabs(os.path.expanduser(path)) else os.path.join(self.cwd, path)))
        root = os.path.realpath(self.cwd)
        return p == root or p.startswith(root + os.sep)


class SessionStore:
    def __init__(self) -> None:
        self._s: dict[str, Session] = {}

    def get(self, sid: str, cwd: str | None = None) -> Session:
        s = self._s.get(sid)
        if s is None:
            s = self._s[sid] = Session(id=sid, cwd=cwd)
        elif cwd and not s.cwd:
            s.cwd = cwd
        return s

    def all(self) -> list[Session]:
        return list(self._s.values())

    def reset(self) -> None:
        self._s.clear()
