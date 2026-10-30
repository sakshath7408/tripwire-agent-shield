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

    def set_task(self, prompt: str, cwd: str | None = None, profile: str | None = None) -> None:
        if profile:
            self.profile = profile
        self.task = (self.task + "\n" + prompt).strip()
        self.taint.add_trusted(prompt)
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
