"""User-editable policy: plain YAML rules that override the scored decision.

Load order: built-in default.yaml, then ~/.tripwire/policy.yaml, then ./.tripwire.yaml.
Later files append rules; first matching rule wins.

./.tripwire.yaml lives in the project, and a project can come from anyone (a cloned repo, a poisoned PR).
So it may only make Tripwire stricter: its allow rules, capability remaps and changes to existing
profiles are ignored. Loosening belongs in ~/.tripwire/policy.yaml, which only you write.
"""

from __future__ import annotations

import fnmatch
import json
import re
from pathlib import Path

import yaml
from pydantic import BaseModel, Field

from .models import Action, Capability

DEFAULT = Path(__file__).with_name("default_policy.yaml")


class Rule(BaseModel):
    id: str
    decision: str  # allow | ask | block
    tool: str = "*"  # glob on tool name
    capability: str | None = None
    match: str | None = None  # regex over the JSON of the args
    reason: str | None = None


class Profile(BaseModel):
    """What one agent role may do. Entries are tool-name globs or `cap:<capability>`.

    deny beats ask beats allow. Anything not listed is outside the profile and is blocked
    (fail closed): an agent asking for a tool it was never given is the clearest sign it was hijacked.
    """

    description: str = ""
    allow: list[str] = Field(default_factory=list)
    ask: list[str] = Field(default_factory=list)
    deny: list[str] = Field(default_factory=list)

    def check(self, tool: str, cap: Capability) -> str:
        def hit(entries: list[str]) -> bool:
            return any((e.startswith("cap:") and e[4:] == cap.value) or fnmatch.fnmatch(tool, e) for e in entries)
        if hit(self.deny):
            return "deny"
        if hit(self.ask):
            return "ask"
        if hit(self.allow):
            return "allow"
        return "outside"


class Policy(BaseModel):
    rules: list[Rule] = Field(default_factory=list)
    capabilities: dict[str, str] = Field(default_factory=dict)  # tool name -> capability override
    profiles: dict[str, Profile] = Field(default_factory=dict)

    ignored: list[str] = Field(default_factory=list)  # project-file entries dropped because they would loosen

    @classmethod
    def load(cls, extra: list[Path] | None = None) -> "Policy":
        p = cls()
        project = Path.cwd() / ".tripwire.yaml"
        for path in [DEFAULT, Path.home() / ".tripwire" / "policy.yaml", project, *(extra or [])]:
            if path.exists():
                data = yaml.safe_load(path.read_text()) or {}
                p.add(data, tighten_only=path == project and path not in (extra or []))
        return p

    def add(self, data: dict, tighten_only: bool = False) -> None:
        rules = [Rule(**r) for r in data.get("rules") or []]
        caps = dict(data.get("capabilities") or {})
        profiles = {k: Profile(**v) for k, v in (data.get("profiles") or {}).items()}
        if tighten_only:
            self.ignored += [f"rule {r.id} ({r.decision})" for r in rules if r.decision != "block"]
            rules = [r for r in rules if r.decision == "block"]
            # A project file must not relabel a tool as harmless; it may only flag a tool as unknown.
            self.ignored += [f"capability {k}: {v}" for k, v in caps.items() if v != Capability.UNKNOWN.value]
            caps = {k: v for k, v in caps.items() if v == Capability.UNKNOWN.value}
            self.ignored += [f"profile {k}" for k in profiles if k in self.profiles]
            profiles = {k: v for k, v in profiles.items() if k not in self.profiles}
        self.rules += rules
        self.capabilities.update(caps)
        self.profiles.update(profiles)

    def match(self, action: Action, cap: Capability) -> Rule | None:
        blob = json.dumps(action.args)
        for r in self.rules:
            if not fnmatch.fnmatch(action.tool, r.tool):
                continue
            if r.capability and r.capability != cap.value:
                continue
            if r.match and not re.search(r.match, blob, re.I):
                continue
            return r
        return None
