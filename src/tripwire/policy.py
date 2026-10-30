"""User-editable policy: plain YAML rules that override the scored decision.

Load order: built-in default.yaml, then ~/.tripwire/policy.yaml, then ./.tripwire.yaml.
Later files append rules; first matching rule wins.
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


class Policy(BaseModel):
    rules: list[Rule] = Field(default_factory=list)
    capabilities: dict[str, str] = Field(default_factory=dict)  # tool name -> capability override

    @classmethod
    def load(cls, extra: list[Path] | None = None) -> "Policy":
        p = cls()
        for path in [DEFAULT, Path.home() / ".tripwire" / "policy.yaml", Path.cwd() / ".tripwire.yaml", *(extra or [])]:
            if path.exists():
                data = yaml.safe_load(path.read_text()) or {}
                p.rules += [Rule(**r) for r in data.get("rules", [])]
                p.capabilities.update(data.get("capabilities", {}))
        return p

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
