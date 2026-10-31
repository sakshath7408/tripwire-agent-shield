"""The reproducible bench policy, without AgentDojo: the shell corpus needs it too, and AgentDojo is an optional
install (`uv sync --group bench`)."""

from __future__ import annotations

from pathlib import Path

import yaml

from tripwire.policy import DEFAULT, Policy, Profile, Rule

OVERRIDES = Path(__file__).parent / "agentdojo_capabilities.yaml"


def load_policy(overrides: bool) -> Policy:
    """Built-in default policy plus (optionally) the bench capability overrides. Ignores ~/.tripwire and
    ./.tripwire.yaml so the numbers are reproducible on any machine."""
    p = Policy()
    files = [DEFAULT] + ([OVERRIDES] if overrides else [])
    for f in files:
        data = yaml.safe_load(f.read_text()) or {}
        p.rules += [Rule(**r) for r in data.get("rules", [])]
        p.capabilities.update(data.get("capabilities") or {})
        p.profiles.update({k: Profile(**v) for k, v in (data.get("profiles") or {}).items()})
    return p
