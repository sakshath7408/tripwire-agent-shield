"""The decision engine: one Action in, one Verdict out.

Pipeline: classify -> capability checks -> shell AST -> provenance (taint) ->
policy overrides -> score -> optional isolated judge for the grey zone.
Deterministic first. The judge never sees untrusted data, so it cannot be injected.
"""

from __future__ import annotations

import json
import re
import time
from typing import Any, Callable

from .analyzers import paths
from .analyzers.secrets import find_secrets, redact
from .analyzers.shell import analyze_shell
from .classify import classify
from .models import (
    CRITICAL, HIGH, LOW, MEDIUM, Action, Capability, Decision, Finding, Observation, TaskSpec, Verdict,
)
from .policy import Policy
from .session import Session, SessionStore

BLOCK_AT = HIGH  # 80
ASK_AT = MEDIUM  # 50

PATH_KEYS = ("file_path", "path", "notebook_path", "filename", "file", "target", "destination", "source")
CMD_KEYS = ("command", "cmd", "script", "code")
SINKS = {Capability.SEND, Capability.MONEY, Capability.EXEC, Capability.DELETE, Capability.WRITE}


def _strings(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, dict):
        return [s for v in value.values() for s in _strings(v)]
    if isinstance(value, (list, tuple)):
        return [s for v in value for s in _strings(v)]
    return [str(value)] if value is not None else []


def _first(args: dict[str, Any], keys: tuple[str, ...]) -> str | None:
    for k in keys:
        if isinstance(args.get(k), str):
            return args[k]
    return None


class Engine:
    def __init__(self, policy: Policy | None = None, judge: Callable[[Session, Action, Verdict], dict] | None = None) -> None:
        self.sessions = SessionStore()
        self.policy = policy or Policy.load()
        self.judge = judge
        self.listeners: list[Callable[[str, dict], None]] = []

    # ---- inputs -------------------------------------------------------------
    def set_task(self, spec: TaskSpec) -> None:
        self.sessions.get(spec.session_id, spec.cwd).set_task(spec.prompt, spec.cwd, spec.profile)
        self._emit("task", spec.model_dump())

    def observe(self, obs: Observation) -> None:
        s = self.sessions.get(obs.session_id)
        s.taint.add_untrusted(obs.tool, obs.output)
        # An output arriving from a tool with a pending secret read means the human let it run.
        for vid, (tool, path) in list(s.pending_secrets.items()):
            if tool == obs.tool:
                s.secrets_read.append(path)
                del s.pending_secrets[vid]
        self._emit("observe", {"session_id": obs.session_id, "tool": obs.tool, "bytes": len(obs.output),
                               "injection": bool(s.taint.injection_seen)})

    def resolve(self, verdict_id: str, decision: Decision) -> None:
        """A human (or a timeout) answered an ASK."""
        for s in self.sessions.all():
            hit = s.pending_secrets.pop(verdict_id, None)
            if hit and decision == Decision.ALLOW:
                s.secrets_read.append(hit[1])

    def evaluate(self, action: Action) -> Verdict:
        try:
            return self._evaluate(action)
        except Exception as e:  # fail closed: an engine bug must never let an action through
            v = Verdict(action=_redacted(action), capability=Capability.UNKNOWN, decision=Decision.BLOCK, risk=100,
                        summary="Blocked: Tripwire could not check this action, so it was stopped to be safe.",
                        findings=[Finding(rule="engine.error", severity=CRITICAL, category="general",
                                          message=f"Internal check failed ({type(e).__name__}); failing closed.")])
            self._emit("verdict", v.model_dump(mode="json"))
            return v

    def _evaluate(self, action: Action) -> Verdict:
        t0 = time.perf_counter()
        s = self.sessions.get(action.session_id, action.cwd)
        cap = classify(action.tool, self.policy.capabilities)
        findings = self._analyze(action, cap, s)

        findings += self._profile(action, cap, s)
        if cap == Capability.MONEY and not any(f.severity >= ASK_AT for f in findings):
            findings.append(Finding(rule="impact.money", severity=ASK_AT, category="scope",
                                    message="Moving money always needs a human to confirm."))

        risk = max((f.severity for f in findings), default=0)
        risk = min(100, risk + 5 * max(0, sum(f.severity >= HIGH for f in findings) - 1))
        decision = Decision.BLOCK if risk >= BLOCK_AT else Decision.ASK if risk >= ASK_AT else Decision.ALLOW

        override = self.policy.match(action, cap)
        if override:
            decision = Decision(override.decision)
            findings.append(Finding(rule=f"policy.{override.id}", severity=risk, category="policy",
                                    message=override.reason or f"Policy rule '{override.id}' says {override.decision}."))

        v = Verdict(action=_redacted(action), capability=cap, decision=decision, risk=risk, findings=findings,
                    summary=_summary(decision, findings, cap))

        if self.judge and decision == Decision.ASK and not override:
            try:
                j = self.judge(s, action, v)
                v.judge = j
                if j.get("decision") in ("allow", "block"):
                    v.decision = Decision(j["decision"])
                    v.summary = f"{v.summary} Judge: {j.get('reason', '')}".strip()
            except Exception as e:  # judge is optional; a broken judge must never weaken the verdict
                v.judge = {"error": str(e)}

        v.elapsed_ms = round((time.perf_counter() - t0) * 1000, 2)
        if any(f.rule == "secrets.read" for f in findings):
            target = _first(action.args, PATH_KEYS) or action.tool
            if v.decision == Decision.ALLOW:
                s.secrets_read.append(target)
            elif v.decision == Decision.ASK:  # not read yet: a denied read must not taint the rest of the session
                s.pending_secrets[v.id] = (action.tool, target)
        s.history.append(v)
        self._emit("verdict", v.model_dump(mode="json"))
        return v

    # ---- permission profile ------------------------------------------------
    def _profile(self, a: Action, cap: Capability, s: Session) -> list[Finding]:
        if not s.profile:
            return []
        prof = self.policy.profiles.get(s.profile)
        if prof is None:
            return [Finding(rule="profile.unknown", severity=CRITICAL, category="scope",
                            message=f"Permission profile '{s.profile}' does not exist, so nothing is allowed.")]
        verdict = prof.check(a.tool, cap)
        if verdict == "deny":
            return [Finding(rule="profile.denied", severity=CRITICAL, category="permission",
                            message=f"The '{s.profile}' role is not allowed to {_verb(cap)} ({a.tool}).")]
        if verdict == "outside":
            return [Finding(rule="profile.outside", severity=HIGH + 5, category="permission",
                            message=f"'{a.tool}' is not one of the tools the '{s.profile}' role was given.")]
        if verdict == "ask":
            return [Finding(rule="profile.ask", severity=ASK_AT, category="permission",
                            message=f"The '{s.profile}' role needs your OK to {_verb(cap)}.")]
        return []

    # ---- analysis -----------------------------------------------------------
    def _analyze(self, a: Action, cap: Capability, s: Session) -> list[Finding]:
        f: list[Finding] = []
        args = a.args or {}
        blob = "\n".join(_strings(args))
        path = _first(args, PATH_KEYS)
        injected = bool(s.taint.injection_seen)

        if cap == Capability.EXEC:
            cmd = _first(args, CMD_KEYS) or blob
            shell = analyze_shell(cmd, s)
            f += shell
            src = s.taint.command_from_data(cmd)
            if src:
                # READMEs legitimately say "run npm test". Copying a command from data is only
                # dangerous when the command itself is risky, or is unfamiliar after an injection.
                risky = any(x.severity >= MEDIUM for x in shell)
                if risky:
                    sev = HIGH + 5
                elif _is_routine(cmd):
                    sev = 0
                else:
                    sev = MEDIUM if s.taint.injection_seen else LOW
                if sev:
                    f.append(Finding(rule="taint.command_from_data", severity=sev, category="injection",
                                     message=f"This exact command was written inside content the agent read ({src.tool}), not by you.",
                                     evidence=src.snippet))

        if path:
            full = paths.expand(path, s.cwd)
            if paths.is_secret(full) and not s.taint.is_trusted_value(path.lower()):
                sev = MEDIUM + 5 if cap == Capability.READ else HIGH
                f.append(Finding(rule="secrets.read" if cap == Capability.READ else "secrets.touch", severity=sev,
                                 category="secrets", message=f"Touches a credential file you did not mention: {path}"))
            if cap in (Capability.WRITE, Capability.DELETE):
                if paths.is_persistence(full):
                    f.append(Finding(rule="scope.persistence", severity=HIGH + 5, category="persistence",
                                     message=f"Changes a file that controls what runs on your machine later: {path}"))
                elif paths.is_system(full):
                    f.append(Finding(rule="scope.system_write", severity=HIGH, category="scope",
                                     message=f"Writes to a system folder: {path}"))
                elif not s.in_workspace(full):
                    f.append(Finding(rule="scope.outside_workspace", severity=MEDIUM, category="scope",
                                     message=f"Writes outside the project folder: {path}"))

        if cap in (Capability.SEND, Capability.MONEY, Capability.FETCH, Capability.EXEC, Capability.WRITE):
            leaked = find_secrets(blob) if cap != Capability.WRITE or not s.in_workspace(paths.expand(path or ".", s.cwd)) else []
            if leaked and cap != Capability.WRITE:
                f.append(Finding(rule="secrets.egress", severity=CRITICAL, category="exfiltration",
                                 message=f"Sends secret material out ({', '.join(leaked)})."))

        if cap in (Capability.SEND, Capability.MONEY, Capability.FETCH) or (cap == Capability.WRITE and not path):
            tainted = s.taint.tainted_values(blob)
            if tainted:
                v, src = max(tainted, key=lambda t: t[1].injected)
                if src.injected:
                    # The value sat next to hidden instructions: it is attacker-chosen.
                    sev = CRITICAL if cap == Capability.MONEY else HIGH + 5
                    msg = f"Uses '{v}', which came from the same content as hidden instructions ({src.tool})."
                elif cap == Capability.WRITE:
                    sev = 0
                elif cap == Capability.FETCH:
                    sev = MEDIUM if injected else LOW
                    msg = f"Visits '{v}', which came from content the agent read ({src.tool}), not from you."
                elif s.intends(cap):
                    # User asked for this kind of action and the value came from a clean document they pointed at.
                    sev = MEDIUM if cap == Capability.MONEY else LOW
                    msg = f"Uses '{v}' from {src.tool}. You asked for this, but check the details."
                else:
                    sev = CRITICAL if cap == Capability.MONEY else HIGH + 5
                    msg = f"Uses '{v}', which came from content the agent read ({src.tool}), not from you."
                if sev:
                    f.append(Finding(rule=f"taint.{cap.value}_target", severity=sev, category="injection",
                                     message=msg, evidence=src.snippet))
            if s.secrets_read and cap in (Capability.SEND, Capability.FETCH):
                f.append(Finding(rule="chain.secret_then_egress", severity=HIGH + 10 if cap == Capability.SEND else HIGH,
                                 category="exfiltration",
                                 message=f"Sends data out after reading secrets ({', '.join(s.secrets_read[-2:])})."))

        if cap == Capability.CREDENTIAL:
            f.append(Finding(rule="impact.credential", severity=ASK_AT if s.intends(cap) else HIGH, category="secrets",
                             message="Changes a password, key or login setting." if s.intends(cap)
                             else "Tries to change a password or login setting you never asked about."))

        if cap in (Capability.SEND, Capability.MONEY, Capability.DELETE) and s.task and not s.intends(cap):
            sev = {Capability.MONEY: HIGH, Capability.DELETE: MEDIUM + 10, Capability.SEND: MEDIUM}[cap]
            f.append(Finding(rule=f"intent.unrequested_{cap.value}", severity=sev, category="scope",
                             message=f"Your task never asked to {_verb(cap)}."))

        if injected and f and (cap in SINKS or any(x.category == "secrets" for x in f)):
            src = s.taint.injection_seen[-1]
            f.append(Finding(rule="taint.injection_context", severity=max(x.severity for x in f) + 5, category="injection",
                             message=f"Hidden instructions were found in {src.tool} earlier in this session.",
                             evidence=src.snippet))

        if cap == Capability.UNKNOWN:  # fail closed: if we can't tell what a tool does, a human decides
            f.append(Finding(rule="classify.unknown", severity=ASK_AT, category="general",
                             message=f"Tripwire doesn't know what '{a.tool}' does, so it needs your OK."))
        return f

    # ---- events -------------------------------------------------------------
    def _emit(self, kind: str, data: dict) -> None:
        for fn in list(self.listeners):
            try:
                fn(kind, data)
            except Exception:
                pass


ROUTINE = re.compile(
    r"^\s*(npm|pnpm|yarn|bun)\s+(test|run (test|lint|build|dev|typecheck)|install|ci)\b|^\s*(pytest|tox|make|cargo (test|build|check)|"
    r"go (test|build|vet)|python -m (pytest|unittest)|uv (run pytest|sync)|git (status|diff|log|show)|ls|pwd|tsc|eslint|ruff)\b")


def _is_routine(cmd: str) -> bool:
    return bool(ROUTINE.match(cmd)) and not re.search(r"[|;&`$><]", cmd)


def _verb(cap: Capability) -> str:
    return {Capability.SEND: "send messages", Capability.MONEY: "move money", Capability.DELETE: "delete anything",
            Capability.EXEC: "run commands", Capability.WRITE: "change files", Capability.READ: "read files",
            Capability.FETCH: "fetch outside content", Capability.AGENT: "start other agents",
            Capability.CREDENTIAL: "change passwords or keys"}.get(cap, "use this tool")


def _redacted(a: Action) -> Action:
    return a.model_copy(update={"args": json.loads(redact(json.dumps(a.args)))})


def _summary(d: Decision, findings: list[Finding], cap: Capability) -> str:
    if not findings:
        return f"Looks like a normal {cap.value} action."
    core = [x for x in findings if x.rule != "taint.injection_context"] or findings
    # On a tie, the role rule reads clearest ("the inbox assistant may not move money").
    top = max(core, key=lambda x: (x.severity, x.category == "permission"))
    lead = {Decision.BLOCK: "Blocked", Decision.ASK: "Needs your OK", Decision.ALLOW: "Allowed"}[d]
    return f"{lead}: {top.message}"
