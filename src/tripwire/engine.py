"""The decision engine: one Action in, one Verdict out.

Pipeline: classify -> capability checks -> shell AST -> provenance (taint) ->
policy overrides -> score -> optional isolated judge for the grey zone.
Deterministic first. The judge never sees untrusted data, so it cannot be injected.
"""

from __future__ import annotations

import json
import os
import re
import shlex
import time
from typing import Any, Callable

from .analyzers import paths
from .analyzers.secrets import find_secrets, redact
from .analyzers.shell import analyze_shell
from .taint import INJECTION_MARKERS, MAX_OBSERVE, canon, indicators
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
ARGV_KEYS = ("argv", "args", "arguments", "command", "cmd")
SINKS = {Capability.SEND, Capability.MONEY, Capability.EXEC, Capability.DELETE, Capability.WRITE, Capability.AGENT}
MAX_ARGS_CHARS = 200_000  # beyond this an action is too big to check fully, so a human decides
MAX_NEST = 32
# Any argument key that names a file or folder, e.g. "uri", "glob", "include", "paths", "src".
PATHISH_KEY = re.compile(r"(?:^|_)(path|file|dir|folder|uri|glob|include|target|dest|source|src|location)")
# Argument keys that say who a message or payment goes to.
RECIPIENT_KEY = re.compile(r"^(to|cc|bcc|recipients?|emails?|email_address(es)?|address(es)?|participants?|attendees?|"
                           r"invitees?|users?|members?|phone|phone_number|number|iban|account|payee|beneficiary|channel|reply_to)$", re.I)
# A picture or link inside a message body: the reader's mail app or chat loads it, sending the URL's data away.
RENDER_EXFIL = re.compile(r"!\[[^\]\n]{0,200}\]\(\s{0,4}(https?://[^\s)]{1,2048})|<img\b[^>]{0,300}?\bsrc\s{0,4}=\s{0,4}[\"']?(https?://[^\s\"'>]{1,2048})", re.I)


def _strings(value: Any, depth: int = 0) -> list[str]:
    if depth > MAX_NEST:
        raise ValueError("arguments nested too deeply")
    if isinstance(value, str):
        return [value]
    if isinstance(value, dict):
        return [str(k) for k in value] + [s for v in value.values() for s in _strings(v, depth + 1)]
    if isinstance(value, (list, tuple)):
        return [s for v in value for s in _strings(v, depth + 1)]
    return [str(value)] if value is not None else []


def _keyed(value: Any, key_re: re.Pattern[str], depth: int = 0, hit: bool = False) -> list[str]:
    """String values that sit under a key matching `key_re`, at any depth (e.g. {"files": [{"uri": ...}]})."""
    if depth > MAX_NEST:
        return []
    if isinstance(value, str):
        return [value] if hit else []
    if isinstance(value, dict):
        return [s for k, v in value.items() for s in _keyed(v, key_re, depth + 1, hit or bool(key_re.search(_key(k))))]
    if isinstance(value, (list, tuple)):
        return [s for v in value for s in _keyed(v, key_re, depth + 1, hit)]
    return []


def _key(k: Any) -> str:
    return re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", str(k)[:64]).lower().replace("-", "_")


def _command(args: dict[str, Any], blob: str) -> str:
    """The shell command an exec tool will run, however the tool spells it: a string, an argv list,
    or a program plus an args list ({"command": "curl", "args": [...]})."""
    base = _first(args, CMD_KEYS)
    for k in ARGV_KEYS:
        v = args.get(k)
        if isinstance(v, (list, tuple)) and v and all(isinstance(x, (str, int, float)) for x in v):
            argv = shlex.join(str(x) for x in v)
            return f"{base} {argv}" if base and k not in ("command", "cmd") else argv
    return base or blob


def _file_paths(args: dict[str, Any]) -> list[str]:
    out: list[str] = []
    for v in _keyed(args, PATHISH_KEY):
        if len(v) > 4096 or "\n" in v:
            continue
        if v.lower().startswith("file://"):
            v = v[7:]
        elif "://" in v:
            continue
        out.append(v)
    return out


def _source_label(s, tool: str) -> str:
    """Name the thing a tool output came from, e.g. "README.md" or a URL, from the last call to that tool."""
    for v in reversed(s.history):
        if v.action.tool != tool:
            continue
        target = _first(v.action.args, PATH_KEYS) or _first(v.action.args, ("url", "uri", "endpoint"))
        if not target:
            break
        cwd = s.cwd or ""
        if cwd and target.startswith(cwd.rstrip("/") + "/"):
            target = target[len(cwd.rstrip("/")) + 1:]
        if len(target) <= 80:
            return target
        break
    low = tool.lower()
    for words, name in (("inbox mail message", "an email"), ("web fetch url http browse", "a web page"),
                        ("file read cat", "a file"), ("search", "a search result")):
        if any(w in low for w in words.split()):
            return name
    return ""


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
        label = _source_label(s, obs.tool)
        s.taint.add_untrusted(obs.tool, obs.output, label)
        # Key material showing up in any output (Grep "API_KEY", an MCP file reader, a log) means the agent
        # now holds a secret, whichever tool fetched it.
        leaked = find_secrets(obs.output[:MAX_OBSERVE])
        if leaked:
            s.secrets_read.append(f"{label or obs.tool} ({leaked[0].replace('_', ' ')})")
        # An output arriving from a tool with a pending secret read means the human let it run.
        for vid, (tool, path) in list(s.pending_secrets.items()):
            if tool == obs.tool:
                s.secrets_read.append(path)
                del s.pending_secrets[vid]
        self._emit("observe", {"session_id": obs.session_id, "tool": obs.tool, "source": label or obs.tool,
                               "bytes": len(obs.output), "injection": bool(s.taint.injection_seen)})

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
            try:
                shown = _redacted(action)
            except Exception:  # args too odd to even redact (e.g. nested thousands deep): show none of them
                shown = action.model_copy(update={"args": {"_": "arguments not shown"}})
            v = Verdict(action=shown, capability=Capability.UNKNOWN, decision=Decision.BLOCK, risk=100,
                        summary="Blocked: Tripwire could not check this action, so it was stopped to be safe.",
                        findings=[Finding(rule="engine.error", severity=CRITICAL, category="general",
                                          message=f"Internal check failed ({type(e).__name__}); failing closed.")])
            self._emit("verdict", v.model_dump(mode="json"))
            return v

    def _evaluate(self, action: Action) -> Verdict:
        t0 = time.perf_counter()
        s = self.sessions.get(action.session_id, action.cwd)
        cap = _effective_cap(classify(action.tool, self.policy.capabilities), action.args or {})
        shell_state: dict = {}
        findings = self._analyze(action, cap, s, shell_state)

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
        if v.decision != Decision.BLOCK:
            # Files that now hold a copy of a secret stay secret for the rest of the session,
            # so `cp .env notes.txt` now and `git push` / `gh gist create notes.txt` later is still caught.
            s.tainted_files |= shell_state.get("tainted_files", set())
            for x in shell_state.get("staged_secrets", []):
                if x not in s.staged_secrets:
                    s.staged_secrets.append(x)
        if any(f.rule == "secrets.read" for f in findings):
            target = next((p for p in _file_paths(action.args or {}) if paths.is_secret(paths.expand(p, s.cwd))),
                          None) or _first(action.args, PATH_KEYS) or action.tool
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
    def _analyze(self, a: Action, cap: Capability, s: Session, shell_state: dict | None = None) -> list[Finding]:
        f: list[Finding] = []
        args = a.args or {}
        strings = _strings(args)
        size = sum(len(x) for x in strings)
        blob = "\n".join(strings)
        if size > MAX_ARGS_CHARS:
            blob = blob[:MAX_ARGS_CHARS]
            f.append(Finding(rule="input.too_big", severity=ASK_AT, category="general",
                             message=f"This action is too big to check fully ({size:,} characters), so it needs your OK."))
        file_paths = _file_paths(args)
        path = _first(args, PATH_KEYS) or (file_paths[0] if file_paths else None)
        injected = bool(s.taint.injection_seen)

        if cap == Capability.EXEC:
            cmd = _command(args, blob)
            shell = analyze_shell(cmd, s, shell_state)
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
                                     message=f"This exact command was written inside content the agent read ({src.where}), not by you.",
                                     evidence=src.snippet))

        for path in file_paths if cap != Capability.EXEC else []:
            full = paths.expand(path, s.cwd)
            if paths.is_secret(full) and not s.taint.is_trusted_value(path.lower()):
                sev = MEDIUM + 5 if cap == Capability.READ else HIGH
                f.append(Finding(rule="secrets.read" if cap == Capability.READ else "secrets.touch", severity=sev,
                                 category="secrets", message=f"Touches a credential file you did not mention: {path}"))
            elif os.path.normpath(full) in s.tainted_files and cap not in (Capability.WRITE, Capability.DELETE):
                f.append(Finding(rule="secrets.read", severity=MEDIUM + 5, category="secrets",
                                 message=f"Reads {path}, which holds a copy of a credential file."))
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

        if cap == Capability.WRITE and file_paths:
            f += _written_code_findings(file_paths[0], args, s, injected)

        if cap in (Capability.SEND, Capability.MONEY, Capability.FETCH, Capability.EXEC, Capability.AGENT):
            leaked = find_secrets(blob)
            if leaked:
                f.append(Finding(rule="secrets.egress", severity=CRITICAL, category="exfiltration",
                                 message=f"Sends secret material out ({', '.join(leaked)})."))
        if cap == Capability.WRITE and file_paths and shell_state is not None and find_secrets(blob):
            # Secret text written into a file: that file is now a secret too (a later push or upload leaks it).
            shell_state.setdefault("tainted_files", set()).update(
                os.path.normpath(paths.expand(p, s.cwd)) for p in file_paths)

        if cap in (Capability.SEND, Capability.MONEY, Capability.FETCH, Capability.AGENT) or (cap == Capability.WRITE and not path):
            tainted = s.taint.tainted_values(blob)
            if tainted:
                v, src = max(tainted, key=lambda t: t[1].injected)
                verb = _TARGET_VERB.get(cap, "Uses")
                if src.injected:
                    # The value sat next to hidden instructions: it is attacker-chosen.
                    sev = CRITICAL if cap == Capability.MONEY else HIGH + 5
                    msg = f"{verb} '{v}', taken from hidden instructions in {src.where}."
                elif cap in (Capability.WRITE, Capability.AGENT):
                    sev = 0
                elif cap == Capability.FETCH:
                    sev = MEDIUM if injected else LOW
                    msg = f"Visits '{v}', which came from content the agent read ({src.where}), not from you."
                elif s.intends(cap):
                    # User asked for this kind of action and the value came from a clean document they pointed at.
                    sev = MEDIUM if cap == Capability.MONEY else LOW
                    msg = f"Uses '{v}' from {src.where}. You asked for this, but check the details."
                else:
                    sev = CRITICAL if cap == Capability.MONEY else HIGH + 5
                    msg = f"{verb} '{v}', which came from {src.where}, not from you."
                if sev:
                    f.append(Finding(rule=f"taint.{cap.value}_target", severity=sev, category="injection",
                                     message=msg, evidence=src.snippet))
            f += self._recipients(args, cap, s, injected)
            tmpl = s.taint.template_source(blob) if cap in (Capability.SEND, Capability.FETCH) else None
            if tmpl:
                f.append(Finding(rule="taint.url_template", severity=HIGH + 5 if tmpl[1].injected else MEDIUM,
                                 category="exfiltration", evidence=tmpl[1].snippet,
                                 message=f"Fills in a web address from {tmpl[1].where} with extra data ({tmpl[0][:80]}), "
                                         "a common way to sneak data out."))
            if cap == Capability.FETCH and injected and not any(x.category in ("injection", "exfiltration") for x in f):
                novel = [u for u in indicators(blob).get("url", ()) if not s.taint.is_trusted_value(u)
                         and not s.taint.is_trusted_value(_url_host(u))]
                if novel:
                    f.append(Finding(rule="taint.fetch_after_injection", severity=MEDIUM, category="injection",
                                     message=f"Visits {novel[0][:80]}, which you never named, after hidden instructions were found."))
            if cap == Capability.SEND:
                for m in RENDER_EXFIL.finditer(blob):
                    u = canon(m.group(1) or m.group(2))
                    if ("?" in u or "=" in u) and not s.taint.is_trusted_value(u):
                        f.append(Finding(rule="exfil.render_link", severity=MEDIUM, category="exfiltration",
                                         message=f"The message embeds an image link that sends data to {_url_host(u)} "
                                                 "as soon as someone opens it.", evidence=u[:160]))
                        break
            if s.secrets_read and cap in (Capability.SEND, Capability.FETCH):
                f.append(Finding(rule="chain.secret_then_egress", severity=HIGH + 10 if cap == Capability.SEND else HIGH,
                                 category="exfiltration",
                                 message=f"Sends data out after reading secrets ({', '.join(s.secrets_read[-2:])})."))

        if cap == Capability.AGENT:
            m = INJECTION_MARKERS.search(blob)
            if m:
                f.append(Finding(rule="taint.agent_forwards_injection", severity=HIGH + 5, category="injection",
                                 message="Starts a helper agent with orders that look like hidden instructions, not your task.",
                                 evidence=m.group(0)))
            src = s.taint.command_from_data(blob) if injected else None
            if src and src.injected:
                f.append(Finding(rule="taint.agent_from_data", severity=HIGH, category="injection",
                                 message=f"Starts a helper agent with orders copied from {src.where}, not from you.",
                                 evidence=src.snippet))

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
                             message=f"Hidden instructions were found in {src.where} earlier in this session.",
                             evidence=src.snippet))

        if cap == Capability.UNKNOWN:  # fail closed: if we can't tell what a tool does, a human decides
            f.append(Finding(rule="classify.unknown", severity=ASK_AT, category="general",
                             message=f"Tripwire doesn't know what '{a.tool}' does, so it needs your OK."))
        return f

    def _recipients(self, args: dict, cap: Capability, s: Session, injected: bool) -> list[Finding]:
        """Who the message goes to. You named the people; anyone else needs a reason."""
        # Payments already always need a human (impact.money), so this is about messages.
        if cap != Capability.SEND:
            return []
        found = indicators("\n".join(_keyed(args, RECIPIENT_KEY)))
        if "iban" in found:  # long digit runs inside an IBAN are not phone numbers
            found["phone"] = {p for p in found.get("phone", ()) if not any(p in i for i in found["iban"])}
        out: list[Finding] = []
        for kind in ("email", "phone"):
            named = s.taint.trusted.get(kind)
            for v in sorted(found.get(kind, ())):
                if s.taint.is_trusted_value(v):
                    continue
                src = s.taint.untrusted.get(v)
                if src and src.injected:
                    continue  # already reported as an attacker value
                if named and src:
                    out.append(Finding(rule=f"intent.other_{kind}", severity=HIGH + 5, category="injection", evidence=src.snippet,
                                       message=f"You named {sorted(named)[0]}, but this goes to {v}, taken from {src.where}."))
                elif named:
                    out.append(Finding(rule=f"intent.other_{kind}", severity=MEDIUM, category="scope",
                                       message=f"You named {sorted(named)[0]}, but this also goes to {v}, which you never mentioned."))
                elif injected and not src:
                    out.append(Finding(rule=f"intent.unknown_{kind}", severity=MEDIUM, category="injection",
                                       message=f"Goes to {v}, which neither you nor anything the agent read mentioned, "
                                               "after hidden instructions were found."))
        return out

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


def _redact_value(v: Any, depth: int = 0) -> Any:
    if depth > MAX_NEST:
        return "…[too deep]"
    if isinstance(v, str):
        return redact(v)
    if isinstance(v, dict):
        return {str(k): _redact_value(x, depth + 1) for k, x in v.items()}
    if isinstance(v, (list, tuple)):
        return [_redact_value(x, depth + 1) for x in v]
    return v


def _redacted(a: Action) -> Action:
    # Redact each string on its own: redacting the JSON text could swallow a closing quote and crash.
    return a.model_copy(update={"args": _redact_value(a.args)})


CONTENT_KEY = re.compile(r"^(content|contents|new_string|new_source|text|code|source_code|body|data|edits|new_str|file_text|insert_text)$")
CODE_RUNNERS = {".py": "python", ".pyw": "python", ".js": "node", ".mjs": "node", ".cjs": "node", ".ts": "node",
                ".rb": "ruby", ".pl": "perl", ".php": "php", ".ps1": "pwsh"}
SHELL_EXT = (".sh", ".bash", ".zsh", ".command", ".envrc")
RUN_LINE = re.compile(r"^\s{0,40}-?\s{0,4}run:\s{0,4}\|?\s{0,4}(.{1,2000})$", re.M)


def _written_code_findings(path: str, args: dict, s: Session, injected: bool) -> list[Finding]:
    """A file the agent writes may run later (`make test`, `npm test`, `python x.py`, CI), out of sight of the
    shell check. So check what the file would do now, the same way a command typed in the shell is checked."""
    content = "\n".join(_keyed(args, CONTENT_KEY))[:MAX_ARGS_CHARS // 4]
    if not content.strip():
        return []
    low = path.lower()
    base = low.rsplit("/", 1)[-1]
    scripts: list[str] = []
    code_file = False
    if low.endswith(SHELL_EXT) or re.match(r"#!\s{0,4}\S{0,40}\b(ba|z|da|k)?sh\b", content):
        scripts.append(content)
    elif base in ("makefile", "gnumakefile", "justfile") or low.endswith(".mk"):
        scripts.append("\n".join(ln.strip().lstrip("@-") for ln in content.splitlines() if ln.startswith("\t")))
    elif base == "package.json":
        try:
            pkg = json.loads(content)
            scripts += [v for v in (pkg.get("scripts") or {}).values() if isinstance(v, str)]
        except (ValueError, AttributeError):
            scripts += re.findall(r'"(?:pre|post)?\w{1,40}"\s{0,4}:\s{0,4}"([^"\n]{1,2000})"', content)
    elif "/.github/workflows/" in low or low.startswith(".github/workflows/") or base in (".gitlab-ci.yml",):
        scripts += [m.group(1) for m in RUN_LINE.finditer(content)]
    else:
        ext = "." + base.rsplit(".", 1)[-1] if "." in base else ""
        runner = CODE_RUNNERS.get(ext)
        if runner:
            code_file = True
            scripts.append(f"{runner} -{'c' if runner in ('python', 'pwsh') else 'e'} {shlex.quote(content)}")
    out: list[Finding] = []
    floor = MEDIUM if injected else HIGH  # without hidden instructions around, only clearly dangerous code counts
    for script in scripts:
        for x in analyze_shell(script, s):
            if x.rule == "shell.pipe_to_shell" and code_file:
                continue  # `python -c` that fetches reads as "download and run"; a source file that calls an API is not that
            if x.severity >= floor and x.category != "obfuscation" or x.severity >= HIGH:
                out.append(Finding(rule="write.risky_code", category=x.category, evidence=x.evidence,
                                   severity=x.severity if injected else min(x.severity, MEDIUM + 5),
                                   message=f"The file it writes ({path.rsplit('/', 1)[-1]}) would run later and "
                                           f"{x.message[0].lower()}{x.message[1:]}"))
    return sorted(out, key=lambda x: -x.severity)[:3]


def _url_host(u: str) -> str:
    m = re.match(r"^[a-z][\w+.-]{0,20}://(?:[^@/\s]{0,256}@)?([^/:?#\s]{1,256})", u, re.I)
    return m.group(1).lower() if m else u


SQL_SHAPES = re.compile(r"(?:^|;)\s{0,40}(?:drop\s{1,10}(?:table|database|schema|index|view|collection)|truncate\b|"
                        r"delete\s{1,10}from|alter\s{1,10}table|update\s{1,10}[\w.\"`\[\]]{1,128}\s{1,10}set\b|"
                        r"insert\s{1,10}into|create\s{1,10}(?:table|database|user|role)|grant\s|replace\s{1,10}into)",
                        re.I | re.M)
SQL_KEY = re.compile(r"(?:^|_)(sql|query|statement|stmt)s?$")


def _effective_cap(cap: Capability, args: dict) -> Capability:
    """A tool named like a reader ("query", "run_report") can still write: judge SQL by what it says."""
    if cap not in (Capability.READ, Capability.FETCH, Capability.UNKNOWN) and \
            not (cap == Capability.EXEC and not _first(args, CMD_KEYS)):
        return cap
    for q in _keyed(args, SQL_KEY):
        m = SQL_SHAPES.search(q[:20_000])
        if m:
            word = m.group(0).strip(" ;\n").split()[0].lower()
            return Capability.DELETE if word in ("drop", "truncate", "delete") else Capability.WRITE
    return cap


_TARGET_VERB = {Capability.SEND: "Sends to", Capability.MONEY: "Pays", Capability.FETCH: "Visits",
                Capability.WRITE: "Writes", Capability.AGENT: "Hands a sub-agent"}


def _summary(d: Decision, findings: list[Finding], cap: Capability) -> str:
    if not findings:
        return f"Looks like a normal {cap.value} action."
    core = [x for x in findings if x.rule != "taint.injection_context"] or findings
    # On a tie, the role rule reads clearest ("the inbox assistant may not move money").
    top = max(core, key=lambda x: (x.severity, x.category == "permission"))
    lead = {Decision.BLOCK: "Blocked", Decision.ASK: "Needs your OK", Decision.ALLOW: "Allowed"}[d]
    return f"{lead}: {top.message}"
