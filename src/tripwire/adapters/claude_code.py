"""Claude Code hooks adapter.

Claude Code runs `tripwire hook <Event>` with one JSON object on stdin
(docs: https://code.claude.com/docs/en/hooks). We forward it to the local daemon:

  UserPromptSubmit -> POST /v1/task      (the only trusted text)
  PostToolUse      -> POST /v1/observe   (tool output, untrusted)
  PreToolUse       -> POST /v1/evaluate  (verdict -> permissionDecision)

Decision mapping for PreToolUse, and why:
  block -> "deny" with the plain-English summary as permissionDecisionReason. For "deny"
           Claude Code shows the reason to Claude, so the agent learns why and can change course.
  ask   -> "ask". Claude Code shows the reason in its own permission prompt. In `claude -p`
           runs nobody can answer, so Claude Code denies and Claude reads the reason.
  allow -> NO decision (exit 0, empty stdout). Per the docs, "allow" skips Claude Code's own
           permission prompt. Tripwire is an extra layer, not a replacement for the user's own
           permission rules, so by default we never widen what Claude Code would allow.
           Set TRIPWIRE_AUTO_APPROVE=1 to return "allow" for verdicts that are allow with risk 0.

Fail closed: on PreToolUse, any failure (daemon down, bad response, bad stdin, crash) denies.
A hook that exits with a code other than 0/2 is a NON-blocking error in Claude Code, so an
uncaught crash would let the tool run. Every path below therefore ends in an explicit deny,
and the last-resort handler uses exit 2 (blocking error, stderr shown to Claude).
TRIPWIRE_FAIL_OPEN=1 turns daemon-unreachable into "no decision" (for people who opt in).

This module is on the hot path of every tool call: stdlib only, no heavy imports.
"""

from __future__ import annotations

import json
import os
import shlex
import sys
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, TextIO

DEFAULT_URL = "http://127.0.0.1:7777"
TIMEOUT = 2.0
MAX_OBSERVE = 200_000  # characters of tool output sent to the daemon
NOT_RUNNING = "Tripwire is not running, so this tool call was blocked. Start it with `tripwire serve`."
EVENTS = ("UserPromptSubmit", "PreToolUse", "PostToolUse")


class DaemonDown(Exception):
    pass


def base_url() -> str:
    return os.environ.get("TRIPWIRE_URL", DEFAULT_URL).rstrip("/")


def _truthy(name: str) -> bool:
    return os.environ.get(name, "").strip().lower() in ("1", "true", "yes", "on")


def post(path: str, body: dict, timeout: float = TIMEOUT) -> dict:
    req = urllib.request.Request(base_url() + path, data=json.dumps(body).encode(),
                                 headers={"Content-Type": "application/json"}, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.loads(r.read() or b"{}")
    except urllib.error.HTTPError as e:  # daemon answered but refused: not "down", still an error
        raise RuntimeError(f"Tripwire daemon returned HTTP {e.code} for {path}") from e
    except (urllib.error.URLError, OSError, TimeoutError) as e:
        raise DaemonDown(str(e)) from e


def flatten(value: Any, limit: int = MAX_OBSERVE) -> str:
    """Tool responses are tool-specific JSON. Pull out every string (stdout, file content...)
    as real text, not JSON-escaped, so the taint checks can match exact commands and URLs."""
    out: list[str] = []
    size = 0

    def walk(v: Any) -> None:
        nonlocal size
        if size >= limit:
            return
        if isinstance(v, str):
            s = v
        elif isinstance(v, dict):
            for x in v.values():
                walk(x)
            return
        elif isinstance(v, (list, tuple)):
            for x in v:
                walk(x)
            return
        elif v is None or isinstance(v, bool):
            return
        else:
            s = str(v)
        if s:
            out.append(s)
            size += len(s) + 1

    walk(value)
    return "\n".join(out)[:limit]


def _pre_output(decision: str, reason: str) -> str:
    return json.dumps({"hookSpecificOutput": {"hookEventName": "PreToolUse",
                                              "permissionDecision": decision,
                                              "permissionDecisionReason": reason}})


def agent_of(data: dict, session: str) -> tuple[str, str | None]:
    """(agent, parent) for the audit trail. Hooks that fire inside a sub-agent (Task/Agent tool) carry
    `agent_id` and `agent_type`; sub-agents share the session id, so their parent is the main agent."""
    main = f"claude-code:{session}"
    aid = str(data.get("agent_id") or "").strip()
    if not aid:
        return main, None
    atype = str(data.get("agent_type") or "subagent").strip() or "subagent"
    return f"{main}/{atype}:{aid[:12]}", main


def handle(event: str, data: dict) -> tuple[int, str]:
    """Pure-ish core: returns (exit_code, stdout). Raises on failure; caller decides fail mode."""
    session = str(data.get("session_id") or "claude-code")
    cwd = data.get("cwd")
    agent, parent = agent_of(data, session)

    if event == "UserPromptSubmit":
        post("/v1/task", {"session_id": session, "prompt": str(data.get("prompt") or ""), "cwd": cwd,
                          "agent": agent, "parent": parent})
        return 0, ""

    if event == "PostToolUse":
        post("/v1/observe", {"session_id": session, "tool": str(data.get("tool_name") or "unknown"),
                             "output": flatten(data.get("tool_response")), "source": "claude-code",
                             "agent": agent, "parent": parent})
        return 0, ""

    if event == "PreToolUse":
        tool = data.get("tool_name")
        if not tool:
            return 0, _pre_output("deny", "Tripwire could not read which tool this is, so it was blocked.")
        tool_input = data.get("tool_input")
        action = {"session_id": session, "tool": str(tool), "cwd": cwd, "source": "claude-code",
                  "agent": agent, "parent": parent,
                  "args": tool_input if isinstance(tool_input, dict) else {"input": tool_input}}
        wait = 0.0
        try:
            wait = max(0.0, min(240.0, float(os.environ.get("TRIPWIRE_ASK_WAIT", "0") or 0)))
        except ValueError:
            pass
        path = f"/v1/evaluate?wait={wait:g}" if wait else "/v1/evaluate"
        v = post(path, action, timeout=TIMEOUT + wait)
        decision, summary = v.get("decision"), str(v.get("summary") or "")
        for lead in ("Blocked: ", "Needs your OK: ", "Allowed: "):
            summary = summary.removeprefix(lead)
        risk = v.get("risk")
        if decision == "block":
            return 0, _pre_output("deny", f"Tripwire blocked this: {summary}")
        if decision == "ask":
            return 0, _pre_output("ask", f"Tripwire wants your OK: {summary}")
        if decision == "allow":
            if risk == 0 and _truthy("TRIPWIRE_AUTO_APPROVE"):
                return 0, _pre_output("allow", "Tripwire: no risk found.")
            return 0, ""  # normal Claude Code permission flow applies
        return 0, _pre_output("deny", "Tripwire got an answer it did not understand, so it blocked this to be safe.")

    return 0, ""  # unknown event: do nothing


def run(event: str, stdin: TextIO, stdout: TextIO, stderr: TextIO) -> int:
    pre = event == "PreToolUse"
    try:
        raw = stdin.read()
        data = json.loads(raw) if raw.strip() else {}
        if not isinstance(data, dict):
            raise ValueError("hook input is not a JSON object")
        code, out = handle(event, data)
    except DaemonDown:
        if not pre:
            # Nothing to block here; the next PreToolUse will deny. Tell the user once.
            stderr.write("Tripwire is not running (start it with `tripwire serve`).\n")
            return 0
        if _truthy("TRIPWIRE_FAIL_OPEN"):
            stderr.write("Tripwire is not running; TRIPWIRE_FAIL_OPEN=1 so the call goes through.\n")
            return 0
        code, out = 0, _pre_output("deny", NOT_RUNNING)
    except Exception as e:  # noqa: BLE001 - any failure must deny on PreToolUse
        if not pre:
            stderr.write(f"Tripwire hook error: {e}\n")
            return 0
        code, out = 0, _pre_output("deny", f"Tripwire hit an error checking this call ({type(e).__name__}), so it was blocked to be safe.")
    try:
        if out:
            stdout.write(out + "\n")
            stdout.flush()
        return code
    except Exception:  # could not even print: exit 2 is a hard block in Claude Code
        if pre:
            try:
                stderr.write("Tripwire hook failed, so this tool call was blocked.\n")
            except Exception:
                pass
            return 2
        return 0


def hook_main(event: str) -> int:
    try:
        return run(event, sys.stdin, sys.stdout, sys.stderr)
    except BaseException:  # last resort: never let PreToolUse fall through as a non-blocking error
        if event == "PreToolUse":
            try:
                sys.stderr.write("Tripwire hook crashed, so this tool call was blocked.\n")
            except Exception:
                pass
            return 2
        return 0


# ---- installer ---------------------------------------------------------------

def hook_command() -> str:
    """Absolute command Claude Code should run. Prefer the venv's console script (fast, no
    `uv run` sync step on every tool call); fall back to `python -m tripwire.cli`."""
    exe = Path(sys.executable)
    script = exe.parent / "tripwire"
    if script.exists() and os.access(script, os.X_OK):
        return shlex.quote(str(script))
    return f"{shlex.quote(str(exe))} -m tripwire.cli"


def settings_path(project: str | None, user: bool) -> Path:
    if user:
        return Path.home() / ".claude" / "settings.json"
    return Path(project or os.getcwd()).expanduser().resolve() / ".claude" / "settings.json"


def _is_ours(h: Any) -> bool:
    cmd = h.get("command", "") if isinstance(h, dict) else ""
    return isinstance(cmd, str) and "tripwire" in cmd and " hook " in f" {cmd} " and any(cmd.rstrip().endswith(e) for e in EVENTS)


def _strip(settings: dict) -> dict:
    hooks = settings.get("hooks")
    if not isinstance(hooks, dict):
        return settings
    for event in list(hooks):
        groups = hooks[event]
        if not isinstance(groups, list):
            continue
        kept = []
        for g in groups:
            if isinstance(g, dict) and isinstance(g.get("hooks"), list):
                inner = [h for h in g["hooks"] if not _is_ours(h)]
                if not inner:
                    continue
                g = {**g, "hooks": inner}
            kept.append(g)
        if kept:
            hooks[event] = kept
        else:
            del hooks[event]
    if not hooks:
        del settings["hooks"]
    return settings


def merge(settings: dict, command: str) -> dict:
    """Add Tripwire's hooks to a settings dict, keeping everything else. Idempotent."""
    settings = _strip(settings)
    hooks = settings.setdefault("hooks", {})
    # PreToolUse timeout is generous on purpose: if a hook times out Claude Code treats it as a
    # non-blocking error and the tool RUNS. Our own HTTP timeouts are short (2 s).
    plan = {
        "UserPromptSubmit": (None, 10),
        "PreToolUse": ("*", 300),
        "PostToolUse": ("*", 15),
    }
    for event, (matcher, timeout) in plan.items():
        group: dict[str, Any] = {}
        if matcher is not None:
            group["matcher"] = matcher
        group["hooks"] = [{"type": "command", "command": f"{command} hook {event}", "timeout": timeout}]
        hooks.setdefault(event, []).append(group)
    return settings


def _load(path: Path) -> dict:
    if not path.exists() or not path.read_text().strip():
        return {}
    data = json.loads(path.read_text())
    if not isinstance(data, dict):
        raise ValueError(f"{path} is not a JSON object")
    return data


def _save(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".json.tripwire-tmp")
    tmp.write_text(json.dumps(data, indent=2) + "\n")
    os.replace(tmp, path)


def install(project: str | None = None, user: bool = False, command: str | None = None) -> Path:
    path = settings_path(project, user)
    _save(path, merge(_load(path), command or hook_command()))
    return path


def uninstall(project: str | None = None, user: bool = False) -> Path:
    path = settings_path(project, user)
    if path.exists():
        _save(path, _strip(_load(path)))
    return path
