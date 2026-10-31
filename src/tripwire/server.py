"""Local daemon. Binds to 127.0.0.1 only. Adapters (Claude Code hook, MCP proxy, SDK) call it.

POST /v1/task       trusted user prompt for a session
POST /v1/observe    untrusted tool output
POST /v1/evaluate   action -> verdict   (?wait=N holds an ASK up to N s for a human answer)
POST /v1/verdicts/{id}/resolve {"decision": "allow"|"block", "remember": null|"session"|"always"}
GET/PUT /v1/settings {"autonomy": "strict"|"balanced"|"autonomous"}   (persisted in ~/.tripwire/settings.json)
GET  /v1/rules      learned rules        DELETE /v1/rules/{id}  forget one
GET  /v1/verdicts   recent verdicts      GET /v1/stats   counts
GET  /v1/audit      audited verdicts (?agent= ?trace= ?session_id=; ?format=tree for agent trees)
GET  /v1/audit/events  raw chained records    GET /v1/audit/verify  walk the hash chain
GET  /v1/audit/tamper-drill  flip a BLOCK to ALLOW in an in-memory copy and show the check catch it
GET  /v1/events     server-sent events (task | observe | verdict | resolved)
POST /v1/pair {"code"}  swap a one-time pairing code for the dashboard cookie
POST /v1/pair/request   `tripwire open` asks to pair; a person approves it (serve's terminal or a paired dashboard)
POST /v1/pair/poll      `tripwire open` collects its code once approved
GET  /v1/pair/requests  POST /v1/pair/requests/{id} {"decision"}   pending requests, for a paired dashboard
POST /v1/pair/new       mint a code: hardened console key or a --demo-admin daemon only
GET  /              dashboard

Credentials (see auth.py): the hook token (X-Tripwire-Token) may only POST /v1/task, /v1/observe and /v1/evaluate.
Everything else, reads included, needs the paired dashboard's cookie. No credential the agent can read on disk
answers an ASK, changes settings or pairs a browser: there is no admin key file, and the daemon stores only digests
of dashboard cookies. /v1/pair*, /healthz, / and /static need no credential (pairing still needs a person). Every
request must name 127.0.0.1/localhost as its Host (stops DNS rebinding).

Who did it: the audit log records the credential used: "hook-token", "dashboard", "console" or "demo-admin". A
session that saw hidden instructions keeps that memory through resets and restarts; while any live session has seen
them, nobody can loosen autonomy and a new browser needs a person to approve it through `tripwire open`.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import os
import threading
import time
from collections import Counter, deque
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from typing import Literal

from pydantic import BaseModel
from sse_starlette.sse import EventSourceResponse

from . import audit as auditlib
from . import auth
from . import autonomy as autolib
from . import daemon_id
from .analyzers.secrets import redact
from .engine import Engine
from .models import Action, Decision, Observation, TaskSpec, Verdict

STATIC = Path(__file__).with_name("static")
HOME = Path(os.environ.get("TRIPWIRE_HOME") or Path.home() / ".tripwire")
log = logging.getLogger("tripwire.server")


class Resolve(BaseModel):
    decision: Decision
    remember: Literal["session", "always"] | None = None


class Pair(BaseModel):
    code: str


class Settings(BaseModel):
    autonomy: Literal["strict", "balanced", "autonomous"]


class PairPoll(BaseModel):
    id: str
    secret: str


class PairDecision(BaseModel):
    decision: Literal["allow", "block"]


class Console:
    """The daemon's own terminal, if it has one. `out` is written to only when it is a real terminal (never a log);
    `interactive` means a person can type into it (serve in the foreground)."""

    def __init__(self, out=None, interactive: bool = False) -> None:
        self.out, self.interactive = out, interactive and out is not None

    def say(self, text: str) -> None:
        if self.out is None:
            return
        try:
            self.out.write(text + "\n")
            self.out.flush()
        except (OSError, ValueError):
            pass


def dashboard_headers(app) -> dict[str, str]:
    """In-process only (tests, in-process tools): pair a browser directly and return its request headers. Nothing
    over HTTP reaches this; an agent that imports it builds its own app, not your daemon's."""
    return {"Cookie": f"{auth.COOKIE}={app.state.pair_browser()}", "Sec-Fetch-Site": "same-origin"}


MUTATING = {"POST", "PUT", "DELETE", "PATCH"}
# All the agent hook's token may do.
HOOK_ENDPOINTS = {("POST", "/v1/task"), ("POST", "/v1/observe"), ("POST", "/v1/evaluate")}
# Open to anyone local: they only ask; a person decides.
PAIR_OPEN = {"/v1/pair", "/v1/pair/request", "/v1/pair/poll"}
MAX_PAIR_REQUESTS = 3
DEMO_PREFIX = "demo-"  # scripted demo sessions: not remembered across a restart


def create_app(engine: Engine | None = None, audit_path: Path | None = None, home: Path | None = None,
               token: str | None = None, demo_admin: str | None = None, console: Console | None = None,
               hardened: bool = False) -> FastAPI:
    engine = engine or Engine()
    home = Path(home) if home else (Path(audit_path).parent if audit_path else
                                    Path(os.environ.get("TRIPWIRE_HOME") or Path.home() / ".tripwire"))
    audit = auditlib.Audit(audit_path or home / "audit.db")
    token = token or auth.load_or_create(home)
    # Migration: earlier versions kept an admin key the agent could read. It must not outlive this version.
    removed_admin = auth.remove_legacy_admin(home)
    if removed_admin:
        log.warning("deleted %s: Tripwire no longer keeps an admin key on disk. Pair browsers with `tripwire open`.",
                    auth.legacy_admin_path(home))
    if not demo_admin:
        with contextlib.suppress(FileNotFoundError):
            auth.demo_admin_path(home).unlink()
    console_key = None
    if hardened:
        problem = auth.hardened_problem(home)
        if problem:
            raise RuntimeError(f"Hardened mode refused: {problem}")
        console_key = auth.new_pair_code()
        auth.write_secret(auth.console_key_path(home), console_key)
    else:
        with contextlib.suppress(FileNotFoundError):
            auth.console_key_path(home).unlink()
    console = console or Console()
    dashboards = auth.DashboardStore(home / "dashboards.json")
    # The level you chose last time, unless whoever built the engine (serve --autonomy, a test) already chose one.
    saved = autolib.load_settings(home).get("autonomy")
    if not engine.autonomy_explicit and saved in autolib.LEVELS:
        engine.autonomy = saved
    if engine.learned.path is None and not engine.learned.rules:
        engine.learned = autolib.LearnedStore(home / "learned.yaml")
    # Sessions survive a daemon restart: the task, what was learned from tool outputs, and above all that hidden
    # instructions were seen. Without this, restarting the daemon mid-session wiped the injection memory and the
    # attacker's next call was allowed (QA 31 Oct).
    sessions_path = home / "sessions.json"
    restored = engine.sessions.load(sessions_path) if not engine.sessions.all() else 0
    # Scripted demo runs (`demo/run_demo.py`, `scripts/seed_demo.py`: session ids "demo-...") see hidden instructions
    # on purpose. Their memory must not outlive the daemon, or trying the README demo once locks a new user out of
    # pairing links and looser levels after every restart. Real sessions (Claude Code's ids, MCP proxies) keep theirs.
    demo_ids = [sid for sid in list(engine.sessions._s) if sid.startswith(DEMO_PREFIX)]
    for sid in demo_ids:
        engine.sessions._s.pop(sid, None)
    for sid in [k for k in engine.sessions.tombstones if k.startswith(DEMO_PREFIX)]:
        engine.sessions.tombstones.pop(sid, None)
    if demo_ids:
        restored = max(0, restored - len(demo_ids))
        engine.sessions.changes += 1  # saved again without them
    if restored:
        log.warning("restored %d session(s) from %s", restored, sessions_path)
    saved_at = {"changes": engine.sessions.changes, "error": None}

    def save_sessions() -> None:
        changes = engine.sessions.changes
        try:
            engine.sessions.save(sessions_path)
            saved_at.update(changes=changes, error=None)
        except Exception as e:  # noqa: BLE001 - a busy dict mid-iteration or a full disk: retry on the next tick
            if saved_at["error"] is None:
                log.error("could not save sessions to %s: %s", sessions_path, e)
            saved_at["error"] = f"{type(e).__name__}: {e}"

    def saver() -> None:
        while True:
            time.sleep(2)
            if engine.sessions.changes != saved_at["changes"]:
                save_sessions()

    threading.Thread(target=saver, name="tripwire-sessions", daemon=True).start()
    app_trace = audit.register
    recent: deque[Verdict] = deque(maxlen=500)
    # A restart brings sessions back with their last verdicts, so the dashboard's feed matches the task it shows.
    for v in sorted((v for x in engine.sessions.all() for v in x.history), key=lambda v: v.ts)[-500:]:
        recent.append(v)
    pending: dict[str, asyncio.Future] = {}
    deadlines: dict[str, float] = {}
    queues: set[asyncio.Queue] = set()
    started = time.time()
    pair_codes: dict[str, tuple[float, str]] = {}  # code -> (expiry, how it was minted)
    pair_requests: dict[str, dict] = {}  # `tripwire open` requests waiting for a person
    pair_lock = threading.Lock()  # the console thread and the event loop both touch the pairing state
    last_pair = {"ts": 0.0}

    def new_pair(origin: str = "console") -> str:
        now = time.time()
        with pair_lock:
            for k in [k for k, (exp, _) in pair_codes.items() if exp < now]:
                pair_codes.pop(k, None)
            code = auth.new_pair_code()
            pair_codes[code] = (now + auth.PAIR_TTL, origin)
        return code

    def broadcast(kind: str, data: dict) -> None:
        if kind == "verdict" and isinstance(data.get("action"), dict) and not data.get("trace"):
            a = data["action"].get("agent") or data["action"].get("session_id")
            data["trace"] = audit.agents.get(a, {}).get("trace")
        for q in list(queues):
            q.put_nowait((kind, data))

    engine.listeners.append(broadcast)
    @contextlib.asynccontextmanager
    async def lifespan(_app):
        yield
        save_sessions()  # a clean stop (Ctrl-C, restart script) writes the latest state

    app = FastAPI(title="Tripwire", version="0.1.0", lifespan=lifespan)
    app.state.open_cmd, app.state.serve_cmd = "tripwire open", "tripwire serve"  # serve sets these with its --port

    def open_cmd() -> str:
        return app.state.open_cmd

    def serve_cmd() -> str:
        return app.state.serve_cmd
    app.state.engine = engine
    app.state.audit = audit
    app.state.token = token
    # Per-boot key for signing verdicts (daemon_id). Lives in memory; `serve` publishes it for the hook.
    app.state.verdict_key = os.urandom(32)
    app.state.demo_admin = demo_admin
    app.state.home = home
    app.state.new_pair = new_pair
    app.state.pair_browser = dashboards.add
    app.state.dashboards = dashboards
    app.state.console = console
    app.state.removed_admin_key = removed_admin
    app.state.save_sessions = save_sessions
    app.state.restored_sessions = restored

    @app.middleware("http")
    async def guard_the_guard(request: Request, call_next):
        # DNS rebinding: a web page that points its own domain at 127.0.0.1 still sends its own Host.
        if not auth.is_local_host(request.headers.get("host")):
            return JSONResponse({"detail": "Tripwire only answers requests addressed to 127.0.0.1 or localhost."}, 403)
        origin = request.headers.get("origin")
        if not auth.is_local_origin(origin):
            return JSONResponse({"detail": "Requests from other websites are refused."}, 403)
        path = request.url.path
        request.state.actor = None
        if path.startswith("/v1/") and path not in PAIR_OPEN:
            sent = request.headers.get(auth.HEADER)
            cookie = request.cookies.get(auth.COOKIE)
            # A mutating cookie request must also look same-origin (SameSite=Strict already keeps other sites out).
            browser_ok = dashboards.check(cookie) and (request.method not in MUTATING or origin is not None or
                                                       request.headers.get("sec-fetch-site") == "same-origin")
            if demo_admin and auth.same(request.headers.get(auth.DEMO_HEADER), demo_admin):
                request.state.actor = "demo-admin"
            elif console_key and auth.same(request.headers.get(auth.CONSOLE_HEADER), console_key):
                if (request.method, path) != ("POST", "/v1/pair/new"):
                    return JSONResponse({"detail": "The console key only mints pairing links. Use the dashboard."}, 403)
                request.state.actor = "console"
            elif browser_ok:
                request.state.actor = "dashboard"
            elif auth.same(sent, token):
                if (request.method, path) not in HOOK_ENDPOINTS:
                    return JSONResponse({"detail": "The agent hook's token can only send tasks, tool outputs and "
                                                   "actions to check. This needs the paired dashboard: run "
                                                   f"`{open_cmd()}` in your terminal."}, 403)
                request.state.actor = "hook-token"
            else:
                return JSONResponse({"detail": f"Not connected. Run `{open_cmd()}` in your terminal to pair this "
                                               "browser; agent hooks send the token from ~/.tripwire/token."}, 401)
        return await call_next(request)

    def actor(request: Request) -> str:
        return getattr(request.state, "actor", None) or "hook-token"

    def soon_after_pair() -> bool:
        """A privileged change within 2 s of a pairing looks scripted, not like a person clicking."""
        return time.time() - last_pair["ts"] < 2.0

    def any_injected() -> bool:
        return any(s.taint.injection_seen for s in engine.sessions.all())

    def injected_pair() -> str:
        return ("Hidden instructions were seen in a live session, so a new browser needs a person's OK: run "
                f"`{open_cmd()}` and approve its code in the `{serve_cmd()}` terminal or a paired dashboard.")

    @app.post("/v1/pair")
    def pair(body: Pair) -> JSONResponse:
        with pair_lock:
            entry = pair_codes.pop(body.code, None) if isinstance(body.code, str) else None
        if entry is None or entry[0] < time.time():
            return JSONResponse({"detail": f"That pairing code is used up or expired. Run `{open_cmd()}` for a new one."},
                                403)
        origin = entry[1]
        if origin not in ("handshake", "console") and any_injected():
            # A link minted before the attack (or by a demo daemon) can't add a browser after it.
            return JSONResponse({"detail": injected_pair()}, 403)
        resp = JSONResponse({"ok": True})
        resp.set_cookie(auth.COOKIE, dashboards.add(), httponly=True, samesite="strict", path="/",
                        max_age=auth.COOKIE_DAYS * 86400)
        last_pair["ts"] = time.time()
        record("pair", body={"by": "dashboard", "minted_by": origin,
                             "note": "a browser was paired with a one-time code"})
        return resp

    @app.post("/v1/pair/new")
    def pair_new(request: Request) -> dict:
        by = actor(request)
        if by not in ("console", "demo-admin"):
            raise HTTPException(403, f"Pairing links come from a person: run `{open_cmd()}` in your terminal.")
        if by == "demo-admin" and any_injected():
            raise HTTPException(403, injected_pair())
        code = new_pair(by)
        record("pair_code", body={"by": by, "note": "a one-time pairing code was minted"})
        return {"code": code, "expires_in": auth.PAIR_TTL}

    def pending_requests() -> list[dict]:
        now = time.time()
        with pair_lock:
            for k in [k for k, r in pair_requests.items() if r["expires"] < now]:
                pair_requests.pop(k, None)
            return [r for r in pair_requests.values() if r["status"] == "pending"]

    def approvers() -> list[str]:
        out = []
        if console.interactive:
            out.append("console")
        if dashboards.count():
            out.append("dashboard")
        return out

    def decide_request(rid: str, decision: str, by: str) -> bool:
        with pair_lock:
            r = pair_requests.get(rid)
            if not r or r["status"] != "pending" or r["expires"] < time.time():
                return False
            r["status"] = "approved" if decision == "allow" else "denied"
        record("pair_request", body={"op": r["status"], "by": by, "request": rid})
        broadcast("pair_resolved", {"id": rid, "status": r["status"]})
        return True

    @app.post("/v1/pair/request")
    def pair_request(request: Request) -> JSONResponse:
        who_ = approvers()
        if not who_:
            return JSONResponse({"detail": "Nobody can approve a new browser right now: the daemon runs in the "
                                           "background and no browser is paired. Restart it from your own terminal "
                                           f"(`{serve_cmd()}`, or scripts/restart_daemon.sh in a checkout): it prints a one-time "
                                           "link there."}, 409)
        pending_requests()
        rid, secret, digits = auth.new_pair_code()[:12], auth.new_pair_code(), auth.new_digits()
        with pair_lock:
            while len(pair_requests) >= MAX_PAIR_REQUESTS:
                pair_requests.pop(min(pair_requests, key=lambda k: pair_requests[k]["expires"]), None)
            pair_requests[rid] = {"id": rid, "secret": secret, "digits": digits, "status": "pending",
                                  "expires": time.time() + auth.REQUEST_TTL}
        console.say("\n`tripwire open` is asking to pair a browser. If you ran it, type the 6 digits it shows, then "
                    "press Enter here. If you didn't, ignore this.")
        broadcast("pair_request", {"id": rid, "digits": digits})
        record("pair_request", body={"op": "asked", "request": rid,
                                     "by": "hook-token" if auth.same(request.headers.get(auth.HEADER), token) else "local"})
        return JSONResponse({"id": rid, "secret": secret, "digits": digits, "approve_in": who_,
                             "expires_in": auth.REQUEST_TTL})

    @app.post("/v1/pair/poll")
    def pair_poll(body: PairPoll) -> dict:
        with pair_lock:
            r = pair_requests.get(body.id)
            if not r or not auth.same(body.secret, r["secret"]) or r["expires"] < time.time():
                raise HTTPException(404, f"That pairing request expired. Run `{open_cmd()}` again.")
            if r["status"] == "pending":
                return {"status": "pending"}
            pair_requests.pop(body.id, None)
        if r["status"] == "denied":
            return {"status": "denied"}
        return {"status": "approved", "code": new_pair("handshake")}

    @app.get("/v1/pair/requests")
    def pair_requests_list(request: Request) -> list[dict]:
        if actor(request) != "dashboard":
            raise HTTPException(403, "Only a paired dashboard can see pairing requests.")
        return [{"id": r["id"], "digits": r["digits"], "expires": r["expires"]} for r in pending_requests()]

    @app.post("/v1/pair/requests/{rid}")
    def pair_requests_decide(rid: str, body: PairDecision, request: Request) -> dict:
        if actor(request) != "dashboard":
            raise HTTPException(403, "Only a paired dashboard can approve a new browser.")
        if not decide_request(rid, body.decision, "dashboard"):
            raise HTTPException(404, "That pairing request is gone or expired.")
        return {"ok": True}

    def console_line(line: str) -> None:
        """One line typed into serve's own terminal: 6 digits approve a `tripwire open` request; Enter alone prints
        a fresh one-time link (not while hidden instructions are live)."""
        text = line.strip().replace(" ", "")
        if text.isdigit() and len(text) == 6:
            match = [r for r in pending_requests() if auth.same(r["digits"], text)]
            if match and decide_request(match[0]["id"], "allow", "console"):
                console.say("Approved. The browser opens from the `tripwire open` terminal.")
            else:
                console.say("No waiting `tripwire open` has those digits. Run it again for a fresh code.")
            return
        if text:
            console.say(f"Type the 6 digits `{open_cmd()}` shows"
                        + ("." if any_injected() else ", or press Enter alone for a one-time link."))
            return
        if any_injected():
            console.say(injected_pair() + f" Or press Ctrl-C and run `{serve_cmd()} --clear-view`: it clears the live "
                        "view (the attack stays remembered) and prints a link.")
            return
        code = new_pair("console")
        record("pair_code", body={"by": "console", "note": "a one-time pairing code was minted in serve's terminal"})
        console.say(f"One-time dashboard link (works once, 10 minutes): {app.state.base_url}#pair={code}")

    def startup_link() -> str | None:
        """The link serve prints once at startup, to its own terminal. None while hidden instructions are live."""
        if any_injected():
            return None
        record("pair_code", body={"by": "console", "note": "startup link printed to serve's terminal"})
        return new_pair("console")

    app.state.console_line = console_line
    app.state.startup_link = startup_link
    app.state.base_url = "http://127.0.0.1:7777/"
    app.state.any_injected = lambda: any_injected()

    def who(x: Action | Observation | TaskSpec) -> tuple[str, str | None, str]:
        """(agent, parent, trace). With no agent given, the session is the agent, as before."""
        agent = x.agent or x.session_id
        parent = x.parent if x.parent != agent else None
        return agent, parent, app_trace(agent, parent)

    def record(kind: str, **kw) -> None:
        # Never let the audit path break a decision; Audit itself logs and reports failures.
        try:
            audit.append(kind, **kw)
        except Exception as e:  # noqa: BLE001
            audit.error = f"{type(e).__name__}: {e}"
            log.error("AUDIT APPEND FAILED: %s", audit.error)

    @app.post("/v1/task")
    def task(spec: TaskSpec, request: Request) -> dict:
        by = actor(request)
        agent, parent, trace = who(spec)
        injected = engine.sessions.was_injected(spec.session_id)
        if injected and spec.profile:
            # A hijacked agent could try to swap in a looser role after the attack. Roles are fixed from then on.
            spec = spec.model_copy(update={"profile": None})
        # After hidden instructions, the user can keep working in the same session (refusing every new prompt made
        # Claude Code unusable). But the new words are unverified: they can't vouch for any address, host or value
        # the hidden instructions supplied, so re-tasking can't launder the attacker's target.
        engine.set_task(spec, verified=not injected)
        record("task", session=spec.session_id, agent=agent, parent=parent, trace=trace,
               body={"prompt": redact(spec.prompt[:2000]), "profile": spec.profile, "cwd": spec.cwd, "by": by,
                     **({"unverified": "hidden instructions were seen"} if injected else {})})
        return {"ok": True}

    @app.post("/v1/observe")
    def observe(obs: Observation) -> dict:
        s = engine.sessions.get(obs.session_id)
        before = len(s.taint.injection_seen)
        engine.observe(obs)
        agent, parent, trace = who(obs)
        # Metadata only: tool output is untrusted and may hold secrets, so it never goes in the log.
        record("observe", session=obs.session_id, agent=agent, parent=parent, trace=trace, tool=obs.tool,
               body={"bytes": len(obs.output), "injection": len(s.taint.injection_seen) > before, "source": obs.source})
        return {"ok": True}

    def record_verdict(v: Verdict, agent: str, parent: str | None) -> None:
        try:  # serialising is part of recording: a failure here must not turn a verdict into an HTTP 500
            body = v.model_dump_json()
        except Exception as e:  # noqa: BLE001
            audit.error = f"{type(e).__name__}: {e}"
            log.error("AUDIT APPEND FAILED: %s", audit.error)
            body = json.dumps({"id": v.id, "decision": v.decision.value, "risk": v.risk, "summary": v.summary,
                               "tool": v.action.tool, "note": "the full verdict could not be encoded"}, ensure_ascii=True)
        record("verdict", id=v.id, ref=v.id, ts=v.ts, session=v.action.session_id, agent=agent, parent=parent,
               trace=v.trace, tool=v.action.tool, decision=v.decision.value, risk=v.risk, body=body)

    def record_resolution(vid: str, v: Verdict | None, decision: Decision, by: str) -> None:
        a = v.action if v else None
        record("resolution", ref=vid, session=a.session_id if a else None, agent=(a.agent or a.session_id) if a else None,
               parent=a.parent if a else None, trace=v.trace if v else None, tool=a.tool if a else None,
               decision=decision.value, body={"verdict": vid, "decision": decision.value, "by": by})

    @app.post("/v1/evaluate", response_model=Verdict)
    async def evaluate(action: Action, request: Request, response: Response, wait: float = 0) -> Verdict:
        agent, parent, trace = who(action)
        action.agent, action.parent = agent, parent
        v = engine.evaluate(action)
        v.trace = trace
        v.action.agent, v.action.parent = agent, parent
        recent.append(v)
        # The verdict is recorded as decided, right away (queued, not waited on). A human answer or a
        # timeout is appended later as its own resolution record; history is never rewritten.
        record_verdict(v, agent, parent)
        if v.decision == Decision.ASK and wait > 0:
            fut = asyncio.get_running_loop().create_future()
            pending[v.id] = fut
            deadlines[v.id] = time.time() + min(wait, 300)
            broadcast("held", {"id": v.id, "deadline": deadlines[v.id]})
            try:
                v.decision = await asyncio.wait_for(fut, timeout=min(wait, 300))
                v.resolved_by = v.resolved_by or "human"  # the resolve endpoint already recorded it
            except asyncio.TimeoutError:
                v.decision, v.resolved_by = Decision.BLOCK, "timeout"
                engine.resolve(v.id, Decision.BLOCK)
                record_resolution(v.id, v, Decision.BLOCK, "timeout")
                broadcast("resolved", {"id": v.id, "decision": "block", "by": "timeout"})
            finally:
                pending.pop(v.id, None)
                deadlines.pop(v.id, None)
        nonce = request.headers.get(daemon_id.NONCE_HEADER)
        if nonce:  # the hook checks this, so an impostor on the port can't just answer "allow"
            response.headers[daemon_id.MAC_HEADER] = daemon_id.mac(app.state.verdict_key, nonce[:128], v.decision.value,
                                                                   await request.body())
        return v

    def record_rule(op: str, rule: autolib.LearnedRule, by: str) -> None:
        record("rule", ref=rule.id, session=rule.session, tool=rule.tool, decision=rule.decision,
               body={"op": op, "by": by, **rule.public()})

    @app.post("/v1/verdicts/{vid}/resolve")
    def resolve(vid: str, body: Resolve, request: Request) -> dict:
        by = actor(request)
        if by not in ("dashboard", "demo-admin"):
            # An ASK is a question for a person. Only a click in the paired dashboard answers it (or the simulated
            # human of a throwaway --demo-admin daemon).
            raise HTTPException(403, "Only a click in the paired dashboard can answer this.")
        for v in recent:
            if v.id == vid:
                break
        else:
            raise HTTPException(404, "unknown verdict")
        engine.resolve(vid, body.decision)
        # "human" only for a click in the paired dashboard; a token holder could be a script or the agent itself.
        v.decision, v.resolved_by = body.decision, "human" if by == "dashboard" else by
        record_resolution(vid, v, body.decision, by)
        fut = pending.get(vid)
        if fut and not fut.done():
            fut.set_result(body.decision)
        broadcast("resolved", {"id": vid, "decision": body.decision.value, "by": v.resolved_by})
        out: dict = {"ok": True, "rule": None, "remember_refused": None}
        if body.remember and by != "dashboard":
            out["remember_refused"] = "Only a click in the dashboard can teach Tripwire a rule."
        elif body.remember:
            try:
                rule = engine.learn(v, body.decision, body.remember)
                record_rule("add", rule, by)
                broadcast("rule", {"op": "add", **rule.public()})
                out["rule"] = rule.public()
            except autolib.LearnRefused as e:
                out["remember_refused"] = str(e)
        return out

    @app.get("/v1/settings")
    def get_settings() -> dict:
        return {"autonomy": engine.autonomy}

    @app.put("/v1/settings")
    def put_settings(body: Settings, request: Request) -> dict:
        by = actor(request)
        before = engine.autonomy
        looser = autolib.LEVELS.index(body.autonomy) > autolib.LEVELS.index(before) if before in autolib.LEVELS else True
        if looser and any_injected():
            # The attack this stops: a hijacked agent that got hold of any credential switches Tripwire to
            # autonomous. Not even the dashboard loosens while an attack is live; reset the view first.
            raise HTTPException(403, "Hidden instructions were seen in a live session, so Tripwire won't loosen "
                                     "now. Press Reset first (the attack stays remembered), then change it.")
        engine.set_autonomy(body.autonomy)
        data = autolib.load_settings(home)
        data["autonomy"] = engine.autonomy
        autolib.save_settings(home, data)
        if before != engine.autonomy:
            record("settings", body={"autonomy": engine.autonomy, "was": before, "by": by,
                                     "seconds_after_pairing": round(time.time() - last_pair["ts"], 2) if soon_after_pair() else None})
        return {"autonomy": engine.autonomy}

    @app.get("/v1/rules")
    def rules() -> list[dict]:
        return [r.public() for r in engine.learned.list()]

    @app.delete("/v1/rules/{rid}")
    def delete_rule(rid: str, request: Request) -> dict:
        r = engine.learned.delete(rid)
        if r is None:
            raise HTTPException(404, "unknown rule")
        record_rule("delete", r, actor(request))
        broadcast("rule", {"op": "delete", **r.public()})
        return {"ok": True}

    @app.get("/v1/verdicts")
    def verdicts(limit: int = 200, session_id: str | None = None, agent: str | None = None,
                 trace: str | None = None) -> list[Verdict]:
        out = [v for v in recent if (not session_id or v.action.session_id == session_id)
               and (not agent or v.action.agent == agent) and (not trace or v.trace == trace)]
        return out[-limit:][::-1]

    @app.get("/v1/stats")
    def stats() -> dict:
        c = Counter(v.decision.value for v in recent)
        cats = Counter(f.category for v in recent if v.decision != Decision.ALLOW for f in v.findings)
        return {"total": len(recent), "allow": c["allow"], "ask": c["ask"], "block": c["block"],
                "categories": dict(cats.most_common(8)), "sessions": len(engine.sessions.all()),
                # True while any live session has seen hidden instructions: the banner must not say "All clear".
                "hidden_instructions_seen": any_injected(),
                "pending": [{"id": k, "deadline": deadlines.get(k)} for k in pending], "uptime_s": round(time.time() - started),
                "judge": engine.judge is not None, "autonomy": engine.autonomy,
                "auto": sum(v.auto for v in recent),
                "avg_ms": round(sum(v.elapsed_ms for v in recent) / len(recent), 2) if recent else 0}

    @app.get("/v1/sessions")
    def sessions() -> list[dict]:
        return [{"id": s.id, "cwd": s.cwd, "task": s.task, "profile": s.profile,
                 "injection_seen": len(s.taint.injection_seen),
                 # The UI must never say "All clear" for a session with this set.
                 "hidden_instructions_seen": bool(s.taint.injection_seen),
                 "injections": [{"tool": i.tool, "source": i.where, "snippet": i.snippet} for i in s.taint.injection_seen[-5:]],
                 "secrets_read": s.secrets_read, "actions": len(s.history)} for s in engine.sessions.all()]

    def clear_view(by: str) -> int:
        for fut in pending.values():  # never leave a held agent hanging: settle as block
            if not fut.done():
                fut.set_result(Decision.BLOCK)
        # Only a person (the paired dashboard, or `serve --clear-view` in their terminal) can reset. Sessions go,
        # but every session that saw hidden instructions leaves a tombstone: if its id comes back, it starts out
        # knowing it was attacked.
        kept = engine.sessions.reset()
        recent.clear()
        record("reset", body={"note": "live view cleared; the audit log keeps everything", "by": by, "kept": kept,
                              "remembered_attacks": len(engine.sessions.tombstones),
                              "seconds_after_pairing": round(time.time() - last_pair["ts"], 2) if soon_after_pair() else None})
        broadcast("reset", {})
        return kept

    app.state.clear_view = clear_view

    @app.post("/v1/reset")
    def reset(request: Request) -> dict:
        return {"ok": True, "kept": clear_view(actor(request))}

    @app.get("/v1/events")
    async def events(request: Request):
        q: asyncio.Queue = asyncio.Queue()
        queues.add(q)

        async def gen():
            try:
                while not await request.is_disconnected():
                    try:
                        kind, data = await asyncio.wait_for(q.get(), timeout=15)
                        yield {"event": kind, "data": json.dumps(data)}
                    except asyncio.TimeoutError:
                        yield {"event": "ping", "data": "{}"}
            finally:
                queues.discard(q)

        return EventSourceResponse(gen())

    @app.get("/v1/audit")
    def audit_log(limit: int = 1000, session_id: str | None = None, agent: str | None = None,
                  trace: str | None = None, format: str = "list"):
        """Default: audited verdicts newest first, resolutions folded in (same shape as before).
        format=tree: {"traces": [...]}, each a tree of agents (who spawned whom) with their actions."""
        audit.flush(2)
        if format == "tree":
            return {"traces": audit.traces(trace=trace, agent=agent, session=session_id, limit=min(limit, 100))}
        return audit.verdicts(limit=limit, session=session_id, agent=agent, trace=trace)

    @app.get("/v1/audit/events")
    def audit_events(since: int = 0, limit: int = 1000, agent: str | None = None, trace: str | None = None) -> list[dict]:
        audit.flush(2)
        return audit.events(since_seq=since, limit=limit, agent=agent, trace=trace)

    @app.get("/v1/audit/verify")
    def audit_verify() -> dict:
        audit.flush(2)
        r = auditlib.verify_db(audit.path, audit.key)
        return {"ok": r.ok, "checked": r.checked, "legacy": r.legacy, "problem": r.problems[0] if r.problems else None,
                "notes": r.notes}

    @app.get("/v1/audit/tamper-drill")
    def audit_tamper_drill() -> dict:
        """Edits a copy in memory only; the real log is opened read-only."""
        audit.flush(2)
        return auditlib.tamper_drill(audit.path, audit.key)

    @app.get("/healthz")
    def healthz() -> dict:
        # "ok" means the daemon is deciding (adapters and scripts poll this). Audit health is separate,
        # so a broken disk shows up as audit "degraded" without making every agent fail closed.
        return {"ok": True, "audit": audit.health(), "demo_admin": bool(demo_admin), "hardened": bool(hardened),
                "sessions": {"live": len(engine.sessions.all()), "restored": restored, "save_error": saved_at["error"]}}

    if STATIC.exists():
        app.mount("/static", StaticFiles(directory=STATIC), name="static")

        @app.middleware("http")
        async def no_stale_dashboard(request: Request, call_next):
            # A browser that cached last week's dashboard must not show it against today's daemon.
            resp = await call_next(request)
            if request.url.path == "/" or request.url.path.startswith("/static/"):
                resp.headers["Cache-Control"] = "no-cache"
            return resp

        @app.get("/")
        def index(request: Request):
            # No key here: any client can send browser headers. The page pairs with a one-time code (POST /v1/pair).
            return FileResponse(STATIC / "index.html")
    else:
        @app.get("/")
        def index_missing():
            return JSONResponse({"tripwire": "running", "dashboard": "not built"})

    return app
