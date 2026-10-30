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
GET  /v1/events     server-sent events (task | observe | verdict | resolved)
POST /v1/pair {"code"}  swap a one-time pairing code for the dashboard cookie   POST /v1/pair/new  mint a code (token)
GET  /              dashboard

Every /v1 endpoint, reads included, needs the per-install token (header X-Tripwire-Token) or the dashboard cookie,
except /v1/pair, which takes a one-time code. /healthz, / and /static are open. Every request must name
127.0.0.1/localhost as its Host (stops DNS rebinding). See auth.py.

Who did it: the audit log records "dashboard" for the cookie and "api-token" for the header. Anything that would
widen what the agent may do (autonomy, learned rules, clearing a session that saw hidden instructions) is
dashboard-only once hidden instructions have been seen, and a task sent with the token after hidden instructions
can't vouch for values that came from them.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import time
from collections import Counter, deque
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from typing import Literal

from pydantic import BaseModel
from sse_starlette.sse import EventSourceResponse

from . import audit as auditlib
from . import auth
from . import autonomy as autolib
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


MUTATING = {"POST", "PUT", "DELETE", "PATCH"}


def create_app(engine: Engine | None = None, audit_path: Path | None = None, home: Path | None = None,
               token: str | None = None) -> FastAPI:
    engine = engine or Engine()
    home = Path(home) if home else (Path(audit_path).parent if audit_path else
                                    Path(os.environ.get("TRIPWIRE_HOME") or Path.home() / ".tripwire"))
    audit = auditlib.Audit(audit_path or home / "audit.db")
    token = token or auth.load_or_create(home)
    # The level you chose last time, unless whoever built the engine (serve --autonomy, a test) already chose one.
    saved = autolib.load_settings(home).get("autonomy")
    if not engine.autonomy_explicit and saved in autolib.LEVELS:
        engine.autonomy = saved
    if engine.learned.path is None and not engine.learned.rules:
        engine.learned = autolib.LearnedStore(home / "learned.yaml")
    app_trace = audit.register
    recent: deque[Verdict] = deque(maxlen=500)
    pending: dict[str, asyncio.Future] = {}
    deadlines: dict[str, float] = {}
    queues: set[asyncio.Queue] = set()
    started = time.time()
    dash = auth.dash_key(token)
    pair_codes: dict[str, float] = {}

    def new_pair() -> str:
        now = time.time()
        for k in [k for k, exp in pair_codes.items() if exp < now]:
            pair_codes.pop(k, None)
        code = auth.new_pair_code()
        pair_codes[code] = now + auth.PAIR_TTL
        return code

    def broadcast(kind: str, data: dict) -> None:
        if kind == "verdict" and isinstance(data.get("action"), dict) and not data.get("trace"):
            a = data["action"].get("agent") or data["action"].get("session_id")
            data["trace"] = audit.agents.get(a, {}).get("trace")
        for q in list(queues):
            q.put_nowait((kind, data))

    engine.listeners.append(broadcast)
    app = FastAPI(title="Tripwire", version="0.1.0")
    app.state.engine = engine
    app.state.audit = audit
    app.state.token = token
    app.state.home = home
    app.state.new_pair = new_pair
    app.state.dash_key = dash

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
        if path.startswith("/v1/") and path != "/v1/pair":
            sent = request.headers.get(auth.HEADER)
            cookie = request.cookies.get(auth.COOKIE)
            # A mutating cookie request must also look same-origin (SameSite=Strict already keeps other sites out).
            browser_ok = auth.same(cookie, dash) and (request.method not in MUTATING or origin is not None or
                                                      request.headers.get("sec-fetch-site") == "same-origin")
            if auth.same(sent, token):
                request.state.actor = "api-token"
            elif browser_ok:
                request.state.actor = "dashboard"
            else:
                return JSONResponse({"detail": "Not connected. Run `tripwire open` to pair this browser; "
                                               "clients send the token from ~/.tripwire/token."}, 401)
        return await call_next(request)

    def actor(request: Request) -> str:
        return getattr(request.state, "actor", None) or "api-token"

    def any_injected() -> bool:
        return any(s.taint.injection_seen for s in engine.sessions.all())

    @app.post("/v1/pair")
    def pair(body: Pair) -> JSONResponse:
        exp = pair_codes.pop(body.code, None) if isinstance(body.code, str) else None
        if exp is None or exp < time.time():
            return JSONResponse({"detail": "That pairing code is used up or expired. Run `tripwire open` for a new one."},
                                403)
        resp = JSONResponse({"ok": True})
        resp.set_cookie(auth.COOKIE, dash, httponly=True, samesite="strict", path="/")
        record("pair", body={"by": "dashboard", "note": "a browser was paired with a one-time code"})
        return resp

    @app.post("/v1/pair/new")
    def pair_new(request: Request) -> dict:
        if actor(request) != "api-token":
            raise HTTPException(403, "Pairing codes are minted from the terminal (`tripwire open`).")
        code = new_pair()
        return {"code": code, "expires_in": auth.PAIR_TTL}

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
        s = engine.sessions._s.get(spec.session_id)
        after_injection = bool(s and s.taint.injection_seen)
        # Sent with the token after hidden instructions: recorded, but it can't vouch for the attacker's values.
        engine.set_task(spec, verified=by == "dashboard" or not after_injection)
        agent, parent, trace = who(spec)
        record("task", session=spec.session_id, agent=agent, parent=parent, trace=trace,
               body={"prompt": redact(spec.prompt[:2000]), "profile": spec.profile, "cwd": spec.cwd, "by": by,
                     "after_injection": after_injection})
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
        record("verdict", id=v.id, ref=v.id, ts=v.ts, session=v.action.session_id, agent=agent, parent=parent,
               trace=v.trace, tool=v.action.tool, decision=v.decision.value, risk=v.risk, body=v.model_dump_json())

    def record_resolution(vid: str, v: Verdict | None, decision: Decision, by: str) -> None:
        a = v.action if v else None
        record("resolution", ref=vid, session=a.session_id if a else None, agent=(a.agent or a.session_id) if a else None,
               parent=a.parent if a else None, trace=v.trace if v else None, tool=a.tool if a else None,
               decision=decision.value, body={"verdict": vid, "decision": decision.value, "by": by})

    @app.post("/v1/evaluate", response_model=Verdict)
    async def evaluate(action: Action, wait: float = 0) -> Verdict:
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
        return v

    def record_rule(op: str, rule: autolib.LearnedRule, by: str) -> None:
        record("rule", ref=rule.id, session=rule.session, tool=rule.tool, decision=rule.decision,
               body={"op": op, "by": by, **rule.public()})

    @app.post("/v1/verdicts/{vid}/resolve")
    def resolve(vid: str, body: Resolve, request: Request) -> dict:
        by = actor(request)
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
        if by != "dashboard" and body.autonomy != before and any_injected():
            # The attack this stops: an agent that got hold of the token switches Tripwire to autonomous.
            raise HTTPException(403, "Hidden instructions were seen in a live session, so the autonomy level can "
                                     "only be changed from the dashboard.")
        engine.set_autonomy(body.autonomy)
        data = autolib.load_settings(home)
        data["autonomy"] = engine.autonomy
        autolib.save_settings(home, data)
        if before != engine.autonomy:
            record("settings", body={"autonomy": engine.autonomy, "was": before, "by": by})
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
                "pending": [{"id": k, "deadline": deadlines.get(k)} for k in pending], "uptime_s": round(time.time() - started),
                "judge": engine.judge is not None, "autonomy": engine.autonomy,
                "auto": sum(v.auto for v in recent),
                "avg_ms": round(sum(v.elapsed_ms for v in recent) / len(recent), 2) if recent else 0}

    @app.get("/v1/sessions")
    def sessions() -> list[dict]:
        return [{"id": s.id, "cwd": s.cwd, "task": s.task, "profile": s.profile,
                 "injection_seen": len(s.taint.injection_seen),
                 "injections": [{"tool": i.tool, "source": i.where, "snippet": i.snippet} for i in s.taint.injection_seen[-5:]],
                 "secrets_read": s.secrets_read, "actions": len(s.history)} for s in engine.sessions.all()]

    @app.post("/v1/reset")
    def reset(request: Request) -> dict:
        by = actor(request)
        for fut in pending.values():  # never leave a held agent hanging: settle as block
            if not fut.done():
                fut.set_result(Decision.BLOCK)
        # A token reset keeps every session that saw hidden instructions, so wiping a session's memory of an
        # attack (then rewriting its task) needs a human at the dashboard.
        kept = engine.sessions.reset(keep_injected=by != "dashboard")
        recent.clear()
        record("reset", body={"note": "live view cleared; the audit log keeps everything", "by": by, "kept": kept})
        broadcast("reset", {})
        return {"ok": True, "kept": kept}

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

    @app.get("/healthz")
    def healthz() -> dict:
        # "ok" means the daemon is deciding (adapters and scripts poll this). Audit health is separate,
        # so a broken disk shows up as audit "degraded" without making every agent fail closed.
        return {"ok": True, "audit": audit.health()}

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
