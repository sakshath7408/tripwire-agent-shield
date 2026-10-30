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
GET  /              dashboard

Every POST/PUT/DELETE needs the per-install token (header X-Tripwire-Token, or the dashboard's cookie), and every
request must name 127.0.0.1/localhost as its Host (stops DNS rebinding). See auth.py.
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

    @app.middleware("http")
    async def guard_the_guard(request: Request, call_next):
        # DNS rebinding: a web page that points its own domain at 127.0.0.1 still sends its own Host.
        if not auth.is_local_host(request.headers.get("host")):
            return JSONResponse({"detail": "Tripwire only answers requests addressed to 127.0.0.1 or localhost."}, 403)
        origin = request.headers.get("origin")
        if not auth.is_local_origin(origin):
            return JSONResponse({"detail": "Requests from other websites are refused."}, 403)
        if request.method in MUTATING:
            sent = request.headers.get(auth.HEADER)
            cookie = request.cookies.get(auth.COOKIE)
            # The cookie only counts for a same-origin browser request (SameSite=Strict already keeps other sites out).
            browser_ok = auth.same(cookie, token) and (origin is not None or
                                                         request.headers.get("sec-fetch-site") == "same-origin")
            if not (auth.same(sent, token) or browser_ok):
                return JSONResponse({"detail": "Missing or wrong Tripwire token. Clients read it from ~/.tripwire/token."},
                                    401)
        return await call_next(request)

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
    def task(spec: TaskSpec) -> dict:
        engine.set_task(spec)
        agent, parent, trace = who(spec)
        record("task", session=spec.session_id, agent=agent, parent=parent, trace=trace,
               body={"prompt": redact(spec.prompt[:2000]), "profile": spec.profile, "cwd": spec.cwd})
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

    def record_rule(op: str, rule: autolib.LearnedRule, by: str = "human") -> None:
        record("rule", ref=rule.id, session=rule.session, tool=rule.tool, decision=rule.decision,
               body={"op": op, "by": by, **rule.public()})

    @app.post("/v1/verdicts/{vid}/resolve")
    def resolve(vid: str, body: Resolve) -> dict:
        for v in recent:
            if v.id == vid:
                break
        else:
            raise HTTPException(404, "unknown verdict")
        engine.resolve(vid, body.decision)
        v.decision, v.resolved_by = body.decision, "human"
        record_resolution(vid, v, body.decision, "human")
        fut = pending.get(vid)
        if fut and not fut.done():
            fut.set_result(body.decision)
        broadcast("resolved", {"id": vid, "decision": body.decision.value, "by": "human"})
        out: dict = {"ok": True, "rule": None, "remember_refused": None}
        if body.remember:
            try:
                rule = engine.learn(v, body.decision, body.remember)
                record_rule("add", rule)
                broadcast("rule", {"op": "add", **rule.public()})
                out["rule"] = rule.public()
            except autolib.LearnRefused as e:
                out["remember_refused"] = str(e)
        return out

    @app.get("/v1/settings")
    def get_settings() -> dict:
        return {"autonomy": engine.autonomy}

    @app.put("/v1/settings")
    def put_settings(body: Settings) -> dict:
        before = engine.autonomy
        engine.set_autonomy(body.autonomy)
        data = autolib.load_settings(home)
        data["autonomy"] = engine.autonomy
        autolib.save_settings(home, data)
        if before != engine.autonomy:
            record("settings", body={"autonomy": engine.autonomy, "was": before, "by": "human"})
        return {"autonomy": engine.autonomy}

    @app.get("/v1/rules")
    def rules() -> list[dict]:
        return [r.public() for r in engine.learned.list()]

    @app.delete("/v1/rules/{rid}")
    def delete_rule(rid: str) -> dict:
        r = engine.learned.delete(rid)
        if r is None:
            raise HTTPException(404, "unknown rule")
        record_rule("delete", r)
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
    def reset() -> dict:
        for fut in pending.values():  # never leave a held agent hanging: settle as block
            if not fut.done():
                fut.set_result(Decision.BLOCK)
        engine.sessions.reset()
        recent.clear()
        record("reset", body={"note": "live view cleared; the audit log keeps everything"})
        broadcast("reset", {})
        return {"ok": True}

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
            resp = FileResponse(STATIC / "index.html")
            # The dashboard's key: an HttpOnly, SameSite=Strict cookie, handed only to a browser opening the page.
            # Agents can't fetch this page (the engine blocks calls aimed at the daemon), and other sites can't use it.
            if request.headers.get("sec-fetch-dest") == "document":
                resp.set_cookie(auth.COOKIE, token, httponly=True, samesite="strict", path="/")
            return resp
    else:
        @app.get("/")
        def index_missing():
            return JSONResponse({"tripwire": "running", "dashboard": "not built"})

    return app
