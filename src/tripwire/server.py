"""Local daemon. Binds to 127.0.0.1 only. Adapters (Claude Code hook, MCP proxy, SDK) call it.

POST /v1/task       trusted user prompt for a session
POST /v1/observe    untrusted tool output
POST /v1/evaluate   action -> verdict   (?wait=N holds an ASK up to N s for a human answer)
POST /v1/verdicts/{id}/resolve {"decision": "allow"|"block"}
GET  /v1/verdicts   recent verdicts      GET /v1/stats   counts
GET  /v1/events     server-sent events (task | observe | verdict | resolved)
GET  /              dashboard
"""

from __future__ import annotations

import asyncio
import json
import sqlite3
import time
from collections import Counter, deque
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from sse_starlette.sse import EventSourceResponse

from .engine import Engine
from .models import Action, Decision, Observation, TaskSpec, Verdict

STATIC = Path(__file__).with_name("static")
HOME = Path.home() / ".tripwire"


class Resolve(BaseModel):
    decision: Decision


class Audit:
    """Append-only local log. Args are already redacted by the engine."""

    def __init__(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(path, check_same_thread=False)
        self.db.execute("create table if not exists verdicts (id text primary key, ts real, session text, tool text, decision text, risk int, json text)")

    def write(self, v: Verdict) -> None:
        self.db.execute("insert or replace into verdicts values (?,?,?,?,?,?,?)",
                        (v.id, v.ts, v.action.session_id, v.action.tool, v.decision.value, v.risk, v.model_dump_json()))
        self.db.commit()


def create_app(engine: Engine | None = None, audit_path: Path | None = None) -> FastAPI:
    engine = engine or Engine()
    audit = Audit(audit_path or HOME / "audit.db")
    recent: deque[Verdict] = deque(maxlen=500)
    pending: dict[str, asyncio.Future] = {}
    deadlines: dict[str, float] = {}
    queues: set[asyncio.Queue] = set()
    started = time.time()

    def broadcast(kind: str, data: dict) -> None:
        for q in list(queues):
            q.put_nowait((kind, data))

    engine.listeners.append(broadcast)
    app = FastAPI(title="Tripwire", version="0.1.0")
    app.state.engine = engine

    @app.post("/v1/task")
    def task(spec: TaskSpec) -> dict:
        engine.set_task(spec)
        return {"ok": True}

    @app.post("/v1/observe")
    def observe(obs: Observation) -> dict:
        engine.observe(obs)
        return {"ok": True}

    @app.post("/v1/evaluate", response_model=Verdict)
    async def evaluate(action: Action, wait: float = 0) -> Verdict:
        v = engine.evaluate(action)
        recent.append(v)
        if v.decision == Decision.ASK and wait > 0:
            fut = asyncio.get_running_loop().create_future()
            pending[v.id] = fut
            deadlines[v.id] = time.time() + min(wait, 300)
            broadcast("held", {"id": v.id, "deadline": deadlines[v.id]})
            try:
                v.decision = await asyncio.wait_for(fut, timeout=min(wait, 300))
                v.resolved_by = "human"
            except asyncio.TimeoutError:
                v.decision, v.resolved_by = Decision.BLOCK, "timeout"
                engine.resolve(v.id, Decision.BLOCK)
                broadcast("resolved", {"id": v.id, "decision": "block", "by": "timeout"})
            finally:
                pending.pop(v.id, None)
                deadlines.pop(v.id, None)
        audit.write(v)
        return v

    @app.post("/v1/verdicts/{vid}/resolve")
    def resolve(vid: str, body: Resolve) -> dict:
        engine.resolve(vid, body.decision)
        for v in recent:
            if v.id == vid:
                v.decision, v.resolved_by = body.decision, "human"
                audit.write(v)
                break
        else:
            raise HTTPException(404, "unknown verdict")
        fut = pending.get(vid)
        if fut and not fut.done():
            fut.set_result(body.decision)
        broadcast("resolved", {"id": vid, "decision": body.decision.value, "by": "human"})
        return {"ok": True}

    @app.get("/v1/verdicts")
    def verdicts(limit: int = 200, session_id: str | None = None) -> list[Verdict]:
        out = [v for v in recent if not session_id or v.action.session_id == session_id]
        return out[-limit:][::-1]

    @app.get("/v1/stats")
    def stats() -> dict:
        c = Counter(v.decision.value for v in recent)
        cats = Counter(f.category for v in recent if v.decision != Decision.ALLOW for f in v.findings)
        return {"total": len(recent), "allow": c["allow"], "ask": c["ask"], "block": c["block"],
                "categories": dict(cats.most_common(8)), "sessions": len(engine.sessions.all()),
                "pending": [{"id": k, "deadline": deadlines.get(k)} for k in pending], "uptime_s": round(time.time() - started),
                "judge": engine.judge is not None,
                "avg_ms": round(sum(v.elapsed_ms for v in recent) / len(recent), 2) if recent else 0}

    @app.get("/v1/sessions")
    def sessions() -> list[dict]:
        return [{"id": s.id, "cwd": s.cwd, "task": s.task, "profile": s.profile,
                 "injection_seen": len(s.taint.injection_seen),
                 "injections": [{"tool": i.tool, "snippet": i.snippet} for i in s.taint.injection_seen[-5:]],
                 "secrets_read": s.secrets_read, "actions": len(s.history)} for s in engine.sessions.all()]

    @app.post("/v1/reset")
    def reset() -> dict:
        for fut in pending.values():  # never leave a held agent hanging: settle as block
            if not fut.done():
                fut.set_result(Decision.BLOCK)
        engine.sessions.reset()
        recent.clear()
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
    def audit_log(limit: int = 1000, session_id: str | None = None) -> list[dict]:
        q = "select json from verdicts" + (" where session=?" if session_id else "") + " order by ts desc limit ?"
        rows = audit.db.execute(q, (session_id, limit) if session_id else (limit,)).fetchall()
        return [json.loads(r[0]) for r in rows]

    @app.get("/healthz")
    def healthz() -> dict:
        return {"ok": True}

    if STATIC.exists():
        app.mount("/static", StaticFiles(directory=STATIC), name="static")

        @app.get("/")
        def index():
            return FileResponse(STATIC / "index.html")
    else:
        @app.get("/")
        def index_missing():
            return JSONResponse({"tripwire": "running", "dashboard": "not built"})

    return app
