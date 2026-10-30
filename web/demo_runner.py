"""The hosted live demo: one scenario, one act, run in-process and returned as JSON.

It reuses the local demo unchanged: the scenarios, the scripted agent, the synthetic world, the in-process
Tripwire engine (run_demo.LocalGuard), the simulated human for ASK verdicts (run_demo.approve, mode "auto")
and the result report (run_demo.report). The only differences from `run_demo.py --offline --approve auto`:
  - the world lives in a fresh temp folder per request (Vercel can only write under /tmp), deleted afterwards
  - every engine event (task / observe / verdict) is recorded, so the web page can replay exactly what the
    local dashboard would have received over SSE
No network, no model, no daemon. The agent is the scripted NaivePlanner, a stand-in for a hijacked AI.
"""

from __future__ import annotations

import contextlib
import io
import json
import shutil
import sys
import tempfile
import time
import uuid
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
for p in (ROOT / "src", ROOT / "demo"):
    if str(p) not in sys.path:
        sys.path.insert(0, str(p))

import run_demo  # noqa: E402  (demo/run_demo.py: scenarios, guards, approve, report)
from world.agent import NaivePlanner, Step  # noqa: E402
from world.world import FIXTURES, World  # noqa: E402

SCENARIOS = list(run_demo.SCENARIOS)
MAX_STEPS = 40  # same cap as run_demo.run_act
OUTPUT_SNIPPET = 400


def _start_balance() -> float:
    b = json.loads((FIXTURES / "bank.json").read_text())
    return float(b["accounts"][b["user_account"]]["balance"])


def _session_summary(engine: Any) -> list[dict]:
    """Same shape as GET /v1/sessions on the daemon (src/tripwire/server.py)."""
    return [{"id": s.id, "cwd": s.cwd, "task": s.task, "profile": s.profile,
             "injection_seen": len(s.taint.injection_seen),
             "injections": [{"tool": i.tool, "source": i.where, "snippet": i.snippet} for i in s.taint.injection_seen[-5:]],
             "secrets_read": s.secrets_read, "actions": len(s.history)} for s in engine.sessions.all()]


def run(scenario: str, guarded: bool) -> dict:
    if scenario not in run_demo.SCENARIOS:
        raise ValueError(f"unknown scenario {scenario!r}; pick one of {', '.join(SCENARIOS)}")
    sc = run_demo.SCENARIOS[scenario]
    t0 = time.perf_counter()
    # /tmp, not the platform default: macOS puts temp dirs under /var/folders, and Tripwire rightly treats
    # writes under /var as system-folder writes. /tmp is also the only writable path on Vercel.
    tmp = Path(tempfile.mkdtemp(prefix="tripwire-demo-", dir="/tmp" if Path("/tmp").is_dir() else None))
    quiet = io.StringIO()  # run_demo's helpers print a terminal transcript; the JSON carries the same facts
    try:
        world = World(root=tmp / "sandbox", drop_path=tmp / "attacker_drop.json").reset(sc.name)
        session = f"{'tripwire' if guarded else 'no-guard'}-{sc.name}-{uuid.uuid4().hex[:4]}"
        guard: Any = run_demo.LocalGuard(session) if guarded else run_demo.NoGuard()
        events: list[dict] = []
        if guarded:
            guard.engine.listeners.append(lambda kind, data: events.append({"kind": kind, "data": data}))
        planner = NaivePlanner(sc.plan())
        guard.set_task(prompt=sc.task, cwd=str(world.project), profile=sc.profile)
        task_events, events[:] = list(events), []
        history: list[Step] = []
        steps: list[dict] = []
        counts = {"allow": 0, "ask": 0, "block": 0}
        with contextlib.redirect_stdout(quiet):
            for _ in range(MAX_STEPS):
                call = planner.next_action(history)
                if call is None:
                    break
                v = guard.evaluate(call)
                decision = v["decision"]
                human = None
                if guarded:
                    counts[decision] = counts.get(decision, 0) + 1
                    if decision == "ask":  # same simulated human as run_demo --approve auto
                        decision = "allow" if run_demo.approve(call, v, "auto") else "block"
                        human = decision
                        if v.get("id"):
                            guard.resolve(v["id"], decision)
                if decision == "allow":
                    out = world.call(call.tool, call.args)
                    guard.observe(call.tool, out)
                    history.append(Step(call, out, v["decision"] if guarded else "unguarded", True))
                else:
                    out = f"Tripwire stopped this action: {v.get('summary', '')}"
                    history.append(Step(call, out, decision, False))
                bank = world.bank()
                steps.append({
                    "tool": call.tool, "args": call.args, "why": call.why,
                    "verdict": v if guarded else None,
                    "human": human,  # the simulated human's answer to an ASK, or None
                    "executed": history[-1].executed,
                    "output": out[:OUTPUT_SNIPPET] + ("..." if len(out) > OUTPUT_SNIPPET else ""),
                    "events": list(events),  # engine events in order: the verdict, then the observe of the output
                    "after": {"attacker_items": len(world.attacker_drop()),
                              "balance": bank["accounts"][bank["user_account"]]["balance"]},
                })
                events.clear()
            result = run_demo.report(world, sc, history, guarded, counts)
        return {
            "scenario": sc.name, "title": sc.title, "story": sc.story, "task": sc.task, "profile": sc.profile,
            "guarded": guarded, "session_id": session,
            "agent": "scripted stand-in for a hijacked AI (demo/world/agent.py NaivePlanner)",
            "engine": "Tripwire engine, in-process on this server" if guarded else "no guard: nothing checks the calls",
            "task_events": task_events,
            "steps": steps,
            "sessions": _session_summary(guard.engine) if guarded else [],
            "task_completed": result["task_completed"], "detail": result["detail"],
            "attacker_inbox": result["attacker_drop"], "attacker_items": result["attacker_items"],
            "balance": result["balance"], "start_balance": _start_balance(),
            "verdicts": counts if guarded else None,
            "server_ms": round((time.perf_counter() - t0) * 1000, 1),
        }
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
