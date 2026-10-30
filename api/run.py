"""Vercel Python function: GET /api/run?scenario=<name>&guard=0|1 -> one act of the live demo as JSON.

Runs the real Tripwire engine in-process against the synthetic world (see web/demo_runner.py). Stateless:
every request builds its own world under /tmp and deletes it afterwards.
"""

from __future__ import annotations

import json
import sys
import traceback
from http.server import BaseHTTPRequestHandler
from pathlib import Path
from urllib.parse import parse_qs, urlparse

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "web"))
import demo_runner  # noqa: E402


def respond(query: str) -> tuple[int, dict]:
    q = parse_qs(query)
    scenario = (q.get("scenario") or ["injected-doc"])[0]
    guard = (q.get("guard") or ["1"])[0]
    if scenario not in demo_runner.SCENARIOS:
        return 400, {"error": f"unknown scenario; pick one of: {', '.join(demo_runner.SCENARIOS)}"}
    if guard not in ("0", "1"):
        return 400, {"error": "guard must be 0 or 1"}
    try:
        return 200, demo_runner.run(scenario, guard == "1")
    except Exception as e:  # never leak a traceback to the page; it goes to the function log
        traceback.print_exc()
        return 500, {"error": f"the demo run failed ({type(e).__name__})"}


class handler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        status, body = respond(urlparse(self.path).query)
        data = json.dumps(body).encode()
        self.send_response(status)
        self.send_header("content-type", "application/json; charset=utf-8")
        self.send_header("cache-control", "no-store")
        self.send_header("content-length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)
