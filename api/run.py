"""Vercel Python function for the live demo.

GET  /api/run?scenario=<name>&guard=0|1      one act of a canned scenario
POST /api/run  {"place", "task", "text", "guard"}  one act of the visitor's own attack ("Try your own attack")

Runs the real Tripwire engine in-process against the synthetic world (see web/demo_runner.py). Stateless:
every request builds its own world under /tmp and deletes it afterwards. The visitor's text is data only: it
is planted in the temp world, read by the scripted agent and returned inside JSON, never as HTML.
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

MAX_BODY = 16 * 1024  # 4 KB of text, even as \uXXXX escapes, fits; anything bigger is refused unread


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


def respond_custom(raw: bytes) -> tuple[int, dict]:
    """The visitor's own attack. Every refusal is one plain sentence the page shows as is."""
    if len(raw) > MAX_BODY:
        return 413, {"error": "That's too long. Keep the attacker's text under 4 KB."}
    try:
        req = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        return 400, {"error": "That looks like binary data. Paste plain text."}
    if not isinstance(req, dict):
        return 400, {"error": "Send the attack as a JSON object."}
    guard = req.get("guard")
    if guard not in (0, 1, True, False):
        return 400, {"error": "guard must be 0 or 1"}
    try:
        return 200, demo_runner.run_custom(str(req.get("place", "")), str(req.get("task", "")), req.get("text"), bool(guard))
    except ValueError as e:
        return 400, {"error": str(e)}
    except Exception as e:
        traceback.print_exc()
        return 500, {"error": f"the demo run failed ({type(e).__name__})"}


def encode(body: dict) -> bytes:
    """JSON with <, > and & escaped, so no part of the visitor's text can ever read as markup, even if sniffed."""
    text = json.dumps(body, ensure_ascii=False)
    return text.replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026").encode("utf-8")


class handler(BaseHTTPRequestHandler):
    def _send(self, status: int, body: dict) -> None:
        data = encode(body)
        self.send_response(status)
        self.send_header("content-type", "application/json; charset=utf-8")
        self.send_header("cache-control", "no-store")
        self.send_header("x-content-type-options", "nosniff")
        self.send_header("content-length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self) -> None:
        self._send(*respond(urlparse(self.path).query))

    def do_POST(self) -> None:
        try:
            n = int(self.headers.get("content-length") or 0)
        except ValueError:
            n = -1
        if n < 0 or n > MAX_BODY:
            self._send(413, {"error": "That's too long. Keep the attacker's text under 4 KB."})
            return
        self._send(*respond_custom(self.rfile.read(n)))
