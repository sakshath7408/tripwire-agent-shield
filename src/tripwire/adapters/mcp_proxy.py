"""MCP stdio proxy: `tripwire mcp-proxy [--name NAME] -- <upstream server command...>`.

Sits between an MCP client (Claude Desktop, Claude Code, any agent) and an MCP server that
speaks newline-delimited JSON-RPC over stdio. Everything is relayed untouched except:

  client -> server  tools/call    evaluated by the daemon first (wait=120, so an ASK is held
                                  for a person: only a click in the paired dashboard answers it,
                                  never the hook token the agent can read; unanswered, it ends as
                                  a block). Anything but allow is answered
                                  by the proxy itself with an isError tool result; the server
                                  never sees the call.
  server -> client  tools/list    tool metadata pinned and signed (see pins.py); changed, new
                                  or poisoned tools are hidden; descriptions recorded as untrusted.
  server -> client  call result   recorded with the daemon as untrusted data BEFORE the client
                                  sees it, so the next call is judged with it in mind.

Fail closed: daemon unreachable, bad daemon answer, pin store error, unparseable client message,
any exception while deciding -> the call is refused. TRIPWIRE_FAIL_OPEN=1 only relaxes the
"daemon unreachable" case.
"""

from __future__ import annotations

import asyncio
import json
import os
import signal
import sys
import threading
from typing import Any

import httpx

from .. import auth
from .. import daemon_id
from .claude_code import IMPOSTOR, _identity, base_url, flatten, not_running
from .pins import Check, PinStore

WAIT = 120
LIMIT = 256 * 1024 * 1024  # biggest single JSON-RPC line we accept from the server
NOT_RUNNING = "Tripwire is not running, so this tool call was blocked. Start it with `tripwire serve`."


def _log(msg: str) -> None:
    try:
        sys.stderr.write(f"[tripwire mcp-proxy] {msg}\n")
        sys.stderr.flush()
    except Exception:
        pass


def _key(msg_id: Any) -> str:
    return json.dumps(msg_id, sort_keys=True)


def blocked_result(msg_id: Any, reason: str) -> dict:
    for lead in ("Blocked: ", "Needs your OK: "):
        if reason.startswith(lead):
            reason = reason[len(lead):]
    return {"jsonrpc": "2.0", "id": msg_id,
            "result": {"content": [{"type": "text", "text": f"Blocked by Tripwire: {reason}"}], "isError": True}}


class Proxy:
    def __init__(self, name: str, command: list[str], *, url: str | None = None, session: str | None = None,
                 wait: float = WAIT, fail_open: bool | None = None, pins: PinStore | None = None,
                 profile: str | None = None, task: str | None = None) -> None:
        self.name = name
        self.command = command
        self.url = (url or base_url()).rstrip("/")
        self.session = session or os.environ.get("TRIPWIRE_SESSION") or f"mcp-{name}"
        # Audit trail identity. TRIPWIRE_PARENT_AGENT links this server's calls under the agent that runs it.
        self.who = {"agent": os.environ.get("TRIPWIRE_AGENT") or f"mcp:{name}",
                    "parent": os.environ.get("TRIPWIRE_PARENT_AGENT") or None}
        self.wait = wait
        self.fail_open = fail_open if fail_open is not None else os.environ.get("TRIPWIRE_FAIL_OPEN", "") in ("1", "true", "yes")
        self.pins = pins
        task = task if task is not None else os.environ.get("TRIPWIRE_TASK")
        # The trusted task / permission profile must reach the daemon before any call is judged,
        # otherwise a profile restriction would silently not apply. Until it lands, calls are refused.
        self.task_body: dict | None = None
        if task or profile:
            self.task_body = {"session_id": self.session, **self.who, "prompt": task or "", "profile": profile}
        self.task_sent = False
        self.check: Check | None = None
        self.lists: dict[str, bool] = {}  # ids of tools/list requests in flight -> is a later page
        self.calls: dict[str, str] = {}  # id -> full tool name for tools/call in flight
        self.listed = asyncio.Event()  # set once a tools/list answer has been checked
        self.tasks: set[asyncio.Task] = set()
        self.out_lock = threading.Lock()
        self.proc: asyncio.subprocess.Process | None = None
        self.http: httpx.AsyncClient | None = None

    # ---- io -------------------------------------------------------------------
    def to_client(self, obj: Any = None, raw: bytes | None = None) -> None:
        data = raw if raw is not None else (json.dumps(obj, separators=(",", ":")) + "\n").encode()
        with self.out_lock:
            sys.stdout.buffer.write(data)
            sys.stdout.buffer.flush()

    async def to_server(self, obj: Any = None, raw: bytes | None = None) -> None:
        assert self.proc and self.proc.stdin
        if self.proc.stdin.is_closing():
            return
        self.proc.stdin.write(raw if raw is not None else (json.dumps(obj, separators=(",", ":")) + "\n").encode())
        await self.proc.stdin.drain()

    async def post(self, path: str, body: dict, timeout: float = 3.0) -> dict:
        assert self.http
        data = json.dumps(body).encode()
        headers = {**auth.headers(), "Content-Type": "application/json"}
        ident = _identity(self.url) if path.startswith("/v1/evaluate") and self.url.startswith("http://") else None
        nonce = os.urandom(16).hex() if ident else None
        if nonce:
            headers[daemon_id.NONCE_HEADER] = nonce
        r = await self.http.post(self.url + path, content=data, timeout=timeout, headers=headers)
        r.raise_for_status()
        out = r.json()
        if ident:  # same check as the Claude Code hook: only the real daemon's signed verdicts count
            want = daemon_id.mac(bytes.fromhex(ident["key"]), nonce, str(out.get("decision") if isinstance(out, dict) else ""), data)
            if not daemon_id.alive(ident) or not daemon_id.same(r.headers.get(daemon_id.MAC_HEADER, ""), want):
                return {"decision": "block", "summary": IMPOSTOR.format(port=ident["_port"], why="its answer could not be checked")}
        return out

    async def send_task(self) -> None:
        if self.task_body and not self.task_sent:
            await self.post("/v1/task", self.task_body)
            self.task_sent = True

    def spawn(self, coro) -> None:
        t = asyncio.create_task(coro)
        self.tasks.add(t)
        t.add_done_callback(self.tasks.discard)

    # ---- decisions ------------------------------------------------------------
    def full_name(self, tool: str) -> str:
        return f"mcp__{self.name}__{tool}"

    def pin_block(self, tool: str) -> str | None:
        if not self.pins:
            return None
        if self.check is not None:
            reason = self.check.blocked_reason(self.name, tool)
            if reason:
                return reason
            if tool not in self.check.ok:
                return f"MCP tool '{tool}' was not in this server's verified tool list."
            return None
        if not self.pins.pinned_ok(self.name, tool):
            return f"MCP tool '{tool}' has not been verified yet (the client called it before listing tools)."
        return None

    async def decide(self, msg: dict) -> str | None:
        """None means forward. A string is the reason to refuse."""
        params = msg.get("params") if isinstance(msg.get("params"), dict) else {}
        tool = params.get("name")
        if not isinstance(tool, str) or not tool:
            return "This tool call had no tool name."
        if self.pins and self.check is None and self.lists:
            # The client pipelined the call behind its own tools/list: wait for that answer instead of refusing.
            try:
                await asyncio.wait_for(self.listed.wait(), timeout=15)
            except asyncio.TimeoutError:
                pass
        reason = self.pin_block(tool)
        if reason:
            return reason
        if self.task_body and not self.task_sent:
            try:
                await self.send_task()
            except Exception:  # noqa: BLE001 - even with FAIL_OPEN, a missing profile must not widen access
                return "Tripwire could not register this session's task and permission profile, so the call was blocked."
        args = params.get("arguments")
        action = {"session_id": self.session, **self.who, "tool": self.full_name(tool), "source": "mcp",
                  "args": args if isinstance(args, dict) else {"arguments": args}}
        try:
            v = await self.post(f"/v1/evaluate?wait={self.wait:g}", action, timeout=self.wait + 10)
        except (httpx.TransportError, OSError):
            if self.fail_open:
                _log("daemon unreachable, TRIPWIRE_FAIL_OPEN=1 so forwarding")
                return None
            return not_running()
        if v.get("decision") == "allow":
            return None
        if v.get("decision") in ("block", "ask"):
            return str(v.get("summary") or "Tripwire refused this call.")
        return "Tripwire got an answer it did not understand, so it blocked this to be safe."

    async def handle_call(self, msg: dict) -> None:
        msg_id = msg.get("id")
        try:
            reason = await self.decide(msg)
        except Exception as e:  # noqa: BLE001 - fail closed
            reason = f"Tripwire hit an error checking this call ({type(e).__name__}), so it was blocked to be safe."
        if reason is None:
            tool = msg["params"]["name"]
            self.calls[_key(msg_id)] = self.full_name(tool)
            await self.to_server(msg)
        else:
            _log(f"blocked {msg.get('params', {}).get('name')}: {reason}")
            self.to_client(blocked_result(msg_id, reason))

    # ---- client -> server -----------------------------------------------------
    async def from_client(self, line: bytes) -> None:
        if not line.strip():
            return
        try:
            msg = json.loads(line)
        except ValueError:
            _log("dropped a client message that is not valid JSON")  # cannot inspect it, so it does not pass
            return
        if isinstance(msg, list):  # JSON-RPC batch (older MCP revisions)
            for m in msg:
                await self.from_client_obj(m, batch=True)
            return
        await self.from_client_obj(msg, raw=line)

    async def from_client_obj(self, msg: Any, raw: bytes | None = None, batch: bool = False) -> None:
        if isinstance(msg, dict) and msg.get("method") == "tools/call":
            if "id" not in msg:
                _log("dropped a tools/call notification without an id")
                return
            self.spawn(self.handle_call(msg))
            return
        if isinstance(msg, dict) and msg.get("method") == "tools/list" and "id" in msg:
            params = msg.get("params")
            self.lists[_key(msg["id"])] = bool(isinstance(params, dict) and params.get("cursor"))
        if batch or raw is None:
            await self.to_server(msg)
        else:
            await self.to_server(raw=raw if raw.endswith(b"\n") else raw + b"\n")

    # ---- server -> client -----------------------------------------------------
    async def from_server(self, line: bytes) -> None:
        try:
            msg = json.loads(line)
        except ValueError:
            self.to_client(raw=line)
            return
        if not isinstance(msg, dict) or "id" not in msg or "method" in msg:
            self.to_client(raw=line)  # notifications and server->client requests pass through
            return
        k = _key(msg["id"])
        if k in self.lists:
            later_page = self.lists.pop(k)
            self.to_client(await self.on_tools_list(msg, later_page))
            self.listed.set()
            return
        if k in self.calls:
            tool = self.calls.pop(k)
            self.to_client(await self.on_tool_result(tool, msg))
            return
        self.to_client(raw=line)

    async def on_tools_list(self, msg: dict, later_page: bool = False) -> dict:
        result = msg.get("result")
        if not isinstance(result, dict) or not isinstance(result.get("tools"), list):
            return msg
        tools = [t for t in result["tools"] if isinstance(t, dict)]
        listed = tools  # every description the server sent, hidden ones too: their addresses and links count as untrusted
        try:
            if self.pins:
                check = self.pins.check(self.name, tools)
                if later_page and self.check:  # paginated list: keep what earlier pages verified
                    check.ok = {**self.check.ok, **check.ok}
                self.check = check
                await self.report_pins(check)
                tools = [t for t in tools if t.get("name") in check.ok]
            desc = "\n".join(f"{t.get('name')}: {flatten(t.get('description'))} {flatten(t.get('inputSchema'))}"
                             for t in listed)
            if desc:
                await self.post("/v1/observe", {"session_id": self.session, **self.who, "tool": f"mcp__{self.name}__tools/list",
                                                "output": desc[:200_000], "source": "mcp"})
        except (httpx.TransportError, OSError):
            if not self.fail_open:
                _log("daemon unreachable while listing tools; tool calls will be refused")
        except Exception as e:  # noqa: BLE001 - cannot verify -> expose nothing
            _log(f"could not verify tools ({e}); exposing none")
            return {"jsonrpc": "2.0", "id": msg["id"],
                    "error": {"code": -32603, "message": f"Tripwire could not verify this server's tools: {e}"}}
        return {**msg, "result": {**result, "tools": tools}}

    async def report_pins(self, c: Check) -> None:
        lines = []
        if c.first_use:
            lines.append(f"First time seeing MCP server '{self.name}': pinned {len(c.ok)} tools.")
        if c.tampered:
            lines.append(f"The signed pin file failed its check. All tools of '{self.name}' are held until you run `tripwire pins approve {self.name}`.")
        for t in c.changed if not c.tampered else []:
            lines.append(f"MCP tool '{t}' on '{self.name}' changed its description or inputs since you approved it. Calls are blocked until `tripwire pins approve {self.name}`.")
        for t in c.new:
            lines.append(f"MCP server '{self.name}' added a new tool '{t}'. Calls are blocked until `tripwire pins approve {self.name}`.")
        for t in c.poisoned:
            lines.append(f"MCP tool '{t}' on '{self.name}' was hidden because {c.poisoned[t]}. It stays hidden, even after approval.")
        for line in lines:
            _log(line)
        if lines:
            try:
                await self.post("/v1/observe", {"session_id": self.session, **self.who, "tool": "tripwire.tool_pin",
                                                "output": "\n".join(lines), "source": "mcp"})
            except Exception as e:  # noqa: BLE001 - reporting only; calls are already refused locally
                _log(f"could not report pin findings to the daemon: {e}")

    async def on_tool_result(self, tool: str, msg: dict) -> dict:
        try:
            await self.post("/v1/observe", {"session_id": self.session, **self.who, "tool": tool,
                                            "output": flatten(msg.get("result", msg.get("error"))), "source": "mcp"})
        except Exception as e:  # noqa: BLE001
            if not (self.fail_open and isinstance(e, (httpx.TransportError, OSError))):
                # Untracked untrusted data would blind the next decision; withhold it.
                return blocked_result(msg["id"], "Tripwire could not record this tool's output, so it was withheld to be safe.")
        return msg

    # ---- lifecycle ------------------------------------------------------------
    async def pump_server(self) -> None:
        assert self.proc and self.proc.stdout
        while True:
            try:
                line = await self.proc.stdout.readline()
            except (asyncio.LimitOverrunError, ValueError):
                _log("server sent a message larger than the limit; stopping")
                return
            if not line:
                return
            await self.from_server(line)

    async def pump_client(self) -> None:
        loop = asyncio.get_running_loop()
        q: asyncio.Queue[bytes | None] = asyncio.Queue()

        def reader() -> None:  # a thread works for pipes, files and ttys alike
            try:
                for line in iter(sys.stdin.buffer.readline, b""):
                    loop.call_soon_threadsafe(q.put_nowait, line)
            except Exception:
                pass
            loop.call_soon_threadsafe(q.put_nowait, None)

        threading.Thread(target=reader, daemon=True, name="tripwire-stdin").start()
        while (line := await q.get()) is not None:
            try:
                await self.from_client(line)
            except (BrokenPipeError, ConnectionResetError):
                return
        # client closed: let in-flight calls finish, then close the server's stdin
        if self.tasks:
            await asyncio.wait(set(self.tasks), timeout=self.wait + 15)

    async def run(self) -> int:
        self.http = httpx.AsyncClient()
        if self.task_body:
            try:
                await self.send_task()
            except Exception as e:  # noqa: BLE001
                _log(f"could not send the task/profile to the daemon ({e}); calls are refused until it is")
        self.proc = await asyncio.create_subprocess_exec(*self.command, stdin=asyncio.subprocess.PIPE,
                                                         stdout=asyncio.subprocess.PIPE, stderr=None, limit=LIMIT)
        loop = asyncio.get_running_loop()
        stop = asyncio.Event()
        for sig in (signal.SIGINT, signal.SIGTERM):
            try:
                loop.add_signal_handler(sig, stop.set)
            except (NotImplementedError, RuntimeError):
                pass
        server = asyncio.create_task(self.pump_server())
        client = asyncio.create_task(self.pump_client())
        stopper = asyncio.create_task(stop.wait())
        done, _ = await asyncio.wait({server, client, stopper}, return_when=asyncio.FIRST_COMPLETED)
        if client in done and server not in done and not stop.is_set():
            # normal shutdown per MCP spec: close the server's stdin, give it time to exit
            if self.proc.stdin and not self.proc.stdin.is_closing():
                self.proc.stdin.close()
            try:
                await asyncio.wait_for(server, timeout=5)
            except asyncio.TimeoutError:
                pass
        for t in (server, client, stopper, *self.tasks):
            t.cancel()
        if self.proc.returncode is None:
            try:
                self.proc.terminate()
                await asyncio.wait_for(self.proc.wait(), timeout=3)
            except (asyncio.TimeoutError, ProcessLookupError):
                try:
                    self.proc.kill()
                except ProcessLookupError:
                    pass
                await self.proc.wait()
        await self.http.aclose()
        return self.proc.returncode or 0


def main(name: str, command: list[str], profile: str | None = None) -> int:
    if not command:
        _log("usage: tripwire mcp-proxy [--name NAME] [--profile NAME] -- <server command...>")
        return 2
    try:
        pins = PinStore() if os.environ.get("TRIPWIRE_PINS", "1") != "0" else None
    except Exception as e:  # noqa: BLE001 - no pin store means we cannot verify: refuse to start
        _log(f"cannot open the tool pin store ({e}); refusing to start")
        return 1
    return asyncio.run(Proxy(name, command, pins=pins, profile=profile).run())
