"""Command line entry point: `tripwire <command>`."""

from __future__ import annotations

import os
import sys

DEFAULT_PORT = 7777


def default_port() -> int:
    """TRIPWIRE_PORT, else 7777. serve, open, install and the hooks all agree on it."""
    try:
        return int(os.environ.get("TRIPWIRE_PORT") or DEFAULT_PORT)
    except ValueError:
        return DEFAULT_PORT


def _port(text: str) -> int:
    import argparse
    try:
        n = int(text)
    except ValueError:
        raise argparse.ArgumentTypeError(f"'{text}' is not a port number (use 1024 to 65535, e.g. 7777)") from None
    if not 1 <= n <= 65535:
        raise argparse.ArgumentTypeError(f"{n} is not a valid port (use 1024 to 65535, e.g. 7777)")
    return n


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if len(argv) == 2 and argv[0] == "hook":  # hot path: runs on every Claude Code tool call (no argparse import)
        from .adapters.claude_code import hook_main
        return hook_main(argv[1])
    try:
        return _main(argv)
    except KeyboardInterrupt:
        return 130
    except OSError as e:  # a missing or unwritable folder, a file where a folder should be: say so, no traceback
        where = f" ({e.filename})" if e.filename else ""
        print(f"Tripwire could not use a file or folder it needs: {e.strerror or e}{where}.\n"
              f"Check that TRIPWIRE_HOME ({_home()}) is a folder you can write to.", file=sys.stderr)
        return 2


def _home() -> str:
    from . import auth
    return str(auth.home())


def _main(argv: list[str]) -> int:
    import argparse

    upstream: list[str] = []
    if argv[:1] == ["mcp-proxy"] and "--" in argv:  # everything after -- is the server command
        i = argv.index("--")
        argv, upstream = argv[:i], argv[i + 1:]

    from . import __version__
    p = argparse.ArgumentParser(prog="tripwire", description="A guard between AI agents and their tools.")
    p.add_argument("--version", action="version", version=f"tripwire {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True, metavar="COMMAND")
    port_help = "daemon port (default: $TRIPWIRE_PORT, else 7777)"
    s = sub.add_parser("serve", help="run the local daemon and dashboard")
    s.add_argument("--port", type=_port, default=default_port(), help=port_help)
    s.add_argument("--judge", action="store_true", help="use the local isolated judge model for grey-zone actions")
    s.add_argument("--autonomy", choices=["strict", "balanced", "autonomous"],
                   help="how much Tripwire decides on its own (default: your saved setting, else balanced)")
    o = sub.add_parser("open", help="open the dashboard in your browser (pairs it with a one-time code)")
    o.add_argument("--port", type=_port, default=default_port(), help=port_help)
    o.add_argument("--print", action="store_true", help="print the one-time link instead of opening a browser")
    h = sub.add_parser("hook", help="Claude Code hook entry (Claude Code runs this, not you)")
    h.add_argument("event", choices=["UserPromptSubmit", "PreToolUse", "PostToolUse"])
    for verb in ("install", "uninstall"):
        i_ = sub.add_parser(verb, help=f"{verb} Tripwire hooks for an agent")
        i_.add_argument("agent", choices=["claude"])
        scope = i_.add_mutually_exclusive_group()
        scope.add_argument("--project", metavar="DIR", help="project folder (default: current folder)")
        scope.add_argument("--user", action="store_true", help="all projects (~/.claude/settings.json)")
        if verb == "install":
            i_.add_argument("--port", type=_port, default=None,
                            help="daemon port the hooks talk to, if not 7777 (saved in the hook command)")
    m = sub.add_parser("mcp-proxy", help="guard an MCP stdio server: tripwire mcp-proxy --name NAME -- <cmd...>")
    m.add_argument("--name", default="mcp", help="server name; tools show up as mcp__NAME__tool")
    m.add_argument("--profile", default=None, help="permission profile from the policy YAML for this session")
    pn = sub.add_parser("pins", help="signed MCP tool pins")
    pn.add_argument("action", choices=["list", "approve"])
    pn.add_argument("server", nargs="?")
    au = sub.add_parser("audit", help="check, export or follow the tamper-evident audit log")
    au.add_argument("action", choices=["verify", "export", "tail"])
    au.add_argument("--db", default=None, help="audit database (default: ~/.tripwire/audit.db)")
    au.add_argument("--key", default=None, help="audit key (default: audit.key next to the database)")
    au.add_argument("--file", default=None, help="verify: check a JSONL export instead of the database")
    au.add_argument("--hash-only", action="store_true", help="verify: check hashes only, without the key")
    au.add_argument("--format", default="jsonl", choices=["jsonl"], help="export format")
    au.add_argument("-o", "--output", default=None, help="export: write to this file (default: stdout)")
    au.add_argument("-n", type=int, default=20, help="tail: how many records")
    au.add_argument("-f", "--follow", action="store_true", help="tail: keep printing new records")
    au.add_argument("--agent", default=None, help="tail: only this agent")
    au.add_argument("--trace", default=None, help="tail: only this trace (an agent and everything it spawned)")
    args, rest = p.parse_known_args(argv)

    if args.cmd == "audit":
        return _audit(args)

    if args.cmd == "hook":
        from .adapters.claude_code import hook_main
        return hook_main(args.event)

    if args.cmd in ("install", "uninstall"):
        from .adapters import claude_code
        try:
            if args.cmd == "install":
                path = claude_code.install(project=args.project, user=args.user, port=args.port)
            else:
                path = claude_code.uninstall(project=args.project, user=args.user)
        except ValueError as e:  # settings.json is not valid JSON: never overwrite it
            print(f"Tripwire did not change anything: {e}", file=sys.stderr)
            return 1
        print(f"Tripwire hooks {'installed in' if args.cmd == 'install' else 'removed from'} {path}")
        if args.cmd == "install":
            port = args.port or default_port()
            print(f"Start the daemon with `tripwire serve{'' if port == DEFAULT_PORT else f' --port {port}'}`. "
                  "While it is down, tool calls are blocked.")
        return 0

    if args.cmd == "mcp-proxy":
        from .adapters import mcp_proxy
        return mcp_proxy.main(args.name, upstream or rest, profile=args.profile)

    if args.cmd == "pins":
        return _pins(args.action, args.server)

    if args.cmd == "open":
        return _open(args.port, args.print)

    if args.cmd == "serve":
        return _serve(args)
    return 1


def _bind(port: int):
    """Bind the port before saying anything, so a busy port is a plain message, not a link that leads nowhere."""
    import errno
    import socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        sock.bind(("127.0.0.1", port))
    except OSError as e:
        sock.close()
        if e.errno == errno.EADDRINUSE:
            print(f"Port {port} is already in use. Is Tripwire already running? Check with "
                  f"`curl -s 127.0.0.1:{port}/healthz`, or pick another port: tripwire serve --port {port + 1}",
                  file=sys.stderr)
        elif e.errno == errno.EACCES:
            print(f"Not allowed to use port {port}. Pick one above 1023, e.g. tripwire serve --port 7777", file=sys.stderr)
        else:
            print(f"Could not use port {port}: {e.strerror or e}.", file=sys.stderr)
        return None
    sock.listen(2048)
    sock.set_inheritable(True)
    return sock


def _judge_hint(judge) -> str | None:
    """One line if the judge model can't answer yet (asks then stay asks, which is safe but worth knowing)."""
    import httpx
    try:
        tags = httpx.get(f"{judge.url}/api/tags", timeout=1.5).json()
    except Exception:  # noqa: BLE001
        return (f"Judge: Ollama is not answering at {judge.url}, so grey-zone calls stay with you until it is. "
                f"Start it with `ollama serve`, then `ollama pull {judge.model}`.")
    names = {m.get("name") for m in tags.get("models", []) if isinstance(m, dict)}
    if judge.model not in names and f"{judge.model}:latest" not in names:
        return f"Judge: model {judge.model} is not pulled yet. Run `ollama pull {judge.model}`."
    return None


def _serve(args) -> int:
    sock = _bind(args.port)
    if sock is None:
        return 1
    import uvicorn

    from .engine import Engine
    from .server import create_app

    judge = None
    if args.judge:
        from .judge import make_judge
        judge = make_judge()
    engine = Engine(judge=judge, autonomy=args.autonomy)
    engine.set_guard_port(args.port)  # agent calls aimed at this port are attacks on the guard
    app = create_app(engine)
    # The dashboard pairs with a one-time code (single use, 10 minutes). It is printed only to a real terminal:
    # redirected into a log file (restart_daemon.sh), a live link would sit where an agent can read it.
    later = f"tripwire open{'' if args.port == default_port() else f' --port {args.port}'}"
    if sys.stdout.isatty():
        print(f"Tripwire is running. Dashboard (one-time link): http://127.0.0.1:{args.port}/#pair={app.state.new_pair()}")
        print(f"Later, or in another browser: {later}")
    else:
        print(f"Tripwire is running on http://127.0.0.1:{args.port}. To open the dashboard, run `{later}` in your terminal.")
    if args.port != DEFAULT_PORT:
        print(f"Agents look for port {DEFAULT_PORT} by default. Point them here with TRIPWIRE_PORT={args.port}, "
              f"or `tripwire install claude --port {args.port}`.")
    if judge is not None:
        hint = _judge_hint(judge)
        if hint:
            print(hint)
    sys.stdout.flush()
    config = uvicorn.Config(app, log_level="warning")
    uvicorn.Server(config).run(sockets=[sock])
    return 0


CONFIRM_WORD = "pair"


def _open(port: int, print_only: bool) -> int:
    """Mint a one-time pairing code with the admin key and open the dashboard. Only from your own terminal: an agent
    runs commands without one, and a pairing code makes its holder the dashboard."""
    import json
    import urllib.error
    import urllib.request
    import webbrowser

    from . import auth
    base = f"http://127.0.0.1:{port}"
    if not (sys.stdin.isatty() and sys.stdout.isatty()):
        print("`tripwire open` only works in your own terminal (it needs you to type a confirmation word), so an AI "
              "agent can't pair itself as the dashboard. Run it yourself in a terminal window.")
        return 1
    admin = auth.read_admin()
    if not admin:
        print(f"No admin key at {auth.admin_path()}. Start the daemon first: tripwire serve")
        return 1
    try:
        answer = input(f"Type '{CONFIRM_WORD}' to make a one-time dashboard link (anything else cancels): ")
    except EOFError:
        answer = ""
    if answer.strip().lower() != CONFIRM_WORD:
        print("Cancelled. No link was made.")
        return 1
    try:
        req = urllib.request.Request(f"{base}/v1/pair/new", data=b"", method="POST", headers={auth.ADMIN_HEADER: admin})
        code = json.loads(urllib.request.urlopen(req, timeout=5).read())["code"]
    except urllib.error.HTTPError as e:
        if e.code in (401, 403):
            print(f"The Tripwire on {base} does not accept the admin key in {auth.admin_path()}. It was started with a "
                  "different TRIPWIRE_HOME (or its key changed). Run `tripwire open` with the same TRIPWIRE_HOME "
                  "as `tripwire serve`, or restart the daemon.")
        else:
            print(f"Tripwire on {base} answered HTTP {e.code}. Is that port really Tripwire?")
        return 1
    except Exception as e:  # noqa: BLE001
        reason = getattr(e, "reason", e)
        print(f"Could not reach Tripwire on {base} ({reason}). Start it with `tripwire serve`"
              + ("" if port == DEFAULT_PORT else f" --port {port}") + ", or pass the port it runs on: tripwire open --port N")
        return 1
    link = f"{base}/#pair={code}"
    if print_only or not webbrowser.open(link):
        print(f"Open this link once (it works one time, for 10 minutes): {link}")
    else:
        print(f"Opened the dashboard ({base}). The link in it works once.")
    return 0


def _audit(args) -> int:
    import json
    import time
    from pathlib import Path

    from . import audit as A

    db = Path(args.db).expanduser() if args.db else A.home() / "audit.db"
    key_path = Path(args.key).expanduser() if args.key else A.default_key_path(db)

    if db.parent.exists() and not db.parent.is_dir():
        import errno
        raise NotADirectoryError(errno.ENOTDIR, "Not a folder", str(db.parent))
    if args.file and not Path(args.file).expanduser().is_file():
        print(f"No such export file: {args.file}")
        return 1
    if args.action == "verify" and not args.file and not db.exists():
        print(f"No audit log yet at {db}. It starts when `tripwire serve` runs, so there is nothing to check.")
        return 1

    if args.action == "verify":
        key = None
        if args.file and not args.key:
            pass  # a third party checks an export by its hashes; pass --key to check signatures too
        elif not args.hash_only:
            key = A.load_key(key_path, create=False)
            if key is None:
                print(f"TAMPER CHECK FAILED: the audit key at {key_path} is missing, so signatures cannot be checked.")
                print("Use --hash-only to check the hash chain alone.")
                return 1
        if args.file:
            with open(args.file) as f:
                r = A.verify_lines(f, key)
            where = args.file
        else:
            r = A.verify_db(db, key)
            where = str(db)
        if r.ok:
            print(f"OK: {r.checked} audit records in {where} are intact"
                  + (" (hashes and signatures checked)." if key else " (hashes checked, signatures not checked)."))
            for n in r.notes:
                print(f"note: {n}")
            return 0
        print(f"TAMPERED: {r.problems[0]}")
        print(f"({r.checked} records before that point are intact.)")
        return 1

    if not db.exists():
        print(f"No audit database at {db}.")
        return 1

    if args.action == "export":
        out = open(args.output, "w") if args.output else sys.stdout
        try:
            n = 0
            for line in A.export_lines(db):
                out.write(line + "\n")
                n += 1
        finally:
            if args.output:
                out.close()
                print(f"Exported {n - 1} records and the signed head to {args.output}. "
                      f"Check it with: tripwire audit verify --file {args.output}")
        return 0

    # tail
    def show(ev: dict) -> None:
        t = time.strftime("%H:%M:%S", time.localtime(ev["ts"] or 0))
        body = json.loads(ev["json"] or "{}")
        what = {"verdict": f"{(ev['decision'] or '').upper():5} {ev['tool']}  {body.get('summary', '')}",
                "resolution": f"{(ev['decision'] or '').upper():5} {ev['ref']} resolved by {body.get('by')}",
                "task": f"TASK  {str(body.get('prompt') or '')[:100]}",
                "observe": f"READ  {ev['tool']} ({body.get('bytes')} bytes)" + ("  HIDDEN INSTRUCTIONS" if body.get("injection") else ""),
                }.get(ev["kind"], f"{ev['kind']}  {body.get('note', '')}")
        who = ev["agent"] or "-"
        if ev["parent"]:
            who += f" (spawned by {ev['parent']})"
        print(f"#{ev['seq']:<6} {t}  {who}  {what}  [{(ev['hash'] or '')[:10]}]")

    evs = A.read_events(db, agent=args.agent, trace=args.trace, limit=args.n, newest=True)[::-1]
    for ev in evs:
        show(ev)
    last = evs[-1]["seq"] if evs else 0
    while args.follow:
        try:
            time.sleep(0.5)
            for ev in A.read_events(db, agent=args.agent, trace=args.trace, since_seq=last):
                show(ev)
                last = ev["seq"]
        except KeyboardInterrupt:
            return 0
    return 0


def _pins(action: str, server: str | None) -> int:
    from .adapters.pins import PinStore

    store = PinStore()
    if action == "list":
        servers, valid = store.load()
        if not valid:
            print("WARNING: the pin file signature does not verify. Calls are held until you approve again.")
        if not servers:
            print(f"No MCP servers pinned yet ({store.path}).")
        for name, entry in sorted(servers.items()):
            if server and name != server:
                continue
            tools, pending = entry.get("tools", {}), entry.get("pending", {})
            print(f"{name}: {len(tools)} pinned tools" + (f", {len(pending)} waiting for approval" if pending else ""))
            for t, h in sorted(tools.items()):
                print(f"  ok       {t}  {h[:12]}")
            for t, h in sorted(pending.items()):
                print(f"  {'changed' if t in tools else 'new':8} {t}  {h[:12]}  (run: tripwire pins approve {name})")
                info = entry.get("pending_info", {}).get(t)
                if info:
                    print(f"           now says: {info}")
        return 0
    if not server:
        print("usage: tripwire pins approve <server>")
        return 2
    try:
        accepted = store.approve(server)
    except KeyError:
        print(f"No pins for MCP server '{server}'.")
        return 1
    print(f"Approved {len(accepted)} tool change(s) for '{server}': {', '.join(accepted) or 'nothing pending'}")
    print("Poisoned tool descriptions stay hidden even after approval.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
