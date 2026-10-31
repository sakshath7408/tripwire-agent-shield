"""Command line entry point: `tripwire <command>`."""

from __future__ import annotations

import contextlib
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
    s.add_argument("--clear-view", action="store_true",
                   help="start with an empty live view (like Reset; attacks stay remembered)")
    s.add_argument("--link-fd", type=int, default=None, metavar="FD",
                   help="print the one-time startup link to this file descriptor, only if it is a terminal "
                        "(scripts/restart_daemon.sh uses it)")
    s.add_argument("--link-path", default="/", metavar="PATH",
                   help="page the one-time link opens, e.g. '/?stage=1&theme=light' (default: /)")
    s.add_argument("--hardened", action="store_true",
                   help="the daemon runs as its own OS user (see `tripwire harden`); refuses to start otherwise")
    s.add_argument("--demo-admin", action="store_true",
                   help="TESTS AND THROWAWAY DEMOS ONLY: writes demo-admin.key, which any process can use to "
                        "answer ASKs. Never on a daemon that guards a real agent")
    o = sub.add_parser("open", help="open the dashboard in your browser (pairs it after a person approves)")
    o.add_argument("--port", type=_port, default=default_port(), help=port_help)
    o.add_argument("--print", action="store_true", help="print the one-time link instead of opening a browser")
    hd = sub.add_parser("harden", help="run the daemon as its own OS user (prints the steps; --apply runs them)")
    hd.add_argument("--apply", action="store_true", help="run the steps with sudo, after you confirm in this terminal")
    hd.add_argument("--system", choices=["macos", "linux"], default=None, help="default: this computer")
    hd.add_argument("--port", type=_port, default=default_port(), help=port_help)
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
            i_.add_argument("--sandbox", action="store_true",
                            help="also turn on Claude Code's OS sandbox for its shell, so the agent can't read Tripwire's "
                                 "files, reach its port or switch the sandbox off (no root needed)")
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
        return _install(args)

    if args.cmd == "mcp-proxy":
        from .adapters import mcp_proxy
        return mcp_proxy.main(args.name, upstream or rest, profile=args.profile)

    if args.cmd == "pins":
        return _pins(args.action, args.server)

    if args.cmd == "open":
        return _open(args.port, args.print)

    if args.cmd == "harden":
        from . import harden
        return harden.main(args.apply, args.system, args.port)

    if args.cmd == "serve":
        return _serve(args)
    return 1


def _serve_cmd(port: int) -> str:
    return "tripwire serve" + ("" if port == DEFAULT_PORT else f" --port {port}")


def _install(args) -> int:
    """install / uninstall claude, saying exactly which folder is guarded and what must be running."""
    from pathlib import Path

    from .adapters import claude_code
    try:
        if args.cmd == "uninstall":
            had = claude_code.has_hooks(project=args.project, user=args.user)
            path = claude_code.uninstall(project=args.project, user=args.user)
            if not had:
                print(f"Nothing to remove: no Tripwire hooks were installed in {path}.")
                return 0
            print(f"Tripwire hooks removed from {path}. Claude Code there is no longer guarded.")
            return 0
        # A port chosen with TRIPWIRE_PORT while installing is saved too: Claude Code may start without that variable.
        port = args.port or default_port()
        path = claude_code.install(project=args.project, user=args.user,
                                   port=args.port or (port if port != DEFAULT_PORT else None), sandbox=args.sandbox)
    except ValueError as e:  # settings.json is not valid JSON: never overwrite it
        print(f"Tripwire did not change anything: {e}", file=sys.stderr)
        return 1
    print(f"Tripwire hooks installed in {path}")
    if args.user:
        print("Guarded: every Claude Code session you start, in any folder (your user settings).")
    else:
        folder = path.parent.parent
        print(f"Guarded: Claude Code sessions started in {folder}")
        if (folder / "src" / "tripwire" / "cli.py").is_file():
            print("Heads up: that is Tripwire's own folder, so only sessions started here are guarded. To guard your "
                  "project, cd into it and run `tripwire install claude` there (or add --user for every project).")
        else:
            print("Other folders are not guarded. Run this again inside each project, or use --user for all of them.")
    print(f"The daemon must be running for this to work: `{_serve_cmd(port)}` (port {port}). "
          "While it is down, every tool call is blocked.")
    hook = claude_code.hook_command(None)
    if ".venv" in Path(hook.split()[-1] if " -m " not in hook else hook.split(" -m ")[0]).parts:
        print("The hooks run Tripwire from this checkout's .venv. Keep that folder where it is (or use "
              "`uv tool install .` from the Tripwire folder, then install again).")
    if args.sandbox:
        _sandbox_summary(claude_code, None if args.user else path.parent.parent, port)
    else:
        print("For an OS-enforced boundary without root, run this again with --sandbox (see docs/HARDENING.md).")
    return 0


def _sandbox_summary(claude_code, project, port: int) -> None:
    g = claude_code.guard_paths(project)
    print("\nClaude Code's OS sandbox is on for the agent's shell (Bash and everything it starts). "
          "macOS Seatbelt / Linux bubblewrap now enforce:")
    print("  - No reading or writing: " + ", ".join(g["guards"] + g["settings"]))
    print("  - No writing: this project's .claude/settings*.json, and Tripwire's code (the hook runs it outside the "
          "sandbox): " + ", ".join(g["code"]))
    print(f"  - No direct connection to any localhost port on macOS (that includes the daemon on {port}), "
          "and no listening on a port, so nothing can pose as the daemon")
    print("  - No escape: dangerouslyDisableSandbox is ignored, and Claude Code refuses to start if the sandbox can't")
    print("  - Writes only inside this project and the temp folder; TRIPWIRE_TOKEN is removed from the shell's environment")
    print("  - No signals to processes outside the sandbox: kill/pkill of the daemon fail with 'operation not "
          "permitted' (macOS; tested with Claude Code 2.1.314)")
    print("Read, Edit and Write tools aren't sandboxed: permissions.deny rules block them on the same paths. "
          "MCP tools go through `tripwire mcp-proxy`.")
    print("Not covered: programs you run yourself, and hooks or MCP servers (they run outside the sandbox by design).")
    print("Expect some friction: writes outside this project (e.g. ~/.cache/uv, ~/.npm) and network hosts you haven't "
          "allowed are refused or asked about. See docs/HARDENING.md for allowWrite / allowedDomains.")
    print("Dev servers: a sandboxed command can't reach localhost:3000 either. If you need that, set "
          "sandbox.network.allowLocalBinding to true in .claude/settings.local.json (this re-opens every local port, "
          "the daemon's too; the engine still blocks calls to it).")


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


def _console(link_fd: int | None):
    """serve's own terminal: stdout if it is one, else --link-fd if that is one. Never a log file: a link written
    there would sit where an agent can read it."""
    from .server import Console
    if sys.stdout.isatty():
        return Console(sys.stdout, interactive=sys.stdin.isatty())
    if link_fd is not None:
        try:
            if os.isatty(link_fd):
                return Console(os.fdopen(link_fd, "w"), interactive=False)  # closed again right after startup
            if link_fd > 2:  # a pipe or file: never write the link there, and don't hold the caller's pipe open
                os.close(link_fd)
        except OSError:
            pass
    return Console()


def _read_console(app) -> None:
    """Lines typed into serve's terminal: 6 digits approve `tripwire open`, Enter alone prints a new link."""
    import threading

    def loop() -> None:
        for line in sys.stdin:
            try:
                app.state.console_line(line)
            except Exception as e:  # noqa: BLE001 - a typo must never stop the daemon
                app.state.console.say(f"(could not do that: {e})")

    threading.Thread(target=loop, name="tripwire-console", daemon=True).start()


def _serve(args) -> int:
    sock = _bind(args.port)
    if sock is None:
        return 1
    import secrets

    import uvicorn

    from . import auth
    from .engine import Engine
    from .server import create_app

    judge = None
    if args.judge:
        from .judge import make_judge
        judge = make_judge()
    engine = Engine(judge=judge, autonomy=args.autonomy)
    engine.set_guard_port(args.port)  # agent calls aimed at this port are attacks on the guard
    engine.set_guard_process(os.getpid(), " ".join([sys.executable] + sys.argv))  # and kills that reach this process
    console = _console(args.link_fd)
    demo_admin = None
    if args.demo_admin:
        demo_admin = secrets.token_urlsafe(32)
        auth.write_secret(auth.demo_admin_path(), demo_admin)
        warn = ("!" * 78 + "\nWARNING: --demo-admin is on. Any program that can read "
                f"{auth.demo_admin_path()} can answer\nASKs, reset and pair as you. Use it only for a throwaway demo "
                "or test daemon.\n" + "!" * 78)
        print(warn, file=sys.stderr)
        print(warn)
    try:
        app = create_app(engine, demo_admin=demo_admin, console=console, hardened=args.hardened)
    except RuntimeError as e:
        print(str(e), file=sys.stderr)
        return 1
    base = f"http://127.0.0.1:{args.port}"
    app.state.base_url = base + "/" + args.link_path.lstrip("/")  # the one-time link is this + "#pair=<code>"
    later = f"tripwire open{'' if args.port == DEFAULT_PORT else f' --port {args.port}'}"
    app.state.open_cmd = later
    app.state.serve_cmd = _serve_cmd(args.port)
    if app.state.removed_admin_key:
        print(f"Deleted the old admin key ({auth.legacy_admin_path()}). Tripwire no longer keeps one on disk: an agent "
              f"running as you could read it. Pair browsers with a one-time link from your terminal or `{later}`.")
    if args.clear_view:
        app.state.clear_view("serve --clear-view")
    print(f"Tripwire is running on {base}.")
    # The one-time link goes only to a real terminal: redirected into a log file, it would sit where an agent can
    # read it. While a live session has seen hidden instructions, no link: approve `tripwire open` instead.
    if console.out is not None:
        code = app.state.startup_link()
        if code:
            console.say(f"Dashboard (one-time link, works once for 10 minutes): {app.state.base_url}#pair={code}")
        else:
            # One clear next step. Enter would only refuse here, so it isn't offered.
            console.say("No link this time: a saved session saw hidden instructions, and while it is live Tripwire "
                        "won't hand out new dashboard links.\n"
                        f"Next step: press Ctrl-C, then run `{_serve_cmd(args.port)} --clear-view` (clears the live "
                        "view; the attack stays remembered) and it prints a link. Or open a dashboard you already "
                        f"paired, or run `{later}` and approve its 6 digits"
                        + (" here." if console.interactive else " in that dashboard."))
        if console.interactive:
            if code:
                console.say(f"Press Enter here for another one-time link. To approve `{later}`, type the 6 digits it shows.")
            _read_console(app)
        elif console.out is not sys.stdout:
            # --link-fd: a background daemon must not keep your terminal open (or wait on it) after its one line.
            with contextlib.suppress(OSError):
                console.out.close()
            console.out = None
    else:
        print(f"No terminal to show a pairing link in. Run `{later}` (a paired dashboard approves it), or start "
              f"`{_serve_cmd(args.port)}` in your own terminal to get a one-time link.")
    if args.port != DEFAULT_PORT:
        print(f"Agents look for port {DEFAULT_PORT} by default. Point them here with TRIPWIRE_PORT={args.port}, "
              f"or `tripwire install claude --port {args.port}`.")
    if judge is not None:
        hint = _judge_hint(judge)
        if hint:
            print(hint)
    sys.stdout.flush()
    from . import daemon_id
    try:  # the hook only trusts verdicts signed with this boot's key, from this PID
        daemon_id.publish(str(app.state.home), args.port, app.state.verdict_key)
    except OSError as e:
        print(f"Could not write {daemon_id.FILE} ({e}); hooks will not be able to check this daemon.", file=sys.stderr)
    config = uvicorn.Config(app, log_level="warning")
    uvicorn.Server(config).run(sockets=[sock])
    return 0


def _open(port: int, print_only: bool) -> int:
    """Pair a browser. Hardened mode (run as the daemon's user via sudo): mint a link with console.key. Otherwise a
    two-terminal handshake: this shows 6 digits, and a person types them into the `tripwire serve` terminal or
    approves them in a dashboard that is already paired. Nothing an agent can read or call approves it."""
    import json
    import time
    import urllib.error
    import urllib.request
    import webbrowser

    from . import auth
    base = f"http://127.0.0.1:{port}"
    if not (sys.stdin.isatty() and sys.stdout.isatty()):
        print("`tripwire open` only works in your own terminal, so an AI agent can't pair itself as the dashboard. "
              "Run it yourself in a terminal window.")
        return 1

    def post(path: str, body: dict, headers: dict | None = None) -> dict:
        req = urllib.request.Request(f"{base}{path}", data=json.dumps(body).encode(), method="POST",
                                     headers={"content-type": "application/json", **(headers or {})})
        return json.loads(urllib.request.urlopen(req, timeout=5).read())

    def detail(e: urllib.error.HTTPError) -> str:
        try:
            return json.loads(e.read()).get("detail") or f"HTTP {e.code}"
        except Exception:  # noqa: BLE001
            return f"HTTP {e.code}"

    try:
        console_key = auth.read_console_key()
        if console_key:
            code = post("/v1/pair/new", {}, {auth.CONSOLE_HEADER: console_key})["code"]
        else:
            req = post("/v1/pair/request", {})
            d = req["digits"]
            where = " or ".join({"console": "type them into the terminal running `tripwire serve`",
                                 "dashboard": "press OK in the prompt a paired dashboard shows (check the digits match)"
                                 }[w] for w in req["approve_in"])
            print(f"\n    {d[:3]} {d[3:]}\n\nTo pair a new browser, {where}. Waiting up to 5 minutes (Ctrl-C cancels).")
            deadline = time.time() + req["expires_in"]
            code = None
            while time.time() < deadline:
                time.sleep(1)
                r = post("/v1/pair/poll", {"id": req["id"], "secret": req["secret"]})
                if r["status"] == "approved":
                    code = r["code"]
                    break
                if r["status"] == "denied":
                    print("Turned down. No browser was paired.")
                    return 1
            if not code:
                print(f"Nobody approved it in time. Run `tripwire open{'' if port == DEFAULT_PORT else f' --port {port}'}` again.")
                return 1
    except urllib.error.HTTPError as e:
        print(detail(e))
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
        if not r.head_missing:
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
