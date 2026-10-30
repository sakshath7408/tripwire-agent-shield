"""Command line entry point: `tripwire <command>`."""

from __future__ import annotations

import argparse
import sys


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if len(argv) == 2 and argv[0] == "hook":  # hot path: runs on every Claude Code tool call
        from .adapters.claude_code import hook_main
        return hook_main(argv[1])

    upstream: list[str] = []
    if argv[:1] == ["mcp-proxy"] and "--" in argv:  # everything after -- is the server command
        i = argv.index("--")
        argv, upstream = argv[:i], argv[i + 1:]

    p = argparse.ArgumentParser(prog="tripwire", description="A guard between AI agents and their tools.")
    sub = p.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("serve", help="run the local daemon and dashboard")
    s.add_argument("--port", type=int, default=7777)
    s.add_argument("--judge", action="store_true", help="use the local isolated judge model for grey-zone actions")
    h = sub.add_parser("hook", help="Claude Code hook entry (Claude Code runs this, not you)")
    h.add_argument("event", choices=["UserPromptSubmit", "PreToolUse", "PostToolUse"])
    for verb in ("install", "uninstall"):
        i_ = sub.add_parser(verb, help=f"{verb} Tripwire hooks for an agent")
        i_.add_argument("agent", choices=["claude"])
        scope = i_.add_mutually_exclusive_group()
        scope.add_argument("--project", metavar="DIR", help="project folder (default: current folder)")
        scope.add_argument("--user", action="store_true", help="all projects (~/.claude/settings.json)")
    m = sub.add_parser("mcp-proxy", help="guard an MCP stdio server: tripwire mcp-proxy --name NAME -- <cmd...>")
    m.add_argument("--name", default="mcp", help="server name; tools show up as mcp__NAME__tool")
    m.add_argument("--profile", default=None, help="permission profile from the policy YAML for this session")
    pn = sub.add_parser("pins", help="signed MCP tool pins")
    pn.add_argument("action", choices=["list", "approve"])
    pn.add_argument("server", nargs="?")
    args, rest = p.parse_known_args(argv)

    if args.cmd == "hook":
        from .adapters.claude_code import hook_main
        return hook_main(args.event)

    if args.cmd in ("install", "uninstall"):
        from .adapters import claude_code
        fn = claude_code.install if args.cmd == "install" else claude_code.uninstall
        path = fn(project=args.project, user=args.user)
        print(f"Tripwire hooks {'installed in' if args.cmd == 'install' else 'removed from'} {path}")
        if args.cmd == "install":
            print("Start the daemon with `tripwire serve`. While it is down, tool calls are blocked.")
        return 0

    if args.cmd == "mcp-proxy":
        from .adapters import mcp_proxy
        return mcp_proxy.main(args.name, upstream or rest, profile=args.profile)

    if args.cmd == "pins":
        return _pins(args.action, args.server)

    if args.cmd == "serve":
        import uvicorn

        from .engine import Engine
        from .server import create_app

        judge = None
        if args.judge:
            from .judge import make_judge
            judge = make_judge()
        uvicorn.run(create_app(Engine(judge=judge)), host="127.0.0.1", port=args.port, log_level="warning")
        return 0
    return 1


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
