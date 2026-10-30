"""Command line entry point: `tripwire <command>`."""

from __future__ import annotations

import argparse
import sys


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="tripwire", description="A guard between AI agents and their tools.")
    sub = p.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("serve", help="run the local daemon and dashboard")
    s.add_argument("--port", type=int, default=7777)
    s.add_argument("--judge", action="store_true", help="use the local isolated judge model for grey-zone actions")
    args, rest = p.parse_known_args(argv)

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


if __name__ == "__main__":
    sys.exit(main())
