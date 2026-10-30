"""What the attacker received. Run in a second terminal during the demo:

    uv run python demo/attacker_view.py --watch

Reads demo/world/attacker_drop.json (written by the synthetic world when data reaches an attacker host,
an attacker email address or an attacker bank account). Everything in it is fake demo data.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path

DROP = Path(__file__).parent / "world" / "attacker_drop.json"


def render() -> str:
    items = json.loads(DROP.read_text() or "[]") if DROP.exists() else []
    lines = ["\033[1mATTACKER'S INBOX\033[0m  (synthetic, demo/world/attacker_drop.json)", ""]
    if not items:
        lines.append("\033[32;1m  empty: the attacker got nothing\033[0m")
    for d in items:
        if d["kind"] == "money":
            what = f"${d['amount']:,.2f} landed in {d['to']}"
        elif d["kind"] == "code_execution":
            what = f"their script ran on your machine (simulated): {d['url']}"
        else:
            what = f"{d.get('to') or d.get('url')}:"
        lines.append(f"\033[31;1m  [{d['ts']}] {d['kind']:15} {what}\033[0m")
        for l in str(d.get("data") or "").strip().splitlines()[:6]:
            lines.append(f"\033[31m      {l[:100]}\033[0m")
    return "\n".join(lines)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--watch", action="store_true", help="refresh every second")
    a = ap.parse_args()
    if not a.watch:
        print(render())
        return 0
    last = None
    try:
        while True:
            out = render()
            if out != last:
                os.system("clear")
                print(out)
                last = out
            time.sleep(1)
    except KeyboardInterrupt:
        return 0


if __name__ == "__main__":
    sys.exit(main())
