"""One summary table for the slide. Reruns every benchmark from scratch (no LLM, zero cost, ~30 s).

Run: uv run python bench/run_all.py [--quick]
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
import agentdojo_replay  # noqa: E402
import run_shell  # noqa: E402

RESULTS = Path(__file__).parent / "results"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--quick", action="store_true", help="3 tasks per suite, 10 commands per corpus (smoke run)")
    a = ap.parse_args()
    lim_ad, lim_sh = (3, 10) if a.quick else (None, None)

    ad = agentdojo_replay.run(limit=lim_ad, write=not a.quick, verbose=False)["overall"]
    sh = run_shell.run(limit=lim_sh, write=not a.quick)
    shm, shb = sh["malicious"], sh["benign"]

    rows = [
        ("AgentDojo (4 suites, important_instructions)",
         f"{ad['attack_stopped']}% ({ad['attack_stopped_by_block']}% hard block)", f"{ad['attack_pairs']} pairs",
         f"{ad['utility_retained']}% tasks ({100 - ad['fp_rate_per_call']:.1f}% calls)", f"{ad['median_latency_ms']} ms"),
        ("Shell attacks, no poisoned context",
         f"{shm['cold']['flagged_pct']}% ({shm['cold']['blocked_pct']}% hard block)", f"{shm['cold']['n']} cmds",
         f"{100 - shb['cold']['flagged_pct']:.1f}% of {shb['cold']['n']}", f"{sh['median_latency_ms']} ms"),
        ("Shell attacks, after reading poisoned file",
         f"{shm['poisoned']['flagged_pct']}% ({shm['poisoned']['blocked_pct']}% hard block)", f"{shm['poisoned']['n']} cmds",
         f"{100 - shb['poisoned']['flagged_pct']:.1f}% of {shb['poisoned']['n']}", f"{sh['median_latency_ms']} ms"),
    ]
    head = ("Benchmark", "Attacks stopped (block or ask)", "Size", "Benign allowed", "Median latency")
    widths = [max(len(str(r[i])) for r in rows + [head]) for i in range(5)]
    line = lambda r: "| " + " | ".join(str(c).ljust(w) for c, w in zip(r, widths)) + " |"  # noqa: E731
    out = [line(head), "|" + "|".join("-" * (w + 2) for w in widths) + "|"] + [line(r) for r in rows]
    table = "\n".join(out)
    print(("QUICK SMOKE RUN, not the real numbers\n" if a.quick else "") + table)
    if not a.quick:
        (RESULTS / "summary.md").write_text("# Tripwire benchmark summary\n\n" + table + "\n")
        (RESULTS / "summary.json").write_text(json.dumps({"agentdojo": ad, "shell": {
            k: {m: {x: v[m][x] for x in ("n", "flagged_pct", "blocked_pct")} for m in ("cold", "poisoned")}
            for k, v in (("malicious", shm), ("benign", shb))}, "shell_median_latency_ms": sh["median_latency_ms"]}, indent=1))
    return 0


if __name__ == "__main__":
    sys.exit(main())
