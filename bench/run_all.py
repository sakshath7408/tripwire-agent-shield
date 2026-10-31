"""Every benchmark from scratch, no LLM, zero cost, about a minute on a laptop.

Run: uv run --group bench python bench/run_all.py [--quick] [--workers N]

Prints two tables:
1. The headline (default AgentDojo attack plus the shell corpus), written to results/summary.{md,json} as before.
2. The honesty matrix: each AgentDojo attack text, with the injection-phrase detector on and off. Columns are
   attacks stopped (block or ask), hard block, and benign tasks allowed. Written to results/matrix.{md,json}.
   Per-configuration results go to results/agentdojo_<attack>[_nomarkers].{json,md}.

"Phrase detector off" swaps taint.INJECTION_MARKERS for a regex that never matches, inside the worker process only.
Benign numbers do not depend on the attack text, so they are measured once per detector setting.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from concurrent.futures import ProcessPoolExecutor
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
import agentdojo_replay  # noqa: E402
import run_shell  # noqa: E402

RESULTS = Path(__file__).parent / "results"
SUITES = ["workspace", "travel", "banking", "slack"]
DEFAULT_ATTACK = "important_instructions"


def _job(attack: str, markers: bool, suite: str, limit: int | None) -> dict:
    sys.path.insert(0, str(Path(__file__).parent))
    import agentdojo_replay as R

    return R.run([suite], limit=limit, write=False, verbose=False, attack=attack, markers=markers,
                 do_benign=attack == DEFAULT_ATTACK)


def _shell(markers: bool, limit: int | None, write: bool) -> dict:
    agentdojo_replay.set_markers(markers)
    try:
        return run_shell.run(limit=limit, write=write)
    finally:
        agentdojo_replay.set_markers(True)


def _table(head: tuple, rows: list[tuple]) -> str:
    widths = [max(len(str(r[i])) for r in rows + [head]) for i in range(len(head))]
    line = lambda r: "| " + " | ".join(str(c).ljust(w) for c, w in zip(r, widths)) + " |"  # noqa: E731
    return "\n".join([line(head), "|" + "|".join("-" * (w + 2) for w in widths) + "|"] + [line(r) for r in rows])


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--quick", action="store_true", help="3 tasks per suite, 10 commands per corpus (smoke run, writes nothing)")
    ap.add_argument("--workers", type=int, default=os.cpu_count() or 4)
    ap.add_argument("--attacks", default=",".join(agentdojo_replay.ATTACKS), help="comma list of AgentDojo attacks")
    a = ap.parse_args()
    lim_ad, lim_sh = (3, 10) if a.quick else (None, None)
    attacks = [x for x in a.attacks.split(",") if x]
    if DEFAULT_ATTACK not in attacks:
        attacks.insert(0, DEFAULT_ATTACK)
    t0 = time.time()

    configs = [(atk, m) for m in (True, False) for atk in attacks]
    with ProcessPoolExecutor(max_workers=a.workers) as pool:
        # Biggest suite first so the slow jobs start early.
        futs = {(atk, m, s): pool.submit(_job, atk, m, s, lim_ad) for s in SUITES for atk, m in configs}
        reports = {(atk, m): agentdojo_replay.merge([futs[(atk, m, s)].result() for s in SUITES]) for atk, m in configs}

    shell = {m: _shell(m, lim_sh, write=(m and not a.quick)) for m in (True, False)}

    # Benign numbers come from the default attack's run of the same detector setting.
    benign = {m: reports[(DEFAULT_ATTACK, m)]["overall"] for m in (True, False)}
    if not a.quick:
        for (atk, m), r in reports.items():
            agentdojo_replay.save(r, full=(atk == DEFAULT_ATTACK))

    ad = reports[(DEFAULT_ATTACK, True)]["overall"]
    shm, shb = shell[True]["malicious"], shell[True]["benign"]
    rows = [
        (f"AgentDojo (4 suites, {DEFAULT_ATTACK})",
         f"{ad['attack_stopped']}% ({ad['attack_stopped_by_block']}% hard block)", f"{ad['attack_pairs']} pairs",
         f"{ad['utility_retained']}% tasks ({100 - ad['fp_rate_per_call']:.1f}% calls)", f"{ad['median_latency_ms']} ms"),
        ("Shell attacks, no poisoned context",
         f"{shm['cold']['flagged_pct']}% ({shm['cold']['blocked_pct']}% hard block)", f"{shm['cold']['n']} cmds",
         f"{100 - shb['cold']['flagged_pct']:.1f}% of {shb['cold']['n']}", f"{shell[True]['median_latency_ms']} ms"),
        ("Shell attacks, after reading poisoned file",
         f"{shm['poisoned']['flagged_pct']}% ({shm['poisoned']['blocked_pct']}% hard block)", f"{shm['poisoned']['n']} cmds",
         f"{100 - shb['poisoned']['flagged_pct']:.1f}% of {shb['poisoned']['n']}", f"{shell[True]['median_latency_ms']} ms"),
    ]
    summary = _table(("Benchmark", "Attacks stopped (block or ask)", "Size", "Benign allowed", "Median latency"), rows)

    mrows, mjson = [], []
    for atk in attacks:
        for m in (True, False):
            o, b = reports[(atk, m)]["overall"], benign[m]
            mrows.append((atk, "on" if m else "OFF", o["attack_pairs"], f"{o['attack_stopped']}%",
                          f"{o['attack_stopped_by_block']}%", f"{b['utility_retained']}%", f"{b['benign_fully_allowed']}%"))
            mjson.append({"attack": atk, "phrase_detector": m, "pairs": o["attack_pairs"], "stopped": o["attack_stopped"],
                          "hard_block": o["attack_stopped_by_block"], "benign_tasks_allowed": b["utility_retained"],
                          "benign_tasks_no_ask": b["benign_fully_allowed"],
                          "by_suite": {k: {"stopped": v["attack_stopped"], "hard_block": v["attack_stopped_by_block"]}
                                       for k, v in reports[(atk, m)]["suites"].items()}})
    for m in (True, False):
        sm, sb = shell[m]["malicious"], shell[m]["benign"]
        for mode in ("cold", "poisoned"):
            mrows.append((f"shell corpus, {mode}", "on" if m else "OFF", sm[mode]["n"], f"{sm[mode]['flagged_pct']}%",
                          f"{sm[mode]['blocked_pct']}%", f"{100 - sb[mode]['flagged_pct']:.1f}% (cmds)", "-"))
            mjson.append({"attack": f"shell_{mode}", "phrase_detector": m, "pairs": sm[mode]["n"],
                          "stopped": sm[mode]["flagged_pct"], "hard_block": sm[mode]["blocked_pct"],
                          "benign_cmds_allowed": round(100 - sb[mode]["flagged_pct"], 1)})
    matrix = _table(("Attack", "Phrase detector", "Pairs", "Stopped (block or ask)", "Hard block",
                     "Benign tasks allowed", "Benign tasks, no ask"), mrows)

    took = time.time() - t0
    print(("QUICK SMOKE RUN, not the real numbers\n" if a.quick else "") + summary + "\n\n" + matrix
          + f"\n\n{len(configs)} AgentDojo configurations in {took:.0f} s")
    if not a.quick:
        stamp = datetime.now().strftime("%d %b %Y %H:%M")
        (RESULTS / "summary.md").write_text("# Tripwire benchmark summary\n\n" + summary + "\n")
        (RESULTS / "summary.json").write_text(json.dumps({"agentdojo": ad, "shell": {
            k: {m: {x: v[m][x] for x in ("n", "flagged_pct", "blocked_pct")} for m in ("cold", "poisoned")}
            for k, v in (("malicious", shm), ("benign", shb))}, "shell_median_latency_ms": shell[True]["median_latency_ms"]}, indent=1))
        (RESULTS / "matrix.md").write_text(
            f"# Tripwire: every AgentDojo attack, with and without the phrase detector\n\nRun {stamp} with "
            "`uv run python bench/run_all.py`. \"Phrase detector OFF\" means `INJECTION_MARKERS` never matches, so "
            "only provenance, intent, secrets, shell and policy checks are left. Benign tasks allowed means no hard "
            "block in the task (an ask still counts as allowed); the last column also excludes asks.\n\n"
            + matrix + "\n")
        (RESULTS / "matrix.json").write_text(json.dumps({"run": stamp, "rows": mjson}, indent=1))
    return 0


if __name__ == "__main__":
    sys.exit(main())
