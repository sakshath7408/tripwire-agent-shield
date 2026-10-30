"""The hosted live demo (web/demo_runner.py, api/run.py): the real engine, every scenario, both acts."""

import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "web"))
sys.path.insert(0, str(ROOT / "api"))

import demo_runner  # noqa: E402
import run as api_run  # noqa: E402

ATTACKS = ["injected-doc", "injected-web", "sensitive-data", "beyond-permission"]


@pytest.mark.parametrize("scenario", ATTACKS)
def test_attack_succeeds_without_tripwire_and_fails_with_it(scenario):
    off = demo_runner.run(scenario, guarded=False)
    on = demo_runner.run(scenario, guarded=True)
    assert off["attacker_items"] > 0 and off["attacker_inbox"], "the unguarded agent should be hijacked"
    assert on["attacker_items"] == 0 and on["attacker_inbox"] == []
    assert on["balance"] == on["start_balance"]
    assert on["task_completed"], on["detail"]
    assert on["verdicts"]["block"] > 0
    # every guarded step carries the engine's own verdict, and the replay events include it
    for step in on["steps"]:
        v = step["verdict"]
        assert v["decision"] in ("allow", "ask", "block") and "findings" in v and "elapsed_ms" in v
        assert any(e["kind"] == "verdict" and e["data"]["id"] == v["id"] for e in step["events"])
        if step["human"]:
            assert v["decision"] == "ask"


def test_money_leaves_only_without_tripwire():
    off = demo_runner.run("beyond-permission", guarded=False)
    on = demo_runner.run("beyond-permission", guarded=True)
    assert off["balance"] < off["start_balance"]
    assert on["balance"] == on["start_balance"]


@pytest.mark.parametrize("guarded", [False, True])
def test_legit_task_completes_and_nothing_leaks(guarded):
    r = demo_runner.run("legit", guarded=guarded)
    assert r["task_completed"], r["detail"]
    assert r["attacker_items"] == 0
    if guarded:
        assert r["verdicts"]["block"] == 0 and r["verdicts"]["ask"] == 0


def test_runs_in_a_temp_world_and_leaves_the_local_sandbox_alone():
    local_drop = ROOT / "demo" / "world" / "attacker_drop.json"
    before = local_drop.read_text() if local_drop.exists() else None
    r = demo_runner.run("injected-doc", guarded=False)
    after = local_drop.read_text() if local_drop.exists() else None
    assert before == after
    assert r["attacker_items"] > 0
    cwd = demo_runner.run("injected-doc", guarded=True)["task_events"][0]["data"]["cwd"]
    assert cwd.startswith("/tmp/") and not Path(cwd).exists()  # built under /tmp, deleted afterwards


def test_api_handler_validates_and_returns_json():
    status, body = api_run.respond("scenario=injected-web&guard=1")
    assert status == 200 and body["guarded"] is True and json.dumps(body)
    assert api_run.respond("scenario=nope&guard=1")[0] == 400
    assert api_run.respond("scenario=legit&guard=2")[0] == 400
