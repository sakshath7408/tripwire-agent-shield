"""Smoke tests: the corpora load, the benchmark runners run on a small subset, the demo world behaves."""

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "bench"))
sys.path.insert(0, str(ROOT / "demo"))


def test_shell_corpus_loads():
    import run_shell
    mal, ben = run_shell.load()
    assert len(mal) >= 80 and len(ben) >= 80
    assert all(m["command"] and m["category"] and m.get("scenario") for m in mal)
    assert len({m["id"] for m in mal + ben}) == len(mal) + len(ben)
    # nothing in the corpus may point at a real attacker host
    assert not any("attacker." in m["command"] and "attacker.invalid" not in m["command"] for m in mal)


def test_shell_runner_subset():
    import run_shell
    r = run_shell.run(limit=5, write=False)
    assert r["malicious"]["cold"]["n"] == 5 and r["benign"]["cold"]["n"] == 5
    assert r["median_latency_ms"] is not None


def test_agentdojo_replay_subset():
    pytest.importorskip("agentdojo")
    import agentdojo_replay
    r = agentdojo_replay.run(suites=["banking"], limit=2, write=False, verbose=False)
    s = r["suites"]["banking"]
    assert s["user_tasks"] == 2 and s["attack_pairs"] > 0
    assert r["overall"]["evaluations"] > 0


def test_agentdojo_overrides_only_known_tools():
    pytest.importorskip("agentdojo")
    import agentdojo_replay
    from agentdojo.task_suite.load_suites import get_suites
    names = {t.name for s in get_suites("v1.2.2").values() for t in s.tools}
    assert set(agentdojo_replay.load_policy(True).capabilities) <= names


@pytest.fixture
def isolated_world(tmp_path, monkeypatch):
    from world import world as w
    monkeypatch.setattr(w, "SANDBOX", tmp_path / "sandbox")
    monkeypatch.setattr(w, "DROP", tmp_path / "drop.json")
    return w


def _run(scenario, guarded, isolated_world, monkeypatch):
    import argparse

    import run_demo
    monkeypatch.setattr(run_demo, "World", lambda: isolated_world.World(root=isolated_world.SANDBOX,
                                                                        drop_path=isolated_world.DROP))
    args = argparse.Namespace(offline=True, url="", delay=0, approve="auto")
    return run_demo.run_act(run_demo.SCENARIOS[scenario], guarded, args)


def test_world_stays_in_sandbox(isolated_world):
    w = isolated_world.World(root=isolated_world.SANDBOX, drop_path=isolated_world.DROP).reset("legit")
    assert w.resolve("~/.ssh/id_rsa").is_relative_to(isolated_world.SANDBOX)
    assert w.resolve("/etc/passwd").is_relative_to(isolated_world.SANDBOX)
    assert "error" in w.call("read_file", {"path": "../../../../../../etc/passwd"})
    assert "not executed" in w.call("run_command", {"command": "rm -rf ~/"})


@pytest.mark.parametrize("scenario", ["injected-doc", "sensitive-data", "beyond-permission"])
def test_attack_succeeds_without_guard_and_fails_with_it(scenario, isolated_world, monkeypatch):
    before = _run(scenario, False, isolated_world, monkeypatch)
    after = _run(scenario, True, isolated_world, monkeypatch)
    assert before["attacker_items"] > 0
    assert after["attacker_items"] == 0 and after["balance"] == 12500
    assert after["task_completed"]


def test_legit_task_untouched(isolated_world, monkeypatch):
    r = _run("legit", True, isolated_world, monkeypatch)
    assert r["task_completed"] and r["verdicts"]["block"] == 0 and r["verdicts"]["ask"] == 0


def test_injected_web_task_still_completes(isolated_world, monkeypatch):
    before = _run("injected-web", False, isolated_world, monkeypatch)
    after = _run("injected-web", True, isolated_world, monkeypatch)
    assert before["attacker_items"] > 0 and after["attacker_items"] == 0
    assert after["task_completed"]
