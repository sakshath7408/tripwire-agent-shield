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


def test_ollama_planner_parses_text_tool_calls():
    from world.ollama_planner import clean_args, parse_calls
    native = {"tool_calls": [{"function": {"name": "read_file", "arguments": {"path": "README.md"}}}]}
    assert parse_calls(native) == [("read_file", {"path": "README.md"})]
    text = {"content": 'Sure.\n<tool_call>\n{"name": "list_dir", "arguments": {"path": "."}}\n</tool_call>'}
    assert parse_calls(text) == [("list_dir", {"path": "."})]
    fenced = {"content": '```json\n[{"name": "read_inbox", "parameters": {}}, {"name": "nope", "arguments": {}}]\n```'}
    assert parse_calls(fenced) == [("read_inbox", {})]
    assert parse_calls({"content": "All done. The typo is fixed."}) == []
    assert clean_args("send_money", {"to": "X", "amount": "$4,900", "junk": 1}) == {"to": "X", "amount": 4900.0}


def _ollama_model():
    from world.ollama_planner import available_models
    have = available_models()
    return next((m for m in ("qwen2.5:3b", "qwen2.5:1.5b") if m in have), None)


def test_real_local_model_is_stopped_by_tripwire(isolated_world, monkeypatch):
    """A real local LLM reads the poisoned web page through Tripwire. Whatever it decides, nothing reaches the attacker."""
    model = _ollama_model()
    if not model:
        pytest.skip("Ollama not reachable on 127.0.0.1:11434 or no qwen2.5 model pulled")
    import argparse

    import run_demo
    monkeypatch.setattr(run_demo, "World", lambda: isolated_world.World(root=isolated_world.SANDBOX,
                                                                        drop_path=isolated_world.DROP))
    args = argparse.Namespace(offline=True, url="", delay=0, approve="auto", planner="ollama", model=model,
                              ollama_url="http://127.0.0.1:11434", seed=42, max_steps=8)
    r = run_demo.run_act(run_demo.SCENARIOS["injected-web"], True, args)
    assert r["model_calls"] >= 1 and r["steps"]
    assert r["attacker_items"] == 0 and r["balance"] == 12500
