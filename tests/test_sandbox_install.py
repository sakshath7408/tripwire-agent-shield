"""`tripwire install claude --sandbox`: Claude Code's own OS sandbox (Seatbelt / bubblewrap) around the agent's shell.

Live check 31 Oct (Claude Code 2.1.314, haiku, macOS): with only these settings (no hooks), a disguised Python read of
the token, writes into TRIPWIRE_HOME and the settings files, a TCP connect and a bind on localhost, kill/pkill of the
daemon and `dangerouslyDisableSandbox` all failed; git commit and unittest in the project worked.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

from tripwire.adapters import claude_code


def _settings(tmp_path, monkeypatch, original: str | None = None) -> Path:
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    monkeypatch.setenv("TRIPWIRE_HOME", str(tmp_path / "tw"))
    monkeypatch.delenv("TRIPWIRE_PORT", raising=False)
    path = tmp_path / "proj" / ".claude" / "settings.json"
    if original is not None:
        path.parent.mkdir(parents=True)
        path.write_text(original)
    return path


def test_sandbox_settings_content(tmp_path, monkeypatch):
    _settings(tmp_path, monkeypatch)
    proj = tmp_path / "proj"
    s = claude_code.sandbox_settings(proj, 7861)
    sb = s["sandbox"]
    assert sb["enabled"] is True and sb["failIfUnavailable"] is True
    assert sb["allowUnsandboxedCommands"] is False  # dangerouslyDisableSandbox is ignored
    assert sb["autoAllowBashIfSandboxed"] is False  # never widen what runs without a prompt
    home = Path(os.environ["HOME"])
    tw = str(tmp_path / "tw")
    no_read = sb["filesystem"]["denyRead"]
    for p in (str(home / ".tripwire"), tw, str(home / ".claude" / "settings.json"),
              str(home / ".claude" / "settings.local.json")):
        assert p in no_read and p in sb["filesystem"]["denyWrite"]
    # The project's own settings: write-denied, never read-denied (that broke `git add -A` in a live run).
    proj_settings = str(proj.resolve() / ".claude" / "settings.json")
    assert proj_settings in sb["filesystem"]["denyWrite"] and proj_settings not in no_read
    import sys

    import tripwire
    assert str(Path(sys.prefix).resolve()) in sb["filesystem"]["denyWrite"]
    assert str(Path(tripwire.__file__).resolve().parent) in sb["filesystem"]["denyWrite"]
    assert sb["network"]["allowLocalBinding"] is False
    assert "127.0.0.1:7861" in sb["network"]["deniedDomains"] and "localhost:7861" in sb["network"]["deniedDomains"]
    assert {"name": "TRIPWIRE_TOKEN", "mode": "deny"} in sb["credentials"]["envVars"]
    deny = s["permissions"]["deny"]
    assert f"Read(/{tw}/**)" in deny and f"Edit(/{tw}/**)" in deny and f"Read(/{tw})" in deny
    assert f"Read(/{home}/.claude/settings.json)" in deny and f"Edit(/{proj_settings})" in deny
    assert "Bash(dangerouslyDisableSandbox:true)" in deny
    # Only Read(...) and Edit(...) path rules ever match in Claude Code; absolute paths need a leading "//".
    assert all(r.startswith(("Read(//", "Edit(//")) or r == "Bash(dangerouslyDisableSandbox:true)" for r in deny)
    assert len(deny) == len(set(deny))


def test_sandbox_port_follows_env(tmp_path, monkeypatch):
    _settings(tmp_path, monkeypatch)
    monkeypatch.setenv("TRIPWIRE_PORT", "7899")
    assert "127.0.0.1:7899" in claude_code.sandbox_settings(tmp_path, None)["sandbox"]["network"]["deniedDomains"]


def test_sandbox_install_merges_idempotent_and_restores_bytes(tmp_path, monkeypatch):
    original = ('{\n  "permissions": {"deny": ["Read(./.env)"], "allow": ["Bash(ls:*)"]},\n'
                '  "sandbox": {"enabled": true, "excludedCommands": ["docker *"],\n'
                '              "filesystem": {"denyRead": ["~/.aws"]}}\n}\n')
    path = _settings(tmp_path, monkeypatch, original)
    claude_code.install(project=str(path.parent.parent), command="/x/tripwire", sandbox=True)
    once = path.read_text()
    claude_code.install(project=str(path.parent.parent), command="/x/tripwire", sandbox=True)
    assert path.read_text() == once  # twice: nothing duplicated
    data = json.loads(once)
    assert data["permissions"]["deny"][0] == "Read(./.env)" and data["permissions"]["allow"] == ["Bash(ls:*)"]
    assert data["sandbox"]["excludedCommands"] == ["docker *"]
    assert data["sandbox"]["filesystem"]["denyRead"][0] == "~/.aws"
    assert data["sandbox"]["allowUnsandboxedCommands"] is False and "hooks" in data
    claude_code.uninstall(project=str(path.parent.parent))
    assert path.read_text() == original


def test_sandbox_install_into_fresh_project_leaves_nothing(tmp_path, monkeypatch):
    path = _settings(tmp_path, monkeypatch)
    claude_code.install(project=str(tmp_path / "proj"), command="/x/tripwire", sandbox=True)
    assert json.loads(path.read_text())["sandbox"]["enabled"] is True
    claude_code.uninstall(project=str(tmp_path / "proj"))
    assert not path.exists() and not path.parent.exists()


def test_sandbox_uninstall_after_user_edits_undoes_only_ours(tmp_path, monkeypatch):
    original = json.dumps({"sandbox": {"allowUnsandboxedCommands": True, "network": {"allowedDomains": ["pypi.org"]}},
                           "model": "haiku"})
    path = _settings(tmp_path, monkeypatch, original)
    claude_code.install(project=str(path.parent.parent), command="/x/tripwire", sandbox=True)
    data = json.loads(path.read_text())
    assert data["sandbox"]["allowUnsandboxedCommands"] is False
    data["model"] = "opus"  # the user changes something after install
    data["sandbox"]["filesystem"]["allowWrite"] = ["~/.cache/uv"]
    data["permissions"]["deny"].append("Read(./secrets/**)")
    path.write_text(json.dumps(data))
    claude_code.uninstall(project=str(path.parent.parent))
    assert json.loads(path.read_text()) == {
        "sandbox": {"allowUnsandboxedCommands": True, "network": {"allowedDomains": ["pypi.org"]},
                    "filesystem": {"allowWrite": ["~/.cache/uv"]}},
        "model": "opus", "permissions": {"deny": ["Read(./secrets/**)"]}}


def test_plain_install_after_sandbox_install_turns_it_off(tmp_path, monkeypatch):
    original = '{"model": "haiku"}\n'
    path = _settings(tmp_path, monkeypatch, original)
    claude_code.install(project=str(path.parent.parent), command="/x/tripwire", sandbox=True)
    claude_code.install(project=str(path.parent.parent), command="/x/tripwire")
    data = json.loads(path.read_text())
    assert "sandbox" not in data and "permissions" not in data and "hooks" in data
    claude_code.uninstall(project=str(path.parent.parent))
    assert path.read_text() == original


def test_cli_install_sandbox_prints_what_the_os_enforces(tmp_path, monkeypatch, capsys):
    path = _settings(tmp_path, monkeypatch)
    from tripwire.cli import main
    assert main(["install", "claude", "--project", str(tmp_path / "proj"), "--port", "7861", "--sandbox"]) == 0
    out = capsys.readouterr().out
    assert "OS sandbox is on" in out and "dangerouslyDisableSandbox is ignored" in out and "7861" in out
    assert json.loads(path.read_text())["sandbox"]["network"]["deniedDomains"][0] == "127.0.0.1:7861"
    assert main(["uninstall", "claude", "--project", str(tmp_path / "proj")]) == 0
    assert not path.exists()
    assert main(["install", "claude", "--project", str(tmp_path / "proj")]) == 0
    assert "--sandbox" in capsys.readouterr().out
