"""`tripwire harden`: run the daemon as its own OS user, so the agent can't read or change anything it keeps.

By default it only prints the steps. `--apply` runs them with sudo, after you type a confirmation word in your own
terminal. Nothing here ever runs sudo on its own, and the plan is plain data so it can be checked without creating
a user (tests/test_guard4.py).
"""

from __future__ import annotations

import getpass
import os
import secrets
import shlex
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path

CONFIRM = "harden"
TOKEN_MARK = "<new hook token>"
PREFIX = "/opt/tripwire"
MAC_USER, LINUX_USER = "_tripwire", "tripwire"
MAC_HOME, LINUX_HOME = "/usr/local/var/tripwire", "/var/lib/tripwire"
PLIST = "/Library/LaunchDaemons/dev.tripwire.daemon.plist"
UNIT = "/etc/systemd/system/tripwire.service"


@dataclass
class Step:
    why: str
    argv: list[str] = field(default_factory=list)
    stdin: str | None = None  # fed to the command; TOKEN_MARK is replaced by the real token on --apply
    sudo: bool = True
    note: bool = False  # a manual step: printed, never run

    def shell(self) -> str:
        if self.note:
            return f"# {self.why}"
        cmd = " ".join(shlex.quote(a) for a in self.argv)
        if self.stdin is not None:
            body = self.stdin if self.stdin == TOKEN_MARK else self.stdin.rstrip("\n")
            cmd = f"{cmd} <<'EOF'\n{body}\nEOF"
        return f"# {self.why}\n{cmd}"


def system_name() -> str:
    return "macos" if sys.platform == "darwin" else "linux"


def free_mac_id(used: set[int]) -> int:
    """A free id below 500 (macOS hides those from the login window) for both the user and its group."""
    for n in range(300, 500):
        if n not in used:
            return n
    raise RuntimeError("no free user id between 300 and 499")


def used_mac_ids() -> set[int]:
    used: set[int] = set()
    for kind, attr in (("/Users", "UniqueID"), ("/Groups", "PrimaryGroupID")):
        try:
            out = subprocess.run(["dscl", ".", "-list", kind, attr], capture_output=True, text=True, timeout=10).stdout
        except (OSError, subprocess.SubprocessError):
            continue
        for line in out.splitlines():
            parts = line.split()
            if parts and parts[-1].lstrip("-").isdigit():
                used.add(int(parts[-1]))
    return used


def user_exists(name: str) -> bool:
    import pwd
    try:
        pwd.getpwnam(name)
        return True
    except KeyError:
        return False


def _write(path: str, content: str, owner: str, mode: str, why: str) -> Step:
    q = shlex.quote(path)
    return Step(why, ["sh", "-c", f"umask 077 && cat > {q} && chown {owner} {q} && chmod {mode} {q}"], stdin=content)


def _sudo(argv: list[str]) -> list[str]:
    return ["sudo", *argv]


def plan(system: str, *, port: int = 7777, source: str | None = None, dev_home: str | None = None,
         used_ids: set[int] | None = None, exists: bool | None = None, python: str = "/usr/bin/python3") -> list[Step]:
    """Every step, in order. `source` is the Tripwire folder to install from (this checkout)."""
    source = source or str(Path(__file__).resolve().parents[2])
    dev_home = dev_home or str(Path.home())
    mac = system == "macos"
    user = MAC_USER if mac else LINUX_USER
    home = MAC_HOME if mac else LINUX_HOME
    exe = f"{PREFIX}/venv/bin/tripwire"
    exists = user_exists(user) if exists is None else exists
    steps = [Step("Stop the daemon you run as yourself (the new one takes over this port)",
                  ["pkill", "-f", f"tripwire serve --port {port}"], sudo=False)]
    if not exists:
        if mac:
            uid = free_mac_id(used_mac_ids() if used_ids is None else used_ids)
            g, u = f"/Groups/{user}", f"/Users/{user}"
            steps += [
                Step(f"Create the group {user}", ["dscl", ".", "-create", g]),
                Step("Give the group its id", ["dscl", ".", "-create", g, "PrimaryGroupID", str(uid)]),
                Step(f"Create the user {user}", ["dscl", ".", "-create", u]),
                Step("Give it an id below 500, so it never shows at login", ["dscl", ".", "-create", u, "UniqueID", str(uid)]),
                Step("Put it in its own group", ["dscl", ".", "-create", u, "PrimaryGroupID", str(uid)]),
                Step("No login shell: nobody can log in as it", ["dscl", ".", "-create", u, "UserShell", "/usr/bin/false"]),
                Step("No home folder of its own", ["dscl", ".", "-create", u, "NFSHomeDirectory", "/var/empty"]),
                Step("No password", ["dscl", ".", "-create", u, "Password", "*"]),
                Step("Name it", ["dscl", ".", "-create", u, "RealName", "Tripwire daemon"]),
                Step("Hide it", ["dscl", ".", "-create", u, "IsHidden", "1"]),
            ]
        else:
            steps.append(Step(f"Create the system user {user} with no login shell",
                              ["useradd", "--system", "--user-group", "--home-dir", home, "--no-create-home",
                               "--shell", "/usr/sbin/nologin", user]))
    steps += [
        Step("Tripwire's private folder (only that user can open it)", ["mkdir", "-p", home]),
        Step("Owned by that user", ["chown", f"{user}:{user}", home]),
        Step("Mode 0700", ["chmod", "700", home]),
        Step("Install Tripwire where only root can change it (the daemon must not run code you or the agent can edit)",
             ["mkdir", "-p", PREFIX]),
        Step("A virtual environment for it", [python, "-m", "venv", f"{PREFIX}/venv"]),
        Step("Install this checkout into it (a copy, not a link to your folder)",
             [f"{PREFIX}/venv/bin/pip", "install", "--quiet", "--no-cache-dir", source]),
        _write(f"{home}/token", TOKEN_MARK, f"{user}:{user}", "600",
               "The daemon's copy of the hook token (the only thing your agent's hooks need)"),
        Step("Your own copy of the hook token, readable by you (and so by your agent): it can only send tasks, tool "
             "outputs and actions to check", ["sh", "-c", f"umask 077 && mkdir -p {shlex.quote(dev_home + '/.tripwire')} "
                                                          f"&& cat > {shlex.quote(dev_home + '/.tripwire/token')}"],
             stdin=TOKEN_MARK, sudo=False),
    ]
    if mac:
        plist = f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>dev.tripwire.daemon</string>
  <key>UserName</key><string>{user}</string>
  <key>GroupName</key><string>{user}</string>
  <key>ProgramArguments</key>
  <array><string>{exe}</string><string>serve</string><string>--port</string><string>{port}</string><string>--hardened</string></array>
  <key>EnvironmentVariables</key><dict><key>TRIPWIRE_HOME</key><string>{home}</string></dict>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>StandardOutPath</key><string>{home}/daemon.log</string>
  <key>StandardErrorPath</key><string>{home}/daemon.log</string>
</dict>
</plist>
"""
        steps += [
            _write(PLIST, plist, "root:wheel", "644", "A launchd job that runs the daemon as that user at boot"),
            Step("Start it now", ["launchctl", "bootstrap", "system", PLIST]),
        ]
    else:
        unit = f"""[Unit]
Description=Tripwire daemon
After=network.target

[Service]
User={user}
Group={user}
Environment=TRIPWIRE_HOME={home}
ExecStart={exe} serve --port {port} --hardened
Restart=on-failure
NoNewPrivileges=yes
ProtectSystem=strict
ReadWritePaths={home}

[Install]
WantedBy=multi-user.target
"""
        steps += [
            _write(UNIT, unit, "root:root", "644", "A systemd service that runs the daemon as that user"),
            Step("Load it", ["systemctl", "daemon-reload"]),
            Step("Start it now and at boot", ["systemctl", "enable", "--now", "tripwire"]),
        ]
    steps += [
        Step("Point Claude Code's hooks at the root-owned copy (your agent can't edit the hook code)",
             [exe, "install", "claude", "--user"] + ([] if port == 7777 else ["--port", str(port)]), sudo=False),
        Step(f"Pair your browser (needs sudo, so the agent can't): sudo -u {user} env TRIPWIRE_HOME={home} "
             f"{exe} open --print   then open the link it prints", note=True),
        Step("Optional: lock the hooks too by copying the `hooks` block into Claude Code's managed settings "
             "(/Library/Application Support/ClaudeCode/managed-settings.json on macOS, "
             "/etc/claude-code/managed-settings.json on Linux)", note=True),
    ]
    for s in steps:
        if s.sudo and not s.note:
            s.argv = _sudo(s.argv)
    return steps


def render(steps: list[Step]) -> str:
    return "\n\n".join(s.shell() for s in steps)


def apply(steps: list[Step], *, run=subprocess.run, ask=input, tty: bool | None = None, out=print,
          port: int = 7777) -> int:
    """Run the plan, only after a person types CONFIRM in a real terminal. sudo itself asks for the password."""
    tty = (sys.stdin.isatty() and sys.stdout.isatty()) if tty is None else tty
    if not tty:
        out("`tripwire harden --apply` only runs in your own terminal, because it uses sudo. Nothing was changed.")
        return 1
    n = sum(1 for s in steps if not s.note)
    out(render(steps))
    out(f"\nThis runs the {n} commands above, {sum(1 for s in steps if s.sudo and not s.note)} of them with sudo.")
    try:
        answer = ask(f"Type '{CONFIRM}' to run them (anything else cancels): ")
    except EOFError:
        answer = ""
    if answer.strip().lower() != CONFIRM:
        out("Cancelled. Nothing was changed.")
        return 1
    token = secrets.token_urlsafe(32)
    for s in steps:
        if s.note:
            continue
        stdin = None if s.stdin is None else s.stdin.replace(TOKEN_MARK, token)
        r = run(s.argv, input=stdin, text=True)
        if r.returncode != 0 and s.argv[:2] != ["pkill", "-f"]:  # pkill exits 1 when nothing was running
            out(f"Stopped: this step failed ({s.why}). Fix it and run `tripwire harden --apply` again.")
            return 1
    out("Done. Waiting for the daemon to answer...")
    for _ in range(50):
        if run(["curl", "-fs", f"http://127.0.0.1:{port}/healthz"], input=None, text=True, capture_output=True).returncode == 0:
            break
        time.sleep(0.2)
    for s in steps:
        if s.note:
            out(s.why)
    return 0


def main(apply_it: bool, system: str | None, port: int) -> int:
    system = system or system_name()
    steps = plan(system, port=port)
    if not apply_it:
        print(f"# Hardened Tripwire for {system} (user: {MAC_USER if system == 'macos' else LINUX_USER}). "
              f"Run these yourself, or `tripwire harden --apply` to run them with sudo after you confirm.\n"
              f"# You are {getpass.getuser()}; your agent keeps only the hook token.\n")
        print(render(steps))
        return 0
    if os.geteuid() == 0:
        print("Run `tripwire harden --apply` as yourself, not as root: it writes your own copy of the hook token.")
        return 1
    return apply(steps, port=port)
