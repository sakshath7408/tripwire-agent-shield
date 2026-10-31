# Who can control Tripwire, and how to make it a hard boundary

## Default mode: no admin key on disk

Tripwire usually runs as you, and so does your agent. So Tripwire keeps nothing on disk that gives control of it.

| File in `~/.tripwire/` | What reading it gives the agent |
|---|---|
| `token` | Send a task, tool outputs and actions to check. Nothing else: every other endpoint answers 403. |
| `dashboards.json` | Nothing usable. It holds SHA-256 digests of paired browsers' cookies, not the cookies. |
| `audit.db`, `audit.key`, `sessions.json`, `settings.json` | History and settings. No credential. |
| `admin.key` | Gone. Older versions wrote it; the daemon deletes it on start and says so. |

Only a paired dashboard (its HttpOnly cookie) can answer an ASK, change settings, delete rules, reset the view, read
the feed or approve a new browser. That includes ASKs the MCP proxy holds: the hook token can't answer them, and an
unanswered one ends as a block.

A browser is paired only where a person is:

1. **`tripwire serve` in a terminal** prints a one-time link at startup, and another each time you press Enter there.
   `scripts/restart_daemon.sh` run from your terminal prints the link straight to that terminal, never to the log.
   Run without a terminal (an agent, cron), no link is printed anywhere.
2. **`tripwire open`** shows a 6-digit code. You approve it by typing the digits into the `tripwire serve` terminal,
   or by clicking OK in a dashboard you already paired, after checking the digits match. The daemon never shows the
   digits itself, so a request made by your agent can't be approved by anything your agent can reach.
3. **Hardened mode** (below): `sudo -u _tripwire tripwire open --print`.

While any live session has seen hidden instructions, Tripwire prints no startup link, refuses Enter-for-a-link and
demo links, and nobody can loosen autonomy (not even the dashboard). Reset the view first; attacks stay remembered.

### What default mode does not stop

A process running as your OS user can still do what you can. Be clear about it:

- **Your browser's cookie store.** Firefox keeps cookies in a plain SQLite file. Chrome encrypts them with a Keychain
  key (macOS asks before handing it out); Safari's are behind macOS privacy prompts. A same-user process that gets
  the cookie is the dashboard.
- **The daemon's memory.** A same-user process can attach a debugger to the daemon (ptrace) unless macOS's
  protections or Linux's `ptrace_scope` stop it.
- **Stopping or replacing the daemon.** A same-user process can kill the daemon. It can then start anything that
  answers on the daemon's port. It can also edit Tripwire's code, its folder, or `~/.claude/settings.json`.

What the engine blocks when the agent tries it (review 5, `tests/test_redteam5.py`):

- Kills that can reach the daemon: `pkill`/`pgrep | xargs kill`/`killall` whose pattern matches the daemon's real
  command line or process names (`pkill -f serve`, `killall Python`, `pkill python`), `kill` of its PID or of
  `kill -1`, `kill $(lsof -ti :PORT)` on its port (computed ports too), `ps | grep | xargs kill` chains, the same
  from Python (`os.kill` after `pgrep`), and `launchctl`/`systemctl` stopping it.
- Anything that serves on the daemon's port: `python -m http.server 7777`, `nc -l`, `socat`, `uvicorn --port`,
  `PORT=7777`, `ssh -L 7777:...`, and code (written, run or inline) that binds it, including `int('77'+'77')`.
- Reading `~/.tripwire`, listing hidden folders to find it, calls to the daemon's port, and running or importing
  Tripwire.

Normal process work still runs: `kill %1`, `kill $(lsof -ti:3000)`, `pkill -f "npm run dev"`, `killall node`.

The hook also checks who answers. At startup the daemon writes a per-boot key, its PID and its start time to
`~/.tripwire/daemon.json` (0600). Each PreToolUse sends a fresh nonce, and the daemon signs its verdict with
HMAC-SHA256 over the nonce, the decision and the request. The hook (and the MCP proxy) deny when the signature is
missing or wrong, or when the PID that wrote the key is gone. So a fake that says "allow" after a kill is refused
("Something other than Tripwire is answering on port 7777"). Cost: under 0.5 ms per call.

Be honest about what that is. A program running as you, outside the agent's tool calls, can read `daemon.json` too
and sign like the daemon. The check raises the bar (a fake must read the key and keep the real PID alive). It is not
an OS boundary. For that, run the daemon as its own user.

## Hardened mode: the daemon as its own OS user

```sh
tripwire harden            # prints every step for this computer (macOS or Linux); runs nothing
tripwire harden --apply    # runs them with sudo, after you type "harden"; sudo asks for your password
```

It never runs sudo on its own, and it refuses to run without a real terminal.

What it does (macOS user `_tripwire`, Linux user `tripwire`):

1. Stops the daemon you run as yourself.
2. Creates the user with no login shell and no password (`dscl` on macOS, with an id below 500 so it never shows at
   login; `useradd --system` on Linux).
3. Makes Tripwire's folder (`/usr/local/var/tripwire` on macOS, `/var/lib/tripwire` on Linux), owned by that user,
   mode 0700.
4. Installs Tripwire into `/opt/tripwire/venv`, owned by root. The daemon must not run code you (or your agent) can
   edit, and the hooks run from there too.
5. Writes one fresh hook token twice: the daemon's copy (0600, its user) and yours in `~/.tripwire/token`.
6. Starts the daemon at boot as that user: a launchd job (`/Library/LaunchDaemons/dev.tripwire.daemon.plist`) or a
   systemd service, with `serve --hardened`. `--hardened` refuses to start unless the user has no login shell and
   owns a 0700 folder, so an agent can't switch it on as you.
7. Points Claude Code's hooks at `/opt/tripwire/venv/bin/tripwire`.

Then pair your browser. This needs sudo, so the agent can't:

```sh
sudo -u _tripwire env TRIPWIRE_HOME=/usr/local/var/tripwire /opt/tripwire/venv/bin/tripwire open --print
```

It reads `console.key` from the daemon's 0700 folder (only that user can) and prints a one-time link. Open it in
your browser. After that, approve new browsers from the dashboard.

In hardened mode your agent keeps only the hook token. It can't read the audit log, the audit key, the dashboard
digests or the console key, and it can't stop the daemon or change its code.

Keep sudo asking for your password: an agent can use a sudo that doesn't ask.

### Lock the hooks too

Your agent can still edit `~/.claude/settings.json`, where the hooks live. Tripwire blocks the known ways, but for a
hard guarantee copy the `hooks` block that `tripwire install claude` wrote into Claude Code's managed settings, which
only root can change:

- macOS: `/Library/Application Support/ClaudeCode/managed-settings.json`
- Linux: `/etc/claude-code/managed-settings.json`

Check your Claude Code version's docs for the exact path.

### Still true in both modes

- If the daemon stops, the hooks deny every tool call (fail closed).
- In hardened mode the daemon can't read files inside your home folder, so checks that read a script from disk before
  it runs (`bash x.sh`, `make`) can't see those files. Checks of what the agent writes and runs still work.
- Tool calls that don't go through a hook or the MCP proxy are invisible to Tripwire.
