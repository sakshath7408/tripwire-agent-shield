# Hardening: run the daemon as its own OS user

By default Tripwire runs as you, and so does your agent. Tripwire splits its credentials and blocks every route to
them that we know of. But a process running as your OS user can, in principle, read any file you can, including
`~/.tripwire/admin.key`. So the default setup raises the bar. It is not a hard boundary.

For a hard boundary, run the daemon as a separate OS user. Then the agent can't read the admin key, the audit key or
the audit log, and it can't kill the daemon. It keeps only the hook token, and that token can do three things:
send a task, send tool outputs, and ask for a verdict.

## What lives where

| File | Who reads it | What it allows |
|---|---|---|
| `/var/lib/tripwire/admin.key` | the `tripwire` user only | everything: pairing, settings, resets, rules, audit |
| `/var/lib/tripwire/audit.db`, `audit.key` | the `tripwire` user only | the signed audit log |
| `~/.tripwire/token` (a copy) | you and your agent | `POST /v1/task`, `/v1/observe`, `/v1/evaluate` only |

## Steps (macOS)

```sh
# 1. A user with no login shell and no home folder to speak of
sudo sysadminctl -addUser _tripwire -fullName "Tripwire daemon" -shell /usr/bin/false -home /var/empty
sudo mkdir -p /var/lib/tripwire && sudo chown _tripwire /var/lib/tripwire && sudo chmod 700 /var/lib/tripwire

# 2. Install Tripwire somewhere that user can run but you can't change
sudo mkdir -p /opt/tripwire && sudo chown root /opt/tripwire
sudo uv venv /opt/tripwire/.venv && sudo uv pip install --python /opt/tripwire/.venv /path/to/agent-shield

# 3. Start the daemon as that user (keep this terminal open, or make it a launchd job)
sudo -u _tripwire env TRIPWIRE_HOME=/var/lib/tripwire /opt/tripwire/.venv/bin/tripwire serve

# 4. Give your own account a copy of the hook token, and only that
mkdir -p ~/.tripwire && chmod 700 ~/.tripwire
sudo cat /var/lib/tripwire/token > ~/.tripwire/token && chmod 600 ~/.tripwire/token

# 5. Install the hooks for your agent (they read ~/.tripwire/token)
/opt/tripwire/.venv/bin/tripwire install claude --user

# 6. Pair the dashboard. This needs sudo, so the agent can't do it
sudo -u _tripwire env TRIPWIRE_HOME=/var/lib/tripwire /opt/tripwire/.venv/bin/tripwire open --print
```

## Steps (Linux)

Same as above, with these two changes:

- Step 1: `sudo useradd --system --home-dir /var/lib/tripwire --shell /usr/sbin/nologin tripwire`.
- Step 3: run the daemon from a systemd unit with `User=tripwire` and `Environment=TRIPWIRE_HOME=/var/lib/tripwire`.

## Lock the hooks too

Your agent can still edit `~/.claude/settings.json`, which is where the hooks live. Tripwire blocks the known ways to
do that (`tripwire uninstall`, `claude config ... hooks`, moving or deleting `~/.claude`, writing the settings file).
For a hard guarantee, put the hooks in Claude Code's managed settings file, which only root can change:

- macOS: `/Library/Application Support/ClaudeCode/managed-settings.json`
- Linux: `/etc/claude-code/managed-settings.json`

Copy the `hooks` block that `tripwire install claude` wrote into that file. Check your Claude Code version's docs for
the exact path.

## What is still true

- If the daemon stops, the hooks deny every tool call (fail closed). Nothing gets through unchecked.
- The agent can still send a task for a new session with the hook token. It cannot re-task a session that saw hidden
  instructions, and it cannot reset sessions, pair a browser or change autonomy.
- Tool calls that don't go through a hook or the MCP proxy are invisible to Tripwire, as before.
