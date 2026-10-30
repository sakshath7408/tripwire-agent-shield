# Presenting Tripwire

The full talk track is `demo/SCRIPT.md`. This page is the stage kit around it.

![Tripwire dashboard during the demo](demo-video/tripwire-demo.gif)

## Two commands before you go on

```
scripts/preflight.sh     # green/red checklist, about 40 s
scripts/stage.sh         # clean daemon, empty view, one-time presenter link, prints the next commands
```

`preflight.sh` checks: uv env synced, daemon healthy and really Tripwire on the port (or the port is free),
the daemon accepts your token (`~/.tripwire/token`), the autonomy level is balanced, dashboard and its assets load, a fast test subset (engine, adapters, shell), all five demo scenarios pass
both acts offline, the backup video exists, Ollama (optional), and AC power. It only reminds you about
Do Not Disturb and fonts. It never changes a system setting.

`stage.sh` restarts the daemon with `scripts/restart_daemon.sh` and an empty view (`--clear-view`; attacks it saw
stay remembered), empties the attacker's inbox, pins the autonomy level to balanced (the level is saved across restarts, so a strict rehearsal would
otherwise change the show; `AUTONOMY=strict scripts/stage.sh` to choose another), lists any learned rules
(they survive a reset and can change what the demo asks; it never deletes them), prints a one-time
presenter link straight to your terminal (Cmd-click it once to pair this browser), opens
`http://127.0.0.1:7777/?stage=1&theme=light`, and prints the exact commands for Act 1, Act 2, "it asks once"
and the proof. Both take a port: `scripts/stage.sh 7778`. `NO_OPEN=1` skips the browser.

Run `stage.sh` (or `scripts/restart_daemon.sh`) in your own terminal: the one-time link is printed only to a
real terminal, never to a log. There is no admin key on disk. The demo's agent uses the hook token
(`$TRIPWIRE_HOME/token`) to send tasks and actions, so run it from a shell with the same `TRIPWIRE_HOME` as the
daemon. Only the paired dashboard can answer an ask, which is why the stage commands use `--approve dashboard`.
`--approve auto` against a live daemon needs a throwaway `serve --demo-admin` daemon; offline it needs nothing.
If the dashboard says it is not connected, Cmd-click a fresh link from `scripts/restart_daemon.sh`, or run
`uv run tripwire open` and type its 6 digits into the serve terminal.

## The story in one breath

Act 1 without a guard: the hijacked agent steals the SSH key and .env and runs the attacker's script.
Act 2 with Tripwire in balanced mode: all six injected calls are blocked on their own, zero questions, the typo
fix and tests go through. Then one beat where it does ask: the inbox assistant's file save waits for a click.
"Always allow this" is allowed once but not learned, because that inbox carried hidden instructions.
Strict mode gets one line: it asks before every secret read, and the mail to the attacker is blocked even if you
say yes.

## Backup video

If the live demo breaks, play these. They were recorded from the real code, not mocked.

| File | What |
|---|---|
| `demo-video/tripwire-demo.mp4` / `.webm` | Dashboard, presenter mode, balanced, 1280x720, 49 s. Act 2 injected-doc: no cards, six blocks decided on its own, the typo fix and tests allowed, the attacker-email reason, the audit log. Then beyond-permission: the $4,900 wire and the command blocked, one card for saving the summary, a real click on "Always allow this" and the toast saying it was allowed once and not learned. |
| `demo-video/tripwire-terminal.mp4` / `.webm` | The terminal story, 42 s: Act 1 (attack lands, attacker's inbox fills), Act 2 (zero questions, inbox stays empty), beyond-permission. Replayed with real timing from captured output. |
| `demo-video/tripwire-demo.gif` | Small loop of the dashboard clip for this page. |
| `demo-video/tripwire-dashboard.png`, `tripwire-terminal.png` | Stills. |

Re-record after any dashboard or engine change (about 3 minutes):

```
uv run --with playwright playwright install chromium        # once
uv run --with playwright --with imageio-ffmpeg python scripts/record_demo.py
```

It runs its own daemon on port 7792 at the balanced level with a throwaway HOME and TRIPWIRE_HOME, so your real
`~/.tripwire/` (audit log, token, settings, learned rules) is never touched. The dashboard opens with
`?stage=1&notour`, so the first-open guide never appears. Record only when the machine is quiet, then look at
`tripwire-dashboard.png` and a few frames before committing. Playwright and imageio-ffmpeg (a pip-packaged ffmpeg) are used only for recording; they are not
Tripwire dependencies.
