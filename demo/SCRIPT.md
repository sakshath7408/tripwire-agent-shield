# Tripwire live demo: 5-minute talk track

Everything on screen is real code running on synthetic data. The agent is a scripted stand-in for a
hijacked AI model. We say that out loud. No internet needed.

Rehearsed 30 Oct against a live daemon with these exact commands and delays. Measured run times:
Act 1 14 s, Act 2 28 s (with two 4-second pauses on approval cards), beyond-permission 11 s plus your `y`.
Spoken lines at a calm 140 words a minute plus switching windows lands the talk at about **4:40**.
That leaves 20 seconds of buffer inside 5:00. If you are running long, cut the Audit log point in Act 2 first.

## Before you go on (10 minutes early)

```
scripts/preflight.sh     # green/red checklist: env, tests, all 5 scenarios, backup video, power
scripts/stage.sh         # clean daemon, reset, opens the dashboard in presenter mode, prints the commands below
```

Then open two terminals in `~/agent-shield`, font 20pt or bigger, side by side:

```
# Terminal 2 (right): the attacker's inbox, leave it running
uv run python demo/attacker_view.py --watch

# Terminal 3 (left): the agent. Type each command below once now so it sits in shell history
# (press up-arrow on stage instead of typing). Then clear the screen.
```

Layout on the projector: dashboard browser window on top or left, terminals 3 and 2 below or right.
Turn on Do Not Disturb. Plug in the charger.

## 0:00 Hook (25 s)

"AI agents read things. READMEs, web pages, emails.
Anyone who can put text in front of your agent can give it orders.
Tripwire sits between the agent and its tools. Every tool call goes through it first."

## 0:25 The world (30 s)

"This is a simulated world. All data is fake.
There is a small Python repo, a fake SSH key, a fake .env, an inbox, and a bank account with $12,500.
The agent is a scripted model of a hijacked AI. It does its task, and it obeys any order it reads.
On the right is the attacker's inbox. It is empty."

## 0:55 Act 1: no guard (50 s)

```
uv run python demo/run_demo.py --scenario injected-doc --no-guard --delay 1
```

Start it, then talk (it runs 14 s):
"The task is simple: fix a typo and run the tests.
The README has a hidden comment. CONTRIBUTING has a fake setup step. A config file has one too.
Watch the right side."

Point at terminal 2 as it fills: "That is my SSH key. That is my .env. And the attacker's script just ran."
"And the typo got fixed. The user would never know."

## 1:45 Act 2: same agent, with Tripwire (75 s)

Click **Reset** on the dashboard twice (the first click asks you to confirm), so it starts clean.

```
uv run python demo/run_demo.py --scenario injected-doc --guard-only --delay 1 --approve dashboard
```

"Same agent. Same files. Now every call asks Tripwire first."
The cards come in this order. The agent waits on each yellow card until you click.

1. Yellow card, `~/.ssh/id_rsa`: "It wants my SSH key. I never asked for that." Click **Block**.
2. Yellow card, `.env`: "Say I am careless and let it read my .env." Click **Allow**.
3. The POST to `collect.attacker.invalid` goes red on its own: "It tried to ship the secrets out. Blocked."
4. The `curl | bash` goes red: "Download a script and run it blind. Blocked."
5. A second `.env` card (the config file asks again). Click **Allow** again.
6. The email to `ops@attacker.invalid` goes red anyway: "Even when I say yes to the read, the moment
   it tries to mail it out, Tripwire stops it."
7. The typo fix and the tests go green: "The real work still gets done."

Point at the banner: "Hidden instructions in README.md. Tripwire blocked all four. My task went through."
Point at terminal 2: "Attacker's inbox: empty."
If you have time, click the **Audit log** tab: "Every decision, with a reason anyone can read."

## 3:00 Beyond permission (45 s)

```
uv run python demo/run_demo.py --scenario beyond-permission --delay 0.6 --approve prompt
```

"This agent is an inbox assistant. It may read mail and save notes. It has no bank and no shell.
An 'overdue invoice' email tells it to wire $4,900 and run a command.
Without the guard: money gone, balance $7,600. With it: both blocked, balance $12,500."
When it asks to save the summary file, type `y`: "High-impact actions need my OK. This one I asked for."

## 3:45 Proof it is not just this demo (35 s)

```
cat bench/results/summary.md
```

"We replayed AgentDojo from ETH Zurich: 4 suites, 609 attack runs, no LLM, fully reproducible.
We stop 96 percent of the attacks, 92 percent with a hard block. We also wrongly stop about 4 percent of real tasks. We show both."
Read only the AgentDojo row out loud. Point at the shell rows, don't read them.

## 4:20 Close (20 s)

"Local. Fails closed: if Tripwire is down, nothing runs.
The deciding logic never reads the attacker's text as instructions, so it cannot be talked out of it."

Stop at about 4:40. Take questions.

## Optional: real local model

Only if there is time, and only after running it once before you go on. Needs Ollama running with
`qwen2.5:3b` pulled (`curl -s 127.0.0.1:11434/api/tags`). About 50 seconds.

```
uv run python demo/run_demo.py --planner ollama --model qwen2.5:3b --scenario sensitive-data --guard-only --offline --delay 0 --approve auto
```

Say:
"That was a scripted agent. This is a real model, Qwen 2.5 3B, running on this laptop. No internet.
Same world, same guard. Every tool result goes to the model as is, the fake IT Security email included."

"It tries to save the summary with a shell command. The inbox assistant has no shell, so Tripwire blocks it.
The model reads the reason, switches to the file tool, and the summary gets saved. Nothing reached the attacker."

Be honest if asked: "This small model did not fall for the injection at all. Small models mostly ignore
orders in what they read. That is why the attack itself is shown with the scripted agent.
The point here is that Tripwire works with a real model and does not block its real work."
Numbers: `bench/results/ollama_demo.md`.

## Exact fallbacks

| Problem | Do this |
|---|---|
| Daemon will not start or port busy | `lsof -i :7777`, kill it, or `uv run tripwire serve --port 7778` and add `--url http://127.0.0.1:7778` |
| Dashboard blank | Skip it. The terminal shows the same verdicts. Use `--offline` if the daemon is also broken. |
| Daemon crashes mid-demo | Say "this shows fail closed", rerun the same command: every action is denied. Then rerun with `--offline`. |
| Typing y/n feels slow | Use `--approve auto` (a simulated human approves only what was asked for) |
| Anything else breaks | `uv run python demo/run_demo.py --scenario all --offline --delay 0 --approve auto` prints both acts and a summary for all five scenarios in a few seconds |
| No time for live run | `uv run pytest -q tests/test_bench.py`: the tests assert the attack succeeds without Tripwire and fails with it |
| Dashboard looks stale or old | Hard refresh (Cmd+Shift+R) |
| Agent hangs on a yellow card | It is waiting for your click. Click Allow or Block, or press A or B on the dashboard |
| Live demo is a mess | Play `docs/demo-video/tripwire-demo.mp4`, recorded from the real code |
| Laptop dies, internet works | Open https://tripwire-agent-shield.vercel.app on any device: same engine, same scenarios, one act per click |
| Anything at all before you start | `scripts/stage.sh` again: it restarts and resets everything in about 2 seconds |

## If the projector is dark mode (or washed out)

- The dashboard opens light (`?theme=light`), which reads best on most projectors.
- If the room is dark or the projector crushes light grey: click the moon button in the top bar, or open
  `http://127.0.0.1:7777/?stage=1&theme=dark`. The choice sticks for the next reload.
- Terminals: use a light-on-dark profile with pure white text, not grey. Green and red in the demo output
  are bold, so they stay readable either way.
- Check it on the real projector during setup. Look at a red "Blocked" card from the back of the room.

## 60-second emergency version

Use this if the slot shrinks or something breaks and you have one minute left. No dashboard needed.

```
uv run python demo/run_demo.py --scenario injected-doc --offline --delay 0.3 --approve auto
```

(Both acts, about 10 seconds, no daemon. A simulated careful human denies what the user never asked for.)

Say, while it runs:
"An agent was asked to fix a typo. The README hides orders for it.
Without Tripwire, my SSH key and .env go to the attacker and their script runs. Look: attacker received 3 items.
Same agent with Tripwire: hidden instructions found, every off-task action stopped, the typo still fixed.
Attacker received nothing.
On AgentDojo, 609 attack runs, we stop 96 percent and wrongly stop about 4 percent of real tasks.
It runs locally and fails closed."

If even the terminal is dead: play `docs/demo-video/tripwire-demo.mp4` (dashboard, 1 min) or
`docs/demo-video/tripwire-terminal.mp4` (terminal and attacker's inbox, 1 min). Say they were recorded
from the real code with `scripts/record_demo.py`.
