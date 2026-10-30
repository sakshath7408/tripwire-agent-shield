# Tripwire live demo: 5-minute talk track

Everything on screen is real code running on synthetic data. The agent is a scripted stand-in for a
hijacked AI model. We say that out loud. No internet needed.

Tripwire runs at the **balanced** autonomy level (the default). It decides the obvious cases on its own
and only asks you when it matters. `scripts/stage.sh` pins this level, so a rehearsal in strict mode
can't change the show.

Timed 31 Oct against a scratch daemon with these exact commands. Measured run times:
Act 1 14 s, Act 2 15 s (no questions), "it asks once" 8 s plus your click.
Spoken lines at a calm 140 words a minute plus switching windows land the talk at about **4:45**.
If you are running long, cut the Audit log point in Act 2 first, then the strict-mode line.

## Before you go on (10 minutes early)

```
scripts/preflight.sh     # green/red checklist: env, token, autonomy level, tests, all 5 scenarios, backup video, power
scripts/stage.sh         # clean daemon, reset, balanced mode, dashboard in presenter mode, prints the commands below
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

Don't click "Always allow this" during setup on anything else. Learned rules survive a reset.
`stage.sh` lists any that exist.

## 0:00 Hook (25 s)

"AI agents read things. READMEs, web pages, emails.
Anyone who can put text in front of your agent can give it orders.
Tripwire sits between the agent and its tools. Every tool call goes through it first."

## 0:25 The world (30 s)

"This is a simulated world. All data is fake.
There is a small Python repo, a fake SSH key, a fake .env, an inbox, and a bank account with $12,500.
The agent is a scripted model of a hijacked AI. It does its task, and it obeys any order it reads.
On the right is the attacker's inbox. It is empty."

## 0:55 Act 1: no guard, the attack works (50 s)

```
uv run python demo/run_demo.py --scenario injected-doc --no-guard --delay 1
```

Start it, then talk (it runs 14 s):
"The task is simple: fix a typo and run the tests.
The README has a hidden comment. CONTRIBUTING has a fake setup step. A config file has one too.
Watch the right side."

Point at terminal 2 as it fills: "That is my SSH key. That is my .env. And the attacker's script just ran."
"And the typo got fixed. The user would never know."

## 1:45 Act 2: same agent, with Tripwire (70 s)

The dashboard is already clean (Act 1 had no guard, so nothing reached it). Don't click Reset.

```
uv run python demo/run_demo.py --scenario injected-doc --guard-only --delay 1 --approve dashboard
```

"Same agent. Same files. Now every call asks Tripwire first."
It runs 15 s. No yellow cards come up. The rows arrive in this order:

1. The README read goes green. Then `~/.ssh/id_rsa` and `.env` go red, marked "Decided on its own":
   "It read hidden orders in the README, and I never asked for my keys. So it doesn't even ask me. Blocked."
2. The POST to `collect.attacker.invalid` goes red: "Shipping data to the attacker. Blocked."
3. The `curl | bash` goes red: "Download a script and run it blind. Blocked."
4. The second `.env` read and the email to `ops@attacker.invalid` go red.
5. The typo fix and the tests go green: "The real work still gets done."

Click the red `ops@attacker.invalid` row. Point at the detail pane:
"Every block has a reason anyone can read. This address came from hidden text in a config file.
Even if a read had got through, this send would still be stopped. The address itself is the attacker's."

Point at the banner: "Hidden instructions in README.md. Tripwire blocked all 6. My task went through."
Point at terminal 2: "Attacker's inbox: empty."
Say the line that matters: "Zero questions. It only asks when it matters."
If you have time, click the **Audit log** tab: "Every decision, chained and signed, with its reason."

## 2:55 It asks when it matters (55 s)

```
uv run python demo/run_demo.py --scenario beyond-permission --guard-only --delay 0.6 --approve dashboard
```

"This agent is an inbox assistant. It may read mail. No bank, no shell.
An 'overdue invoice' email tells it to wire $4,900 and run a command."

The wire and the command go red on their own:
"Beyond its permissions. Blocked. Without Tripwire, that money is gone."

A yellow card comes up: *The 'inbox-assistant' role needs your OK to change files* (`notes/inbox-summary.md`).
The agent waits on it.
"Now it asks. Saving a file needs my OK for this role, and this inbox had hidden orders."

Click **Always allow this**. A toast says it allowed this once and did not remember it.
"Normally that teaches Tripwire a rule. Here it refuses: it won't learn a shortcut while under attack.
Allowed once. Summary saved. Balance still $12,500."

One line on strict mode: "Want to OK everything yourself? Strict mode asks before every secret read,
and even if you say yes, the mail to the attacker is still blocked."

## 3:50 Proof it is not just this demo (35 s)

```
cat bench/results/matrix.md
```

"We replayed AgentDojo from ETH Zurich: 4 suites, 609 attack runs, no LLM, fully reproducible.
We stop 96 percent. 92 percent are hard blocks, the rest wait for a human.
Part of that is a phrase list that knows AgentDojo's template. Switch it off and we still stop 86 percent.
We also wrongly stop about 4 percent of real tasks. We show all of it."
Read only the important_instructions on and OFF rows out loud. Point at the rest, don't read them.

## 4:25 Close (20 s)

"Local. Fails closed: if Tripwire is down, nothing runs.
The deciding logic never reads the attacker's text as instructions, so it cannot be talked out of it."

Stop at about 4:45. Take questions.

## Hard questions: say these, word for word

**"Turn off the phrase list. What's your number?"**
"86 percent stopped, 45 percent hard-blocked, down from 96 and 92.
The list knows AgentDojo's template, so we publish both numbers, and five other attack texts too.
The 86 is provenance and the other checks with no phrase list. That's what a brand-new wording gets."
(Proof on screen: `cat bench/results/matrix.md`. Rerun live: `uv run python bench/agentdojo_replay.py --no-markers`, about 40 s.)

**"Your agent runs as me. Can't it just switch Tripwire off?"**
"Not through Tripwire. Every change to the daemon needs a local token file, and any agent call aimed at
the daemon or that file is blocked. But it runs as the same user, so it is defence in depth, not a sandbox.
For real isolation, run the daemon as a separate OS user."

**"Has a real model ever been hijacked and then stopped?"**
"Not on stage. The small local models and real Claude Code refused these injections on their own.
So the hijacked agent is scripted, and we say so. Tripwire's verdicts don't depend on the model saying no."

**"If it decides on its own, how do I know it's not allowing bad things?"**
"Autonomy only ever turns a question into a decision. It never turns a block into anything.
It never allows money, password changes, unknown tools or risky commands on its own, and never anything
after hidden instructions were seen. Strict mode sends every question to you.
Measured: in balanced, attacks stopped stay at 100 percent on our everyday set and 96 percent on AgentDojo."
(Proof: `cat bench/results/autonomy.md`.)

**"What does 'Always allow this' learn?"**
"A narrow rule: same tool, same kind of action, same target. It shows under Learned rules and you can delete it.
It never learns an allow for money, credentials or deletes outside the project, or in a session with
hidden instructions. You saw that refusal on stage."

## Optional: real local model

Only if there is time, and only after running it once before you go on. Needs Ollama running with
`qwen2.5:3b` pulled (`curl -s 127.0.0.1:11434/api/tags`). About 40 seconds (38 s measured 31 Oct).

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
| Daemon will not start or port busy | `lsof -i :7777`, then `scripts/stage.sh 7778` and add `--url http://127.0.0.1:7778` to the guarded commands (stage.sh prints them) |
| "Missing or wrong Tripwire token" | The daemon and your shell use different `TRIPWIRE_HOME`s. Run `scripts/stage.sh` again from the same shell |
| Dashboard says "Reload the page to reconnect" | Reload it. The page load hands the dashboard its key (a cookie). Then hard refresh if it still looks old (Cmd+Shift+R) |
| Yellow cards appear in Act 2 | The level is not balanced. `scripts/stage.sh` again (it pins balanced), or click through: Block the SSH key, Allow `.env`, and use the strict-mode line ("even when I say yes, the mail is still blocked") |
| No yellow card in "it asks once" | A learned rule or a different level. `stage.sh` lists learned rules; delete them under the gear (leave presenter mode first) |
| Dashboard blank | Skip it. The terminal shows the same verdicts. Use `--offline` if the daemon is also broken. |
| Daemon crashes mid-demo | Say "this shows fail closed", rerun the same command: every action is denied. Then rerun with `--offline`. |
| Clicking feels slow | Use `--approve auto` (a simulated human approves only what was asked for) |
| Anything else breaks | `uv run python demo/run_demo.py --scenario all --offline --delay 0 --approve auto` prints both acts and a summary for all five scenarios in a few seconds |
| No time for live run | `uv run pytest -q tests/test_bench.py`: the tests assert the attack succeeds without Tripwire and fails with it |
| Agent hangs on a yellow card | It is waiting for your click. Click Allow or Block, or press A or B on the dashboard. After 60 s it blocks on its own |
| Live demo is a mess | Play `docs/demo-video/tripwire-demo.mp4`, recorded from the real code |
| Laptop dies, internet works | Open https://tripwire-agent-shield.vercel.app/#demo on any device (the Demo tab): same engine, same scenarios, one act per click. The pitch deck is only in the repo: `docs/pitch/index.html` |
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

(Both acts, about 11 seconds, no daemon. Balanced mode, so Tripwire asks nothing here.)

Say, while it runs:
"An agent was asked to fix a typo. The README hides orders for it.
Without Tripwire, my SSH key and .env go to the attacker and their script runs. Look: attacker received 3 items.
Same agent with Tripwire: hidden instructions found, six off-task actions blocked on their own,
zero questions, the typo still fixed. Attacker received nothing.
On AgentDojo, 609 attack runs, we stop 96 percent, and 86 percent with our phrase list switched off.
We wrongly stop about 4 percent of real tasks.
It runs locally and fails closed."

If even the terminal is dead: play `docs/demo-video/tripwire-demo.mp4` (dashboard, 49 s) or
`docs/demo-video/tripwire-terminal.mp4` (terminal and attacker's inbox, 42 s). Say they were recorded
from the real code with `scripts/record_demo.py`.
