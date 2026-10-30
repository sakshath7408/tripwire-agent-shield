# Tripwire live demo: 5-minute talk track

Everything on screen is real code running on synthetic data. The agent is a scripted stand-in for a
hijacked AI model. We say that out loud. No internet needed.

## Before you go on (5 minutes early)

Open three terminals in `~/agent-shield` and one browser tab.

```
# Terminal 1: the guard
uv run tripwire serve

# Browser: the dashboard
open http://127.0.0.1:7777

# Terminal 2: the attacker's inbox (keep it visible)
uv run python demo/attacker_view.py --watch

# Terminal 3: the agent. Dry run once, then clear the screen.
uv run python demo/run_demo.py --scenario legit --guard-only --delay 0 --approve auto
```

Make the font big. Put terminal 2 next to terminal 3.

## 0:00 Hook (30 s)

"AI agents read things. READMEs, web pages, emails.
Anyone who can put text in front of your agent can give it orders.
Tripwire sits between the agent and its tools. Every tool call goes through it first."

## 0:30 The world (30 s)

"This is a simulated world. All data is fake.
There is a small Python repo, a fake SSH key, a fake .env, an inbox, and a bank account with $12,500.
The agent is a scripted model of a hijacked AI. It does its task, and it obeys any order it reads.
On the right is the attacker's inbox. It is empty."

## 1:00 Act 1: no guard (60 s)

```
uv run python demo/run_demo.py --scenario injected-doc --no-guard --delay 1
```

"The task is simple: fix a typo and run the tests.
The README has a hidden HTML comment. CONTRIBUTING has a fake setup step. A config file has a comment.
Watch the right side."

Point at terminal 2 as it fills: "That is my SSH key. That is my .env. And the attacker's script just ran."
"And the typo got fixed. The user would never know."

## 2:00 Act 2: same agent, with Tripwire (75 s)

Click **Reset** on the dashboard first, so it starts clean.

```
uv run python demo/run_demo.py --scenario injected-doc --guard-only --delay 1 --approve dashboard
```

"Same agent. Same files. Now every call asks Tripwire first."

- The yellow banner appears: read it out. "Found hidden instructions in README.md." Point at the evidence box on the right: "From README.md, not from you."
- The POST and `curl | bash` go red on their own. "Blocked. The address came from the README, not from me."
- On the projector, click **Block** on `~/.ssh/id_rsa`. Then click **Allow** on `.env`.
- The email to the attacker goes red anyway. Say: "Even when I say yes to the read, the moment the agent tries to mail it out, Tripwire stops it. Secret material leaving after a secret read."
- The typo fix and the tests go green. "The real work still gets done."

Point at terminal 2: "Attacker's inbox: empty." Point at the Audit log tab: "Every decision, with a reason anyone can read."

## 3:15 Beyond permission (45 s)

```
uv run python demo/run_demo.py --scenario beyond-permission --delay 0.6 --approve prompt
```

"This agent is an inbox assistant. It may read mail and save notes. It has no bank and no shell.
An 'overdue invoice' email tells it to wire $4,900 and run a command.
Without the guard: money gone, balance $7,600. With it: both blocked, balance $12,500."
When it asks to save the summary file, type `y`: "High-impact actions need my OK. This one I asked for."

## 4:00 Proof it is not just this demo (40 s)

```
cat bench/results/summary.md
```

"We replayed AgentDojo from ETH Zurich: 4 suites, 609 attack runs, no LLM, fully reproducible.
Read the numbers as they are, including false positives. We do not hide them."
Read the table row by row. Say the false-positive number out loud.

## 4:40 Close (20 s)

"Local. Fails closed: if Tripwire is down, nothing runs.
The deciding logic never reads the attacker's text as instructions, so it cannot be talked out of it."

## Exact fallbacks

| Problem | Do this |
|---|---|
| Daemon will not start or port busy | `lsof -i :7777`, kill it, or `uv run tripwire serve --port 7778` and add `--url http://127.0.0.1:7778` |
| Dashboard blank | Skip it. The terminal shows the same verdicts. Use `--offline` if the daemon is also broken. |
| Daemon crashes mid-demo | Say "this shows fail closed", rerun the same command: every action is denied. Then rerun with `--offline`. |
| Typing y/n feels slow | Use `--approve auto` (a simulated human approves only what was asked for) |
| Anything else breaks | `uv run python demo/run_demo.py --scenario all --offline --delay 0 --approve auto` prints both acts and a summary for all four scenarios in a few seconds |
| No time for live run | `uv run pytest -q tests/test_bench.py`: the tests assert the attack succeeds without Tripwire and fails with it |
| Dashboard looks stale or old | Hard refresh (Cmd+Shift+R) |
