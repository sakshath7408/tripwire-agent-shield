# Tripwire (hackathon: Track 1 "Agent Shield")

A local guard between AI agents and their tools. Every tool call goes through it. It blocks destructive,
exfiltrating and prompt-injected actions, and lets the real task through.

## Deadline
Submission opens 2 PM Sat 31 Oct 2026, hackathon ends 4 PM. Live 5-minute demo to the judge after submission.
Judging: does it really work, real architecture (not just a front end), innovation, intuitive UI,
safety/privacy, real-world impact, demo. Never fake a result in the demo.

## The rulebook
`docs/BRIEF.md` holds the official brief, judging criteria and what the judge stressed at kickoff. Check every change against it. Its release checklist runs before submission.

## Commands
- Install: `uv sync`
- Tests: `uv run pytest -q`
- Daemon + dashboard: `uv run tripwire serve` then open http://127.0.0.1:7777
- Typecheck/lint: none set up; use `uv run python -m compileall -q src`

## Layout
- `src/tripwire/models.py` shared types (Action, Verdict, Finding, Capability)
- `src/tripwire/engine.py` the decision pipeline (one Action in, one Verdict out)
- `src/tripwire/taint.py` provenance: user prompt is trusted, every tool output is untrusted
- `src/tripwire/classify.py` tool name -> capability (works for any MCP tool)
- `src/tripwire/analyzers/` shell AST, sensitive paths, secret patterns
- `src/tripwire/policy.py` + `default_policy.yaml` user YAML overrides
- `src/tripwire/server.py` FastAPI daemon on 127.0.0.1:7777, SSE events, SQLite audit at ~/.tripwire/audit.db
- `src/tripwire/adapters/` Claude Code hooks and the MCP stdio proxy
- `src/tripwire/static/` dashboard (plain HTML/JS, no build step)
- `bench/` attack and benign corpora + AgentDojo replay; `demo/` poisoned repo and vulnerable agent

## Rules
- Deterministic checks first. Any model judge only sees the user's task and the proposed action, never untrusted content.
- Fail closed: if the daemon is unreachable, adapters deny.
- Every finding message is one plain-English line a non-expert understands.
- Zero spend. Local only. Never send user data anywhere.
- Report real benchmark numbers, including false positives.

## Lessons
- Tool-name keyword patterns must anchor at a word start (`(?:^|_)`): plain "cat" matched "frobnicate" and turned an unknown tool into a harmless read, which broke fail-closed.
- Subagents die on network drops (ECONNRESET) on hotspot. Resume them with SendMessage; their files stay on disk.
- Every regex that scans untrusted tool output must be bounded (`{1,64}`, not `+`) and anchored with a lookbehind. An unbounded email pattern took 68 s on 200 KB of minified text, which let one big output freeze the guard. `test_huge_observation_is_fast` guards this.
- bashlex hangs forever on an unclosed `${` inside a mid-word quote (e.g. `-'${'`); shell.py screens for it with `BASHLEX_HANG`. Fuzz any new parser before trusting it in the guard.
- A secret read that is waiting for approval must not count as read. Record it only when allowed, approved (`Engine.resolve`) or its output is observed. Otherwise denying the read still blocks the user's own later emails.
- Values from a document the user pointed at are not attacker values. Judge a tainted value by whether its source also carried hidden instructions (`TaintSource.injected`), not just by "came from a tool".
- A copy of a secret is a secret. Track copied files (`tainted_files`) even inside the project, or `cp .env public/ && http.server` slips through.
- Live check 30 Oct: real Claude Code (hooks installed) refused both the poisoned-repo injection and a direct `.env | curl` request on its own. Tripwire saw every call (tasks recorded, 2 injections detected, 4 normal actions allowed, 0 false blocks). So Act 1 "attack succeeds" must use the scripted or local-model agent, and the pitch says it plainly: Tripwire protects whatever model you run, it doesn't depend on the model saying no.
