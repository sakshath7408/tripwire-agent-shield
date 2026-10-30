# Tripwire (hackathon: Track 1 "Agent Shield")

A local guard between AI agents and their tools. Every tool call goes through it. It blocks destructive,
exfiltrating and prompt-injected actions, and lets the real task through.

## Deadline
Submission opens 2 PM Sat 31 Oct 2026, hackathon ends 4 PM. Live 5-minute demo to the judge after submission.
Judging: does it really work, real architecture (not just a front end), innovation, intuitive UI,
safety/privacy, real-world impact, demo. Never fake a result in the demo.

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
