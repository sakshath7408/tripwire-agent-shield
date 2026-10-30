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
- Stage: `scripts/preflight.sh` (green/red checklist), `scripts/stage.sh` (clean daemon + presenter dashboard), `scripts/record_demo.py` (re-record backup video after UI/engine changes)
- Typecheck/lint: none set up; use `uv run python -m compileall -q src`
- Hosted live demo: https://tripwire-agent-shield.vercel.app (Vercel Hobby, project tripwire-agent-shield). `api/run.py` runs one act in-process per request (`web/demo_runner.py` reuses run_demo); `web/build.sh` generates the page from `src/tripwire/static/index.html`. Deploy committed HEAD from a clean worktree: `git worktree add --detach <tmp> HEAD && cp -r .vercel <tmp>/ && cd <tmp> && npx --yes vercel deploy --prod --yes`.

## Layout
- `src/tripwire/models.py` shared types (Action, Verdict, Finding, Capability)
- `src/tripwire/engine.py` the decision pipeline (one Action in, one Verdict out)
- `src/tripwire/taint.py` provenance: user prompt is trusted, every tool output is untrusted
- `src/tripwire/classify.py` tool name -> capability (works for any MCP tool)
- `src/tripwire/analyzers/` shell AST, sensitive paths, secret patterns
- `src/tripwire/policy.py` + `default_policy.yaml` user YAML overrides
- `src/tripwire/server.py` FastAPI daemon on 127.0.0.1:7777, SSE events
- `src/tripwire/audit.py` tamper-evident audit chain (SHA-256 + HMAC, ~/.tripwire/audit.db + audit.key) and agent trees; `tripwire audit verify|export|tail`
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
- Red team 30 Oct (`tests/test_redteam.py`): bound evaluate-time regexes too, not just observe. `FORK_BOMB` (`[\w:]+\(`) took 8 s on one 50 KB command and the `env_assignment` secret regex took 287 s on 800 KB; both now `{1,64}`-style bounded.
- Redact each string in the args, never the JSON text: a secret regex swallowed the closing quote, `json.loads` crashed, and the fail-closed handler crashed with it.
- `./.tripwire.yaml` comes with the repo, so it is tighten-only (block rules and new profiles). Loosening lives in `~/.tripwire/policy.yaml`.
- A getter prefix proves a read only when no other verb follows (`get_and_send_report`, `list_and_delete_files`). Judge SQL args by what they say, not by the tool name.
- Files the agent writes can run later (`make test`, `npm test`, CI), so Write/Edit content of scripts, Makefiles, package.json scripts and source files is checked like a command at write time.
- Never `git stash` here while other agents are working: it yanks their uncommitted files out from under them.
- Restart the daemon with `scripts/restart_daemon.sh`, never `pkill` then start. The health check answered from the old process while it was shutting down, the new one failed to bind the port, and the demo then failed closed on every step.
- A plain rule beat the 3B judge model: after hidden instructions are seen, an ASK on a high-impact action the user never asked for becomes BLOCK (`chain.injected_unrequested`). AgentDojo hard blocks 85.9% -> 92.1%, benign unchanged. The judge added no stops and wrongly blocked 7 real calls (benign tasks 95.9% -> 90.7%), so it stays opt-in (`serve --judge`).
- qwen2.5 3B and 1.5B never fell for any injection (0 of 8 attack acts, four wordings), so Act 1 "attack succeeds" stays on the scripted NaivePlanner. Say so if a judge asks. `--planner ollama` is an optional live bit, not the main demo.
- The audit log is append-only: never UPDATE or `insert or replace` an audit row. A resolution is its own chained record; readers fold it into the verdict. Audit writes go through the background writer so `/v1/evaluate` never waits on disk; a failed write keeps the verdict and shows up as `/healthz` audit "degraded".
- Verified 30 Oct with real Claude Code 2.1.241: PreToolUse from inside a sub-agent carries `agent_id` and `agent_type` (e.g. "Explore"); the main agent's calls carry neither. The spawn tool is named `Agent` (older docs say `Task`); both are handled.
- `.vercelignore` is gitignore-style: an unanchored `tests` also dropped `demo/poisoned-repo/tests`, so the hosted unittest ran 0 tests and the task showed "not done". Anchor root-only entries with `/`.
- macOS temp dirs live under `/var/folders`, and Tripwire rightly calls writes under `/var` system-folder writes. Demo worlds go under `/tmp` (also Vercel's only writable path).
