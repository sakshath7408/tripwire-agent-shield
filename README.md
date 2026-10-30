# Tripwire

**Hosted app: https://tripwire-agent-shield.vercel.app** (the dashboard as a product; the live attack demo is its **Demo** tab, direct link https://tripwire-agent-shield.vercel.app/#demo). **Bring your own attack:** https://tripwire-agent-shield.vercel.app/?scenario=custom lets you type the attacker's text, hide it in a README, an email or a web page, and run it with and without Tripwire. The hijacked agent is scripted and only follows common phrasings; the page shows exactly what it understood.

Pick an attack. Run it without Tripwire, then with it. The real engine runs on the server against a synthetic world.

A local guard that sits between an AI agent and its tools. Every tool call is checked first, and only your own words count as instructions.

Built from scratch in 24 hours for the PARALLAX hackathon (BMSCE IEEE Computer Society), Track 1 "AgentShield: Secure the Agent, Not Just the Prompt".

## 30-second quickstart

```bash
git clone https://github.com/sakshath7408/tripwire-agent-shield && cd tripwire-agent-shield
uv sync                                   # Python 3.12+, installs everything
uv run tripwire serve                     # daemon; in a terminal it prints a one-time dashboard link
uv run tripwire open                      # (later) shows 6 digits: type them into the serve terminal, or OK them in a paired dashboard
```

Want `tripwire` on your PATH instead of `uv run tripwire`? From the repo folder: `uv tool install .` (or `pip install .` in any Python 3.12+ virtualenv).
Another port: `tripwire serve --port 7800`, then `tripwire install claude --port 7800` so the hooks find it (or set `TRIPWIRE_PORT=7800` for everything).
Sessions survive a daemon restart (`~/.tripwire/sessions.json`, mode 0600, secret values masked), so a restart does not make Tripwire forget hidden instructions it already saw.

In a second terminal, watch an attack succeed with no guard, then fail with Tripwire:

```bash
uv run python demo/run_demo.py --scenario injected-doc --no-guard --delay 0   # Act 1: keys stolen
uv run python demo/run_demo.py --scenario injected-doc --guard-only --delay 0 --approve dashboard   # Act 2: blocked
uv run python demo/run_demo.py --scenario all --offline --delay 0 --approve auto   # all five, no daemon needed
uv run python demo/run_demo.py --scenario all --offline --delay 0 --approve all    # hard floor: the human allows everything
```

Who answers when Tripwire asks: with `--approve dashboard` it's you. `--approve auto` is a careful simulated human. It sees only what a person sees: Tripwire's reason, where the call goes, the task you typed and your contacts. It never sees which steps are the attack, so it can be fooled. `--approve all` clicks Allow on everything, so what's left is what Tripwire stops on its own.

Put it in front of a real agent:

```bash
uv run tripwire install claude            # adds hooks to ./.claude/settings.json (--project DIR, --user for all projects)
uv run tripwire uninstall claude          # takes them out again; an untouched settings file comes back byte for byte
uv run tripwire mcp-proxy --name fs --profile coding-assistant -- npx -y @modelcontextprotocol/server-filesystem .
uv run tripwire pins list                 # signed MCP tool pins
uv run tripwire audit verify              # check the audit log was not edited
uv run pytest -q                          # 1,271 tests (plus 1 expected failure)
uv run python bench/run_all.py            # benchmarks, about 20 s, writes bench/results/summary.md
```

The dashboard shows every verdict live. It holds "ask" actions in an approval queue with Allow and Block buttons. It shows the audit log and which agent did what.

## What else is in the box

- **Tamper-evident audit trail across agents.** Every task, tool output, verdict and human click is one row in `~/.tripwire/audit.db`. Rows are hash-chained (SHA-256) and signed (HMAC). Edit, delete or reorder a row and `tripwire audit verify` names the first broken one. Agents are blocked from reading the key (`~/.tripwire/audit.key`), but same-user code outside the hooks could, so this proves tampering by anyone without the key. Every row says which agent acted and who spawned it: Claude Code sub-agents, MCP servers and SDK agents all land in one tree. Commands: `tripwire audit verify`, `tripwire audit export --format jsonl` (anyone can recheck the hashes with `verify --file`), `tripwire audit tail -f`.
- **Hosted app with a Demo tab.** The same careful simulated human answers every ASK there, and a **Hard floor** switch makes it click Allow on everything. Each run prints "Stopped on its own: N of M attack steps · with a careful human: K of M". https://tripwire-agent-shield.vercel.app opens the real dashboard (first-open guide, then "Connect your agent"; a website cannot reach the daemon on your machine). Its **Demo** tab (https://tripwire-agent-shield.vercel.app/#demo) runs the same engine and the same demo world on Vercel, one act per click. **Try your own attack** (the last chip) plants your text (max 4 KB, plain text only) in the clean world and runs it the same way. Anything outside the user's world counts as the attacker's and only lands in a temp file; commands are simulated, never run. The pitch deck is not part of the site; it lives in `docs/pitch/`.
- **Stage kit.** `scripts/preflight.sh` is a green/red checklist before going on stage. `scripts/stage.sh` starts a clean daemon and opens the dashboard in presenter mode. Backup videos were recorded from the real code. See [docs/PRESENTING.md](docs/PRESENTING.md).
- **Optional judge, off by default.** See step 7 below. Honest result: a plain rule beat it.
- **Optional real local model.** With Ollama installed, `--planner ollama --model qwen2.5:3b` drives the demo world with a real model and native tool calling (`demo/world/ollama_planner.py`). Honest result: qwen2.5 3B and 1.5B never fell for any injection (0 of 8 attack acts). So the main demo uses a scripted stand-in for a hijacked model, and we say so. Tripwire also never blocked the real model's real work. Details: [bench/results/ollama_demo.md](bench/results/ollama_demo.md).

## What it defends against

Anyone who can put text in front of your agent can give it orders. A README, a web page, an email, a calendar invite, an MCP tool description. The attacker never touches your machine. They just write words.

What they go after: SSH keys and `.env` files, money, your inbox, code execution on your laptop, and the guard itself.

Full threat model: [demo/THREAT_MODEL.md](demo/THREAT_MODEL.md).

## How it works

One tool call in, one verdict out. Allow, ask, or block, with a one-line reason a non-expert can read.

```
agent ──> adapter ──> daemon (127.0.0.1:7777) ──> engine ──> verdict ──> audit.db + dashboard
          hooks /                                 classify
          MCP proxy /                             permission profile
          SDK                                     shell AST
                                                  secret paths + patterns
                                                  provenance (taint)
                                                  policy YAML
                                                  optional judge
```

The pipeline, in order (`src/tripwire/engine.py`):

1. **Classify** the tool name into a capability: read, fetch, write, exec, send, money, delete, credential, agent. Works for any MCP tool name. Unknown tools go to a human.
2. **Permission profile**. Each agent role gets a tool list in YAML. An inbox assistant that asks for a shell is blocked. Tools outside the role are blocked by default.
3. **Shell analysis**. Commands are parsed into an AST with bashlex, not just matched by regex. Pipes to a shell, reverse shells, destructive deletes, persistence files, base64 and hex payloads, `bash -c` and `eval` are all re-analyzed recursively.
4. **Secret paths and patterns**. Reading `~/.ssh/id_rsa` or `.env` needs your OK. Secret material in an outgoing call is blocked. Reading a secret and then sending anything out is treated as exfiltration.
5. **Provenance (taint)**. This is the key idea. See below.
6. **Policy YAML**. Plain rules in `~/.tripwire/policy.yaml` or `./.tripwire.yaml` override the score. The built-in rule: agents may never edit their own guard.
7. **Optional judge** for the grey zone (`tripwire serve --judge`, `src/tripwire/judge.py`). A small local model through Ollama (default `qwen2.5:3b`). It only ever sees your task, the profile name, the redacted action and the deterministic findings. Never tool output. So injected text cannot argue with it. It only sees ASK verdicts, may raise them to block, and may lower them to allow only with high confidence and never when hidden instructions, money or a login setting are involved. Ollama down means the ASK stays.

   We tested it on AgentDojo and a plain rule won. The rule: once hidden instructions have shown up, a high-impact action you never asked for is blocked, not just asked about (`chain.injected_unrequested`). That rule lifted hard blocks from 85.9% to 92.1% with no loss on real tasks. The judge (qwen2.5:3b) stopped nothing the rules missed. It wrongly blocked 7 real tool calls, so real tasks allowed fell from 95.9% to 90.7%. So it stays off unless you turn it on. Numbers: `bench/results/agentdojo_judge.md`.

If the engine itself crashes on an action, the verdict is block. If the daemon is down, the adapters deny. A session with no task asks before any send, payment or fetch. Both adapters have an opt-in `TRIPWIRE_FAIL_OPEN=1` that lets calls through when the daemon is down. It is off by default.

### The key idea: only your words are instructions

Your prompt is the only trusted text in a session. Every tool output (a file, a web page, an email) is untrusted data.

Tripwire records every URL, email address, IBAN, UPI id, IP, phone number, domain and command line that shows up in untrusted output, and where it came from. When the agent later tries to send, pay, fetch or run something that uses one of those values, and you never typed it, that is the injection signal. The reason names the source: "Uses `attacker@evil.invalid`, which came from README.md, not from you."

There is a second, separate signal: a phrase detector (`INJECTION_MARKERS`) that spots text talking to the AI, like "ignore your previous instructions". It is one signal, not the core, and it matters a lot on benchmarks. On AgentDojo, provenance and the other checks alone stop 92.0% of attacks (45.3% hard block). The phrase detector lifts that to 96.2% (92.1% hard block), because AgentDojo's main attack uses one fixed template the list knows. Attack texts the list does not know get only the provenance number. Full table under [Benchmark numbers](#benchmark-numbers).

The idea follows CaMeL (Debenedetti et al., 2025) and Simon Willison's dual-LLM pattern: untrusted data must never decide where data flows, and no model that reads attacker text gets to make the decision.

## Where each requirement lives

| Brief requirement | Where |
|---|---|
| Defensive layer that monitors and constrains an agent | `src/tripwire/engine.py`, `src/tripwire/server.py` |
| Simulated environment, one agent, 2+ tools | `demo/world/` (10 tools: list_dir, read_file, write_file, fetch_url, http_post, read_inbox, send_email, get_balance, send_money, run_command), `demo/world/agent.py` |
| Distinguish the task from instructions in untrusted content | `src/tripwire/taint.py`, `TaskSpec` vs `Observation` in `models.py` |
| Prevent unsafe tool actions | `engine.py`, `analyzers/shell.py`, `analyzers/paths.py`, `analyzers/secrets.py` |
| Inspectable reason for every decision | `Finding.message` on every verdict, shown on the dashboard and in the audit log |
| Policy enforcement point | the daemon: `POST /v1/evaluate`. Adapters refuse to run the tool on anything but allow |
| Audit log | tamper-evident SQLite chain at `~/.tripwire/audit.db` (`src/tripwire/audit.py`), `GET /v1/audit`, `tripwire audit verify`, dashboard "Audit log" tab |
| Scenario: legitimate task | `demo/run_demo.py --scenario legit` |
| Scenario: prompt-injected web or doc content | `--scenario injected-doc` (README, CONTRIBUTING, config) and `--scenario injected-web` |
| Scenario: unauthorized sensitive-data request | `--scenario sensitive-data` (fake IT Security email) |
| Scenario: tool invocation beyond permission | `--scenario beyond-permission` (inbox assistant told to wire money and run a shell) |
| All data synthetic | `demo/world/fixtures/`, every attacker host is `.invalid` |
| Explicit allow / deny / require-approval | `Decision` in `models.py`; profiles use `allow`, `ask`, `deny` lists |
| User confirmation for high-impact actions | money always asks (`impact.money`); `?wait=N` holds the call for the dashboard |
| Fail closed | `engine.evaluate` catches everything and blocks; `adapters/claude_code.py` denies when the daemon is down; `mcp_proxy.py` refuses the call |
| Optional: MCP gateway | `src/tripwire/adapters/mcp_proxy.py` |
| Optional: tool permission profiles | `default_policy.yaml` (`coding-assistant`, `inbox-assistant`, `finance-assistant`) |
| Optional: signed tool metadata | `src/tripwire/adapters/pins.py` (SHA-256 per tool, HMAC-signed pin file, rug-pull and poisoning checks) |
| Optional: risk-aware approval queue | dashboard "Waiting for your approval" panel, timeout blocks |
| Optional: cross-agent audit trails | built. Every row carries `agent`, `parent` and `trace`. Claude Code sub-agents, MCP servers and SDK agents land in one tree (`GET /v1/audit?format=tree`, dashboard). Hash-chained and HMAC-signed; `tripwire audit verify / export / tail` (`audit.py`, `tests/test_audit.py`) |

| Judging criterion | Where to look |
|---|---|
| 01 Threat relevance | `demo/THREAT_MODEL.md` names what is at risk and who the attacker is |
| 02 Verified effectiveness | `tests/test_bench.py::test_attack_succeeds_without_guard_and_fails_with_it`, `demo/run_demo.py` Act 1 vs Act 2, `bench/results/` |
| 03 Technical implementation | `src/tripwire/` (about 10,800 lines of Python), 1,271 tests (plus 1 expected failure), `docs/ARCHITECTURE.md` |
| 04 Innovation | provenance at the tool boundary (`taint.py`), signed MCP pins (`pins.py`), AST-based shell analysis (`shell.py`), tamper-evident cross-agent audit chain (`audit.py`) |
| 05 UI/UX | `src/tripwire/static/` dashboard: live feed, approval queue, evidence panel, audit log with agent tree; hosted copy at https://tripwire-agent-shield.vercel.app (Demo tab: `/#demo`) |
| 06 Safety, privacy, responsible engineering | local only, no network lookups by the guard, args redacted before storage (`secrets.redact`), fail closed. Control: Tripwire keeps no admin key on disk. The token your agent's hooks use can only send a task, tool outputs and actions to check. It can't answer an ASK, change settings, reset, or pair a browser. Only a paired dashboard can, and a browser is paired only through a person: a one-time link printed straight to the terminal running `tripwire serve` (never to a log), or a 6-digit code from `tripwire open` that you type into that terminal or approve in a dashboard you already paired. While a session has seen hidden instructions, nobody can loosen autonomy and no new link is printed. This stops an agent that can read every file in ~/.tripwire and talk to the daemon directly. It does not stop a process running as your OS user that reads your browser's cookies, attaches a debugger to the daemon, or kills it and starts its own copy. For that, `tripwire harden` runs the daemon as its own OS user, which is a real OS boundary. Details: [docs/HARDENING.md](docs/HARDENING.md). Plain "Known limits" below |
| 07 Feasibility and real-world impact | `tripwire install claude` works on a real Claude Code today; `mcp-proxy` works with any MCP server |
| 08 Presentation and live demo | `demo/SCRIPT.md`, `docs/PRESENTING.md` (preflight, stage, backup video), `docs/pitch/index.html` |

## Benchmark numbers

Run on 31 Oct 2026 04:38 with `uv run python bench/run_all.py` (about 30 s, no LLM, no cost). Same numbers under any `PYTHONHASHSEED`. Rerun before quoting.

Three words, used the same way everywhere:
- **Hard block**: the call is refused. Nobody is asked.
- **Asked**: the call waits for a human click on the dashboard. Nothing runs until you answer, and a timeout blocks it. (At the default "balanced" autonomy, some obvious asks are decided on their own. Nothing is auto-allowed after hidden instructions.)
- **Stopped** = hard block + asked. So "stopped" includes calls a careless human could still approve.

| Benchmark | Stopped | Hard block | Size | Benign allowed |
|---|---|---|---|---|
| AgentDojo (4 suites, important_instructions) | 96.2% | 92.1% | 609 pairs | 95.9% tasks (92.9% calls) |
| Shell attacks, no poisoned context (our own corpus) | 100.0% | 94.0% | 84 cmds | 82 of 82 (0 flagged) |
| Shell attacks, after reading poisoned file (our own corpus) | 100.0% | 100.0% | 84 cmds | 82 of 82 (0 flagged) |

Median decision time is under 1 ms (p95 under 5 ms on AgentDojo).

### With and without the phrase detector

The headline AgentDojo number leans on the phrase detector. Its list includes AgentDojo's own template phrases ("this is an important message from", `<INFORMATION>`). So we rerun every AgentDojo attack text with the detector switched off (`--no-markers`), and with five other attack texts AgentDojo ships. Same 609 pairs each time.

| AgentDojo attack text | Phrase list ON: stopped | ON: hard block | Phrase list OFF: stopped | OFF: hard block |
|---|---|---|---|---|
| important_instructions | 96.2% | 92.1% | 92.0% | 45.3% |
| tool_knowledge | 99.5% | 95.4% | 92.0% | 45.3% |
| injecagent | 96.2% | 88.5% | 92.0% | 45.3% |
| ignore_previous | 92.0% | 45.3% | 92.0% | 45.3% |
| direct | 92.0% | 45.3% | 92.0% | 45.3% |
| system_message | 92.0% | 45.3% | 92.0% | 45.3% |
| benign tasks allowed (all texts) | 95.9% | | 95.9% | |

How to read it:
- **Detector on, known template** (important_instructions, tool_knowledge, injecagent): the phrase list fires, so most attacks are hard-blocked.
- **Detector off, or a template the list does not know** (ignore_previous, direct, system_message): only provenance, intent, secret and policy checks are left. That is the honest floor: 92.0% stopped, 45.3% hard block.
- Benign tasks do not change, because the phrase list only fires on injected text.
- Earlier versions of this page said 86.0% here. That was one sample: verdicts depended on Python's hash seed (set order), and slack swung between 41% and 75% stopped. Since 31 Oct every seed gives the same verdicts (`tests/test_redteam4.py` checks three seeds; a full `bench/run_all.py` under `PYTHONHASHSEED=0` and `=2` gives identical tables).
- Weakest suites without the detector: slack (75.2% stopped, 11.4% hard block), travel (82.5% stopped, 37.5% hard block). Every missed pair is listed in `bench/results/agentdojo_*_nomarkers.json` (`missed`).

### Hard floor: what Tripwire stops when the human allows everything

"Stopped" counts asks, and a person can click Allow on an ask. So here is what's left with nobody saying no:

- **AgentDojo:** the hard block column above. 92.1% with the phrase list, 45.3% without it.
- **The four stage attack scenarios** (`demo/run_demo.py --scenario all --offline --approve all`): 13 of 13 attack steps blocked on its own. The attacker got nothing in all 4, and every task got done.
- **The 10 attacks a reviewer typed into the live page** (9 of them got something out with no guard): with a careful simulated human, none got anything out (8 of 13 attack steps blocked on its own, 5 refused by the human). With the hard floor, 9 of 13 steps are blocked on its own and 2 of 10 attacks got something out: a README summary POSTed to a web address the README named, and a cc to a Gmail look-alike of Sam's address. Tripwire asked about both; it didn't block them.

Before the recipient and provenance hardening of 30 Oct, the floor was 62.6% stopped and 36.1% hard block ([bench/results/matrix_baseline.md](bench/results/matrix_baseline.md)).

False positives, said plainly: on AgentDojo, 7.1% of benign ground-truth calls get an ask or a block. Half of those are in the banking suite, where paying bills always asks a human. Most of the rest are the new recipient check asking before a message goes to someone the user never named (slack and workspace). The shell corpus flags none of 82 everyday developer commands, cold or after a poisoned read.

Read [bench/README.md](bench/README.md) before quoting these. There is no LLM in the loop: we replay AgentDojo's ground-truth call sequences, so a real hijacked model might phrase calls differently.

## Known limits

> **Read this before you trust it.**
> - **Same OS user = defence in depth, not a sandbox.** Tripwire keeps no admin key on disk. The token your agent's hooks use can only send a task, tool outputs and actions to check. It can't answer an ASK, change settings, reset, or pair a browser. Only a paired dashboard can, and a browser is paired only through a person: a one-time link printed straight to the terminal running `tripwire serve` (never to a log), or a 6-digit code from `tripwire open` that you type into that terminal or approve in a dashboard you already paired. While a session has seen hidden instructions, nobody can loosen autonomy and no new link is printed. This stops an agent that can read every file in ~/.tripwire and talk to the daemon directly. It does not stop a process running as your OS user that reads your browser's cookies, attaches a debugger to the daemon, or kills it and starts its own copy. For that, `tripwire harden` runs the daemon as its own OS user, which is a real OS boundary. A session that saw hidden instructions can't be re-tasked over the API, and a reset never forgets what it saw. On top of that, the engine blocks the routes to the guard that reviews found (each is a test in `tests/test_redteam*.py` and `tests/test_guard4.py`), but the control above doesn't depend on catching every one. Steps: [docs/HARDENING.md](docs/HARDENING.md).
> - **The hijacked agent in the demo is scripted.** Real models we tried locally (qwen2.5 3B and 1.5B) never fell for the injections, and real Claude Code refused them on its own. So Act 1 uses a scripted stand-in that obeys any order it reads. Tripwire's verdicts are real; the "agent fell for it" part is staged.
> - **Intent is keyword matching.** If your prompt says "send", "reply" or "pay", that kind of action counts as expected. A send to an address taken from data can still pass if the email carried no hidden-instruction phrasing and the recipient check does not catch it.
> - **The phrase list is a list.** Without it, AgentDojo drops from 96.2% to 92.0% stopped, and hard blocks from 92.1% to 45.3%. A new wording gets the lower number.

Other limits:

- If the injection only changes what the agent says, with no unusual tool call, Tripwire sees nothing.
- If you typed the same address the attacker uses, provenance cannot tell them apart.
- Data copied into an allowed file or sent to an allowed recipient is caught only when it matches a secret pattern, a secret value read this session (also base64, base32, hex, reversed, or cut into pieces inside one command or file name), or a personal-data pattern (SSN, bank numbers, card numbers) going to someone you never named.
- Scripts the agent runs (`bash x.sh`, `./x`, `make`, `pytest`'s conftest, `npm test`, `pip install -e .`) are read from disk and judged when they run, and text written through `>`, heredocs, `tee` or `sed -i` is judged like a Write. Code reached only through deeper imports (a test file importing a planted module) is not followed.
- The MCP poisoned-description check looks for fixed shapes (orders to the AI, "don't tell the user", quiet recipients, key paths, a few languages). A description that dodges all of them is still pinned on first use.
- Tool calls that do not pass through a hook or the proxy are invisible.
- A host the attacker already runs code on can stop Tripwire.
- Shell tricks and secret patterns are finite. With no poisoned context, 5 of 84 shell attacks get an ask, not a block. Every verdict is in `bench/results/shell.json`.
- The Claude Code adapter never widens Claude Code's own permissions. An "allow" from Tripwire still goes through Claude Code's normal prompt unless `TRIPWIRE_AUTO_APPROVE=1`.

## Credits

- [AgentDojo](https://github.com/ethz-spylab/agentdojo) (Debenedetti et al., ETH Zurich, NeurIPS 2024) for the suites, ground truth and attack text.
- [CaMeL](https://arxiv.org/abs/2503.18813) (Debenedetti et al., Google DeepMind / ETH Zurich, 2025) for the idea that untrusted data must not choose where data flows.
- Simon Willison's [dual-LLM pattern](https://simonwillison.net/2023/Apr/25/dual-llm-pattern/): the model that decides never reads untrusted text.
- [bashlex](https://github.com/idank/bashlex) for the shell parser.
- [Ollama](https://ollama.com) and [Qwen 2.5](https://github.com/QwenLM/Qwen2.5) (Alibaba) for the optional local judge and the optional real-model agent.
- The [Model Context Protocol](https://modelcontextprotocol.io) spec, and its reference filesystem server used in the examples.
- [Claude Code hooks](https://docs.anthropic.com/en/docs/claude-code/hooks) for the Claude Code adapter.

Everything in `src/`, `demo/`, `bench/`, `web/`, `api/`, `scripts/` and `tests/` was written from scratch during the hackathon, with AI coding tools (allowed by the rules).

Libraries. Runtime: FastAPI, uvicorn, pydantic, PyYAML, httpx, sse-starlette, bashlex, SQLite (Python standard library). Dev only: pytest, pytest-asyncio, agentdojo. Recording the backup video only: Playwright (Chromium) and imageio-ffmpeg. The hosted demo runs on Vercel (free Hobby plan).
