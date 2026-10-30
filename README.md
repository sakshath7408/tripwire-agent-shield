# Tripwire

**Live demo: https://tripwire-agent-shield.vercel.app**

Pick an attack. Run it without Tripwire, then with it. The real engine runs on the server against a synthetic world.

A local guard that sits between an AI agent and its tools. Every tool call is checked first, and only your own words count as instructions.

Built from scratch in 24 hours for the PARALLAX hackathon (BMSCE IEEE Computer Society), Track 1 "AgentShield: Secure the Agent, Not Just the Prompt".

## 30-second quickstart

```bash
git clone <this repo> && cd agent-shield
uv sync                                   # Python 3.12+, installs everything
uv run tripwire serve                     # daemon + dashboard at http://127.0.0.1:7777
```

In a second terminal, watch an attack succeed with no guard, then fail with Tripwire:

```bash
uv run python demo/run_demo.py --scenario injected-doc --no-guard --delay 0   # Act 1: keys stolen
uv run python demo/run_demo.py --scenario injected-doc --guard-only --delay 0 --approve auto   # Act 2: blocked
uv run python demo/run_demo.py --scenario all --offline --delay 0 --approve auto   # all five, no daemon needed
```

Put it in front of a real agent:

```bash
uv run tripwire install claude            # adds hooks to ./.claude/settings.json (--user for all projects)
uv run tripwire mcp-proxy --name fs --profile coding-assistant -- npx -y @modelcontextprotocol/server-filesystem .
uv run tripwire pins list                 # signed MCP tool pins
uv run tripwire audit verify              # check the audit log was not edited
uv run pytest -q                          # 506 tests
uv run python bench/run_all.py            # benchmarks, about 20 s, writes bench/results/summary.md
```

The dashboard shows every verdict live. It holds "ask" actions in an approval queue with Allow and Block buttons. It shows the audit log and which agent did what.

## What else is in the box

- **Tamper-evident audit trail across agents.** Every task, tool output, verdict and human click is one row in `~/.tripwire/audit.db`. Rows are hash-chained (SHA-256) and signed (HMAC). Edit, delete or reorder a row and `tripwire audit verify` names the first broken one. Every row says which agent acted and who spawned it: Claude Code sub-agents, MCP servers and SDK agents all land in one tree. Commands: `tripwire audit verify`, `tripwire audit export --format jsonl` (anyone can recheck the hashes with `verify --file`), `tripwire audit tail -f`.
- **Hosted live demo.** https://tripwire-agent-shield.vercel.app runs the same engine and the same demo world on Vercel, one act per click.
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

If the engine itself crashes on an action, the verdict is block. If the daemon is down, the adapters deny. Fail closed everywhere.

### The key idea: only your words are instructions

Your prompt is the only trusted text in a session. Every tool output (a file, a web page, an email) is untrusted data.

Tripwire records every URL, email address, IBAN, UPI id, IP, phone number, domain and command line that shows up in untrusted output, and where it came from. When the agent later tries to send, pay, fetch or run something that uses one of those values, and you never typed it, that is the injection signal. The reason names the source: "Uses `attacker@evil.invalid`, which came from README.md, not from you."

This does not depend on spotting the phrasing of an injection. It follows the data. The wording detector (`INJECTION_MARKERS`) is a bonus signal that raises severity when the same content also carried hidden instructions.

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
| 03 Technical implementation | `src/tripwire/` (about 5,800 lines), 506 tests, `docs/ARCHITECTURE.md` |
| 04 Innovation | provenance at the tool boundary (`taint.py`), signed MCP pins (`pins.py`), AST-based shell analysis (`shell.py`), tamper-evident cross-agent audit chain (`audit.py`) |
| 05 UI/UX | `src/tripwire/static/` dashboard: live feed, approval queue, evidence panel, audit log with agent tree; hosted copy at https://tripwire-agent-shield.vercel.app |
| 06 Safety, privacy, responsible engineering | local only, args redacted before storage (`secrets.redact`), fail closed, guard cannot be edited by the agent (`never-touch-tripwire` rule) |
| 07 Feasibility and real-world impact | `tripwire install claude` works on a real Claude Code today; `mcp-proxy` works with any MCP server |
| 08 Presentation and live demo | `demo/SCRIPT.md`, `docs/PRESENTING.md` (preflight, stage, backup video), `docs/pitch/index.html` |

## Benchmark numbers

Run on 30 Oct 2026, 21:31 IST, with `uv run python bench/run_all.py`. Rerun before quoting.

| Benchmark | Attacks stopped (block or ask) | Size | Benign allowed | Decision time |
|---|---|---|---|---|
| AgentDojo (4 suites, important_instructions) | 96.2% (92.1% hard block) | 609 pairs | 95.9% tasks (95.0% calls) | under 1 ms |
| Shell attacks, no poisoned context | 100% (92.9% hard block) | 84 cmds | 82 of 82 (0 flagged) | under 1 ms |
| Shell attacks, after reading poisoned file | 100% (100% hard block) | 84 cmds | 82 of 82 (0 flagged) | under 1 ms |

False positives, said plainly: on AgentDojo, 5.0% of benign ground-truth calls get an ask or a block. Most of that is the banking suite, where paying bills always asks a human (36.4% of banking calls). The shell corpus flags none of 82 everyday developer commands, cold or after a poisoned read.

Read [bench/README.md](bench/README.md) before quoting these. There is no LLM in the loop: we replay AgentDojo's ground-truth call sequences, so a real hijacked model might phrase calls differently. One injection-marker pattern is fitted to AgentDojo's wrapper text. The provenance check does not depend on wording.

## Limitations

- If the injection only changes what the agent says, with no unusual tool call, Tripwire sees nothing.
- If you typed the same address the attacker uses, provenance cannot tell them apart.
- Data copied into an allowed file or sent to an allowed recipient is caught only when it matches a secret pattern.
- Tool calls that do not pass through a hook or the proxy are invisible.
- A host the attacker already runs code on can stop Tripwire.
- Shell tricks and secret patterns are finite. With no poisoned context, 6 of 84 shell attacks get an ask, not a block. Every verdict is in `bench/results/shell.json`.
- The intent check is keyword-based: if your prompt says "send", sending is expected.
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
