# Tripwire

**Live demo: https://tripwire-agent-shield.vercel.app** Pick an attack, run it without Tripwire, then with it. The real engine runs on the server against a synthetic world.

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
uv run python demo/run_demo.py --scenario all --offline --delay 0 --approve auto   # all four, no daemon needed
```

Put it in front of a real agent:

```bash
uv run tripwire install claude            # adds hooks to ./.claude/settings.json (--user for all projects)
uv run tripwire mcp-proxy --name fs --profile coding-assistant -- npx -y @modelcontextprotocol/server-filesystem .
uv run tripwire pins list                 # signed MCP tool pins
uv run pytest -q                          # 320 tests
uv run python bench/run_all.py            # benchmarks, about 20 s, writes bench/results/summary.md
```

The dashboard shows every verdict live, holds "ask" actions in an approval queue with Allow and Block buttons, and keeps an audit log.

The demo agent is a scripted stand-in for a hijacked model by default. With Ollama installed, `--planner ollama --model qwen2.5:3b` runs a real local model with native tool calling through the same world and guard (`demo/world/ollama_planner.py`).

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
| Audit log | SQLite at `~/.tripwire/audit.db` (`server.py`, class `Audit`), `GET /v1/audit`, dashboard "Audit log" tab |
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
| Optional: cross-agent audit trails | partial. One audit log for every adapter, keyed by session id; the dashboard lists all sessions. No cross-session correlation yet |

| Judging criterion | Where to look |
|---|---|
| 01 Threat relevance | `demo/THREAT_MODEL.md` names what is at risk and who the attacker is |
| 02 Verified effectiveness | `tests/test_bench.py::test_attack_succeeds_without_guard_and_fails_with_it`, `demo/run_demo.py` Act 1 vs Act 2, `bench/results/` |
| 03 Technical implementation | `src/tripwire/` (about 4,000 lines), 320 tests |
| 04 Innovation | provenance at the tool boundary (`taint.py`), signed MCP pins (`pins.py`), AST-based shell analysis (`shell.py`) |
| 05 UI/UX | `src/tripwire/static/` dashboard: live feed, approval queue, evidence panel, audit log |
| 06 Safety, privacy, responsible engineering | local only, args redacted before storage (`secrets.redact`), fail closed, guard cannot be edited by the agent (`never-touch-tripwire` rule) |
| 07 Feasibility and real-world impact | `tripwire install claude` works on a real Claude Code today; `mcp-proxy` works with any MCP server |
| 08 Presentation and live demo | `demo/SCRIPT.md`, `docs/pitch/index.html` |

## Benchmark numbers

Run on 30 Oct 2026, 19:23 IST, with `uv run python bench/run_all.py`. The shell analyzer is still being improved, so rerun before quoting.

| Benchmark | Attacks stopped (block or ask) | Size | Benign allowed | Median latency |
|---|---|---|---|---|
| AgentDojo (4 suites, important_instructions) | 96.2% (85.9% hard block) | 609 pairs | 95.9% tasks (95.0% calls) | 0.029 ms |
| Shell attacks, no poisoned context | 88.1% (79.8% hard block) | 84 cmds | 100.0% of 82 | 0.175 ms |
| Shell attacks, after reading poisoned file | 100.0% (88.1% hard block) | 84 cmds | 100.0% of 82 | 0.175 ms |

False positives, said plainly: on AgentDojo, 5.0% of benign ground-truth calls get an ask or a block. Most of that is the banking suite, where paying bills always asks a human (36.4% of banking calls). The shell corpus has zero false positives on 82 everyday developer commands.

Read [bench/README.md](bench/README.md) before quoting these. There is no LLM in the loop: we replay AgentDojo's ground-truth call sequences, so a real hijacked model might phrase calls differently. One injection-marker pattern is fitted to AgentDojo's wrapper text. The provenance check does not depend on wording.

## Limitations

- If the injection only changes what the agent says, with no unusual tool call, Tripwire sees nothing.
- If you typed the same address the attacker uses, provenance cannot tell them apart.
- Data copied into an allowed file or sent to an allowed recipient is caught only when it matches a secret pattern.
- Tool calls that do not pass through a hook or the proxy are invisible.
- A host the attacker already runs code on can stop Tripwire.
- Shell tricks and secret patterns are finite. `bench/results/shell.md` lists the misses.
- The intent check is keyword-based: if your prompt says "send", sending is expected.
- The Claude Code adapter never widens Claude Code's own permissions. An "allow" from Tripwire still goes through Claude Code's normal prompt unless `TRIPWIRE_AUTO_APPROVE=1`.

## Credits

- [AgentDojo](https://github.com/ethz-spylab/agentdojo) (Debenedetti et al., ETH Zurich, NeurIPS 2024) for the suites, ground truth and attack text.
- [CaMeL](https://arxiv.org/abs/2503.18813) (Debenedetti et al., Google DeepMind / ETH Zurich, 2025) for the idea that untrusted data must not choose where data flows.
- Simon Willison's [dual-LLM pattern](https://simonwillison.net/2023/Apr/25/dual-llm-pattern/): the model that decides never reads untrusted text.
- [bashlex](https://github.com/idank/bashlex) for the shell parser.

Everything in `src/`, `demo/`, `bench/` and `tests/` was written from scratch during the hackathon. Dependencies: FastAPI, uvicorn, pydantic, PyYAML, httpx, sse-starlette, bashlex. Dev only: pytest, agentdojo.
