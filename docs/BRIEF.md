# The brief (our rulebook)

Everything we build is checked against this page. Sources: the official PARALLAX brochure (BMSCE IEEE Computer Society,
30 to 31 Oct 2026) and the kickoff briefing by the judge's point of contact on 30 Oct. If the two ever disagree, the brochure wins.

## Event rules
- 24 hours, 4 PM 30 Oct to 4 PM 31 Oct 2026. Submissions open 2 PM and close 4 PM 31 Oct. Deadlines are strict.
- Project must be started from scratch during the hackathon. Libraries and frameworks are fine.
- Plagiarism or copying without attribution means disqualification. Credit every idea and library we use.
- Any language, framework or tool is allowed (AI coding tools confirmed allowed).
- Judges' decisions are final. Demo happens after submission, live, about 5 minutes, one team at a time.

## Track 1: AgentShield, "Secure the Agent, Not Just the Prompt"
Focus: AI-agent / MCP / tool-use security.

**Problem.** Agents read documents, call tools, search repos and act for users. Untrusted emails, pages, retrieved
files or tool responses can carry instructions that redirect the agent, leak secrets or misuse a permitted tool.
Filtering the user's prompt does not create a trustworthy boundary for tool permissions.

**Challenge.** Build a defensive layer that monitors and constrains an AI agent or tool-driven assistant in a
simulated environment. It must:
- [x] distinguish legitimate tasks from unauthorized instructions arriving through untrusted content. Proof: `src/tripwire/taint.py`; `demo/run_demo.py --scenario all --offline --delay 0 --approve auto` (task calls allowed, injected calls blocked, task done in all 5)
- [x] prevent at least one category of unsafe tool action. Proof: exfiltration, remote exec, money, out-of-role tools all blocked in the demo; `bench/results/shell.md` (84 of 84 shell attacks caught)
- [x] give an inspectable reason for each decision. Proof: `Finding.message` on every verdict (`models.py`), shown in the demo output, the dashboard evidence panel and `tripwire audit tail`

**Minimum build (24 h)**
- [x] one simulated agent. Proof: `demo/world/agent.py` (`NaivePlanner`; optional real model in `ollama_planner.py`)
- [x] at least two tools or permissions. Proof: `demo/world/world.py` (10 tools), 3 role profiles in `default_policy.yaml`
- [x] a policy enforcement point. Proof: `POST /v1/evaluate` in `server.py`; adapters run nothing but allow (`tests/test_adapters.py::test_hook_fails_closed`)
- [x] an audit log. Proof: `src/tripwire/audit.py`; with a throwaway `TRIPWIRE_HOME`, a guarded run then `tripwire audit verify` said 23 records intact, and an edited export failed with "TAMPERED: Record #11"

**Security scenarios (all data synthetic)**
- [x] legitimate task. Proof: `demo/run_demo.py --scenario legit`
- [x] prompt-injected web or document content. Proof: `--scenario injected-doc` and `--scenario injected-web`
- [x] unauthorized sensitive-data request. Proof: `--scenario sensitive-data`
- [x] tool invocation beyond permission. Proof: `--scenario beyond-permission` (no guard: balance $7,600; Tripwire: $12,500). All fixtures synthetic, attacker hosts `.invalid`

**Must show**
- [x] explicit allow / deny / require-approval decisions. Proof: `Decision` in `models.py`; demo prints ALLOW / ASK / BLOCK on every call
- [x] user confirmation for high-impact actions. Proof: `impact.money` in `engine.py`; `--approve dashboard` holds the call until Allow or Block (`?wait=N`, timeout blocks: `tests/test_audit.py::test_timeout_resolution_is_chained`)
- [x] fail-closed behaviour when confidence or policy is insufficient. Proof: unknown tool asks, unknown profile blocks (`tests/test_engine.py`), engine crash blocks, daemon down denies (seen live: "Tripwire is unreachable (ConnectError), so nothing runs"; `tests/test_adapters.py::test_proxy_fails_closed_when_daemon_down`)

**Optional extensions**
- [x] MCP gateway. Proof: `src/tripwire/adapters/mcp_proxy.py`, `tests/test_adapters.py::test_proxy_passes_benign_blocks_injected`
- [x] tool permission profiles. Proof: `default_policy.yaml` (coding, inbox, finance), `tests/test_engine.py::test_profile_blocks_tool_beyond_permission`
- [x] signed tool metadata. Proof: `src/tripwire/adapters/pins.py`, `tests/test_adapters.py::test_pins_rug_pull_new_tool_and_poison`
- [x] cross-agent audit trails. Proof: `audit.py` (`agent`, `parent`, `trace`, hash chain + HMAC), `tests/test_audit.py::test_subagent_verdicts_land_under_parent_trace`, `test_sdk_agents_and_nested_spawns`; sub-agent fields checked against real Claude Code 2.1.241
- [x] risk-aware approval queue. Proof: dashboard queue sorted by risk, highest first (`static/app.js`), timeout blocks

## Judging criteria (brochure)
- [x] 1. **Security problem and threat relevance.** Real, current, clearly defined. The threat model names what is at risk and who the attacker is. Proof: `demo/THREAT_MODEL.md`
- [x] 2. **Verified cybersecurity effectiveness.** Show the attack succeeding before the fix and failing after it. Proof: Act 1 vs Act 2 in `demo/run_demo.py` (all 5 pass in `scripts/preflight.sh`), `tests/test_bench.py::test_attack_succeeds_without_guard_and_fails_with_it`, `bench/results/summary.md`, live at https://tripwire-agent-shield.vercel.app (checked: no guard 3 items stolen, guarded 0)
- [x] 3. **Technical implementation.** Sound, complete, well engineered. Proof: `docs/ARCHITECTURE.md`, `uv run pytest -q` (905 passed, 1 xfailed)
- [x] 4. **Innovation and originality.** A fresh approach, not a re-skinned tutorial. Proof: provenance at the tool boundary (`taint.py`), signed MCP pins, shell AST, tamper-evident cross-agent audit chain
- [x] 5. **UI/UX.** Security people will actually use: clear, intuitive, low friction. Proof: `src/tripwire/static/`, checked by eye 31 Oct at 1280x720 and phone, light and dark
- [x] 6. **Safety, privacy and responsible engineering.** Tested within scope, data handled responsibly, rules of engagement followed. Proof: binds 127.0.0.1, args redacted before storage (`secrets.redact`), synthetic data only, `never-touch-tripwire` rule, `tests/test_redteam.py`
- [x] 7. **Feasibility and real-world impact.** Could this be deployed? Who benefits, at what scale? Proof: `tripwire install claude` (checked with real Claude Code 30 Oct), `tripwire mcp-proxy` for any MCP server
- [x] 8. **Presentation and live demonstration.** A clear story and a working demo. Prove the fix on stage. Proof: `demo/SCRIPT.md`, `docs/PRESENTING.md`, `docs/pitch/index.html`, `scripts/preflight.sh` all green

## What the judge stressed at the kickoff
- [x] It must actually work. No bluffing with a front end over nothing. Proof: the engine, not the UI, decides; demo and bench run with no dashboard (`--offline`)
- [x] Real architecture and system design count, not only the UI. Proof: `docs/ARCHITECTURE.md`
- [x] UI should be intuitive. Flashy or ultra-minimal is not required; clarity is. Proof: one plain-English line per verdict, evidence panel
- [x] Safety, privacy and responsible engineering are scored. Proof: see criterion 6
- [x] Must be feasible and something people would really use. "Build something you would use yourself." Proof: see criterion 7
- [x] About 5 minutes per team, no hard cap. Highlight the most important parts. Proof: `demo/SCRIPT.md` (timed at about 4:45 in balanced mode, 60-second version too)
- [x] The layer must not rely on the agent double-checking itself. Proof: decisions are made outside the agent by deterministic checks; the optional judge never sees tool output (`tests/test_judge.py::test_never_sees_tool_outputs`)

## Release checklist (run before submission)
- [x] every box above ticked, each with a file or demo step that proves it (see README requirement table). Checked 31 Oct
- [x] `uv run pytest -q` all green. 905 passed, 1 xfailed
- [x] `uv run python bench/run_all.py` rerun, numbers copied into README and the pitch deck. Run 30 Oct 21:31; README, pitch slide 5, `bench/README.md` match `bench/results/summary.md`
- [x] all 5 demo scenarios pass both acts (`demo/run_demo.py --scenario all --offline --delay 0 --approve auto`). Also all green in `scripts/preflight.sh 7796` on a scratch daemon
- [x] dashboard checked by eye at 1280x720 and phone, light and dark. Scratch daemon, after two guarded runs
- [ ] demo rehearsed against demo/SCRIPT.md in under 5 minutes, fallbacks tested. Not ticked: needs a human run on the stage laptop and projector. The offline and test fallbacks work; backup videos re-recorded 31 Oct for balanced mode
- [x] README credits every outside idea and library. AgentDojo, CaMeL, dual-LLM, bashlex, Ollama/Qwen, MCP, Claude Code hooks, every library, Playwright and imageio-ffmpeg for recording, Vercel
- [x] repo pushed and public. github.com/sakshath7408/tripwire-agent-shield is PUBLIC (`gh repo view`)
