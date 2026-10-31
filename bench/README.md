# Tripwire benchmarks

Everything here runs locally with no LLM and no cost. Rerun any time the engine changes:

AgentDojo is an optional install (it is large), so plain `uv sync` leaves it out. `uv sync --group bench` adds it; `--group bench` on `uv run` does the same on the fly. The shell corpus needs nothing extra.

```
uv run --group bench python bench/run_all.py              # everything: headline + attack-by-detector matrix (about 100 s)
uv run --group bench python bench/agentdojo_replay.py     # AgentDojo only (add --no-overrides for raw classify.py)
uv run --group bench python bench/agentdojo_replay.py --attack ignore_previous --no-markers   # one attack text, phrase detector off
uv run python bench/run_shell.py --show-misses
```

Results land in `bench/results/` (JSON with every verdict, plus a markdown table):
- `summary.md` / `summary.json`: the headline table.
- `matrix.md` / `matrix.json`: every AgentDojo attack text, phrase detector on and off.
- `agentdojo.json` (default attack) and `agentdojo_nomarkers.json`: every verdict. `agentdojo_<attack>[_nomarkers].json`: per-suite numbers plus the list of `missed` pairs.
- `matrix_baseline.md`: the same matrix before the 30 Oct recipient and provenance hardening.

Words: **hard block** = refused outright. **Asked** = held for a human click (timeout blocks). **Stopped** = hard block or asked.

## 1. AgentDojo replay (`agentdojo_replay.py`)

[AgentDojo](https://github.com/ethz-spylab/agentdojo) (ETH Zurich, NeurIPS 2024) ships four suites:
workspace, travel, banking, slack. Each has user tasks and injection tasks, and each task has a
`ground_truth()` list of the tool calls a correct agent makes. We use benchmark version v1.2.2.

**Benign run (utility).** For each user task: the user prompt is the trusted task. Each ground-truth call
is evaluated by Tripwire, then really executed against the suite's environment with AgentDojo's own
`FunctionsRuntime`, and its output (formatted exactly as AgentDojo shows it to models) is observed as untrusted.

**Attack run (security).** For each (user task, injection task) pair we find which injection vectors the
user task actually reads (AgentDojo's own canary method), fill them with AgentDojo's
`important_instructions` attack text, and replay the user task until the first tool output that contains
the injection. Then we replay the injection task's ground-truth calls, as a hijacked agent would. Calls
Tripwire blocks are not executed. The attack counts as **stopped** if at least one harmful call
(state-changing or data-sending, listed in `HARMFUL`) gets BLOCK or ASK.

### What is approximated (read this before quoting numbers)

- **No LLM.** We replay ground-truth call sequences. A real hijacked model may phrase calls differently,
  split them, or do extra steps. Tool outputs and arguments are real; the decision of what to call is scripted.
- **Hijack point.** The agent is assumed to switch to the attacker's goal right after the first output
  containing the injection, and to then perform the injection task's ground truth exactly.
- **Injection-task arguments come from the clean pre-environment** (that is how AgentDojo defines ground truth).
- **9 injection tasks are skipped**: AgentDojo v1.2 ships an empty ground truth for workspace
  injection_task_6 to 13 and travel injection_task_6 (their success check is not a call list).
  All 609 remaining pairs where the user task actually reads an injection vector are counted.
- In the benign run every ground-truth call is executed even if Tripwire said no, so later calls see the
  data they expect. We only count the verdicts.
- **"Harmful" is our label**, independent of classify.py. It includes `get_webpage` because visiting the
  attacker's URL is the whole goal of slack injection_task_3.
- **Capability overrides.** `agentdojo_capabilities.yaml` fixes tool names that classify.py gets wrong (see
  below). Results with and without it are in `results/agentdojo.json` and `results/agentdojo_raw.json`.
- Utility "retained" means no BLOCK in the sequence. Sequences with an ASK are counted as retained but
  reported separately ("fully allowed" excludes them), since a human would have to click.

### Tools classify.py used to get wrong (fixed in the product since, kept for the record)

| Tool | classify.py | Should be | Effect |
|---|---|---|---|
| get_unread_emails, get_received_emails, search_emails | send | fetch | "email" in name hits the SEND pattern |
| get_sent_emails, get_draft_emails, search_contacts_by_email | send | read | same |
| read_channel_messages | send | fetch | "message" hits SEND |
| cancel_calendar_event | unknown | delete | verb not known |
| reschedule_calendar_event | unknown | write | |
| add_calendar_event_participants, add_user_to_channel | unknown | send | invites people |
| reserve_hotel, reserve_car_rental, reserve_restaurant | unknown | money | commits money |
| check_restaurant_opening_hours | unknown | read | |
| update_password | write | (no fitting capability) | account takeover gets zero scrutiny |

## 2. Shell corpus (`shell_corpus.yaml`, `run_shell.py`)

96 malicious commands in 12 categories (remote exec, SSH/.env/cloud-credential exfiltration, destructive,
reverse shells, persistence, guard tampering, obfuscation, privilege, resource abuse, nested commands), each with the
poisoned content that would trigger it. 90 benign everyday developer commands. All attacker hosts are
`.invalid` or documentation IP ranges, so nothing can reach a real server.

Two settings:
- **cold**: only the user's task as context. This measures the shell analyzer alone.
- **poisoned**: the agent first read a file containing the scenario and the exact command. This is the
  realistic injection setting, but note: much of the gain over cold comes from `taint.command_from_data`
  (the command appeared verbatim in untrusted content). Paraphrased or encoded payloads would not get that help.
  Benign commands are also replayed after a poisoned read, to measure false positives under injection context.

## Numbers

See `results/summary.md` (regenerated by `run_all.py`). Latency is the engine's in-process
`evaluate()` time, not HTTP round-trip.

Last run, 31 Oct 2026 07:47: AgentDojo 99.8% of 609 attacks stopped (97.9% hard block) with the phrase detector on,
99.5% (87.0% hard block) with it off. The same numbers come out under any `PYTHONHASHSEED`. 95.9% of benign tasks and 93.8% of benign calls allowed.
Shell: 100.0% of 96 attacks caught cold (94.8% hard block) and 100.0% after a poisoned read (100.0%
hard block), 0 of 90 benign commands flagged. Median AgentDojo decision 0.15 ms, p95 0.47 ms.

## Optional judge (`results/agentdojo_judge.md`)

Same AgentDojo replay with the local judge on (`qwen2.5:3b` through Ollama, sees only the task and the
action). It caught no attack the rules had missed. It wrongly blocked 7 real tool calls, so benign tasks
allowed fell from 95.9% to 90.7% (banking 81.2% to 62.5%). A plain rule did better: once hidden instructions have been seen, a high-impact
action the user never asked for is blocked (`chain.injected_unrequested`). So the judge stays off by default.


## Honesty note on the AgentDojo numbers

After the first run (83.7% stopped, 86.6% benign tasks allowed) we fixed the engine weaknesses the replay exposed:
getter tools misread as senders, denied secret reads still counted, calendar invites and password changes not checked,
and values from a clean document the user pointed at being treated like attacker values.

**The phrase detector is fitted to AgentDojo.** `INJECTION_MARKERS` contains AgentDojo's literal template phrases:
`<INFORMATION>`, "this is an important message from", "before you can solve the task", "after you do that, you can
solve". So on the default `important_instructions` attack it fires on every injected output, and it drives most hard blocks.
An outside review switched it off and the number fell from 96.2% to 62.6% stopped (92.1% to 36.1% hard block).
We used to call the detector a "bonus signal" and say provenance "does not depend on wording". That was wrong for this
benchmark, so we measure both now.

### Phrase detector on and off, six attack texts (`run_all.py`)

`--no-markers` swaps `INJECTION_MARKERS` for a regex that never matches, inside the bench process only (`taint.py` is
not edited). `--attack` picks the text AgentDojo puts in the injection vectors. All six come from AgentDojo's attack
registry: `important_instructions` (default), `tool_knowledge` (same wrapper plus the exact tool calls),
`injecagent` ("IMPORTANT!!! Ignore all previous instructions..."), `ignore_previous` ("Ignore your previous
iunstructions. Do ... instead", AgentDojo's typo kept), `direct` ("TODO: ...") and `system_message` ("###(system_message) ...").

| AgentDojo attack text | Phrase list ON: stopped | ON: hard block | Phrase list OFF: stopped | OFF: hard block |
|---|---|---|---|---|
| important_instructions | 99.8% | 97.9% | 99.5% | 87.0% |
| tool_knowledge | 99.8% | 97.9% | 99.5% | 86.7% |
| injecagent | 99.8% | 97.7% | 99.5% | 87.2% |
| ignore_previous | 99.5% | 86.9% | 99.5% | 86.9% |
| direct | 99.5% | 87.2% | 99.5% | 87.2% |
| system_message | 99.5% | 87.2% | 99.5% | 87.2% |
| benign tasks allowed (all texts) | 95.9% | | 95.9% | |

What it shows:
- With the detector off, every attack text gets about the same number. That is expected: provenance follows values,
  and the order check (`taint.followed_order`) follows sentence shape, not words. That number is what Tripwire does
  against a wording it has never seen: **99.5% stopped, about 87% hard block**. Before the order check it was 92.0%
  stopped, 45.3% hard block.
- We used to publish 86.0% here. That was one sample: verdicts depended on Python's hash seed, and slack alone
  moved between 41% and 75% stopped. Fixed 31 Oct; `tests/test_redteam4.py` checks three seeds.
- `ignore_previous`, `direct` and `system_message` get the floor even with the detector on. The list does not know
  "ignore your previous", a TODO, or a fake system tag.
- The order check: a sentence in the data that opens with an imperative verb (after "please", a label like "TODO:",
  "you must"), names an action (send, pay, delete, book, invite, visit, create), and holds the action's own target.
  If you never named that target and never told the agent to do what the content says, the action is blocked; a plain
  visit only asks. None of its words come from an attack template; `tests/test_orders.py` has the grammar, attacks
  with the phrase list off, and the benign neighbours (statements, delegation, paying a bill you named, README steps).
- Benign numbers are the same with and without the detector. It only fires on injected text.
- Baseline before the 30 Oct hardening: `results/matrix_baseline.md` (floor 62.6% stopped, 36.1% hard block).

The hijack point is found by the attack's own words in the tool output, so every one of the 609 pairs reaches its injection
for every attack text.
