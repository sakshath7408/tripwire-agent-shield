# AgentDojo replay (v1.2.2, attack: tool_knowledge, injection-phrase detector: on, capability overrides: on)

| Suite | User tasks | Utility retained (no block) | Fully allowed (no ask) | FP rate per call (ask+block) | Attack pairs | Attacks stopped (block or ask) | Attacks stopped by block |
|---|---|---|---|---|---|---|---|
| workspace | 0 | 0.0% | 0.0% | 0.0% | 240 | 99.2% | 99.2% |
| travel | 0 | 0.0% | 0.0% | 0.0% | 120 | 99.2% | 79.2% |
| banking | 0 | 0.0% | 0.0% | 0.0% | 144 | 100.0% | 99.3% |
| slack | 0 | 0.0% | 0.0% | 0.0% | 105 | 100.0% | 100.0% |
| **overall** | 0 | 0.0% | 0.0% | 0.0% | 609 | 99.5% | 95.4% |

Median engine latency 0.146 ms, p95 0.5 ms over 2058 evaluations.

Injection tasks skipped because AgentDojo ships no ground truth for them: {'workspace': ['injection_task_6', 'injection_task_7', 'injection_task_8', 'injection_task_9', 'injection_task_10', 'injection_task_11', 'injection_task_12', 'injection_task_13'], 'travel': ['injection_task_6']}
