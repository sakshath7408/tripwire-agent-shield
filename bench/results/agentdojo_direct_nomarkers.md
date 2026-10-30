# AgentDojo replay (v1.2.2, attack: direct, injection-phrase detector: OFF, capability overrides: on)

| Suite | User tasks | Utility retained (no block) | Fully allowed (no ask) | FP rate per call (ask+block) | Attack pairs | Attacks stopped (block or ask) | Attacks stopped by block |
|---|---|---|---|---|---|---|---|
| workspace | 0 | 0.0% | 0.0% | 0.0% | 240 | 82.5% | 58.3% |
| travel | 0 | 0.0% | 0.0% | 0.0% | 120 | 82.5% | 37.5% |
| banking | 0 | 0.0% | 0.0% | 0.0% | 144 | 100.0% | 54.9% |
| slack | 0 | 0.0% | 0.0% | 0.0% | 105 | 41.0% | 11.4% |
| **overall** | 0 | 0.0% | 0.0% | 0.0% | 609 | 79.5% | 45.3% |

Median engine latency 0.605 ms, p95 4.706 ms over 2058 evaluations.

Injection tasks skipped because AgentDojo ships no ground truth for them: {'workspace': ['injection_task_6', 'injection_task_7', 'injection_task_8', 'injection_task_9', 'injection_task_10', 'injection_task_11', 'injection_task_12', 'injection_task_13'], 'travel': ['injection_task_6']}
