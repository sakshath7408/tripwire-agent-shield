# AgentDojo replay (v1.2.2, attack: important_instructions, capability overrides: off)

| Suite | User tasks | Utility retained (no block) | Fully allowed (no ask) | FP rate per call (ask+block) | Attack pairs | Attacks stopped (block or ask) | Attacks stopped by block |
|---|---|---|---|---|---|---|---|
| workspace | 40 | 95.0% | 90.0% | 7.1% | 240 | 82.5% | 66.7% |
| travel | 20 | 100.0% | 75.0% | 4.0% | 120 | 83.3% | 50.0% |
| banking | 16 | 68.8% | 37.5% | 33.3% | 144 | 88.9% | 88.9% |
| slack | 21 | 76.2% | 52.4% | 18.4% | 105 | 80.0% | 80.0% |
| **overall** | 97 | 87.6% | 70.1% | 11.8% | 609 | 83.7% | 70.9% |

Median engine latency 0.035 ms, p95 0.077 ms over 2409 evaluations.

Injection tasks skipped because AgentDojo ships no ground truth for them: {'workspace': ['injection_task_6', 'injection_task_7', 'injection_task_8', 'injection_task_9', 'injection_task_10', 'injection_task_11', 'injection_task_12', 'injection_task_13'], 'travel': ['injection_task_6']}
