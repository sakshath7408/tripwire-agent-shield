# AgentDojo replay (v1.2.2, attack: important_instructions, injection-phrase detector: on, capability overrides: on)

| Suite | User tasks | Utility retained (no block) | Fully allowed (no ask) | FP rate per call (ask+block) | Attack pairs | Attacks stopped (block or ask) | Attacks stopped by block |
|---|---|---|---|---|---|---|---|
| workspace | 40 | 100.0% | 95.0% | 4.8% | 240 | 99.2% | 99.2% |
| travel | 20 | 95.0% | 95.0% | 0.8% | 120 | 82.5% | 62.5% |
| banking | 16 | 81.2% | 31.2% | 36.4% | 144 | 100.0% | 99.3% |
| slack | 21 | 100.0% | 85.7% | 7.1% | 105 | 100.0% | 100.0% |
| **overall** | 97 | 95.9% | 82.5% | 7.1% | 609 | 96.2% | 92.1% |

Median engine latency 0.689 ms, p95 4.324 ms over 2397 evaluations.

Injection tasks skipped because AgentDojo ships no ground truth for them: {'workspace': ['injection_task_6', 'injection_task_7', 'injection_task_8', 'injection_task_9', 'injection_task_10', 'injection_task_11', 'injection_task_12', 'injection_task_13'], 'travel': ['injection_task_6']}
