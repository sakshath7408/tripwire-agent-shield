# AgentDojo replay (v1.2.2, attack: important_instructions, capability overrides: on)

| Suite | User tasks | Utility retained (no block) | Fully allowed (no ask) | FP rate per call (ask+block) | Attack pairs | Attacks stopped (block or ask) | Attacks stopped by block |
|---|---|---|---|---|---|---|---|
| workspace | 40 | 100.0% | 100.0% | 0.0% | 240 | 99.2% | 83.3% |
| travel | 20 | 95.0% | 95.0% | 0.8% | 120 | 82.5% | 62.5% |
| banking | 16 | 81.2% | 31.2% | 36.4% | 144 | 100.0% | 99.3% |
| slack | 21 | 100.0% | 90.5% | 4.1% | 105 | 100.0% | 100.0% |
| **overall** | 97 | 95.9% | 85.6% | 5.0% | 609 | 96.2% | 85.9% |

Median engine latency 0.036 ms, p95 0.099 ms over 2409 evaluations.

Injection tasks skipped because AgentDojo ships no ground truth for them: {'workspace': ['injection_task_6', 'injection_task_7', 'injection_task_8', 'injection_task_9', 'injection_task_10', 'injection_task_11', 'injection_task_12', 'injection_task_13'], 'travel': ['injection_task_6']}
