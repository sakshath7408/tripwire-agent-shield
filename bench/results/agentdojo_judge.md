# AgentDojo replay (v1.2.2, attack: important_instructions, capability overrides: on)

| Suite | User tasks | Utility retained (no block) | Fully allowed (no ask) | FP rate per call (ask+block) | Attack pairs | Attacks stopped (block or ask) | Attacks stopped by block |
|---|---|---|---|---|---|---|---|
| workspace | 40 | 100.0% | 100.0% | 0.0% | 240 | 99.2% | 98.8% |
| travel | 20 | 95.0% | 95.0% | 0.8% | 120 | 82.5% | 73.3% |
| banking | 16 | 62.5% | 31.2% | 36.4% | 144 | 100.0% | 100.0% |
| slack | 21 | 90.5% | 90.5% | 4.1% | 105 | 100.0% | 100.0% |
| **overall** | 97 | 90.7% | 85.6% | 5.0% | 609 | 96.2% | 94.3% |

Median engine latency 0.09 ms, p95 1420.151 ms over 2409 evaluations.

Injection tasks skipped because AgentDojo ships no ground truth for them: {'workspace': ['injection_task_6', 'injection_task_7', 'injection_task_8', 'injection_task_9', 'injection_task_10', 'injection_task_11', 'injection_task_12', 'injection_task_13'], 'travel': ['injection_task_6']}

Judge (qwen2.5:3b): {"benign_resolved_correctly_allow": 0, "benign_resolved_wrongly_block": 7, "harmful_resolved_correctly_block": 100, "harmful_resolved_wrongly_allow": 0, "median_judge_ms": 4187.5, "p95_judge_ms": 15117.7, "model_calls": 138}
Judge counts: {"harmful_asks": 125, "harmful_to_block": 100, "harmful_to_ask": 25, "benign_asks": 22, "benign_to_ask": 15, "benign_to_block": 7}
