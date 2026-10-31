# Tripwire benchmark summary

| Benchmark                                    | Attacks stopped (block or ask) | Size      | Benign allowed            | Median latency |
|----------------------------------------------|--------------------------------|-----------|---------------------------|----------------|
| AgentDojo (4 suites, important_instructions) | 99.8% (97.9% hard block)       | 609 pairs | 95.9% tasks (93.8% calls) | 0.584 ms       |
| Shell attacks, no poisoned context           | 100.0% (94.8% hard block)      | 96 cmds   | 100.0% of 90              | 1.267 ms       |
| Shell attacks, after reading poisoned file   | 100.0% (100.0% hard block)     | 96 cmds   | 100.0% of 90              | 1.267 ms       |
