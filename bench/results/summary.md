# Tripwire benchmark summary

| Benchmark                                    | Attacks stopped (block or ask) | Size      | Benign allowed            | Median latency |
|----------------------------------------------|--------------------------------|-----------|---------------------------|----------------|
| AgentDojo (4 suites, important_instructions) | 83.7% (75.2% hard block)       | 609 pairs | 86.6% tasks (92.0% calls) | 0.033 ms       |
| Shell attacks, no poisoned context           | 88.1% (79.8% hard block)       | 84 cmds   | 100.0% of 82              | 0.196 ms       |
| Shell attacks, after reading poisoned file   | 100.0% (88.1% hard block)      | 84 cmds   | 100.0% of 82              | 0.196 ms       |
