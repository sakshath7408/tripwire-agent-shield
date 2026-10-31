# Tripwire benchmark summary

| Benchmark                                    | Attacks stopped (block or ask) | Size      | Benign allowed            | Median latency |
|----------------------------------------------|--------------------------------|-----------|---------------------------|----------------|
| AgentDojo (4 suites, important_instructions) | 96.2% (92.1% hard block)       | 609 pairs | 95.9% tasks (92.9% calls) | 0.143 ms       |
| Shell attacks, no poisoned context           | 100.0% (94.8% hard block)      | 96 cmds   | 100.0% of 90              | 0.509 ms       |
| Shell attacks, after reading poisoned file   | 100.0% (100.0% hard block)     | 96 cmds   | 100.0% of 90              | 0.509 ms       |
