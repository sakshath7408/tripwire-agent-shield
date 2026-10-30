# Tripwire: every AgentDojo attack, with and without the phrase detector

Run 30 Oct 2026 23:17 with `uv run python bench/run_all.py`. "Phrase detector OFF" means `INJECTION_MARKERS` never matches, so only provenance, intent, secrets, shell and policy checks are left. Benign tasks allowed means no hard block in the task (an ask still counts as allowed); the last column also excludes asks.

| Attack                 | Phrase detector | Pairs | Stopped (block or ask) | Hard block | Benign tasks allowed | Benign tasks, no ask |
|------------------------|-----------------|-------|------------------------|------------|----------------------|----------------------|
| important_instructions | on              | 609   | 96.2%                  | 92.1%      | 95.9%                | 82.5%                |
| important_instructions | OFF             | 609   | 86.0%                  | 45.3%      | 95.9%                | 82.5%                |
| tool_knowledge         | on              | 609   | 99.5%                  | 95.4%      | 95.9%                | 82.5%                |
| tool_knowledge         | OFF             | 609   | 86.0%                  | 45.3%      | 95.9%                | 82.5%                |
| ignore_previous        | on              | 609   | 86.0%                  | 45.3%      | 95.9%                | 82.5%                |
| ignore_previous        | OFF             | 609   | 86.0%                  | 45.3%      | 95.9%                | 82.5%                |
| injecagent             | on              | 609   | 96.2%                  | 88.5%      | 95.9%                | 82.5%                |
| injecagent             | OFF             | 609   | 86.0%                  | 45.3%      | 95.9%                | 82.5%                |
| direct                 | on              | 609   | 86.0%                  | 45.3%      | 95.9%                | 82.5%                |
| direct                 | OFF             | 609   | 86.0%                  | 45.3%      | 95.9%                | 82.5%                |
| system_message         | on              | 609   | 86.0%                  | 45.3%      | 95.9%                | 82.5%                |
| system_message         | OFF             | 609   | 86.0%                  | 45.3%      | 95.9%                | 82.5%                |
| shell corpus, cold     | on              | 84    | 100.0%                 | 94.0%      | 100.0% (cmds)        | -                    |
| shell corpus, poisoned | on              | 84    | 100.0%                 | 100.0%     | 100.0% (cmds)        | -                    |
| shell corpus, cold     | OFF             | 84    | 100.0%                 | 94.0%      | 100.0% (cmds)        | -                    |
| shell corpus, poisoned | OFF             | 84    | 100.0%                 | 100.0%     | 100.0% (cmds)        | -                    |
