# Tripwire: every AgentDojo attack, with and without the phrase detector

Run 31 Oct 2026 07:47 with `uv run python bench/run_all.py`. "Phrase detector OFF" means `INJECTION_MARKERS` never matches, so only provenance, intent, secrets, shell and policy checks are left. Benign tasks allowed means no hard block in the task (an ask still counts as allowed); the last column also excludes asks.

| Attack                 | Phrase detector | Pairs | Stopped (block or ask) | Hard block | Benign tasks allowed | Benign tasks, no ask |
|------------------------|-----------------|-------|------------------------|------------|----------------------|----------------------|
| important_instructions | on              | 609   | 99.8%                  | 97.9%      | 95.9%                | 82.5%                |
| important_instructions | OFF             | 609   | 99.5%                  | 87.0%      | 95.9%                | 82.5%                |
| tool_knowledge         | on              | 609   | 99.8%                  | 97.9%      | 95.9%                | 82.5%                |
| tool_knowledge         | OFF             | 609   | 99.5%                  | 86.7%      | 95.9%                | 82.5%                |
| ignore_previous        | on              | 609   | 99.5%                  | 86.9%      | 95.9%                | 82.5%                |
| ignore_previous        | OFF             | 609   | 99.5%                  | 86.9%      | 95.9%                | 82.5%                |
| injecagent             | on              | 609   | 99.8%                  | 97.7%      | 95.9%                | 82.5%                |
| injecagent             | OFF             | 609   | 99.5%                  | 87.2%      | 95.9%                | 82.5%                |
| direct                 | on              | 609   | 99.5%                  | 87.2%      | 95.9%                | 82.5%                |
| direct                 | OFF             | 609   | 99.5%                  | 87.2%      | 95.9%                | 82.5%                |
| system_message         | on              | 609   | 99.5%                  | 87.2%      | 95.9%                | 82.5%                |
| system_message         | OFF             | 609   | 99.5%                  | 87.2%      | 95.9%                | 82.5%                |
| shell corpus, cold     | on              | 96    | 100.0%                 | 94.8%      | 100.0% (cmds)        | -                    |
| shell corpus, poisoned | on              | 96    | 100.0%                 | 100.0%     | 100.0% (cmds)        | -                    |
| shell corpus, cold     | OFF             | 96    | 100.0%                 | 94.8%      | 100.0% (cmds)        | -                    |
| shell corpus, poisoned | OFF             | 96    | 100.0%                 | 100.0%     | 100.0% (cmds)        | -                    |
