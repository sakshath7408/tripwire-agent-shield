# The brief (our rulebook)

Everything we build is checked against this page. Sources: the official PARALLAX brochure (BMSCE IEEE Computer Society,
30 to 31 Oct 2026) and the kickoff briefing by the judge's point of contact on 30 Oct. If the two ever disagree, the brochure wins.

## Event rules
- 24 hours, 4 PM 30 Oct to 4 PM 31 Oct 2026. Submissions open 2 PM and close 4 PM 31 Oct. Deadlines are strict.
- Project must be started from scratch during the hackathon. Libraries and frameworks are fine.
- Plagiarism or copying without attribution means disqualification. Credit every idea and library we use.
- Any language, framework or tool is allowed (AI coding tools confirmed allowed).
- Judges' decisions are final. Demo happens after submission, live, about 5 minutes, one team at a time.

## Track 1: AgentShield, "Secure the Agent, Not Just the Prompt"
Focus: AI-agent / MCP / tool-use security.

**Problem.** Agents read documents, call tools, search repos and act for users. Untrusted emails, pages, retrieved
files or tool responses can carry instructions that redirect the agent, leak secrets or misuse a permitted tool.
Filtering the user's prompt does not create a trustworthy boundary for tool permissions.

**Challenge.** Build a defensive layer that monitors and constrains an AI agent or tool-driven assistant in a
simulated environment. It must:
- [ ] distinguish legitimate tasks from unauthorized instructions arriving through untrusted content
- [ ] prevent at least one category of unsafe tool action
- [ ] give an inspectable reason for each decision

**Minimum build (24 h)**
- [ ] one simulated agent
- [ ] at least two tools or permissions
- [ ] a policy enforcement point
- [ ] an audit log

**Security scenarios (all data synthetic)**
- [ ] legitimate task
- [ ] prompt-injected web or document content
- [ ] unauthorized sensitive-data request
- [ ] tool invocation beyond permission

**Must show**
- [ ] explicit allow / deny / require-approval decisions
- [ ] user confirmation for high-impact actions
- [ ] fail-closed behaviour when confidence or policy is insufficient

**Optional extensions**
- [ ] MCP gateway
- [ ] tool permission profiles
- [ ] signed tool metadata
- [ ] cross-agent audit trails
- [ ] risk-aware approval queue

## Judging criteria (brochure)
1. **Security problem and threat relevance.** Real, current, clearly defined. The threat model names what is at risk and who the attacker is.
2. **Verified cybersecurity effectiveness.** Show the attack succeeding before the fix and failing after it.
3. **Technical implementation.** Sound, complete, well engineered.
4. **Innovation and originality.** A fresh approach, not a re-skinned tutorial.
5. **UI/UX.** Security people will actually use: clear, intuitive, low friction.
6. **Safety, privacy and responsible engineering.** Tested within scope, data handled responsibly, rules of engagement followed.
7. **Feasibility and real-world impact.** Could this be deployed? Who benefits, at what scale?
8. **Presentation and live demonstration.** A clear story and a working demo. Prove the fix on stage.

## What the judge stressed at the kickoff
- It must actually work. No bluffing with a front end over nothing.
- Real architecture and system design count, not only the UI.
- UI should be intuitive. Flashy or ultra-minimal is not required; clarity is.
- Safety, privacy and responsible engineering are scored.
- Must be feasible and something people would really use. "Build something you would use yourself."
- About 5 minutes per team, no hard cap. Highlight the most important parts.
- The layer must not rely on the agent double-checking itself.

## Release checklist (run before submission)
- [ ] every box above ticked, each with a file or demo step that proves it (see README requirement table)
- [ ] `uv run pytest -q` all green
- [ ] `uv run python bench/run_all.py` rerun, numbers copied into README and the pitch deck
- [ ] all 5 demo scenarios pass both acts (`demo/run_demo.py --scenario all --offline --delay 0 --approve auto`)
- [ ] dashboard checked by eye at 1280x720 and phone, light and dark
- [ ] demo rehearsed against demo/SCRIPT.md in under 5 minutes, fallbacks tested
- [ ] README credits every outside idea and library
- [ ] repo pushed and public
