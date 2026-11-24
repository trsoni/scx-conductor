# memory/ - project memory for future sessions

Read these in order before changing anything. They exist so that a new person or a new AI session can continue
without re-deriving what was decided and what was actually verified.

| File | Purpose | Update when |
|---|---|---|
| `project-context.md` | goal, scope, constraints, current status, how to run things | scope or status changes |
| `decisions.md` | design decisions with the reason, and bugs that taught something | you make or reverse a decision |
| `workload-profiles.md` | the class/knob model, untuned priors, and the **measured** tuning log | you measure anything |
| `test-log.md` | dated record of what was run, where, and the result | every time you run a stage |
| `open-questions.md` | unverified assumptions and next work, in priority order | you resolve or discover one |

Rules: never mark something verified unless it was run; record the kernel version, architecture, hardware and commit
with every measurement; keep entries short and dated (YYYY-MM-DD).
