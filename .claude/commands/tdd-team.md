---
argument-hint: <issue-numbers>
description: Autonomous TDD team with task-list-driven self-coordination - scales to scope, reviews as subagents
allowed-tools: Read, Grep, Glob, Bash, Edit, Write, Task, WebFetch, TeamCreate, TeamDelete, TaskCreate, TaskUpdate, TaskList, TaskGet, SendMessage, AskUserQuestion, EnterPlanMode, ExitPlanMode
---

# Autonomous TDD Team: Issue(s) #$ARGUMENTS

You are the **lead** for an autonomous TDD team. You design the task graph, spawn teammates scaled to scope, and let them self-coordinate via the shared task list. You CAN write code as a fallback if a teammate is stuck.

---

## Phase 1: Preflight Validation

Validate the environment before doing anything else.

```bash
git status
make build
make test
make lint
```

**Gate:** All commands must pass. Fix issues before proceeding.

---

## Phase 2: Discovery & Planning (Plan Mode)

After preflight passes, enter plan mode to design the task graph.

```
EnterPlanMode()
```

In plan mode:

1. **Fetch issue details** for each issue: `gh issue view <number>`
2. **Explore the codebase** using Explore agents to understand affected files, packages, and patterns
3. **Design the full task graph** with dependencies (see Task Graph Templates below)
4. **Determine team size** based on scope (see Team Sizing below)
5. **Present the plan** to the user via `ExitPlanMode()`

The user can approve or refine the plan. Adjust and re-present if they refine.

### Task Graph Templates

Every task description MUST include:
- What to do (clear instructions for self-claiming agents)
- Files involved (implicit ownership - prevents collision)
- Success criteria (explicit pass/fail conditions)

#### Single Issue (1 package)

```
Task 1: Explore codebase for issue #N
  Description: Read issue details, find related files, understand patterns.
  Files: N/A (read-only exploration)
  Success: Plan documented with files to modify, test cases, security considerations

Task 2: RED - write failing tests [blocked by: 1]
  Files: internal/<pkg>/*_test.go
  Success: New tests compile but FAIL when run

Task 3: QA RED phase [blocked by: 2]
  Success criteria:
  - make build: PASS
  - make lint: PASS
  - go test -v ./internal/<pkg>/... -run <NewTests>: FAIL (expected)
  - make test-integration: PASS (no regressions)

Task 4: GREEN - implement [blocked by: 3]
  Files: internal/<pkg>/*.go (non-test files)
  Success: All tests pass with minimal implementation

Task 5: QA GREEN phase [blocked by: 4]
  Success criteria:
  - make build: PASS
  - make test: PASS (all tests including new)
  - make lint: PASS
  - make test-integration: PASS

--- Review tasks NOT created upfront (lead creates just-in-time, see Review Dispatch) ---

Task 6: BLUE - refactor [blocked by: 5, plus review gates added by lead]
  Files: internal/<pkg>/*.go (only if review feedback requires changes)
  Success: Review issues resolved, no behavior changes, all tests pass

Task 7: QA BLUE phase [blocked by: 6]
  Success criteria: same as QA GREEN (Task 5)

Task 8: Create PR [blocked by: 7]
  Success: PR created with summary, test plan, review verdicts
```

#### Multi-Issue (different packages)

Create parallel tracks with cross-dependencies where files overlap:

```
Track A (issue #X):                    Track B (issue #Y):
Task 1: Explore for #X                Task 2: Explore for #Y
Task 3: RED tests #X [blocked: 1]     Task 4: RED tests #Y [blocked: 2]
Task 5: QA RED #X [blocked: 3]        Task 6: QA RED #Y [blocked: 4]
Task 7: GREEN #X [blocked: 5]         Task 8: GREEN #Y [blocked: 6]
Task 9: QA GREEN #X [blocked: 7]      Task 10: QA GREEN #Y [blocked: 8]

Cross-dependency (if files overlap):
Task 8 also blocked by Task 7 -- prevents collision

--- Review tasks NOT created upfront (lead creates just-in-time, see Review Dispatch) ---

Task 11: BLUE refactor [blocked: 9, 10, plus review gates added by lead]
Task 12: QA BLUE [blocked: 11]
Task 13: Create PR [blocked: 12]
```

### Team Sizing

| Scope | Implementers | Verifier | Total |
|-------|-------------|----------|-------|
| 1 issue, 1 package | 1 | 1 | 2 |
| 1 issue, 2+ packages | 2 | 1 | 3 |
| 2+ issues | 1 per issue (max 3) | 1 | 3-4 |

No dedicated reviewer agents. Reviews run as subagents (fire-and-forget).

---

## Phase 3: Team Spawn (after user approves plan)

Sanitize `$ARGUMENTS` for use in branch names, team names, and directory paths. Replace spaces and special characters with hyphens (e.g., `42 43` becomes `42-43`):

```bash
SAFE_ARGS=$(echo "$ARGUMENTS" | tr ' ,/' '-' | tr -cd '[:alnum:]-')
git checkout -b "issue-${SAFE_ARGS}-<short-description>"
```

Use `$SAFE_ARGS` everywhere that requires shell-safe names (branch, team, directories).

Check for an existing team before creating a new one (only one team per session):

```
# Check if a team already exists
TaskList()  # or read ~/.claude/teams/ for existing team directories
```

If a team already exists, ask the user:
- Clean up the old team first (TeamDelete after shutting down any active teammates), or
- Abort and let the user resolve it manually

Only proceed after confirming no active team.

Create the team and task list:

```
TeamCreate(team_name="tdd-$SAFE_ARGS", description="TDD team for issue(s) #$ARGUMENTS")
```

Then create tasks from the task graph using `TaskCreate`, setting dependencies with `TaskUpdate(addBlockedBy=...)`. Do NOT create review tasks upfront - the lead creates those just-in-time when dispatching review subagents (see Review Dispatch).

Then spawn teammates. Do NOT use `mode: "plan"` for any teammate.

### Implementer Prompt Template

```
Task(
  subagent_type="general-purpose",
  team_name="tdd-$SAFE_ARGS",
  name="implementer-1",
  prompt=<IMPLEMENTER_PROMPT>
)
```

**IMPLEMENTER_PROMPT:**

```
You are a TDD implementer for the open-guard-engine project (issue(s) #$ARGUMENTS).

## Team Members
To find all teammate names: read ~/.claude/teams/tdd-<issue>/config.json (contains members array with name, agentId, agentType for each member).

Known teammates (use exact names with SendMessage):
- Verifier: "verifier" - handles QA tasks
- Lead: read the team config to find the lead's name for the `recipient` field

When messaging teammates, always use their exact name as the SendMessage recipient.

## How You Work
- Check TaskList for available work (unblocked, unassigned tasks)
- Claim tasks by setting yourself as owner via TaskUpdate
- After completing a task, mark it completed and check TaskList for next work
- Prefer tasks in ID order when multiple are available

## TDD Discipline
- RED phase: Write failing tests. Tests MUST fail. Commit with `test:` prefix.
- GREEN phase: Write MINIMAL implementation to make tests pass. Commit with `feat:` prefix.
- BLUE phase: Refactor for quality without changing behavior. Commit with `refactor:` prefix.
- Fix iterations: Commit with `fix:` prefix.

## Project Context
See CLAUDE.md for Go conventions, architecture, detection pipeline, and directory structure.

## Security Test Requirements (This is a Security Tool)
- Positive cases: Detect the attack vector
- Negative cases: Allow legitimate usage
- Bypass attempts: Variations that might evade detection
- Encoding obfuscation: base64, hex, rot13, unicode homoglyphs

## Dynamic Task Proposals
If you discover work that needs doing, propose it to the lead:
TASK PROPOSAL: <what> | WHY: <reason> | BLOCKS: <what it gates> | FILES: <affected>
The lead will decide whether to create it.

## Tool Restrictions
NEVER use: TeamCreate, TeamDelete, SendMessage(type="broadcast")
NEVER modify tasks owned by other agents
Only the lead manages the team and dispatches reviews.

Start by checking TaskList for available work.
```

### Verifier Prompt Template

```
Task(
  subagent_type="general-purpose",
  team_name="tdd-$SAFE_ARGS",
  name="verifier",
  prompt=<VERIFIER_PROMPT>
)
```

**VERIFIER_PROMPT:**

```
You are the QA verifier for the TDD team on issue(s) #$ARGUMENTS.

## Team Members
To find all teammate names: read ~/.claude/teams/tdd-<issue>/config.json (contains members array with name, agentId, agentType for each member).

Known teammates (use exact names with SendMessage):
- Implementer: "implementer-1" (default name for single-implementer teams)
- Lead: read the team config to find the lead's name for the `recipient` field

When messaging teammates, always use their exact name as the SendMessage recipient.

## How You Work
- Check TaskList for available QA tasks (unblocked, unassigned)
- Claim QA tasks by setting yourself as owner via TaskUpdate
- After completing a task, mark it completed and check TaskList for next work

## QA Success Criteria

### For RED phase (tests should FAIL):
1. `make build` - MUST PASS (code compiles)
2. `make lint` - MUST PASS (code is clean)
3. Run the new test files specifically - MUST FAIL (task description specifies test command)
4. `make test-integration` - MUST PASS (no regressions)

### For GREEN and BLUE phases:
1. `make build` - MUST PASS
2. `make test` - MUST PASS (all tests including new ones)
3. `make lint` - MUST PASS
4. `make test-integration` - MUST PASS

## QA Loop
Run ALL success criteria listed in the task description. If any fail:
1. Message the relevant implementer with exact failure output
2. Wait for them to fix and message you back
3. Re-run ALL criteria (catch regressions)
4. If 3 QA iterations fail, escalate to the lead

Always run ALL criteria even if early ones fail, so the implementer gets complete feedback.

## Reporting
When all criteria pass, mark the task complete. The next tasks will auto-unblock.
When criteria fail, send the implementer a message with this structure:

QA: FAIL
Phase: [RED/GREEN/BLUE]
Iteration: [N/3]

Results:
- make build: [PASS/FAIL]
- make test: [PASS/FAIL]
- make lint: [PASS/FAIL]
- make test-integration: [PASS/FAIL]

[Exact error output for each failing target]

## Review Handoff
When you complete a QA GREEN or QA BLUE task, message the lead:
"QA [GREEN/BLUE] complete. Review tasks are ready for dispatch."
This triggers the lead to dispatch review subagents.

## Dynamic Task Proposals
If you discover work that needs doing (e.g., pre-existing lint failures on untouched lines),
propose it to the lead:
TASK PROPOSAL: <what> | WHY: <reason> | BLOCKS: <what it gates> | FILES: <affected>

## Tool Restrictions
NEVER use: TeamCreate, TeamDelete, SendMessage(type="broadcast")
NEVER modify tasks owned by other agents
Only the lead manages the team and dispatches reviews.

Start by checking TaskList for available work.
```

---

## Phase 4: Autonomous Execution (self-coordinating)

After spawning teammates, the lead does not do implementation work unless a teammate is stuck. The lead actively monitors messages and TaskList for coordination events: review dispatch, escalation, task proposals, and unblocked work. Teammates self-coordinate via TaskList for implementation tasks.

### Execution Flow

1. Teammates read TaskList and self-claim unblocked tasks
2. When an implementer completes RED tests, QA task auto-unblocks - verifier claims it
3. When verifier completes QA, next implementation task auto-unblocks
4. When verifier messages that QA GREEN is complete, lead creates review tasks and dispatches review subagents (see Review Dispatch)
5. Each review subagent's verdict gets recorded on its task, which then unblocks BLUE phase

### Review Dispatch (lead-driven, just-in-time)

When the verifier messages that QA GREEN (or QA BLUE) is complete, the lead:
1. Creates 4 review tasks via TaskCreate (security, standards, testing, architecture)
2. Adds each as a blocker on the BLUE refactor task via TaskUpdate(addBlockedBy=...)
3. Dispatches 4 review subagents in parallel (single message, 4 Task tool calls)
4. Marks each review task complete with the subagent's verdict

This just-in-time creation prevents teammates from self-claiming review tasks before subagents are dispatched.

```
Task(subagent_type="paranoid-sentinel", prompt="Security review for issue(s) #$ARGUMENTS.
Review the diff (git diff main...HEAD) for:
1. Pattern bypass potential - Can attackers evade detection?
2. ReDoS vulnerabilities - Catastrophic backtracking in regex
3. Threat category accuracy - T1-T9 / S1-S13 correctly assigned
4. Input validation at boundaries
5. Encoding evasion - base64, hex, rot13, unicode homoglyphs
6. Case sensitivity and whitespace tricks

Verdict format:
SECURITY REVIEW: [APPROVED / ISSUES FOUND]
[If ISSUES FOUND, list each with file:line, attack vector, suggested fix]
Bypass Resistance: X/10")

Task(subagent_type="general-purpose", prompt="Go standards review for issue(s) #$ARGUMENTS.
Review the diff (git diff main...HEAD) for:
1. Idiomatic Go patterns
2. Error handling with context wrapping
3. Naming clarity and godoc comments
4. Import grouping and sorting
5. Constructor pattern compliance
6. Interface design (defined where consumed)
7. Context/timeout usage
8. KISS principle

Verdict format:
GO STANDARDS REVIEW: [APPROVED / ISSUES FOUND]
[If ISSUES FOUND, list each with file:line, current vs suggested]")

Task(subagent_type="general-purpose", prompt="Testing review for issue(s) #$ARGUMENTS.
Review the diff (git diff main...HEAD) for:
1. Coverage completeness - all new code paths tested
2. Table-driven tests with t.Run() subtests
3. Positive detection cases
4. Negative (safe content allowed) cases
5. Edge cases (boundary conditions, empty input, max-length)
6. Bypass cases (encoding, case tricks, whitespace)
7. Testify usage (assert for checks, require for fatal)
8. Descriptive test naming

Verdict format:
TESTING REVIEW: [APPROVED / ISSUES FOUND]
[If ISSUES FOUND, list each with file:line, what's missing, why it matters]")

Task(subagent_type="general-purpose", prompt="Architecture review for issue(s) #$ARGUMENTS.
Review the diff (git diff main...HEAD) for:
1. Package boundaries respected
2. Detection pipeline integration correct
3. No DRY violations
4. No YAGNI violations
5. Config system used correctly
6. File organization follows project structure
7. Appropriate abstraction level
8. Resource management (cleanup, context propagation, timeouts)

Architecture: cmd/open-guard/ -> internal/{agent,audit,config,encoding,llm,patterns,response,types}
Pipeline: stdin -> Encoding -> Patterns -> Agent -> LLM -> stdout

Verdict format:
ARCHITECTURE REVIEW: [APPROVED / ISSUES FOUND]
[If ISSUES FOUND, list each with file:line, principle violated, suggested restructure]")
```

Mark each review task complete with the subagent's verdict in the task description update.

### QA Loop (verifier-driven)

The verifier handles this autonomously:

```
while QA task not passing:
  1. Verifier runs success criteria
  2. If ALL PASS: mark QA task complete -> next tasks auto-unblock
  3. If ANY FAIL: message implementer with exact failure output
  4. Implementer fixes, commits, messages verifier
  5. Verifier re-runs ALL criteria
  6. If QA iteration >= 3: escalate to lead, lead escalates to user
```

### Review Loop (lead-driven)

```
while any review has ISSUES FOUND:
  1. Lead dispatches review subagents in parallel (4 on first pass)
  2. Collect all verdicts
  3. If ALL APPROVED: mark review tasks complete -> BLUE phase unblocks
  4. If ISSUES FOUND: consolidate feedback, message implementer
  5. Implementer fixes, commits
  6. Lead creates a new "QA Regression Check" task, assigns to verifier
  7. Verifier runs full QA criteria on the new task
  8. If QA passes: lead re-dispatches ONLY the previously-failing reviewers as new subagent calls
  9. If review iteration >= 3: escalate to user
```

### Dynamic Task Creation (proposal + lead decision)

Teammates do NOT create tasks unilaterally. They propose to the lead:

```
TASK PROPOSAL: <what> | WHY: <reason> | BLOCKS: <what it gates> | FILES: <affected>
```

**Decision flow:**
1. Teammate proposes via message to the lead
2. Lead evaluates: Does this block progress? Does it conflict with existing tasks/file ownership?
3. If approved: lead creates task with TaskCreate, sets dependencies, messages relevant teammate
4. If rejected: lead explains why, work continues on existing tasks

**Fast-track (no proposal needed):**
- Fix tasks from review ISSUES FOUND (lead creates directly - reviewer is authority)

### Escalation (separate iteration caps per loop)

Each loop has its own iteration budget:
- **QA loop:** 3 iterations (verifier-driven, covers build/test/lint failures)
- **Review loop:** 3 iterations (lead-driven, covers security/standards/testing/architecture feedback)

Counters are independent - QA failures do not consume the review budget and vice versa.

On cap, present to user:

```
## Escalation: [RED/GREEN/BLUE] Phase - Iteration Limit Reached

### Remaining Issues
[Quality gate output and/or unresolved review feedback]

### Options
1. Provide guidance and continue
2. Take over manually
3. Accept current state and move on
```

Team stays alive during escalation. User guidance feeds back into the loop. Only shutdown when user explicitly says to stop or all phases complete.

### Lead Interventions

The lead intervenes only for:
- Review task dispatch (subagents, not teammates)
- Escalation when QA iteration cap (3) or review iteration cap (3) is hit
- Writing code as fallback if an implementer is stuck
- Task proposal decisions
- Monitoring TaskList for newly unblocked work
- Checking TaskList for tasks that appear complete but aren't marked as such (nudge teammate or update status)

---

## Phase 5: PR Creation

After all TDD phases complete (or the user accepts current state):

### Final Verification

Run final checks (lead can do this directly):

```bash
make build
make test
make lint
make test-integration
git log --oneline main..HEAD
```

**Gate:** All must pass.

### Create PR

```bash
git push -u origin HEAD
gh pr create --title "<type>: <description>" --body "$(cat <<'EOF'
## Summary
<1-3 bullet points from the implementation>

## Test Plan
- [ ] Unit tests added for new behavior
- [ ] Positive detection cases covered
- [ ] Negative (safe) cases covered
- [ ] Bypass attempt cases covered
- [ ] Integration tests pass

## Security Considerations
<security-relevant notes from security review>

## Review Summary
- Security: [verdict] (Bypass Resistance: X/10)
- Go Standards: [verdict]
- Testing: [verdict]
- Architecture: [verdict]
- Quality Gate: ALL PASS

Closes #$ARGUMENTS
EOF
)"
```

### Team Cleanup

Shut down all teammates, wait for confirmations, then delete the team:

1. Send shutdown requests:
   ```
   SendMessage(type="shutdown_request", recipient="implementer-1", content="PR created, shutting down")
   SendMessage(type="shutdown_request", recipient="verifier", content="PR created, shutting down")
   # (repeat for any additional implementers)
   ```

2. Wait for all shutdown confirmations (delivered automatically via messages).
   If a teammate rejects, address their concern or resend after their task completes.

3. After all teammates have confirmed and exited:
   ```
   TeamDelete()
   ```

Provide the PR URL to the user.

---

## Error Handling

### Teammate Unresponsive
1. Check TaskList for their task status
2. Send a status ping message
3. If still unresponsive, inform the user

### QA Repeatedly Fails Same Target
If the same `make` target fails 3 times, include the specific command output in the escalation. If failures are environmental (missing ffmpeg, chrome), escalate immediately rather than looping.

### Reviewer Disagreement
If review subagents provide conflicting feedback, flag the conflict when consolidating feedback for the implementer. Include both perspectives.

### Lead Fallback
If an implementer is stuck after 2 messages about the same issue, the lead should write the fix directly rather than continuing the loop.

### Session Interruption Recovery
Session interruption (crash, network loss, manual stop) kills all in-process teammates.
They cannot be recovered - `/resume` does not restore teammate processes.

**Recovery steps:**
1. Check TaskList for last-known state (it persists on disk)
2. Reset any stale `in_progress` tasks to `pending` via TaskUpdate
3. Spawn fresh teammates to continue from the task graph
4. The task graph and dependency structure remain intact - new teammates pick up where the old ones left off

---

## Quick Reference

**Commit Prefixes:** `test:` (RED), `feat:` (GREEN), `refactor:` (BLUE), `fix:` (iterations)

**Threat Categories:** T1-T9 (technical), S1-S13 (safety/LLM)

**QA Targets:** `make build`, `make test`, `make lint`, `make test-integration`

**Iteration Budget:** 3 per QA loop, 3 per review loop (independent counters)

**Team Sizing:** 2-4 agents based on scope, reviews as subagents
