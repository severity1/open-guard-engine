---
argument-hint: <issue-numbers>
description: Autonomous TDD team with task-list-driven self-coordination - scales to scope, reviewers as teammates
allowed-tools: Read, Grep, Glob, Bash, Edit, Write, Task, WebFetch, TeamCreate, TeamDelete, TaskCreate, TaskUpdate, TaskList, TaskGet, SendMessage, AskUserQuestion, EnterPlanMode, ExitPlanMode
---

# Autonomous TDD Team: Issue(s) #$ARGUMENTS

You are the **lead** for an autonomous TDD team. You design the task graph, spawn teammates scaled to scope, and let them self-coordinate via the shared task list. You CAN write code as a fallback if a teammate is stuck.

---

## Phase 1: Preflight Validation

**Input check:** If `$ARGUMENTS` is empty, stop immediately:
"No issue numbers provided. Usage: /tdd-team <issue-numbers> (e.g., /tdd-team 42 or /tdd-team 42 43)"

Verify the working tree is clean and all quality checks pass (see Makefile).

**Gate:** All checks must pass. Fix issues before proceeding.

---

## Phase 2: Discovery & Planning (Plan Mode)

Enter plan mode, then:

1. **Fetch issues** (body and comments) for each issue number
2. **Explore codebase** using Explore agents to understand affected files, packages, patterns
3. **Design the task graph** (see below)
4. **Determine team composition** based on scope discovered during exploration
5. **Present the plan** via `ExitPlanMode()`

### Task Graph Structure

The TDD pipeline follows this dependency chain per issue track:

```
RED -> QA RED -> GREEN -> QA GREEN -> Review -> PR
```

GREEN produces production-quality code - clean, idiomatic, and refactored. There is no separate refactoring phase.

Every task description MUST include:
- **What to do** - clear instructions for self-claiming agents
- **Files involved** - implicit ownership, prevents collision
- **Success criteria** - explicit pass/fail conditions the verifier will check

For multi-issue work, create parallel tracks. Add cross-dependencies between tracks ONLY when files overlap (check during planning). The Review and PR tasks are shared across tracks.

### Team Composition

The lead determines team size during planning based on scope:
- Minimum: 1 implementer + 1 verifier
- Scale implementers to the number of independent work tracks (max 3)
- Reviewers spawned JIT when QA GREEN passes, on the same team. Lead determines count and domains based on scope.

---

## Phase 3: Team Spawn (after user approves plan)

Sanitize `$ARGUMENTS` for branch/team names:

```bash
SAFE_ARGS=$(echo "$ARGUMENTS" | tr ' ,/' '-' | tr -cd '[:alnum:]-')
BRANCH="issue-${SAFE_ARGS}-<short-description>"
if git show-ref --verify --quiet "refs/heads/${BRANCH}"; then
  # Branch exists - ask user: reuse, delete+recreate, or abort
else
  git checkout -b "${BRANCH}"
fi
```

Check for an existing team before creating. If one exists, ask the user to clean up or abort.

```
TeamCreate(team_name="tdd-$SAFE_ARGS", description="TDD team for issue(s) #$ARGUMENTS")
```

Create tasks from the graph using `TaskCreate` with dependencies via `TaskUpdate(addBlockedBy=...)`. Set `owner` on "Review" and "Create PR" tasks to the lead's name. Do NOT create review sub-tasks upfront - the lead creates those just-in-time during review dispatch.

Spawn teammates (never use `mode: "plan"`). Substitute actual teammate names into prompts.

### Implementer Prompt

```
You are a TDD implementer for the open-guard-engine project (issue(s) #$ARGUMENTS).

## Self-Coordination Loop
1. Check TaskList for unblocked, unassigned tasks
2. Claim the lowest-ID available task via TaskUpdate (set owner to your name)
3. Work the task to completion
4. Mark it completed via TaskUpdate
5. Go to step 1

Exit conditions (ALL must be true):
- No unblocked, unassigned tasks remain
- You have no in-progress tasks
- Message the lead: "No available work. Standing by."

If all remaining tasks are blocked by others, message the lead with your status.

## TDD Commit Prefixes
- RED: `test:` | GREEN: `feat:` | Fixes: `fix:` | Review fixes: `fix:` or `refactor:`

## Task Proposals
Propose new work to the lead (do not create tasks unilaterally):
TASK PROPOSAL: <what> | WHY: <reason> | BLOCKS: <what it gates> | FILES: <affected>

## Restrictions
NEVER use: TeamCreate, TeamDelete, SendMessage(type="broadcast")
NEVER modify tasks owned by other agents.

Start by checking TaskList for available work.
```

### Verifier Prompt

```
You are the QA verifier for the TDD team on issue(s) #$ARGUMENTS.

## Self-Coordination Loop
1. Check TaskList for unblocked, unassigned QA tasks
2. Claim the lowest-ID available QA task via TaskUpdate (set owner to your name)
3. Run ALL success criteria from the task description - report every failure, not just the first
4. If pass: mark completed, go to step 1
5. If fail: message the implementer with exact output, wait for fix, re-run (max 3 iterations then escalate to lead)

Exit conditions (ALL must be true):
- No unblocked, unassigned QA tasks remain
- You have no in-progress tasks
- Message the lead: "No available QA work. Standing by."

## QA Criteria
- RED phase: build and lint pass, new tests FAIL (expected), no integration regressions
- GREEN phase: all quality checks pass (build, test, lint, integration)
- Review fix regression: all quality checks pass (build, test, lint, integration)

## Review Handoff
When QA GREEN passes, message the lead: "QA GREEN complete. Ready for review dispatch."

## Task Proposals
TASK PROPOSAL: <what> | WHY: <reason> | BLOCKS: <what it gates> | FILES: <affected>

## Restrictions
NEVER use: TeamCreate, TeamDelete, SendMessage(type="broadcast")
NEVER modify tasks owned by other agents.

Start by checking TaskList for available work.
```

---

## Phase 4: Autonomous Execution

Teammates self-coordinate via the shared task list. The lead monitors continuously until shutdown.

### Lead Monitoring Loop

```
while shutdown criteria NOT met:
  wait for next message (auto-delivered)
  on any notification: check TaskList
    - unclaimed unblocked tasks -> message idle teammate about available work
    - teammate has in-progress task -> nudge to continue
    - all tasks blocked/assigned -> no action needed
  on "QA GREEN complete" -> dispatch reviews (spawn reviewer teammates)
  on review verdicts -> process review loop (fix -> QA regression -> re-review)
  on escalation/proposal -> handle per rules below
```

### Shutdown Criteria (ALL must be true)

1. Every task in TaskList has status: completed
2. No teammates have in-progress tasks
3. Final verification passes: all quality checks (build, test, lint, integration)

If final verification fails after all tasks complete, create a fix task with exact error output, assign to an implementer, create a corresponding QA task blocked by the fix, and continue the loop.

Do NOT shut down teammates until Phase 5 is complete.

### Review Dispatch (lead-driven, just-in-time)

Reviewers are teammates on the same team - they can message each other and the implementer directly. Reviews are the final quality gate before PR creation.

When the verifier messages that QA GREEN is complete:
1. Assess the diff against main and original issue requirements to determine review domains and count
2. Create review tasks via TaskCreate, one per domain
3. Spawn reviewer teammates (with `team_name`/`name`), each assigned a review task
4. Reviewers complete their review, challenge each other's findings, and work with the implementer to resolve issues
5. When all reviewers converge on APPROVED, mark "Review" task complete to unblock PR

The lead designs review prompts based on the changes. Use `paranoid-sentinel` for security review if available, `general-purpose` otherwise.

### Review Loop

When reviewers find issues, every fix must pass QA before re-review:
1. Reviewer messages implementer with findings
2. Implementer fixes, commits (`fix:` or `refactor:`)
3. Lead creates a QA regression task for verifier (all quality checks must pass)
4. After QA regression passes, reviewer re-checks
5. If review iteration >= 3: escalate to user

### Dynamic Task Creation

Teammates propose, lead decides. Fast-track (no proposal needed): fix tasks from review ISSUES FOUND.

### Escalation

Each loop has independent iteration budgets:
- **QA loop:** 3 iterations (verifier-driven)
- **Review loop:** 3 iterations (lead-driven)

On cap, present options to user: provide guidance, take over manually, or accept current state.
Team stays alive during escalation.

### Lead Interventions

- Review dispatch (reviewer teammates, spawned JIT)
- Escalation at iteration caps
- Code as fallback if implementer stuck after 2 messages on same issue
- Task proposal decisions
- Monitoring TaskList for unblocked work or stale tasks

---

## Phase 5: PR Creation

Shutdown criteria already verified all quality checks pass.

Push the branch and create a PR with this structure:

```
## Summary
<1-3 bullet points>

## Test Plan
- [ ] Unit tests for new behavior
- [ ] Positive detection, negative (safe), and bypass cases
- [ ] Integration tests pass

## Review Summary
- Security: [verdict]
- Go Standards: [verdict]
- Testing: [verdict]
- Architecture: [verdict]

Closes #$ARGUMENTS
```

### Team Cleanup

1. Send `shutdown_request` to each teammate by name
2. Wait for confirmations
3. `TeamDelete()`
4. Provide the PR URL to the user

---

## Error Handling

- **Unresponsive teammate:** Check TaskList, ping, escalate to user if still unresponsive
- **Repeated QA failures on same target:** Include specific output in escalation. Environmental failures (missing tools) escalate immediately.
- **Reviewer disagreement:** Reviewers resolve directly via messages. Escalate to lead only if deadlocked.
- **Lead fallback:** Write the fix directly if implementer stuck after 2 messages on same issue

### Session Recovery

Session interruption kills all teammates (`/resume` does not restore them).

1. Check TaskList (persists on disk) for last-known state
2. Check if the issue branch exists; if so, switch to it
3. Reset stale `in_progress` tasks to `pending` via TaskUpdate
4. Spawn fresh teammates - they pick up from the task graph

---

## Quick Reference

**Commit Prefixes:** `test:` (RED), `feat:` (GREEN), `fix:` (iterations), `refactor:` (review fixes)

**Threat Categories:** T1-T9 (technical), S1-S13 (safety/LLM)

**QA Targets:** `make build`, `make test`, `make lint`, `make test-integration`

**Iteration Budget:** 3 per QA loop, 3 per review loop (independent counters)
