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

Verify the working tree is clean and all existing quality checks pass.

**Gate:** All checks must pass. Fix issues before proceeding.

---

## Phase 2: Discovery & Planning (Plan Mode)

Enter plan mode, then:

1. **Fetch issues** (body and comments) for each issue number
2. **Build a project profile** by exploring the codebase (use Explore agents):
   - Build system and commands (e.g., Makefile, package.json, Cargo.toml)
   - Test framework, how to run tests, and what test failure looks like
   - Linter and quality gate commands
   - What "RED" means for this language (compilation error, test failure, type error)
   - Existing commit message conventions (check git log)
   - Code patterns, architecture, and conventions (check CLAUDE.md if present)
3. **Explore affected files**, packages/modules, and dependencies for the target issues
4. **Design the task graph** (see below)
5. **Determine team composition** based on scope discovered during exploration
6. **Present the plan** via `ExitPlanMode()`

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

### Track Types

**Standard Track** (default): For issues requiring new tests and implementation.
```
RED -> QA RED -> GREEN -> QA GREEN
```

**Lightweight Track**: For cleanup, deletion, or mechanical changes where the "test" is an existing tool output (lint, build).
```
IMPLEMENT -> QA VERIFY
```

The lead determines track type during planning based on scope:
- Standard: New features, interfaces, validation logic, anything requiring new test code
- Lightweight: Dead code removal, renames, mechanical refactors with existing test coverage

Both track types converge at the shared Review task.

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
You are a TDD implementer on issue(s) #$ARGUMENTS.

## Self-Coordination Loop
1. Check TaskList for unblocked, unassigned tasks
2. Filter to implementation tasks only (names containing RED, GREEN, IMPLEMENT, or fix - NOT containing QA or verify)
3. Claim the lowest-ID matching task via TaskUpdate (set owner to your name)
4. Work the task to completion
5. Mark it completed via TaskUpdate
6. Go to step 1

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
1. Check TaskList for unblocked, unassigned tasks
2. Filter to QA/verification tasks only (names containing QA, verify, or VERIFY)
3. Claim the lowest-ID matching task via TaskUpdate (set owner to your name)
4. Run ALL success criteria from the task description - report every failure, not just the first
5. If pass: mark completed, go to step 1
6. If fail: message the implementer with exact output, wait for fix, re-run (max 3 iterations then escalate to lead)

Exit conditions (ALL must be true):
- No unblocked, unassigned QA tasks remain
- You have no in-progress tasks
- Message the lead: "No available QA work. Standing by."

## QA Criteria
- RED phase: existing quality gates pass, new tests FAIL as expected, no regressions
- GREEN phase: all quality gates pass (per task success criteria)
- Review fix regression: all quality gates pass (per task success criteria)

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
  on task completion notification: check TaskList for stale or stuck state
  on "QA GREEN complete" -> dispatch reviews (spawn reviewer teammates)
  on review verdicts -> process review loop (fix -> QA regression -> re-review)
  on escalation/proposal -> handle per rules below
  on idle notification with no available work -> acknowledge, no action needed
```

Teammates self-coordinate via TaskList - the lead does NOT need to direct them to unclaimed tasks or nudge in-progress work. Only intervene on stale state (task in-progress with no activity) or escalation.

### Shutdown Criteria (ALL must be true)

1. Every task in TaskList has status: completed
2. No teammates have in-progress tasks
3. Final verification passes: all project quality gates pass

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
3. Lead creates a QA regression task for verifier (all quality gates must pass)
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

Shutdown criteria already verified all quality gates pass.

Push the branch and create a PR with this structure:

```
## Summary
<1-3 bullet points>

## Test Plan
<checklist derived from the task graph's QA criteria>

## Review Summary
<one line per review domain, derived from review dispatch>

Closes #$ARGUMENTS
```

### Team Cleanup

1. Stop any background tasks related to the team's work (test runs, builds, etc.) via TaskStop
2. Send `shutdown_request` to each teammate by name
3. Wait for confirmations
4. `TeamDelete()`
5. Provide the PR URL to the user

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

**Commit Prefixes:** Discover from git log during Phase 2. Fallback: `test:` (RED), `feat:` (GREEN), `fix:` (iterations), `refactor:` (review fixes)

**QA Targets:** Discover from project build system during Phase 2.

**Iteration Budget:** 3 per QA loop, 3 per review loop (independent counters)
