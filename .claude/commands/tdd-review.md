---
argument-hint: [pr-number] (optional, defaults to current branch)
description: Comprehensive code review with parallel specialized reviewers for security-focused analysis
allowed-tools: Read, Grep, Glob, Bash(go test:*), Bash(make test:*), Bash(make lint:*), Bash(git diff:*), Bash(gh pr:*), Bash(gh issue:*), Task
---

# TDD Code Review

You are performing a comprehensive code review for open-guard-engine, a security tool. This review uses specialized reviewers in parallel for thorough analysis.

## Argument Interpretation

- **No arguments provided**: Review current branch (uncommitted + staged changes vs HEAD)
- **PR number provided ($ARGUMENTS)**: Review that specific pull request

---

## Phase 1: Context Gathering

Gather the changes to review based on the argument.

**If no argument (current branch):**
```bash
git status                              # Show current state
git diff HEAD                           # All uncommitted changes
git diff --cached                       # Staged changes only
git log --oneline -10                   # Recent commits for context
```

**If PR number provided:**
```bash
gh pr view $ARGUMENTS                   # PR details
gh pr diff $ARGUMENTS                   # PR diff
gh pr checks $ARGUMENTS                 # CI status
```

**Identify Changed Files:**
List all files that will be reviewed. Group by category:
- `internal/patterns/` - Pattern matching (security critical)
- `internal/agent/` - Agent analysis
- `internal/llm/` - LLM safety
- `internal/encoding/` - Encoding detection
- `tests/` - Test files
- Other

**Cross-Reference Open GitHub Issues:**
```bash
gh issue list --state open --limit 50 --json number,title,labels,body
```

Filter the fetched issues to only those relevant to the changes. An issue is relevant if:
- It mentions a changed file, package, or function by name
- It describes a bug or gap in functionality touched by the diff
- It references a threat category (T1-T9, S1-S13) affected by the changes
- Its labels correspond to changed areas (e.g. `agent`, `patterns`, `encoding`)

Discard all other issues. Produce a short list of relevant issues (number, title, one-line summary of relevance) to pass to reviewers. If no issues are relevant, note "No related open issues" and skip issue context in reviewer prompts.

**Build Known Issues Exclusion List:**
For each relevant open issue, extract the core problem it describes (the bug, gap, missing feature, or vulnerability). This becomes the **exclusion list** - reviewers MUST NOT report findings that are already covered by these open issues. The purpose of the review is to catch NEW problems, not re-report known ones.

---

## Phase 2: Parallel Specialized Review

Launch these four reviewers in parallel using the Task tool. Each reviewer focuses on their specialty.

**IMPORTANT - Known Issue Exclusion:** Every reviewer prompt MUST include the exclusion list from Phase 1. Reviewers must NOT report findings that match problems already tracked by open GitHub issues. The review's purpose is to surface NEW issues only.

### Reviewer 1: Security Review - Paranoid Sentinel (CRITICAL)

**Use the `paranoid-sentinel` agent** for comprehensive security analysis.

Spawn the agent with this prompt:
```
Review the following code changes for security vulnerabilities. Focus on:
1. Pattern bypass potential - can attackers evade detection?
2. ReDoS vulnerabilities in regex patterns
3. Threat category accuracy (T1-T9, S1-S13)
4. Input validation at boundaries
5. Information leakage in errors

IMPORTANT: Do NOT report findings that are already covered by the open GitHub issues listed below.
Only report NEW problems not already tracked. If a finding overlaps with a known issue, skip it.

Changed files:
<list the files from Phase 1>

Diff content:
<include the diff from Phase 1>

Known open issues (DO NOT re-report these):
<include relevant issues from Phase 1 with number, title, and core problem summary, or "None">
```

The paranoid-sentinel will provide:
- BYPASS CONFIDENCE score
- MARCUS SUSPICION METER (security theater detection)
- Concrete attack vectors that would work
- Evidence-based security findings

**Severity:** Issues from paranoid-sentinel are Critical or Major.

### Reviewer 2: Go Standards Review

**Focus Areas:**
- Idiomatic Go code patterns
- Error handling (wrapped with context?)
- Godoc comments on exported functions
- Naming conventions (clear, descriptive)
- Import grouping (stdlib, third-party, local)
- Interface design (defined where consumed)

Do NOT report findings already covered by open GitHub issues (include the exclusion list in the prompt).

**Severity:** Usually Minor unless affecting maintainability.

### Reviewer 3: Testing Review

**Focus Areas:**
- Test coverage for new code
- Table-driven test patterns used
- Both positive (detect) and negative (allow) cases
- Edge cases and boundary conditions
- Mock usage appropriate
- Integration test coverage if applicable

Do NOT report findings already covered by open GitHub issues (include the exclusion list in the prompt). This includes issues requesting test improvements or reporting test gaps - if an issue already tracks it, skip it.

**Severity:** Missing tests for security code is Major.

### Reviewer 4: Architecture Review

**Focus Areas:**
- Package boundaries respected
- DRY violations (code duplication)
- YAGNI violations (over-engineering)
- Detection pipeline integration correct
- Configuration handling appropriate

Do NOT report findings already covered by open GitHub issues (include the exclusion list in the prompt). Do NOT flag "unaddressed issues" - if an open issue exists, it is already tracked and does not belong in this review.

**Severity:** Usually Minor unless breaking architecture.

### Launching Reviewers

Use the Task tool to launch reviewers in parallel:

```
Task(subagent_type="paranoid-sentinel", prompt="Review these changes for security: <diff> Known open issues (DO NOT re-report): <issues>")
Task(subagent_type="general-purpose", prompt="Review Go standards: <diff> Known open issues (DO NOT re-report): <issues>")
Task(subagent_type="general-purpose", prompt="Review test coverage: <diff> Known open issues (DO NOT re-report): <issues>")
Task(subagent_type="general-purpose", prompt="Review architecture: <diff> Known open issues (DO NOT re-report): <issues>")
```

Include the exclusion list from Phase 1 in ALL reviewer prompts. Each prompt must contain: "Do NOT report findings that are already covered by these known open issues. Only report NEW problems."

Wait for all reviewers to complete before proceeding to Phase 3.

---

## Phase 3: Findings Aggregation

Consolidate findings from all reviewers into a structured report.

**Severity Categories:**

| Severity | Description | Action |
|----------|-------------|--------|
| **Critical** | Security vulnerabilities, test failures, breaking changes | MUST fix before merge |
| **Major** | Missing error handling, missing tests, significant issues | Should fix |
| **Minor** | Style, docs, minor improvements | Nice to fix |

**Deduplication Step:**
Before writing the report, compare every reviewer finding against the exclusion list from Phase 1. Drop any finding where the core problem is already tracked by an open GitHub issue. If a reviewer reported something that overlaps with a known issue despite instructions, remove it here.

**Report Format:**
```
## Code Review Summary

### Critical Issues (BLOCKING)
- [ ] Issue 1: [file:line] Description
- [ ] Issue 2: [file:line] Description

### Major Issues
- [ ] Issue 1: [file:line] Description

### Minor Issues
- [ ] Issue 1: [file:line] Description

### Excluded (Already Tracked)
Issues filtered out because they match open GitHub issues:
- #N: Issue title - finding that was excluded

### Positive Observations
- Good: Description of well-done aspects
```

The "Excluded" section provides transparency about what was filtered. If no findings were excluded, omit this section.

---

## Phase 4: Blocking Gate Decision

Determine if the code can proceed.

**BLOCK if any:**
- Critical issues exist
- Tests are failing
- Lint errors present
- Security vulnerabilities identified

**Verification Commands:**
```bash
make test                    # Must pass
make lint                    # Must pass
make test-integration        # Should pass
make test-integration-all    # Full integration (requires Ollama + Claude)
```

**Output Decision:**
```
## Review Decision

**Status:** BLOCKED / APPROVED

**Blocking Issues:** (if any)
1. ...

**Required Before Merge:**
1. ...
```

---

## Phase 5: Fix Mode (Optional)

If the user requests fixes, apply them systematically.

**For each fix:**
1. Edit the file to address the issue
2. Run relevant tests: `go test -v ./internal/<pkg>/...`
3. Run lint: `make lint`
4. Mark issue as resolved in the report

**After all fixes:**
```bash
make test                    # Unit tests
make test-integration        # Pattern integration tests
make test-integration-all    # Full integration tests
make lint                    # Full lint
```

**Commit fixes:**
```bash
git add <fixed-files>
git commit -m "fix: address code review feedback

- Fix 1: description
- Fix 2: description"
```

---

## Quick Reference

**Review Commands:**
```bash
git diff HEAD                          # Current branch changes
gh pr diff <number>                    # PR diff
go test -v ./internal/<pkg>/...        # Package tests
make lint                              # Lint check
```

**Security Checklist for open-guard:**
- [ ] No pattern bypass opportunities
- [ ] No ReDoS vulnerabilities
- [ ] Threat categories correctly assigned
- [ ] Input validation at boundaries
- [ ] No sensitive data in logs/errors
- [ ] Tests cover attack and safe cases

**Threat Categories Reference:**
- T1: Network exfiltration
- T2: Credential access
- T3: Command injection
- T4: Filesystem attacks
- T5: Prompt injection
- T6: Privilege escalation
- T7: Persistence mechanisms
- T8: Reconnaissance
- T9: Output monitoring
- S1-S13: LLM safety categories
