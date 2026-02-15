---
argument-hint: <issue-number>
description: Test-Driven Development workflow for implementing GitHub issues with RED/GREEN/BLUE phases
allowed-tools: Read, Grep, Glob, Bash, Write, Edit, Task, LSP, WebFetch
---

# TDD Workflow: Issue #$ARGUMENTS

You are implementing a GitHub issue using strict Test-Driven Development. Follow each phase in order. Do not skip phases or proceed without completing the required steps.

## Phase 1: Pre-flight Validation

Validate the development environment before starting.

**Required Commands:**
```bash
git status                    # Check for uncommitted changes
make build                    # Verify build succeeds
make test                     # Verify unit tests pass
make test-integration         # Verify pattern integration tests pass
make lint                     # Verify no lint errors
```

**Gate:** All commands must succeed. If any fail, fix the issue before proceeding.

## Phase 2: Issue Validation

Fetch and understand the issue requirements.

**Required Commands:**
```bash
gh issue view $ARGUMENTS      # Fetch issue details
```

**Create Feature Branch:**
```bash
git checkout -b issue-$ARGUMENTS-<short-description>
```

**Gate:** Issue must exist and have clear acceptance criteria. If unclear, ask user for clarification.

## Phase 3: Discovery & Planning

Explore the codebase to understand implementation context.

**Exploration Tasks:**
1. Read related files mentioned in the issue
2. Find similar implementations using Grep/Glob
3. Understand the detection pipeline layers
4. Identify test files that need updates

**Reference Architecture:**
```
stdin -> Layer 0: Encoding Detection
      -> Layer 1: Pattern Matching (internal/patterns/)
      -> Layer 2: Agent Analysis (internal/agent/)
      -> Layer 3: LLM Safety (internal/llm/)
      -> stdout: JSON decision
```

**Create Implementation Plan:**
Document in a concise format:
- Files to create/modify
- Test cases needed (positive and negative)
- Security considerations for this feature

**USER CHECKPOINT:** Present the plan to the user and wait for approval before proceeding.

## Phase 4: RED Phase - Write Failing Tests

Write tests BEFORE implementation. Tests must fail initially.

**Test Conventions:**
- Unit tests: `internal/<pkg>/<file>_test.go`
- Integration tests: `tests/integration/`
- Table-driven tests with `testify/assert` and `testify/require`

**Test Structure Pattern:**
```go
func TestFeatureName(t *testing.T) {
    tests := []struct {
        name     string
        input    string
        expected bool
        // Add relevant fields
    }{
        {"positive case - detects attack", "...", true},
        {"negative case - allows safe", "...", false},
        {"edge case - boundary", "...", true},
    }

    for _, tc := range tests {
        t.Run(tc.name, func(t *testing.T) {
            // Test logic
            assert.Equal(t, tc.expected, actual)
        })
    }
}
```

**Security Test Requirements (This is a Security Tool):**
- Test positive cases: Detects the attack vector
- Test negative cases: Allows legitimate usage
- Test bypass attempts: Variations that might evade detection
- Test encoding obfuscation: base64, hex, rot13, unicode homoglyphs

**Verify Failure:**
```bash
go test -v ./internal/<pkg>/... -run TestFeatureName
```

**Gate:** Tests MUST fail. If they pass, the tests are not testing new behavior.

**Commit:**
```bash
git add <test-files>
git commit -m "test: add failing tests for issue #$ARGUMENTS

- Test case 1: description
- Test case 2: description
- Tests currently fail (RED phase)"
```

## Phase 5: GREEN Phase - Minimal Implementation

Write the minimum code to make tests pass. No more, no less.

**Implementation Guidelines:**
- Follow existing patterns in the codebase
- Use constructor pattern: `NewTypeName(dependencies) *TypeName`
- Wrap errors with context: `fmt.Errorf("operation: %w", err)`
- Early return on error, avoid deep nesting

**Verify Success:**
```bash
go test -v ./internal/<pkg>/... -run TestFeatureName
make lint
make test                     # Ensure no unit test regressions
make test-integration         # Ensure no integration regressions
```

**Gate:** All tests must pass. Lint must pass.

**Commit:**
```bash
git add <implementation-files>
git commit -m "feat: implement <feature> for issue #$ARGUMENTS

<Brief description of what was implemented>

Closes #$ARGUMENTS"
```

## Phase 6: BLUE Phase - Refactor

Improve code quality without changing behavior.

**Refactoring Checklist:**
- [ ] Remove duplication (DRY)
- [ ] Improve naming clarity
- [ ] Simplify complex logic (KISS)
- [ ] Add godoc comments for exported functions
- [ ] Check for security vulnerabilities (OWASP top 10)
- [ ] Verify no secrets in code

**Security Review (Critical for open-guard):**
- Pattern bypass potential
- ReDoS in regex patterns
- Input validation at boundaries
- Error message information leakage

**Verify No Regression:**
```bash
make test
make test-integration
make lint
```

**Commit (if changes made):**
```bash
git add -A
git commit -m "refactor: improve <component> for issue #$ARGUMENTS

<Brief description of improvements>"
```

## Phase 7: PR Creation

Submit the work for review.

**Pre-PR Checklist:**
```bash
make test                     # All unit tests pass
make lint                     # No lint errors
make test-integration         # Pattern integration tests pass
make test-integration-all     # Full integration tests pass (requires Ollama + Claude)
git log --oneline main..HEAD  # Review commits
```

**Push and Create PR:**
```bash
git push -u origin HEAD
gh pr create --title "<type>: <description>" --body "## Summary
<1-3 bullet points>

## Test Plan
- [ ] Unit tests added for new behavior
- [ ] Positive detection cases covered
- [ ] Negative (safe) cases covered
- [ ] Integration tests pass

## Security Considerations
<Any security-relevant notes>

Closes #$ARGUMENTS"
```

**Gate:** PR must be created. Provide the PR URL to the user.

---

## Quick Reference

**Commit Prefixes:**
- `test:` - Test changes (RED phase)
- `feat:` - New feature (GREEN phase)
- `fix:` - Bug fix
- `refactor:` - Code improvement (BLUE phase)
- `docs:` - Documentation only

**Test Commands:**
```bash
go test -v ./internal/<pkg>/...           # Run package tests
go test -v ./... -run TestName            # Run specific test
make test-coverage                         # Coverage report
```

**Threat Categories:**
- T1-T9: Technical threats
- S1-S13: Safety categories (LLM-based)
