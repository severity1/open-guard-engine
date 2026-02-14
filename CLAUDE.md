# open-guard

<!-- AUTO-MANAGED: project-description -->
## Overview

Defense-in-depth security engine for AI coding assistants. Protects codebases from prompt injection, malicious commands, and harmful content through layered detection: fast pattern matching, agent-based analysis, and LLM content safety.

**Key Features:**
- 96 threat patterns (T1-T9) with regex matching
- Claude SDK integration for semantic injection detection (T5)
- Ollama llama-guard3 for content safety (S1-S13)
- Encoding detection (base64, hex, ROT13, Unicode homoglyphs, fullwidth/NFKC, recursive decoding)
- Three decision modes: strict, confirm, permissive

<!-- END AUTO-MANAGED -->

<!-- AUTO-MANAGED: build-commands -->
## Build & Development Commands

```bash
# Build
make build              # Build for current platform
make build-all          # Build for all platforms (linux, darwin, windows)
make install            # Install to GOPATH/bin

# Test
make test               # Run all unit tests
make test-coverage      # Run tests with coverage report
make test-integration   # Run pattern-only integration tests (no external deps)
make test-integration-all  # Run all integration tests (requires Ollama + Claude)
make bench              # Run benchmarks

# Quality
make lint               # Run golangci-lint

# Maintenance
make clean              # Remove build artifacts
make deps               # Download and tidy dependencies
```

**Single test file:**
```bash
go test -v ./internal/agent/...
go test -v ./internal/patterns/... -run TestMatcher
```

<!-- END AUTO-MANAGED -->

<!-- AUTO-MANAGED: architecture -->
## Architecture

```
open-guard-engine/
├── cmd/open-guard/          # CLI entry point (Cobra)
│   └── main.go              # Command definitions, analysis pipeline, --config flag
├── internal/
│   ├── agent/               # Claude SDK prompt injection detection
│   ├── audit/               # Audit logging
│   ├── config/              # YAML config loading with priority merging
│   ├── encoding/            # Obfuscation detection and decoding
│   ├── llm/                 # Ollama LLM content safety analysis
│   ├── patterns/            # Regex pattern matching engine
│   ├── response/            # Hook response building
│   └── types/               # Shared type definitions
├── tests/integration/       # End-to-end integration tests
├── Makefile                 # Build automation
└── .open-guard.yaml.example # Config template
```

**Detection Pipeline (layered, short-circuit on match):**
```
stdin -> Layer 0: Encoding Detection (decode obfuscated content)
      -> Layer 1: Pattern Matching (fast, deterministic, 96 patterns)
      -> Layer 2: Agent Analysis (Claude SDK semantic detection)
      -> Layer 3: LLM Safety (llama-guard3 content classification)
      -> stdout: JSON decision
```

**Data Flow:**
1. CLI reads stdin with hardcoded 10MB limit (prevents OOM before config loads)
2. Config loaded via --config flag or auto-discovery (project > global > defaults)
3. Input size validated against config's MaxInputSize (may be stricter than hardcoded limit)
4. Encoding detector decodes obfuscated content (base64, hex, etc.)
5. Pattern matcher checks against 96 compiled regex patterns
6. If no match and agent enabled, Claude analyzes with timeout and context cancellation
7. If agent/LLM errors occur, handleAnalysisError applies mode-aware handling (permissive: continue, others: confirm)
8. If safe and LLM enabled, llama-guard3 classifies content safety
9. Response handler builds JSON output based on mode (strict/confirm/permissive)

**Resource Limits:**
- Hardcoded 10MB stdin limit applied before config load
- Configurable MaxInputSize (default: 10MB) for stricter per-environment limits
- Agent analysis timeout (default: 60s) with context cancellation support
- LLM request timeout (default: 30s) for content safety checks

<!-- END AUTO-MANAGED -->

<!-- AUTO-MANAGED: conventions -->
## Code Conventions

**Go Patterns:**
- Constructor functions: `NewTypeName(dependencies)` returning `*TypeName`
- Type constants with `String()` and JSON marshal/unmarshal methods
- Parse functions for validation: `ParseTypeName(s)` returns error for invalid values
- Interfaces defined where consumed, not where implemented
- Exported interfaces enable external testing and mocking
- Compile-time interface checks: `var _ Interface = (*Implementation)(nil)`
- Embedded resources via `//go:embed` for single-binary distribution

**Testing:**
- Table-driven tests with `testify/assert` and `testify/require`
- Test files named `*_test.go` adjacent to source
- Mock implementations in `mock.go` files (e.g., `agent.MockAnalyzer`)
- Exported interfaces enable dependency injection for testing
- Integration tests in `tests/integration/` with build tags
- Use `t.Run()` for subtests, `t.Logf()` for diagnostic output

**Error Handling:**
- Wrap errors with context: `fmt.Errorf("operation: %w", err)`
- Early return on error, avoid deep nesting
- Silence expected Close() errors in deferred calls: `defer func() { _ = resp.Body.Close() }()`
- Distinguish context cancellation: check `ctx.Err()` separately from operation errors

**Context & Timeout Handling:**
- Use `context.WithTimeout()` for operations with configurable timeouts
- Check `ctx.Done()` in loops with `select` statements
- Defer cancel functions immediately after context creation
- Propagate context cancellation errors up the call stack

**Imports:**
- Group: stdlib, third-party, local packages
- Sort alphabetically within groups

**Naming:**
- Threat categories: `T1`-`T9` (technical), `S1`-`S13` (safety)
- Decision types: `allow`, `block`, `confirm`, `log`
- Detection sources: `pattern`, `llm`, `agent`

<!-- END AUTO-MANAGED -->

<!-- AUTO-MANAGED: patterns -->
## Detected Patterns

**Security Isolation for Agent Analysis:**
- Runs from isolated temp directory (no `.claude/` configs)
- Read-only tools only: `Read`, `Glob`, `Grep`, `LS`, `LSP`, `NotebookRead`
- User settings only via `--setting-sources user`
- MCP servers disabled via `--strict-mcp-config`

**Response Building:**
- Mode overrides applied in `response.Handler`
- Strict: `confirm` -> `block`
- Permissive: `block`/`confirm` -> `log`
- Audit IDs generated via UUID

**Error Handling (handleAnalysisError):**
- Agent/LLM analysis errors handled based on mode
- Permissive mode: errors ignored, pipeline continues (fail-open)
- Other modes: errors produce `confirm` decision with medium severity (fail-closed)
- Generic error messages prevent information leakage (no hostnames, connection strings)
- Detailed errors logged to stderr for operator diagnostics (all modes)

**Pattern File Structure:**
- YAML-based pattern definitions in `internal/patterns/patterns.yaml`
- Compiled at startup via `//go:embed`
- Each pattern has: id, category, name, description, severity, regex, extract rules

<!-- END AUTO-MANAGED -->

<!-- AUTO-MANAGED: git-insights -->
## Git Insights

**Recent Design Decisions:**
- Extracted collectResponse() for testability and improved context cancellation handling (PR #4)
- Race condition fix: replaced setupOllamaEnv (parent env mutation) with buildEnv (subprocess env map) to eliminate shared state mutation (PR #8)
- buildEnv() returns new map each call to ensure concurrent access safety and isolation
- Strict validation for ThreatCategory and Config values to fail fast on invalid YAML/config (PR #15)
- Exported Analyzer interface for external testing and mocking (PR #12)
- Tool-agnostic pattern matching (not tied to specific tool names)
- Security isolation for agent analysis to prevent malicious project configs
- Three-layer detection with short-circuit evaluation for performance
- Explicit config path support via --config flag for multi-environment setups
- Critical path hardening against DoS attacks (input size limits, timeouts, context cancellation)
- Two-stage input validation: hardcoded limit before config, then config limit
- Recursive base64 decoding with max depth (3 layers) to catch nested encoding without unbounded recursion (#19)
- Fullwidth/NFKC Unicode normalization to detect obfuscated injection keywords (#19)
- Short base64 payload detection for single-keyword injection attempts (#19)
- Removed hardcoded LLM HTTP timeout - relies on context cancellation for timeout control (#25)
- Unknown LLM responses default to unsafe (fail-closed) to prevent bypass via malformed output (#19)
- Deferred Close() errors explicitly silenced where cleanup failure is non-critical (#6)
- Audit log sanitization to prevent log injection via ANSI escapes, control chars, and newlines (#22, #6)
- SSRF patterns added: AWS metadata (169.254.169.254), GCP metadata (metadata.google.internal), ECS credentials (169.254.170.2) (#19)
- Mode-aware error handling: agent/LLM errors fail-open in permissive mode, fail-closed otherwise (#19)
- Endpoint validation enforces http/https schemes for LLM and agent endpoints to prevent file:// and other protocol exploits (#19)
- Error message sanitization: generic "service error" prevents leakage of internal details (hostnames, connection strings), detailed errors logged to stderr (#32)
- SessionID sanitization added to audit logger to prevent log injection via session identifiers (#32)
- UTF-8 safe truncation in audit logs uses utf8.RuneStart() to avoid splitting multi-byte sequences (#32)
- GCP metadata pattern (T1-005) case-insensitive to catch obfuscation variants like Metadata.Google.Internal (#32)

**Commit Style:**
- Conventional format: `type: description (#issue)`
- Types: `fix`, `feat`, `docs`, `security`, `refactor`, `test`

<!-- END AUTO-MANAGED -->

<!-- MANUAL -->
## Project Notes

Add project-specific notes, TODOs, or context here. This section is never auto-modified.

<!-- END MANUAL -->
