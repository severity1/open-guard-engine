# open-guard

<!-- AUTO-MANAGED: project-description -->
## Overview

Defense-in-depth security engine for AI coding assistants. Protects codebases from prompt injection, malicious commands, and harmful content through layered detection: fast pattern matching, agent-based analysis, and LLM content safety.

**Key Features:**
- 93 threat patterns (T1-T9) with regex matching
- Claude SDK integration for semantic injection detection (T5)
- Ollama llama-guard3 for content safety (S1-S13)
- Encoding detection (base64, hex, ROT13, Unicode homoglyphs)
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
      -> Layer 1: Pattern Matching (fast, deterministic, 93 patterns)
      -> Layer 2: Agent Analysis (Claude SDK semantic detection)
      -> Layer 3: LLM Safety (llama-guard3 content classification)
      -> stdout: JSON decision
```

**Data Flow:**
1. CLI receives raw text via stdin (optional --config flag for explicit config path)
2. Encoding detector decodes obfuscated content (base64, hex, etc.)
3. Pattern matcher checks against 93 compiled regex patterns
4. If no match and agent enabled, Claude analyzes for semantic injection
5. If safe and LLM enabled, llama-guard3 classifies content safety
6. Response handler builds JSON output based on mode (strict/confirm/permissive)

<!-- END AUTO-MANAGED -->

<!-- AUTO-MANAGED: conventions -->
## Code Conventions

**Go Patterns:**
- Constructor functions: `NewTypeName(dependencies)` returning `*TypeName`
- Type constants with `String()` and JSON marshal/unmarshal methods
- Interfaces defined where consumed, not where implemented
- Embedded resources via `//go:embed` for single-binary distribution

**Testing:**
- Table-driven tests with `testify/assert` and `testify/require`
- Test files named `*_test.go` adjacent to source
- Integration tests in `tests/integration/` with build tags
- Use `t.Run()` for subtests, `t.Logf()` for diagnostic output

**Error Handling:**
- Wrap errors with context: `fmt.Errorf("operation: %w", err)`
- Early return on error, avoid deep nesting
- Check error from deferred Close() only when it matters

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

**Pattern File Structure:**
- YAML-based pattern definitions in `internal/patterns/patterns.yaml`
- Compiled at startup via `//go:embed`
- Each pattern has: id, category, name, description, severity, regex, extract rules

<!-- END AUTO-MANAGED -->

<!-- AUTO-MANAGED: git-insights -->
## Git Insights

**Recent Design Decisions:**
- Tool-agnostic pattern matching (not tied to specific tool names)
- Security isolation for agent analysis to prevent malicious project configs
- Three-layer detection with short-circuit evaluation for performance
- Explicit config path support via --config flag for multi-environment setups

**Commit Style:**
- Conventional format: `type: description (#issue)`
- Types: `fix`, `feat`, `docs`, `security`, `refactor`

<!-- END AUTO-MANAGED -->

<!-- MANUAL -->
## Project Notes

Add project-specific notes, TODOs, or context here. This section is never auto-modified.

<!-- END MANUAL -->
