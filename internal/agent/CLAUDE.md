# agent

<!-- AUTO-MANAGED: module-description -->
## Purpose

Claude SDK-based prompt injection detection using semantic analysis. Provides Layer 2 detection in the pipeline, catching sophisticated injection attempts that bypass regex patterns. Supports both Claude (Anthropic API) and Ollama (local models) as providers.

<!-- END AUTO-MANAGED -->

<!-- AUTO-MANAGED: architecture -->
## Module Architecture

```
agent/
├── analyzer.go       # ClaudeAnalyzer implementation, exported Analyzer interface
├── analyzer_test.go  # Comprehensive test coverage
└── mock.go           # MockAnalyzer for testing
```

**Key Types:**
- `Analyzer` - Exported interface with `Analyze()` and `IsAvailable()` methods
- `ClaudeAnalyzer` - Main analyzer using Claude Code CLI via Agent SDK
- `MockAnalyzer` - Test implementation for unit testing without Claude Code installation
- `Result` - Analysis result (Safe, Categories, Reason)

**Key Functions:**
- `collectResponse()` - Extracts text from iterator with context cancellation between iterations

**Security Isolation:**
The analyzer runs in a hardened sandbox:
- Creates isolated temp directory (no `.claude/` configs to load)
- Limited to read-only tools: `Read`, `Glob`, `Grep`, `LS`, `LSP`, `NotebookRead`
- Bypasses project settings via `--setting-sources user`
- Disables MCP servers via `--strict-mcp-config`

<!-- END AUTO-MANAGED -->

<!-- AUTO-MANAGED: conventions -->
## Module-Specific Conventions

**Provider Pattern:**
- `provider` field: `"claude"` (default) or `"ollama"`
- `buildEnv()` always unsets `CLAUDECODE` env var to enable nested SDK invocation from Claude Code hooks/plugins (#102)
- Ollama provider additionally sets `ANTHROPIC_BASE_URL`, `ANTHROPIC_AUTH_TOKEN`, `ANTHROPIC_API_KEY`
- Returns new env map each call for subprocess isolation (avoids race conditions)

**Context & Timeout Handling:**
- `Analyze()` accepts context for timeout and cancellation
- `collectResponse()` checks `ctx.Done()` before each iterator iteration using `select`
- Distinguishes `ctx.Err()` from operation errors
- Returns context errors immediately without wrapping
- `IsAvailable()` uses 3s timeout via `exec.CommandContext`

**Response Parsing:**
- Expected format: `"SAFE"` or `"INJECTION: reason"`
- Case-insensitive matching with `strings.ToUpper()`
- Unknown responses treated as errors

**Prompt Engineering:**
- Structured prompt with `<<<BEGIN_UNTRUSTED>>>` markers
- Explicit instruction to NOT execute input content
- Multi-language injection pattern awareness

**Testing Pattern:**
- Compile-time interface checks: `var _ Analyzer = (*ClaudeAnalyzer)(nil)`
- `MockAnalyzer` for testing without actual Claude Code installation
- Configurable mock responses: `SafeResponse`, `Categories`, `Reason`, `ShouldError`, `Available`
- Table-driven tests with `testify/assert` and `testify/require`
- Custom `mockIterator` for testing `collectResponse()` with various scenarios
- Tests for context cancellation, `ErrNoMoreMessages` handling, and error propagation
- `buildEnv()` tests verify map isolation and concurrent access safety
- TDD approach: tests written before implementation (e.g., `buildEnv()` tests)
- Coverage: 95.5% as of commit cad6545

<!-- END AUTO-MANAGED -->

<!-- AUTO-MANAGED: dependencies -->
## Key Dependencies

- `github.com/severity1/claude-agent-sdk-go` - Claude Code SDK for query API
- Internal: `(none)` - Standalone module with no internal dependencies

<!-- END AUTO-MANAGED -->

<!-- MANUAL -->
## Module Notes

<!-- END MANUAL -->
