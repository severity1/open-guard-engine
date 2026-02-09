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
- Ollama requires env var setup via `setupOllamaEnv()`
- Cleanup functions restore original env vars

**Context & Timeout Handling:**
- `Analyze()` accepts context for timeout and cancellation
- Checks `ctx.Done()` before each iterator iteration
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

<!-- END AUTO-MANAGED -->

<!-- AUTO-MANAGED: dependencies -->
## Key Dependencies

- `github.com/severity1/claude-agent-sdk-go` - Claude Code SDK for query API
- Internal: `(none)` - Standalone module with no internal dependencies

<!-- END AUTO-MANAGED -->

<!-- MANUAL -->
## Module Notes

<!-- END MANUAL -->
