# agent

<!-- AUTO-MANAGED: module-description -->
## Purpose

Claude SDK-based prompt injection detection using semantic analysis. Provides Layer 2 detection in the pipeline, catching sophisticated injection attempts that bypass regex patterns. Supports both Claude (Anthropic API) and Ollama (local models) as providers.

<!-- END AUTO-MANAGED -->

<!-- AUTO-MANAGED: architecture -->
## Module Architecture

```
agent/
├── analyzer.go       # ClaudeAnalyzer implementation
└── analyzer_test.go  # Comprehensive test coverage
```

**Key Types:**
- `ClaudeAnalyzer` - Main analyzer using Claude Code CLI via Agent SDK
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

**Response Parsing:**
- Expected format: `"SAFE"` or `"INJECTION: reason"`
- Case-insensitive matching with `strings.ToUpper()`
- Unknown responses treated as errors

**Prompt Engineering:**
- Structured prompt with `<<<BEGIN_UNTRUSTED>>>` markers
- Explicit instruction to NOT execute input content
- Multi-language injection pattern awareness

<!-- END AUTO-MANAGED -->

<!-- AUTO-MANAGED: dependencies -->
## Key Dependencies

- `github.com/severity1/claude-agent-sdk-go` - Claude Code SDK for query API
- Internal: `(none)` - Standalone module with no internal dependencies

<!-- END AUTO-MANAGED -->

<!-- MANUAL -->
## Module Notes

<!-- END MANUAL -->
