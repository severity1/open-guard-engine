# llm

<!-- AUTO-MANAGED: module-description -->
## Purpose

LLM-based content safety analysis via Ollama. Layer 3 in the detection pipeline - uses llama-guard3 to classify content against 13 safety categories (S1-S13) for harmful content detection.

<!-- END AUTO-MANAGED -->

<!-- AUTO-MANAGED: architecture -->
## Module Architecture

```
llm/
├── analyzer.go       # LlamaGuardAnalyzer implementation
├── analyzer_test.go  # Test coverage
└── mock.go           # Mock analyzer for testing
```

**Key Types:**
- `Analyzer` - Interface for LLM-based analysis
- `LlamaGuardAnalyzer` - Ollama llama-guard3 integration
- `Result` - Analysis result (Safe, Categories, Confidence, Reason)

**API Integration:**
- Uses Ollama `/api/chat` endpoint
- Non-streaming mode for simplicity
- 30-second HTTP timeout

<!-- END AUTO-MANAGED -->

<!-- AUTO-MANAGED: conventions -->
## Module-Specific Conventions

**Response Parsing:**
- Format: `"safe"` or `"unsafe\nS1,S2,..."`
- Categories may be on same line: `"unsafe S1,S2"`
- Unknown responses treated as safe with low confidence (0.3)

**Availability Check:**
- Uses `/api/tags` endpoint to list models
- Verifies required model is present

**Interface Design:**
- `Analyzer` interface for testability
- `mock.go` provides test double

<!-- END AUTO-MANAGED -->

<!-- AUTO-MANAGED: dependencies -->
## Key Dependencies

- `net/http` - HTTP client for Ollama API
- Internal: `(none)` - Standalone module

<!-- END AUTO-MANAGED -->

<!-- MANUAL -->
## Module Notes

<!-- END MANUAL -->
