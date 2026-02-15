# patterns

<!-- AUTO-MANAGED: module-description -->
## Purpose

Regex-based threat pattern matching engine. Layer 1 in the detection pipeline - fast, deterministic matching against 97 patterns covering technical threats (T1-T9) including prompt injection (T5) and SSRF (T1).

<!-- END AUTO-MANAGED -->

<!-- AUTO-MANAGED: architecture -->
## Module Architecture

```
patterns/
├── matcher.go        # Pattern matching engine
├── matcher_test.go   # Test coverage
└── patterns.yaml     # Embedded pattern definitions (97 patterns)
```

**Key Types:**
- `Matcher` - Pattern matching engine with pre-compiled regex
- `CompiledPattern` - Pattern with compiled regex and extract rules
- `MatchResult` - Match details including extracted values
- `PatternDef` - YAML pattern definition structure

**Pattern Categories:**
| Category | Description | Count |
|----------|-------------|-------|
| T1 | Network exfiltration & SSRF | 7 |
| T2 | Credential access | 7 |
| T3 | Command injection | 5+ |
| T4 | Filesystem attacks | 5+ |
| T5 | Prompt injection | 51 |
| T6 | Privilege escalation | 5+ |
| T7 | Persistence mechanisms | 5+ |
| T8 | Reconnaissance | 5+ |
| T9 | Output monitoring | 5+ |

<!-- END AUTO-MANAGED -->

<!-- AUTO-MANAGED: conventions -->
## Module-Specific Conventions

**Embedded Patterns:**
- Uses `//go:embed patterns.yaml` for single-binary distribution
- Patterns compiled at startup via `NewMatcher()`
- Compilation errors are fatal (returned from constructor)
- Category and severity validated at startup using `types.ParseThreatCategory()` and `types.ParseThreatLevel()`
- Invalid pattern definitions fail fast with clear error messages

**Pattern YAML Structure:**
```yaml
patterns:
  - id: T5-001
    category: T5
    name: pattern_name
    description: Human-readable description
    severity: critical|high|medium|low
    pattern: 'regex pattern'
    extract:
      field_name: 'extraction regex'
```

**Matching Behavior:**
- Returns all matching patterns (not short-circuit)
- `HighestSeverity()` helper for prioritization
- Extraction patterns capture named groups
- Case-insensitive patterns use `(?i)` prefix (e.g., GCP metadata pattern T1-005)
- Multiline patterns use `(?im)` flag to enable start-of-line ^ matching (e.g., T5-003 system: override)
- Scoped patterns match specific operations (e.g., T4-001 /etc/ write commands only, not read operations)

<!-- END AUTO-MANAGED -->

<!-- AUTO-MANAGED: dependencies -->
## Key Dependencies

- `regexp` - Standard library regex
- `gopkg.in/yaml.v3` - YAML parsing for patterns
- Internal: `types` - Threat category and level types

<!-- END AUTO-MANAGED -->

<!-- MANUAL -->
## Module Notes

<!-- END MANUAL -->
