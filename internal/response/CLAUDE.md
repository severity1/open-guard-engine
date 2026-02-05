# response

<!-- AUTO-MANAGED: module-description -->
## Purpose

Hook response building with mode-based decision adjustment. Constructs JSON output for Claude Code hooks, applying mode overrides (strict/confirm/permissive) to base decisions.

<!-- END AUTO-MANAGED -->

<!-- AUTO-MANAGED: architecture -->
## Module Architecture

```
response/
├── handler.go       # Response handler implementation
└── handler_test.go  # Test coverage
```

**Key Types:**
- `Handler` - Response builder with config-based mode logic

**Mode Overrides:**
| Mode | Transform |
|------|-----------|
| strict | confirm -> block |
| confirm | (no change) |
| permissive | block/confirm -> log |

<!-- END AUTO-MANAGED -->

<!-- AUTO-MANAGED: conventions -->
## Module-Specific Conventions

**Builder Methods:**
- `Allow(message)` - Simple allow response
- `Build(decision, level, category, message)` - Full response
- `BuildWithSource(...)` - Include detection source
- `BuildWithModeOverride(...)` - Apply mode transformations
- `BuildWithModeOverrideAndSource(...)` - Combined

**Severity to Decision Mapping:**
| Severity | Default Decision |
|----------|------------------|
| critical | block |
| high | confirm (strict: block) |
| medium | confirm (strict: block) |
| low | log |
| none | allow |

**Audit IDs:**
- Generated via `github.com/google/uuid`
- Included in all non-allow responses

<!-- END AUTO-MANAGED -->

<!-- AUTO-MANAGED: dependencies -->
## Key Dependencies

- `github.com/google/uuid` - Audit ID generation
- Internal: `config`, `types` - Config and shared types

<!-- END AUTO-MANAGED -->

<!-- MANUAL -->
## Module Notes

<!-- END MANUAL -->
