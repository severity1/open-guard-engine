# types

<!-- AUTO-MANAGED: module-description -->
## Purpose

Shared type definitions for the open-guard security engine. Defines the core domain types: decisions, threat levels, categories, detection sources, and hook I/O structures.

<!-- END AUTO-MANAGED -->

<!-- AUTO-MANAGED: architecture -->
## Module Architecture

```
types/
├── types.go       # All type definitions
└── types_test.go  # Type behavior tests
```

**Key Types:**

**Decision** - Action to take for a hook event:
- `allow` - Permit the operation
- `block` - Deny the operation
- `confirm` - Prompt user for confirmation
- `scrub` - Sanitize content
- `remediate` - Auto-fix the content
- `log` - Log only, allow operation

**ThreatLevel** - Severity of detected threat:
- `critical`, `high`, `medium`, `low`, `none`

**ThreatCategory** - Type of threat:
- `T1`-`T9`: Technical security (pattern-detected)
- `S1`-`S13`: Content safety (LLM-detected)

**DetectionSource** - Which layer detected:
- `pattern`, `llm`, `agent`

**HookInput/HookOutput** - JSON structures for Claude Code hooks

<!-- END AUTO-MANAGED -->

<!-- AUTO-MANAGED: conventions -->
## Module-Specific Conventions

**Type Pattern:**
- String-based types with constants
- `String()` method for display
- `MarshalJSON()`/`UnmarshalJSON()` for serialization

**Validation:**
- `ParseThreatCategory(s)` - Parse and validate category strings (case-insensitive, returns error for invalid)
- `ParseThreatLevel(s)` - Parse and validate severity levels (case-insensitive, returns error for invalid)
- Validation performed at startup in pattern matcher to fail fast on invalid YAML

**Category Helpers:**
- `Description()` - Human-readable description
- `IsSafetyCategory()` - Check if S1-S13
- `IsThreatCategory()` - Check if T1-T9

**Hook Input Helpers:**
- `GetCommand()` - Extract command from Bash tool input
- `GetFilePath()` - Extract path from Read/Write tool input

<!-- END AUTO-MANAGED -->

<!-- AUTO-MANAGED: dependencies -->
## Key Dependencies

- `encoding/json` - JSON marshaling
- Internal: `(none)` - Foundation module with no dependencies

<!-- END AUTO-MANAGED -->

<!-- MANUAL -->
## Module Notes

<!-- END MANUAL -->
