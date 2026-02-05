# audit

<!-- AUTO-MANAGED: module-description -->
## Purpose

Audit logging for security decisions. Provides a structured logging interface for recording threat detection events, decisions, and metadata for compliance and debugging purposes.

<!-- END AUTO-MANAGED -->

<!-- AUTO-MANAGED: architecture -->
## Module Architecture

```
audit/
├── logger.go       # Audit logger implementation
└── logger_test.go  # Test coverage
```

**Key Types:**
- `Logger` - Audit event logger with structured output

<!-- END AUTO-MANAGED -->

<!-- AUTO-MANAGED: conventions -->
## Module-Specific Conventions

**Logging Pattern:**
- Structured JSON output for machine parsing
- Include audit ID (UUID) for event correlation
- Timestamp all events in UTC

<!-- END AUTO-MANAGED -->

<!-- AUTO-MANAGED: dependencies -->
## Key Dependencies

- Internal: `types` - Shared type definitions

<!-- END AUTO-MANAGED -->

<!-- MANUAL -->
## Module Notes

<!-- END MANUAL -->
