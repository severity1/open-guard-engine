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
- `Logger` - Audit event logger with structured JSON output
- `Entry` - Audit log entry with timestamp, decision, threat metadata

**Key Functions:**
- `sanitizeLogField()` - Strips ANSI escapes, control chars, replaces newlines, UTF-8 safe truncation to 4096 chars

<!-- END AUTO-MANAGED -->

<!-- AUTO-MANAGED: conventions -->
## Module-Specific Conventions

**Logging Pattern:**
- Structured JSON output for machine parsing
- Include audit ID (UUID) for event correlation
- Timestamp all events in UTC

**Security Hardening:**
- All log fields sanitized to prevent log injection (Event, Message, SessionID)
- ANSI escape sequences stripped via regex
- Control characters replaced with spaces
- Newlines replaced with spaces
- Max field length: 4096 characters with UTF-8 safe truncation
- Truncation uses utf8.RuneStart() walk-back to avoid splitting multi-byte sequences

<!-- END AUTO-MANAGED -->

<!-- AUTO-MANAGED: dependencies -->
## Key Dependencies

- Internal: `types` - Shared type definitions

<!-- END AUTO-MANAGED -->

<!-- MANUAL -->
## Module Notes

<!-- END MANUAL -->
