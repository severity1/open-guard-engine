# encoding

<!-- AUTO-MANAGED: module-description -->
## Purpose

Detection and decoding of obfuscated content. Layer 0 in the detection pipeline - processes input before pattern matching to catch encoded injection attempts (base64, hex, ROT13, Unicode tricks).

<!-- END AUTO-MANAGED -->

<!-- AUTO-MANAGED: architecture -->
## Module Architecture

```
encoding/
├── detector.go       # Encoding detection and decoding
└── detector_test.go  # Test coverage for all encoding types
```

**Key Types:**
- `Detector` - Encoding detector with compiled regex patterns
- `DetectionResult` - Results including decoded content and suspicion flag

**Supported Encodings:**
1. **Base64** - Standard and URL-safe variants
2. **Hexadecimal** - `0x` prefix and `\x` escape sequences
3. **ROT13** - Caesar cipher (triggered by keyword hints)
4. **Zero-width chars** - Invisible Unicode (U+200B, U+200C, U+200D, U+FEFF)
5. **Homoglyphs** - Cyrillic/Greek lookalikes mapped to Latin
6. **Reversed text** - Backwards injection attempts

<!-- END AUTO-MANAGED -->

<!-- AUTO-MANAGED: conventions -->
## Module-Specific Conventions

**Detection Strategy:**
- Returns `DetectionResult` with both `HasObfuscation` and `Suspicious` flags
- `HasObfuscation`: Any encoding detected
- `Suspicious`: Decoded content contains injection keywords

**Decoded Content Format:**
- Appends `[DECODED TYPE]: content` to original for analysis
- Multiple decodings concatenated with newlines

**Injection Keywords:**
- Regex pattern: `ignore|forget|disregard|override|bypass|system|instruction|prompt|jailbreak|DAN|admin|developer`

<!-- END AUTO-MANAGED -->

<!-- AUTO-MANAGED: dependencies -->
## Key Dependencies

- `encoding/base64`, `encoding/hex` - Standard library decoders
- Internal: `(none)` - Standalone module

<!-- END AUTO-MANAGED -->

<!-- MANUAL -->
## Module Notes

<!-- END MANUAL -->
