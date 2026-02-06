# config

<!-- AUTO-MANAGED: module-description -->
## Purpose

Configuration loading and validation for open-guard. Handles YAML config files with priority merging (project > global > defaults) and backwards compatibility for deprecated fields.

<!-- END AUTO-MANAGED -->

<!-- AUTO-MANAGED: architecture -->
## Module Architecture

```
config/
├── config.go       # Config loading and validation
└── config_test.go  # Test coverage including edge cases
```

**Key Types:**
- `Config` - Root configuration struct with MaxInputSize (10MB default)
- `LLMConfig` - Ollama content safety settings with TimeoutSeconds (30s default)
- `AgentConfig` - Claude/Ollama agent detection settings with TimeoutSeconds (60s default)
- `Mode` - Decision mode (strict/confirm/permissive)

**Config Loading Functions:**
- `Load(projectRoot)` - Auto-discover config (project > global > defaults)
- `LoadFromPath(path)` - Explicit path (must exist, errors if not found)
- `LoadWithHome()`, `LoadFromPathWithHome()` - Testable versions with explicit home dir

**Config Priority (Load):**
1. Project config: `./.open-guard.yaml`
2. Global config: `~/.open-guard/config.yaml`
3. Defaults: `DefaultConfig()`

**Config Priority (LoadFromPath):**
1. Explicit file path (required)
2. Global config: `~/.open-guard/config.yaml`
3. Defaults: `DefaultConfig()`

**Resource Limits:**
- `MaxInputSize` - Maximum stdin bytes (default: 10MB, prevents OOM attacks)
- `LLMConfig.TimeoutSeconds` - HTTP request timeout for content safety (default: 30s)
- `AgentConfig.TimeoutSeconds` - Analysis timeout for semantic detection (default: 60s)

<!-- END AUTO-MANAGED -->

<!-- AUTO-MANAGED: conventions -->
## Module-Specific Conventions

**YAML Merging:**
- Uses raw map parsing to detect which fields were explicitly set
- Only overrides defaults for fields present in config file
- Preserves unset optional fields from lower-priority configs
- `loadAndMerge()` - Optional files (no error if missing)
- `loadAndMergeRequired()` - Required files (errors if missing)
- `mergeConfigData()` - Shared parsing logic

**Backwards Compatibility:**
- `ml_enabled` deprecated but still supported
- Syncs to `llm.enabled` if `llm` section not present

**Testing Pattern:**
- `LoadWithHome()` for testability (explicit home directory)
- `LoadFromPathWithHome()` for testing explicit paths
- Test both global and project config precedence

**Error Handling:**
- `Load()` - No error if config files missing (uses defaults)
- `LoadFromPath()` - Errors if explicit path doesn't exist
- Clear error messages: "config file not found: {path}"

<!-- END AUTO-MANAGED -->

<!-- AUTO-MANAGED: dependencies -->
## Key Dependencies

- `gopkg.in/yaml.v3` - YAML parsing
- Internal: `(none)` - Standalone module

<!-- END AUTO-MANAGED -->

<!-- MANUAL -->
## Module Notes

<!-- END MANUAL -->
