// Package config handles loading and validating configuration for open-guard.
package config

import (
	"fmt"
	"net/url"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// Mode determines how threats are handled.
type Mode string

const (
	ModeStrict     Mode = "strict"     // Block all detected threats
	ModeConfirm    Mode = "confirm"    // Prompt user for confirmation
	ModePermissive Mode = "permissive" // Log only, allow all
)

// LLMConfig configures raw LLM calls via Ollama for content safety (internal/llm/).
// Content safety only (S1-S13) - prompt injection is handled by Agent.
type LLMConfig struct {
	Enabled            bool   `yaml:"enabled"`
	Endpoint           string `yaml:"endpoint"`             // http://localhost:11434
	ContentSafetyModel string `yaml:"content_safety_model"` // llama-guard3:latest
	TimeoutSeconds     int    `yaml:"timeout_seconds"`      // HTTP request timeout (default: 30)
}

// AgentConfig configures prompt injection detection (T5) using Claude Code as the agent harness.
// Supports two providers: "claude" (Anthropic API) or "ollama" (local models).
// Session is READ-ONLY - can read project files for context but cannot modify.
type AgentConfig struct {
	Enabled        bool   `yaml:"enabled"`
	Provider       string `yaml:"provider"`        // "claude" (default) or "ollama"
	Model          string `yaml:"model"`            // Model name (e.g., claude-sonnet-4-20250514 or llama3:latest)
	Endpoint       string `yaml:"endpoint"`         // Ollama endpoint (only for ollama provider)
	TimeoutSeconds int    `yaml:"timeout_seconds"`  // Analysis timeout (default: 60)
}

// Config holds the open-guard configuration.
type Config struct {
	Mode         Mode        `yaml:"mode"`
	MaxInputSize int64       `yaml:"max_input_size"` // Max stdin bytes (default: 10MB)
	MLEnabled    bool        `yaml:"ml_enabled"`     // Deprecated: use LLM.Enabled instead
	LLM          LLMConfig   `yaml:"llm"`
	Agent        AgentConfig `yaml:"agent"`
}

// DefaultConfig returns a Config with sensible defaults.
func DefaultConfig() *Config {
	return &Config{
		Mode:         ModeConfirm,
		MaxInputSize: 10 * 1024 * 1024, // 10MB
		MLEnabled:    true,             // Deprecated but kept for backwards compatibility
		LLM: LLMConfig{
			Enabled:        true,
			Endpoint:       "http://localhost:11434",
			TimeoutSeconds: 30,
		},
		Agent: AgentConfig{
			Enabled:        false,
			TimeoutSeconds: 60,
		},
	}
}

// Validate checks if the configuration is valid.
func (c *Config) Validate() error {
	switch c.Mode {
	case ModeStrict, ModeConfirm, ModePermissive:
		// valid
	default:
		return fmt.Errorf("invalid mode: %q (must be strict, confirm, or permissive)", c.Mode)
	}

	if c.MaxInputSize < 0 {
		return fmt.Errorf("max_input_size must be non-negative, got %d", c.MaxInputSize)
	}
	if c.Agent.TimeoutSeconds < 0 {
		return fmt.Errorf("agent.timeout_seconds must be non-negative, got %d", c.Agent.TimeoutSeconds)
	}
	if c.LLM.TimeoutSeconds < 0 {
		return fmt.Errorf("llm.timeout_seconds must be non-negative, got %d", c.LLM.TimeoutSeconds)
	}
	if c.Agent.Provider != "" && c.Agent.Provider != "claude" && c.Agent.Provider != "ollama" {
		return fmt.Errorf("invalid agent provider: %q (must be claude or ollama)", c.Agent.Provider)
	}

	if err := validateEndpoint(c.LLM.Endpoint, "llm.endpoint"); err != nil {
		return err
	}
	if err := validateEndpoint(c.Agent.Endpoint, "agent.endpoint"); err != nil {
		return err
	}

	return nil
}

// validateEndpoint checks that an endpoint URL is empty or uses http/https scheme.
func validateEndpoint(endpoint, fieldName string) error {
	if endpoint == "" {
		return nil
	}
	u, err := url.Parse(endpoint)
	if err != nil {
		return fmt.Errorf("invalid %s endpoint: %w", fieldName, err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("invalid %s endpoint: scheme must be http or https, got %q", fieldName, u.Scheme)
	}
	return nil
}

// Load loads configuration from the project directory.
// Priority: project config > global config > defaults
func Load(projectRoot string) (*Config, error) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		homeDir = ""
	}
	return LoadWithHome(projectRoot, homeDir)
}

// LoadFromPath loads configuration from an explicit file path.
// Unlike Load(), this returns an error if the file doesn't exist.
// Priority: explicit path > global config > defaults
func LoadFromPath(path string) (*Config, error) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		homeDir = ""
	}
	return LoadFromPathWithHome(path, homeDir)
}

// LoadFromPathWithHome loads configuration from an explicit file path with an explicit home directory.
// Used for testing to avoid depending on actual home directory.
func LoadFromPathWithHome(path, homeDir string) (*Config, error) {
	if path == "" {
		return nil, fmt.Errorf("config path cannot be empty")
	}

	cfg := DefaultConfig()

	// Load global config first
	if homeDir != "" {
		globalPath := filepath.Join(homeDir, ".open-guard", "config.yaml")
		if err := loadAndMerge(cfg, globalPath); err != nil {
			return nil, fmt.Errorf("loading global config: %w", err)
		}
	}

	// Load explicit config file (must exist)
	if err := loadAndMergeRequired(cfg, path); err != nil {
		return nil, err
	}

	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	return cfg, nil
}

// LoadWithHome loads configuration with an explicit home directory.
// Used for testing to avoid depending on actual home directory.
func LoadWithHome(projectRoot, homeDir string) (*Config, error) {
	cfg := DefaultConfig()

	// Load global config first
	if homeDir != "" {
		globalPath := filepath.Join(homeDir, ".open-guard", "config.yaml")
		if err := loadAndMerge(cfg, globalPath); err != nil {
			return nil, fmt.Errorf("loading global config: %w", err)
		}
	}

	// Load project config (takes priority)
	if projectRoot != "" {
		projectPath := filepath.Join(projectRoot, ".open-guard.yaml")
		if err := loadAndMerge(cfg, projectPath); err != nil {
			return nil, fmt.Errorf("loading project config: %w", err)
		}
	}

	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	return cfg, nil
}

// loadAndMerge loads a config file and merges it into the existing config.
// If the file doesn't exist, this is not an error - it simply returns without changes.
func loadAndMerge(cfg *Config, path string) error {
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil // File doesn't exist, nothing to merge
	}
	if err != nil {
		return err
	}

	return mergeConfigData(cfg, data, path)
}

// loadAndMergeRequired loads a config file and merges it into the existing config.
// Unlike loadAndMerge, this returns an error if the file doesn't exist.
func loadAndMergeRequired(cfg *Config, path string) error {
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return fmt.Errorf("config file not found: %s", path)
	}
	if err != nil {
		return fmt.Errorf("reading config file: %w", err)
	}

	return mergeConfigData(cfg, data, path)
}

// mergeConfigData parses config data and merges it into the existing config.
func mergeConfigData(cfg *Config, data []byte, path string) error {

	var fileCfg Config
	if err := yaml.Unmarshal(data, &fileCfg); err != nil {
		return fmt.Errorf("parsing %s: %w", path, err)
	}

	// Parse raw config to check which fields were explicitly set
	var rawCfg map[string]any
	if err := yaml.Unmarshal(data, &rawCfg); err != nil {
		rawCfg = make(map[string]any)
	}

	// Merge values (file values override defaults)
	if fileCfg.Mode != "" {
		cfg.Mode = fileCfg.Mode
	}
	if _, ok := rawCfg["max_input_size"]; ok {
		cfg.MaxInputSize = fileCfg.MaxInputSize
	}

	// Handle deprecated ml_enabled for backwards compatibility
	if _, ok := rawCfg["ml_enabled"]; ok {
		cfg.MLEnabled = fileCfg.MLEnabled
		// If ml_enabled is set but llm is not, sync the value
		if _, llmOk := rawCfg["llm"]; !llmOk {
			cfg.LLM.Enabled = fileCfg.MLEnabled
		}
	}

	// Merge LLM config
	if llmRaw, ok := rawCfg["llm"]; ok {
		if llmMap, ok := llmRaw.(map[string]any); ok {
			if _, ok := llmMap["enabled"]; ok {
				cfg.LLM.Enabled = fileCfg.LLM.Enabled
			}
			if fileCfg.LLM.Endpoint != "" {
				cfg.LLM.Endpoint = fileCfg.LLM.Endpoint
			}
			if fileCfg.LLM.ContentSafetyModel != "" {
				cfg.LLM.ContentSafetyModel = fileCfg.LLM.ContentSafetyModel
			}
			if _, ok := llmMap["timeout_seconds"]; ok {
				cfg.LLM.TimeoutSeconds = fileCfg.LLM.TimeoutSeconds
			}
		}
	}

	// Merge Agent config
	if agentRaw, ok := rawCfg["agent"]; ok {
		if agentMap, ok := agentRaw.(map[string]any); ok {
			if _, ok := agentMap["enabled"]; ok {
				cfg.Agent.Enabled = fileCfg.Agent.Enabled
			}
			if fileCfg.Agent.Provider != "" {
				cfg.Agent.Provider = fileCfg.Agent.Provider
			}
			if fileCfg.Agent.Model != "" {
				cfg.Agent.Model = fileCfg.Agent.Model
			}
			if fileCfg.Agent.Endpoint != "" {
				cfg.Agent.Endpoint = fileCfg.Agent.Endpoint
			}
			if _, ok := agentMap["timeout_seconds"]; ok {
				cfg.Agent.TimeoutSeconds = fileCfg.Agent.TimeoutSeconds
			}
		}
	}

	return nil
}
