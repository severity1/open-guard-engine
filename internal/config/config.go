// Package config handles loading and validating configuration for open-guard.
package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// Mode determines how threats are handled.
type Mode string

const (
	ModeStrict     Mode = "strict"     // Block all detected threats
	ModeConfirm    Mode = "confirm"    // Prompt user for confirmation
	ModePermissive Mode = "permissive" // Log only, allow all
)

// Allowlist defines domains and paths that are considered safe.
type Allowlist struct {
	Domains []string `yaml:"domains,omitempty"`
	Paths   []string `yaml:"paths,omitempty"`
}

// LLMConfig configures raw LLM calls via Ollama for content safety (internal/llm/).
// Content safety only (S1-S13) - prompt injection is handled by Agent.
type LLMConfig struct {
	Enabled            bool   `yaml:"enabled"`
	Endpoint           string `yaml:"endpoint"`             // http://localhost:11434
	ContentSafetyModel string `yaml:"content_safety_model"` // llama-guard3:latest
}

// AgentConfig configures prompt injection detection (T5) using Claude Code as the agent harness.
// Supports two providers: "claude" (Anthropic API) or "ollama" (local models).
// Session is READ-ONLY - can read project files for context but cannot modify.
type AgentConfig struct {
	Enabled  bool   `yaml:"enabled"`
	Provider string `yaml:"provider"` // "claude" (default) or "ollama"
	Model    string `yaml:"model"`    // Model name (e.g., claude-sonnet-4-20250514 or llama3:latest)
	Endpoint string `yaml:"endpoint"` // Ollama endpoint (only for ollama provider)
}

// Config holds the open-guard configuration.
type Config struct {
	Mode      Mode        `yaml:"mode"`
	MLEnabled bool        `yaml:"ml_enabled"` // Deprecated: use LLM.Enabled instead
	LLM       LLMConfig   `yaml:"llm"`
	Agent     AgentConfig `yaml:"agent"`
	Allowlist Allowlist   `yaml:"allowlist,omitempty"`
}

// DefaultConfig returns a Config with sensible defaults.
func DefaultConfig() *Config {
	return &Config{
		Mode:      ModeConfirm,
		MLEnabled: true, // Deprecated but kept for backwards compatibility
		LLM: LLMConfig{
			Enabled:  true,
			Endpoint: "http://localhost:11434",
		},
		Agent: AgentConfig{
			Enabled: false,
		},
		Allowlist: Allowlist{
			Domains: []string{
				"github.com",
				"api.github.com",
				"githubusercontent.com",
				"api.anthropic.com",
				"registry.npmjs.org",
				"pypi.org",
				"pkg.go.dev",
				"crates.io",
			},
			Paths: []string{},
		},
	}
}

// Validate checks if the configuration is valid.
func (c *Config) Validate() error {
	switch c.Mode {
	case ModeStrict, ModeConfirm, ModePermissive:
		return nil
	default:
		return fmt.Errorf("invalid mode: %q (must be strict, confirm, or permissive)", c.Mode)
	}
}

// IsAllowedDomain checks if a domain is in the allowlist.
// Subdomains of allowed domains are also considered allowed.
func (c *Config) IsAllowedDomain(domain string) bool {
	domain = strings.ToLower(domain)
	for _, allowed := range c.Allowlist.Domains {
		allowed = strings.ToLower(allowed)
		if domain == allowed {
			return true
		}
		// Check if it's a subdomain
		if strings.HasSuffix(domain, "."+allowed) {
			return true
		}
	}
	return false
}

// IsAllowedPath checks if a path is in the allowlist.
// Paths under allowed directories are also considered allowed.
func (c *Config) IsAllowedPath(path string) bool {
	for _, allowed := range c.Allowlist.Paths {
		if path == allowed {
			return true
		}
		// Check if path is under allowed directory
		if strings.HasPrefix(path, allowed+"/") {
			return true
		}
	}
	return false
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
func loadAndMerge(cfg *Config, path string) error {
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil // File doesn't exist, nothing to merge
	}
	if err != nil {
		return err
	}

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
		}
	}

	// Merge allowlists (append, don't replace)
	cfg.Allowlist.Domains = appendUnique(cfg.Allowlist.Domains, fileCfg.Allowlist.Domains)
	cfg.Allowlist.Paths = appendUnique(cfg.Allowlist.Paths, fileCfg.Allowlist.Paths)

	return nil
}

// appendUnique appends items to a slice, avoiding duplicates.
func appendUnique(slice, items []string) []string {
	seen := make(map[string]bool)
	for _, s := range slice {
		seen[s] = true
	}
	for _, item := range items {
		if !seen[item] {
			slice = append(slice, item)
			seen[item] = true
		}
	}
	return slice
}
