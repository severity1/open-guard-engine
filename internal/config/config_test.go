package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()

	assert.Equal(t, ModeConfirm, cfg.Mode)
	assert.True(t, cfg.MLEnabled)
}

func TestMode_Validation(t *testing.T) {
	tests := []struct {
		mode    Mode
		isValid bool
	}{
		{ModeStrict, true},
		{ModeConfirm, true},
		{ModePermissive, true},
		{Mode("invalid"), false},
		{Mode(""), false},
	}

	for _, tc := range tests {
		t.Run(string(tc.mode), func(t *testing.T) {
			cfg := DefaultConfig()
			cfg.Mode = tc.mode
			err := cfg.Validate()
			if tc.isValid {
				assert.NoError(t, err)
			} else {
				assert.Error(t, err)
			}
		})
	}
}

func TestConfig_LoadFromYAML(t *testing.T) {
	// Create temp directory
	tmpDir := t.TempDir()

	// Create config file
	configContent := `
mode: strict
ml_enabled: false
`
	configPath := filepath.Join(tmpDir, ".open-guard.yaml")
	err := os.WriteFile(configPath, []byte(configContent), 0644)
	require.NoError(t, err)

	cfg, err := Load(tmpDir)
	require.NoError(t, err)

	assert.Equal(t, ModeStrict, cfg.Mode)
	assert.False(t, cfg.MLEnabled)
}

func TestConfig_LoadPriority(t *testing.T) {
	// Create temp directories for global and project configs
	homeDir := t.TempDir()
	projectDir := t.TempDir()

	// Set up global config path
	globalDir := filepath.Join(homeDir, ".open-guard")
	err := os.MkdirAll(globalDir, 0755)
	require.NoError(t, err)

	// Create global config (permissive mode)
	globalConfig := `
mode: permissive
ml_enabled: true
`
	err = os.WriteFile(filepath.Join(globalDir, "config.yaml"), []byte(globalConfig), 0644)
	require.NoError(t, err)

	// Create project config (strict mode - should override)
	projectConfig := `
mode: strict
`
	err = os.WriteFile(filepath.Join(projectDir, ".open-guard.yaml"), []byte(projectConfig), 0644)
	require.NoError(t, err)

	// Load with project root, using custom home
	cfg, err := LoadWithHome(projectDir, homeDir)
	require.NoError(t, err)

	// Project config should take priority
	assert.Equal(t, ModeStrict, cfg.Mode)
	// Global config value should be preserved for unspecified fields
	assert.True(t, cfg.MLEnabled)
}

func TestConfig_NoConfigFile(t *testing.T) {
	// Empty directory - should use defaults
	tmpDir := t.TempDir()

	cfg, err := Load(tmpDir)
	require.NoError(t, err)

	// Should have default values
	assert.Equal(t, ModeConfirm, cfg.Mode)
	assert.True(t, cfg.MLEnabled)
}

func TestConfig_InvalidYAML(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, ".open-guard.yaml")
	err := os.WriteFile(configPath, []byte("invalid: yaml: content:"), 0644)
	require.NoError(t, err)

	_, err = Load(tmpDir)
	assert.Error(t, err)
}

func TestConfig_LLMConfig(t *testing.T) {
	tmpDir := t.TempDir()
	configContent := `
llm:
  enabled: true
  endpoint: http://localhost:11434
  content_safety_model: llama-guard3:latest
agent:
  enabled: false
`
	configPath := filepath.Join(tmpDir, ".open-guard.yaml")
	err := os.WriteFile(configPath, []byte(configContent), 0644)
	require.NoError(t, err)

	cfg, err := Load(tmpDir)
	require.NoError(t, err)

	assert.True(t, cfg.LLM.Enabled)
	assert.Equal(t, "http://localhost:11434", cfg.LLM.Endpoint)
	assert.Equal(t, "llama-guard3:latest", cfg.LLM.ContentSafetyModel)
	assert.False(t, cfg.Agent.Enabled)
}

func TestConfig_AgentConfig(t *testing.T) {
	tmpDir := t.TempDir()
	configContent := `
llm:
  enabled: false
agent:
  enabled: true
  provider: claude
  model: claude-sonnet-4-20250514
`
	configPath := filepath.Join(tmpDir, ".open-guard.yaml")
	err := os.WriteFile(configPath, []byte(configContent), 0644)
	require.NoError(t, err)

	cfg, err := Load(tmpDir)
	require.NoError(t, err)

	assert.False(t, cfg.LLM.Enabled)
	assert.True(t, cfg.Agent.Enabled)
	assert.Equal(t, "claude", cfg.Agent.Provider)
	assert.Equal(t, "claude-sonnet-4-20250514", cfg.Agent.Model)
}

func TestConfig_AgentOllamaConfig(t *testing.T) {
	tmpDir := t.TempDir()
	configContent := `
llm:
  enabled: false
agent:
  enabled: true
  provider: ollama
  model: llama3:latest
  endpoint: http://localhost:11434
`
	configPath := filepath.Join(tmpDir, ".open-guard.yaml")
	err := os.WriteFile(configPath, []byte(configContent), 0644)
	require.NoError(t, err)

	cfg, err := Load(tmpDir)
	require.NoError(t, err)

	assert.False(t, cfg.LLM.Enabled)
	assert.True(t, cfg.Agent.Enabled)
	assert.Equal(t, "ollama", cfg.Agent.Provider)
	assert.Equal(t, "llama3:latest", cfg.Agent.Model)
	assert.Equal(t, "http://localhost:11434", cfg.Agent.Endpoint)
}

func TestConfig_HybridMode(t *testing.T) {
	tmpDir := t.TempDir()
	configContent := `
llm:
  enabled: true
  endpoint: http://localhost:11434
  content_safety_model: llama-guard3:latest
agent:
  enabled: true
  provider: claude
  model: claude-sonnet-4-20250514
`
	configPath := filepath.Join(tmpDir, ".open-guard.yaml")
	err := os.WriteFile(configPath, []byte(configContent), 0644)
	require.NoError(t, err)

	cfg, err := Load(tmpDir)
	require.NoError(t, err)

	assert.True(t, cfg.LLM.Enabled)
	assert.True(t, cfg.Agent.Enabled)
	assert.Equal(t, "llama-guard3:latest", cfg.LLM.ContentSafetyModel)
	assert.Equal(t, "claude", cfg.Agent.Provider)
	assert.Equal(t, "claude-sonnet-4-20250514", cfg.Agent.Model)
}

func TestConfig_LLMDefaults(t *testing.T) {
	// When LLM is enabled but no endpoint specified, use default
	tmpDir := t.TempDir()
	configContent := `
llm:
  enabled: true
`
	configPath := filepath.Join(tmpDir, ".open-guard.yaml")
	err := os.WriteFile(configPath, []byte(configContent), 0644)
	require.NoError(t, err)

	cfg, err := Load(tmpDir)
	require.NoError(t, err)

	assert.True(t, cfg.LLM.Enabled)
	assert.Equal(t, "http://localhost:11434", cfg.LLM.Endpoint)
}

func TestConfig_BackwardsCompatibility_MLEnabled(t *testing.T) {
	// Old ml_enabled: true should still work for backwards compatibility
	tmpDir := t.TempDir()
	configContent := `
ml_enabled: true
`
	configPath := filepath.Join(tmpDir, ".open-guard.yaml")
	err := os.WriteFile(configPath, []byte(configContent), 0644)
	require.NoError(t, err)

	cfg, err := Load(tmpDir)
	require.NoError(t, err)

	// ml_enabled: true should enable LLM with defaults
	assert.True(t, cfg.LLM.Enabled)
}
