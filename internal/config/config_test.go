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

func TestLoadFromPath_ValidFile(t *testing.T) {
	tmpDir := t.TempDir()
	configContent := `
mode: strict
llm:
  enabled: false
agent:
  enabled: true
  provider: claude
`
	configPath := filepath.Join(tmpDir, "custom-config.yaml")
	err := os.WriteFile(configPath, []byte(configContent), 0644)
	require.NoError(t, err)

	cfg, err := LoadFromPathWithHome(configPath, "")
	require.NoError(t, err)

	assert.Equal(t, ModeStrict, cfg.Mode)
	assert.False(t, cfg.LLM.Enabled)
	assert.True(t, cfg.Agent.Enabled)
	assert.Equal(t, "claude", cfg.Agent.Provider)
}

func TestLoadFromPath_NonExistent(t *testing.T) {
	_, err := LoadFromPathWithHome("/nonexistent/path/config.yaml", "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "config file not found")
}

func TestLoadFromPath_InvalidYAML(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "invalid.yaml")
	err := os.WriteFile(configPath, []byte("invalid: yaml: content:"), 0644)
	require.NoError(t, err)

	_, err = LoadFromPathWithHome(configPath, "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "parsing")
}

func TestLoadFromPath_MergesWithGlobal(t *testing.T) {
	// Create temp directories for global config and explicit config
	homeDir := t.TempDir()
	configDir := t.TempDir()

	// Set up global config path
	globalDir := filepath.Join(homeDir, ".open-guard")
	err := os.MkdirAll(globalDir, 0755)
	require.NoError(t, err)

	// Create global config (sets agent model)
	globalConfig := `
agent:
  model: global-model
  provider: claude
`
	err = os.WriteFile(filepath.Join(globalDir, "config.yaml"), []byte(globalConfig), 0644)
	require.NoError(t, err)

	// Create explicit config (sets mode but not agent model)
	explicitConfig := `
mode: strict
agent:
  enabled: true
`
	explicitPath := filepath.Join(configDir, "my-config.yaml")
	err = os.WriteFile(explicitPath, []byte(explicitConfig), 0644)
	require.NoError(t, err)

	// Load with explicit path
	cfg, err := LoadFromPathWithHome(explicitPath, homeDir)
	require.NoError(t, err)

	// Explicit config value should be applied
	assert.Equal(t, ModeStrict, cfg.Mode)
	assert.True(t, cfg.Agent.Enabled)
	// Global config values should be preserved for fields not set in explicit config
	assert.Equal(t, "global-model", cfg.Agent.Model)
	assert.Equal(t, "claude", cfg.Agent.Provider)
}

func TestLoadFromPath_EmptyPath(t *testing.T) {
	_, err := LoadFromPathWithHome("", "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "config path cannot be empty")
}

// --- Tests for #20: MaxInputSize config field ---

func TestDefaultConfig_MaxInputSize(t *testing.T) {
	cfg := DefaultConfig()
	assert.Equal(t, int64(10*1024*1024), cfg.MaxInputSize, "default max input size should be 10MB")
}

func TestConfig_MaxInputSize_FromYAML(t *testing.T) {
	tmpDir := t.TempDir()
	configContent := `
max_input_size: 5242880
`
	configPath := filepath.Join(tmpDir, ".open-guard.yaml")
	err := os.WriteFile(configPath, []byte(configContent), 0644)
	require.NoError(t, err)

	cfg, err := Load(tmpDir)
	require.NoError(t, err)
	assert.Equal(t, int64(5*1024*1024), cfg.MaxInputSize)
}

func TestConfig_MaxInputSize_MergePreservesExplicit(t *testing.T) {
	homeDir := t.TempDir()
	projectDir := t.TempDir()

	globalDir := filepath.Join(homeDir, ".open-guard")
	err := os.MkdirAll(globalDir, 0755)
	require.NoError(t, err)

	// Global config sets max_input_size
	globalConfig := `
max_input_size: 1048576
`
	err = os.WriteFile(filepath.Join(globalDir, "config.yaml"), []byte(globalConfig), 0644)
	require.NoError(t, err)

	// Project config does NOT set max_input_size - should preserve global value
	projectConfig := `
mode: strict
`
	err = os.WriteFile(filepath.Join(projectDir, ".open-guard.yaml"), []byte(projectConfig), 0644)
	require.NoError(t, err)

	cfg, err := LoadWithHome(projectDir, homeDir)
	require.NoError(t, err)
	assert.Equal(t, int64(1048576), cfg.MaxInputSize, "global max_input_size should be preserved")
	assert.Equal(t, ModeStrict, cfg.Mode, "project mode should override")
}

// --- Tests for #15: Config.Validate additional checks ---

func TestConfig_Validate_MaxInputSize(t *testing.T) {
	cfg := DefaultConfig()
	cfg.MaxInputSize = -1
	err := cfg.Validate()
	require.Error(t, err, "negative MaxInputSize should fail validation")
	assert.Contains(t, err.Error(), "max_input_size")
}

func TestConfig_Validate_TimeoutSeconds(t *testing.T) {
	t.Run("negative agent timeout", func(t *testing.T) {
		cfg := DefaultConfig()
		cfg.Agent.TimeoutSeconds = -1
		err := cfg.Validate()
		require.Error(t, err, "negative agent timeout should fail validation")
		assert.Contains(t, err.Error(), "timeout")
	})

	t.Run("negative LLM timeout", func(t *testing.T) {
		cfg := DefaultConfig()
		cfg.LLM.TimeoutSeconds = -1
		err := cfg.Validate()
		require.Error(t, err, "negative LLM timeout should fail validation")
		assert.Contains(t, err.Error(), "timeout")
	})
}

func TestConfig_Validate_InvalidProvider(t *testing.T) {
	tests := []struct {
		name     string
		provider string
		wantErr  bool
	}{
		{"valid claude", "claude", false},
		{"valid ollama", "ollama", false},
		{"empty default", "", false},
		{"invalid azure", "azure", true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := DefaultConfig()
			cfg.Agent.Provider = tc.provider
			err := cfg.Validate()
			if tc.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), "provider")
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// --- Tests for #21: TimeoutSeconds config fields ---

func TestDefaultConfig_TimeoutDefaults(t *testing.T) {
	cfg := DefaultConfig()
	assert.Equal(t, 60, cfg.Agent.TimeoutSeconds, "default agent timeout should be 60s")
	assert.Equal(t, 30, cfg.LLM.TimeoutSeconds, "default LLM timeout should be 30s")
}

func TestConfig_TimeoutSeconds_FromYAML(t *testing.T) {
	tmpDir := t.TempDir()
	configContent := `
agent:
  enabled: true
  timeout_seconds: 120
llm:
  enabled: true
  timeout_seconds: 45
`
	configPath := filepath.Join(tmpDir, ".open-guard.yaml")
	err := os.WriteFile(configPath, []byte(configContent), 0644)
	require.NoError(t, err)

	cfg, err := Load(tmpDir)
	require.NoError(t, err)
	assert.Equal(t, 120, cfg.Agent.TimeoutSeconds)
	assert.Equal(t, 45, cfg.LLM.TimeoutSeconds)
}

func TestConfig_TimeoutSeconds_MergePreservesExplicit(t *testing.T) {
	homeDir := t.TempDir()
	projectDir := t.TempDir()

	globalDir := filepath.Join(homeDir, ".open-guard")
	err := os.MkdirAll(globalDir, 0755)
	require.NoError(t, err)

	// Global config sets agent timeout
	globalConfig := `
agent:
  timeout_seconds: 90
`
	err = os.WriteFile(filepath.Join(globalDir, "config.yaml"), []byte(globalConfig), 0644)
	require.NoError(t, err)

	// Project config sets agent enabled but not timeout - should preserve global
	projectConfig := `
agent:
  enabled: true
`
	err = os.WriteFile(filepath.Join(projectDir, ".open-guard.yaml"), []byte(projectConfig), 0644)
	require.NoError(t, err)

	cfg, err := LoadWithHome(projectDir, homeDir)
	require.NoError(t, err)
	assert.Equal(t, 90, cfg.Agent.TimeoutSeconds, "global timeout should be preserved")
	assert.True(t, cfg.Agent.Enabled, "project enabled should override")
}

// --- Tests for #19: Endpoint URL validation ---

func TestConfig_Validate_Endpoints(t *testing.T) {
	tests := []struct {
		name        string
		llmEndpoint string
		agentEndpoint string
		wantErr     bool
	}{
		{
			name:        "invalid LLM endpoint - not a URL",
			llmEndpoint: "not-a-url",
			wantErr:     true,
		},
		{
			name:        "invalid LLM endpoint - wrong scheme",
			llmEndpoint: "ftp://wrong",
			wantErr:     true,
		},
		{
			name:        "valid LLM endpoint - empty uses default",
			llmEndpoint: "",
			wantErr:     false,
		},
		{
			name:        "valid LLM endpoint - http localhost",
			llmEndpoint: "http://localhost:11434",
			wantErr:     false,
		},
		{
			name:          "invalid Agent endpoint - not a URL",
			agentEndpoint: "not-a-url",
			wantErr:       true,
		},
		{
			name:          "invalid Agent endpoint - wrong scheme",
			agentEndpoint: "ftp://wrong",
			wantErr:       true,
		},
		{
			name:          "valid Agent endpoint - empty uses default",
			agentEndpoint: "",
			wantErr:       false,
		},
		{
			name:          "valid Agent endpoint - http localhost",
			agentEndpoint: "http://localhost:11434",
			wantErr:       false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := DefaultConfig()
			if tc.llmEndpoint != "" {
				cfg.LLM.Endpoint = tc.llmEndpoint
			}
			if tc.agentEndpoint != "" {
				cfg.Agent.Endpoint = tc.agentEndpoint
			}
			err := cfg.Validate()
			if tc.wantErr {
				require.Error(t, err, "expected validation error for endpoint")
				assert.Contains(t, err.Error(), "endpoint")
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
