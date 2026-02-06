package agent

import (
	"context"
	"errors"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseClaudeResponse(t *testing.T) {
	tests := []struct {
		name     string
		response string
		wantSafe bool
		wantErr  bool
	}{
		{"safe response", "SAFE", true, false},
		{"safe with explanation", "SAFE - This is a normal coding request", true, false},
		{"injection detected", "INJECTION: Attempts to override system instructions", false, false},
		{"injection simple", "INJECTION", false, false},
		{"lowercase safe", "safe", true, false},
		{"lowercase injection", "injection: bypass", false, false},
		{"safe with whitespace", "  SAFE  ", true, false},
		{"empty response", "", false, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := parseClaudeResponse(tt.response)
			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.wantSafe, result.Safe)
		})
	}
}

func TestInjectionAnalysisPrompt(t *testing.T) {
	// Test that various raw content types are included in the prompt
	tests := []struct {
		name    string
		content string
	}{
		{"simple prompt", "Help me write a function"},
		{"multiline", "First line\nSecond line\nThird line"},
		{"bash command", "rm -rf /tmp/cache"},
		{"unicode", "Bonjour, aidez-moi"},
		{"special chars", "echo $HOME && ls -la"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			prompt := injectionAnalysisPrompt(tt.content)
			assert.Contains(t, prompt, tt.content)
			assert.Contains(t, prompt, "INJECTION DETECTOR")
			assert.Contains(t, prompt, "SAFE")
			assert.Contains(t, prompt, "INJECTION")
		})
	}
}

func TestClaudeAnalyzer_IsAvailable(t *testing.T) {
	// IsAvailable checks if the SDK can connect to Claude Code
	// This will fail in test environments without Claude Code installed
	analyzer := &ClaudeAnalyzer{
		model:    "claude-sonnet-4-20250514",
		provider: "claude",
	}

	// Just verify it doesn't panic - actual availability depends on environment
	_ = analyzer.IsAvailable()
}

func TestClaudeAnalyzer_Interface(t *testing.T) {
	// Verify ClaudeAnalyzer implements the expected interface
	type Analyzer interface {
		Analyze(ctx context.Context, content string) (*Result, error)
		IsAvailable() bool
	}

	var _ Analyzer = (*ClaudeAnalyzer)(nil)
}

func TestNewClaudeAnalyzer(t *testing.T) {
	tests := []struct {
		name         string
		model        string
		projectRoot  string
		provider     string
		endpoint     string
		wantModel    string
		wantProvider string
		wantEndpoint string
	}{
		{
			name:         "default claude provider",
			model:        "",
			projectRoot:  ".",
			provider:     "",
			endpoint:     "",
			wantModel:    "claude-sonnet-4-20250514",
			wantProvider: "claude",
			wantEndpoint: "",
		},
		{
			name:         "explicit claude provider",
			model:        "claude-sonnet-4-20250514",
			projectRoot:  ".",
			provider:     "claude",
			endpoint:     "",
			wantModel:    "claude-sonnet-4-20250514",
			wantProvider: "claude",
			wantEndpoint: "",
		},
		{
			name:         "ollama provider",
			model:        "llama3:latest",
			projectRoot:  "/tmp",
			provider:     "ollama",
			endpoint:     "http://localhost:11434",
			wantModel:    "llama3:latest",
			wantProvider: "ollama",
			wantEndpoint: "http://localhost:11434",
		},
		{
			name:         "ollama provider default endpoint",
			model:        "llama3:70b",
			projectRoot:  ".",
			provider:     "ollama",
			endpoint:     "",
			wantModel:    "llama3:70b",
			wantProvider: "ollama",
			wantEndpoint: "http://localhost:11434",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			analyzer := NewClaudeAnalyzer(tt.model, tt.projectRoot, tt.provider, tt.endpoint)
			assert.NotNil(t, analyzer)
			assert.Equal(t, tt.wantModel, analyzer.model)
			assert.Equal(t, tt.wantProvider, analyzer.provider)
			assert.Equal(t, tt.wantEndpoint, analyzer.endpoint)
		})
	}
}

func TestResult_Fields(t *testing.T) {
	result := &Result{
		Safe:       false,
		Categories: []string{"T5"},
		Reason:     "Attempts to override system instructions",
	}

	assert.False(t, result.Safe)
	assert.Contains(t, result.Categories, "T5")
	assert.NotEmpty(t, result.Reason)
}

func TestClaudeAnalyzer_SetupOllamaEnv(t *testing.T) {
	t.Run("ollama provider sets env vars", func(t *testing.T) {
		analyzer := NewClaudeAnalyzer("llama3:latest", ".", "ollama", "http://localhost:11434")

		// Call setupOllamaEnv and get cleanup function
		cleanup := analyzer.setupOllamaEnv()
		defer cleanup()

		// Verify env vars are set for Ollama
		assert.Equal(t, "ollama", os.Getenv("ANTHROPIC_AUTH_TOKEN"))
		assert.Equal(t, "", os.Getenv("ANTHROPIC_API_KEY"))
		assert.Equal(t, "http://localhost:11434", os.Getenv("ANTHROPIC_BASE_URL"))
	})

	t.Run("claude provider does not change env vars", func(t *testing.T) {
		analyzer := NewClaudeAnalyzer("claude-sonnet-4-20250514", ".", "claude", "")

		cleanup := analyzer.setupOllamaEnv()
		defer cleanup()

		// For claude provider, no env vars should be changed
		// (just verify cleanup function is returned and callable)
	})
}

func TestParseClaudeResponse_Comprehensive(t *testing.T) {
	tests := []struct {
		name       string
		response   string
		wantSafe   bool
		wantReason string
		wantErr    bool
	}{
		// Safe responses
		{"SAFE uppercase", "SAFE", true, "", false},
		{"safe lowercase", "safe", true, "", false},
		{"Safe mixed case", "Safe", true, "", false},
		{"SAFE with explanation", "SAFE - This is a normal request", true, "", false},
		{"SAFE with whitespace", "  SAFE  \n", true, "", false},
		{"SAFE with trailing text", "SAFE: benign coding request", true, "", false},

		// Injection responses
		{"INJECTION uppercase", "INJECTION", false, "", false},
		{"injection lowercase", "injection", false, "", false},
		{"INJECTION with colon reason", "INJECTION: Attempts to override instructions", false, "ATTEMPTS TO OVERRIDE INSTRUCTIONS", false},
		{"INJECTION with whitespace", "  INJECTION  ", false, "", false},
		{"injection with reason", "injection: bypass security", false, "BYPASS SECURITY", false},
		{"INJECTION multiline", "INJECTION\nWith extra details", false, "", false},
		{"INJECTION double colon", "INJECTION::reason", false, "REASON", false},

		// Error cases
		{"empty response", "", false, "", true},
		{"unexpected format", "UNKNOWN", false, "", true},
		{"random text", "Hello world", false, "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := parseClaudeResponse(tt.response)

			if tt.wantErr {
				assert.Error(t, err)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.wantSafe, result.Safe)

			if !tt.wantSafe {
				assert.Contains(t, result.Categories, "T5", "Should have T5 category for injections")
				if tt.wantReason != "" {
					assert.Equal(t, tt.wantReason, result.Reason)
				}
			}
		})
	}
}

func TestClaudeAnalyzer_SetupOllamaEnv_RestoresOriginal(t *testing.T) {
	// Set original values
	originalToken := "original-token"
	originalKey := "original-key"
	originalURL := "http://original.com"

	os.Setenv("ANTHROPIC_AUTH_TOKEN", originalToken)
	os.Setenv("ANTHROPIC_API_KEY", originalKey)
	os.Setenv("ANTHROPIC_BASE_URL", originalURL)
	defer func() {
		os.Unsetenv("ANTHROPIC_AUTH_TOKEN")
		os.Unsetenv("ANTHROPIC_API_KEY")
		os.Unsetenv("ANTHROPIC_BASE_URL")
	}()

	analyzer := NewClaudeAnalyzer("llama3:latest", ".", "ollama", "http://localhost:11434")

	// Setup and verify changes
	cleanup := analyzer.setupOllamaEnv()
	assert.Equal(t, "ollama", os.Getenv("ANTHROPIC_AUTH_TOKEN"))
	assert.Equal(t, "", os.Getenv("ANTHROPIC_API_KEY"))
	assert.Equal(t, "http://localhost:11434", os.Getenv("ANTHROPIC_BASE_URL"))

	// Cleanup and verify restoration
	cleanup()
	assert.Equal(t, originalToken, os.Getenv("ANTHROPIC_AUTH_TOKEN"))
	assert.Equal(t, originalKey, os.Getenv("ANTHROPIC_API_KEY"))
	assert.Equal(t, originalURL, os.Getenv("ANTHROPIC_BASE_URL"))
}

func TestClaudeAnalyzer_SetupOllamaEnv_RestoresEmptyOriginal(t *testing.T) {
	// Clear env vars first
	os.Unsetenv("ANTHROPIC_AUTH_TOKEN")
	os.Unsetenv("ANTHROPIC_API_KEY")
	os.Unsetenv("ANTHROPIC_BASE_URL")

	analyzer := NewClaudeAnalyzer("llama3:latest", ".", "ollama", "http://localhost:11434")

	// Setup and verify changes
	cleanup := analyzer.setupOllamaEnv()
	assert.Equal(t, "ollama", os.Getenv("ANTHROPIC_AUTH_TOKEN"))

	// Cleanup should restore to empty
	cleanup()
	assert.Equal(t, "", os.Getenv("ANTHROPIC_AUTH_TOKEN"))
	assert.Equal(t, "", os.Getenv("ANTHROPIC_API_KEY"))
	assert.Equal(t, "", os.Getenv("ANTHROPIC_BASE_URL"))
}

func TestNewClaudeAnalyzer_AllDefaults(t *testing.T) {
	// Test with all empty strings - should use all defaults
	analyzer := NewClaudeAnalyzer("", "", "", "")

	assert.Equal(t, "claude-sonnet-4-20250514", analyzer.model)
	assert.Equal(t, ".", analyzer.projectRoot)
	assert.Equal(t, "claude", analyzer.provider)
	assert.Equal(t, "", analyzer.endpoint) // endpoint only defaults for ollama
}

func TestNewClaudeAnalyzer_OllamaDefaultEndpoint(t *testing.T) {
	// Ollama provider with empty endpoint should use default
	analyzer := NewClaudeAnalyzer("llama3:latest", "/tmp", "ollama", "")

	assert.Equal(t, "llama3:latest", analyzer.model)
	assert.Equal(t, "/tmp", analyzer.projectRoot)
	assert.Equal(t, "ollama", analyzer.provider)
	assert.Equal(t, "http://localhost:11434", analyzer.endpoint)
}

func TestNewClaudeAnalyzer_CustomEndpoint(t *testing.T) {
	// Custom endpoint should be preserved
	analyzer := NewClaudeAnalyzer("llama3:latest", "/project", "ollama", "http://custom:8080")

	assert.Equal(t, "http://custom:8080", analyzer.endpoint)
}

func TestClaudeAnalyzer_Close(t *testing.T) {
	analyzer := NewClaudeAnalyzer("claude-sonnet-4-20250514", ".", "claude", "")

	// Close should return nil (no resources to clean up)
	err := analyzer.Close()
	assert.NoError(t, err)

	// Should be safe to call multiple times
	err = analyzer.Close()
	assert.NoError(t, err)
}

func TestInjectionAnalysisPrompt_Structure(t *testing.T) {
	content := "Test input"
	prompt := injectionAnalysisPrompt(content)

	// Verify prompt structure
	assert.Contains(t, prompt, "INJECTION DETECTOR")
	assert.Contains(t, prompt, "SAFE")
	assert.Contains(t, prompt, "INJECTION")
	assert.Contains(t, prompt, content)
	assert.Contains(t, prompt, "DIRECT:")
	assert.Contains(t, prompt, "JAILBREAK:")
	assert.Contains(t, prompt, "SOCIAL:")
	assert.Contains(t, prompt, "ENCODING:")
	assert.Contains(t, prompt, "BEGIN_UNTRUSTED")
	assert.Contains(t, prompt, "END_UNTRUSTED")
}

// --- Tests for #14: Context cancellation in iterator loop ---

func TestAnalyze_AlreadyCancelledContext(t *testing.T) {
	analyzer := NewClaudeAnalyzer("claude-sonnet-4-20250514", ".", "claude", "")

	// Create an already-cancelled context
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	result, err := analyzer.Analyze(ctx, "test content")

	// Should return context.Canceled error, not hang or succeed
	require.Error(t, err)
	assert.Nil(t, result)
	assert.True(t, errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded),
		"error should be a context error, got: %v", err)
}

func TestAnalyze_DeadlineExceeded(t *testing.T) {
	analyzer := NewClaudeAnalyzer("claude-sonnet-4-20250514", ".", "claude", "")

	// Create a context that's already past its deadline
	ctx, cancel := context.WithTimeout(context.Background(), 0)
	defer cancel()

	result, err := analyzer.Analyze(ctx, "test content")

	// Should return deadline exceeded error
	require.Error(t, err)
	assert.Nil(t, result)
	assert.True(t, errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded),
		"error should be a context error, got: %v", err)
}
