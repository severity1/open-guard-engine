package agent

import (
	"context"
	"errors"
	"sync"
	"testing"

	claudecode "github.com/severity1/claude-agent-sdk-go"
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
		{"injection simple", "INJECTION", false, false}, // now returns default reason
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
	// Verify ClaudeAnalyzer implements the exported Analyzer interface
	var _ Analyzer = (*ClaudeAnalyzer)(nil)
}

func TestMockAnalyzer_Analyze(t *testing.T) {
	tests := []struct {
		name           string
		mock           MockAnalyzer
		wantSafe       bool
		wantCategories []string
		wantReason     string
		wantErr        bool
	}{
		{
			name:     "safe response",
			mock:     MockAnalyzer{SafeResponse: true},
			wantSafe: true,
		},
		{
			name:           "unsafe response with categories and reason",
			mock:           MockAnalyzer{SafeResponse: false, Categories: []string{"T5"}, Reason: "injection detected"},
			wantSafe:       false,
			wantCategories: []string{"T5"},
			wantReason:     "injection detected",
		},
		{
			name:    "error case",
			mock:    MockAnalyzer{ShouldError: true},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := tt.mock.Analyze(context.Background(), "test content")
			if tt.wantErr {
				assert.Error(t, err)
				assert.Nil(t, result)
				return
			}
			require.NoError(t, err)
			require.NotNil(t, result)
			assert.Equal(t, tt.wantSafe, result.Safe)
			assert.Equal(t, tt.wantCategories, result.Categories)
			assert.Equal(t, tt.wantReason, result.Reason)
		})
	}
}

func TestMockAnalyzer_IsAvailable(t *testing.T) {
	t.Run("available true", func(t *testing.T) {
		mock := MockAnalyzer{Available: true}
		assert.True(t, mock.IsAvailable())
	})

	t.Run("available false", func(t *testing.T) {
		mock := MockAnalyzer{Available: false}
		assert.False(t, mock.IsAvailable())
	})
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
		{"INJECTION uppercase", "INJECTION", false, "detected by semantic analysis", false},
		{"injection lowercase", "injection", false, "detected by semantic analysis", false},
		{"INJECTION with colon reason", "INJECTION: Attempts to override instructions", false, "Attempts to override instructions", false},
		{"INJECTION with whitespace", "  INJECTION  ", false, "detected by semantic analysis", false},
		{"injection with reason", "injection: bypass security", false, "bypass security", false},
		{"INJECTION multiline", "INJECTION\nWith extra details", false, "With extra details", false},
		{"INJECTION double colon", "INJECTION::reason", false, "reason", false},

		// Error cases
		{"empty response", "", false, "", true},
		{"unexpected format", "UNKNOWN", false, "", true},
		{"random text", "Hello world", false, "", true},

		// Lenient parsing - keyword in body (Ollama models add preamble)
		{"SAFE keyword in body", "Based on my analysis, this is SAFE", true, "", false},
		{"SAFE on later line", "The input appears benign.\n\nSAFE", true, "", false},
		{"SAFE with verbose preamble", "Let me analyze this carefully.\n\nSAFE", true, "", false},
		{"INJECTION keyword in body", "I believe this is an INJECTION: bypass attempt", false, "bypass attempt", false},
		{"INJECTION on later line", "After review:\nINJECTION: attempts to override", false, "attempts to override", false},
		{"INJECTION takes priority over SAFE", "This mentions SAFE but is really INJECTION: sneaky", false, "sneaky", false},
		// Error cases - no keywords
		{"no keywords verbose", "I don't know what to say about this input", false, "", true},
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
				assert.Equal(t, tt.wantReason, result.Reason)
			}
		})
	}
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
	assert.Contains(t, prompt, "CLASSIFY AS INJECTION")
	assert.Contains(t, prompt, "CLASSIFY AS SAFE")
	assert.Contains(t, prompt, "DECISION THRESHOLD")
	assert.Contains(t, prompt, "BEGIN_UNTRUSTED")
	assert.Contains(t, prompt, "END_UNTRUSTED")
	assert.Contains(t, prompt, "brief reason")
	assert.Contains(t, prompt, "CRITICAL RESPONSE FORMAT")
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

// --- mockIterator for testing collectResponse ---

type mockIterator struct {
	messages []claudecode.Message
	errors   []error // parallel to messages; nil means no error for that call
	index    int
	closed   bool
}

func (m *mockIterator) Next(_ context.Context) (claudecode.Message, error) {
	if m.index >= len(m.messages) {
		return nil, claudecode.ErrNoMoreMessages
	}
	i := m.index
	m.index++
	if m.errors != nil && m.errors[i] != nil {
		return nil, m.errors[i]
	}
	return m.messages[i], nil
}

func (m *mockIterator) Close() error {
	m.closed = true
	return nil
}

// --- Tests for collectResponse ---

func TestCollectResponse_SafeText(t *testing.T) {
	iter := &mockIterator{
		messages: []claudecode.Message{
			&claudecode.AssistantMessage{
				Content: []claudecode.ContentBlock{
					&claudecode.TextBlock{Text: "SAFE"},
				},
			},
		},
	}

	result, err := collectResponse(context.Background(), iter)
	require.NoError(t, err)
	assert.True(t, result.Safe)
}

func TestCollectResponse_InjectionText(t *testing.T) {
	iter := &mockIterator{
		messages: []claudecode.Message{
			&claudecode.AssistantMessage{
				Content: []claudecode.ContentBlock{
					&claudecode.TextBlock{Text: "INJECTION: override system prompt"},
				},
			},
		},
	}

	result, err := collectResponse(context.Background(), iter)
	require.NoError(t, err)
	assert.False(t, result.Safe)
	assert.Contains(t, result.Categories, "T5")
}

func TestCollectResponse_MultipleMessages(t *testing.T) {
	iter := &mockIterator{
		messages: []claudecode.Message{
			&claudecode.AssistantMessage{
				Content: []claudecode.ContentBlock{
					&claudecode.TextBlock{Text: "SA"},
				},
			},
			&claudecode.AssistantMessage{
				Content: []claudecode.ContentBlock{
					&claudecode.TextBlock{Text: "FE"},
				},
			},
		},
	}

	result, err := collectResponse(context.Background(), iter)
	require.NoError(t, err)
	assert.True(t, result.Safe)
}

func TestCollectResponse_IteratorError(t *testing.T) {
	iter := &mockIterator{
		messages: []claudecode.Message{nil},
		errors:   []error{errors.New("connection lost")},
	}

	result, err := collectResponse(context.Background(), iter)
	require.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "reading response")
}

func TestCollectResponse_ContextCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	iter := &mockIterator{
		messages: []claudecode.Message{
			&claudecode.AssistantMessage{
				Content: []claudecode.ContentBlock{
					&claudecode.TextBlock{Text: "SAFE"},
				},
			},
		},
	}

	result, err := collectResponse(ctx, iter)
	require.Error(t, err)
	assert.Nil(t, result)
	assert.True(t, errors.Is(err, context.Canceled))
}

func TestCollectResponse_IteratorErrorWithCancelledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())

	// Iterator returns one message, then an error after context is cancelled
	iter := &mockIterator{
		messages: []claudecode.Message{
			&claudecode.AssistantMessage{
				Content: []claudecode.ContentBlock{
					&claudecode.TextBlock{Text: "partial"},
				},
			},
			nil, // second call will error
		},
		errors: []error{nil, errors.New("stream error")},
	}

	// Cancel context after first successful message
	// collectResponse should check ctx after first iteration
	cancel()

	result, err := collectResponse(ctx, iter)
	require.Error(t, err)
	assert.Nil(t, result)
	// Should return context error since ctx was cancelled
	assert.True(t, errors.Is(err, context.Canceled))
}

func TestCollectResponse_EmptyResponse(t *testing.T) {
	// Iterator has no messages - produces empty string which parseClaudeResponse rejects
	iter := &mockIterator{}

	result, err := collectResponse(context.Background(), iter)
	require.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "empty response")
}

func TestClaudeAnalyzer_BuildEnv(t *testing.T) {
	tests := []struct {
		name     string
		provider string
		endpoint string
		wantEnv  map[string]string
	}{
		{
			name:     "claude provider returns CLAUDECODE unset only",
			provider: "claude",
			endpoint: "",
			wantEnv: map[string]string{
				"CLAUDECODE": "",
			},
		},
		{
			name:     "ollama provider returns env map with CLAUDECODE",
			provider: "ollama",
			endpoint: "http://localhost:11434",
			wantEnv: map[string]string{
				"CLAUDECODE":           "",
				"ANTHROPIC_BASE_URL":   "http://localhost:11434",
				"ANTHROPIC_AUTH_TOKEN": "ollama",
				"ANTHROPIC_API_KEY":    "",
			},
		},
		{
			name:     "ollama custom endpoint",
			provider: "ollama",
			endpoint: "http://custom:8080",
			wantEnv: map[string]string{
				"CLAUDECODE":           "",
				"ANTHROPIC_BASE_URL":   "http://custom:8080",
				"ANTHROPIC_AUTH_TOKEN": "ollama",
				"ANTHROPIC_API_KEY":    "",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			analyzer := NewClaudeAnalyzer("test-model", ".", tt.provider, tt.endpoint)
			env := analyzer.buildEnv()

			require.NotNil(t, env)
			for key, want := range tt.wantEnv {
				assert.Equal(t, want, env[key], "env key %s", key)
			}
		})
	}
}

func TestClaudeAnalyzer_BuildEnv_MapIsolation(t *testing.T) {
	analyzer := NewClaudeAnalyzer("llama3:latest", ".", "ollama", "http://localhost:11434")
	env1 := analyzer.buildEnv()
	env2 := analyzer.buildEnv()

	// Mutating one map must not affect the other
	env1["ANTHROPIC_AUTH_TOKEN"] = "modified"
	assert.Equal(t, "ollama", env2["ANTHROPIC_AUTH_TOKEN"])
}

func TestAnalyze_CancelledContext_BothProviders(t *testing.T) {
	tests := []struct {
		name     string
		provider string
		endpoint string
	}{
		{"claude provider", "claude", ""},
		{"ollama provider", "ollama", "http://localhost:11434"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			analyzer := NewClaudeAnalyzer("test-model", ".", tt.provider, tt.endpoint)

			ctx, cancel := context.WithCancel(context.Background())
			cancel()

			result, err := analyzer.Analyze(ctx, "test content")
			require.Error(t, err)
			assert.Nil(t, result)
			assert.True(t, errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded),
				"error should be a context error, got: %v", err)
		})
	}
}

func TestClaudeAnalyzer_BuildEnv_Concurrent(t *testing.T) {
	analyzer := NewClaudeAnalyzer("test-model", ".", "ollama", "http://localhost:11434")

	const goroutines = 10
	var wg sync.WaitGroup
	wg.Add(goroutines)

	results := make([]map[string]string, goroutines)
	for i := range goroutines {
		go func(idx int) {
			defer wg.Done()
			results[idx] = analyzer.buildEnv()
		}(i)
	}

	wg.Wait()

	// All goroutines should produce identical, correct results
	for i, env := range results {
		require.NotNil(t, env, "goroutine %d returned nil", i)
		assert.Equal(t, "http://localhost:11434", env["ANTHROPIC_BASE_URL"], "goroutine %d", i)
		assert.Equal(t, "ollama", env["ANTHROPIC_AUTH_TOKEN"], "goroutine %d", i)
		assert.Equal(t, "", env["ANTHROPIC_API_KEY"], "goroutine %d", i)
	}
}
