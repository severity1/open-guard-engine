package llm

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestResult_IsSafe(t *testing.T) {
	tests := []struct {
		name   string
		result Result
		safe   bool
	}{
		{"safe result", Result{Safe: true, Categories: nil, Confidence: 1.0}, true},
		{"unsafe result", Result{Safe: false, Categories: []string{"S1"}, Confidence: 0.9}, false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.safe, tc.result.Safe)
		})
	}
}

func TestLlamaGuardAnalyzer_ParseSafeResponse(t *testing.T) {
	// Mock server that returns "safe"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := map[string]any{
			"message": map[string]any{
				"content": "safe",
			},
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(resp); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}))
	defer server.Close()

	analyzer := NewLlamaGuardAnalyzer(server.URL, "llama-guard3:1b")
	result, err := analyzer.Analyze(context.Background(), "hello world")

	require.NoError(t, err)
	assert.True(t, result.Safe)
	assert.Empty(t, result.Categories)
}

func TestLlamaGuardAnalyzer_ParseUnsafeResponse(t *testing.T) {
	// Mock server that returns "unsafe S1"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := map[string]any{
			"message": map[string]any{
				"content": "unsafe\nS1",
			},
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(resp); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}))
	defer server.Close()

	analyzer := NewLlamaGuardAnalyzer(server.URL, "llama-guard3:1b")
	result, err := analyzer.Analyze(context.Background(), "dangerous content")

	require.NoError(t, err)
	assert.False(t, result.Safe)
	assert.Contains(t, result.Categories, "S1")
}

func TestLlamaGuardAnalyzer_ParseMultipleCategoriesResponse(t *testing.T) {
	// Mock server that returns "unsafe S1,S5"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := map[string]any{
			"message": map[string]any{
				"content": "unsafe\nS1,S5",
			},
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(resp); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}))
	defer server.Close()

	analyzer := NewLlamaGuardAnalyzer(server.URL, "llama-guard3:1b")
	result, err := analyzer.Analyze(context.Background(), "very dangerous content")

	require.NoError(t, err)
	assert.False(t, result.Safe)
	assert.Contains(t, result.Categories, "S1")
	assert.Contains(t, result.Categories, "S5")
}

func TestLlamaGuardAnalyzer_Timeout(t *testing.T) {
	// Mock server that delays response
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(100 * time.Millisecond)
		resp := map[string]any{
			"message": map[string]any{
				"content": "safe",
			},
		}
		if err := json.NewEncoder(w).Encode(resp); err != nil {
			return
		}
	}))
	defer server.Close()

	analyzer := NewLlamaGuardAnalyzer(server.URL, "llama-guard3:1b")

	// Use a very short timeout
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()

	_, err := analyzer.Analyze(ctx, "test content")
	assert.Error(t, err)
}

func TestLlamaGuardAnalyzer_UnavailableEndpoint(t *testing.T) {
	// Use an invalid endpoint
	analyzer := NewLlamaGuardAnalyzer("http://localhost:99999", "llama-guard3:1b")

	result, err := analyzer.Analyze(context.Background(), "test content")

	assert.Error(t, err)
	assert.Nil(t, result)
}

func TestLlamaGuardAnalyzer_IsAvailable(t *testing.T) {
	// Mock server for /api/tags
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/tags" {
			resp := map[string]any{
				"models": []map[string]any{
					{"name": "llama-guard3:1b"},
					{"name": "llama3:8b"},
				},
			}
			if err := json.NewEncoder(w).Encode(resp); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	analyzer := NewLlamaGuardAnalyzer(server.URL, "llama-guard3:1b")
	assert.True(t, analyzer.IsAvailable())
}

func TestLlamaGuardAnalyzer_IsAvailable_ModelNotFound(t *testing.T) {
	// Mock server without the required model
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/tags" {
			resp := map[string]any{
				"models": []map[string]any{
					{"name": "llama3:8b"},
				},
			}
			if err := json.NewEncoder(w).Encode(resp); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	analyzer := NewLlamaGuardAnalyzer(server.URL, "llama-guard3:1b")
	assert.False(t, analyzer.IsAvailable())
}

func TestLlamaGuardAnalyzer_IsAvailable_Unavailable(t *testing.T) {
	analyzer := NewLlamaGuardAnalyzer("http://localhost:99999", "llama-guard3:1b")
	assert.False(t, analyzer.IsAvailable())
}

func TestLlamaGuardAnalyzer_RequestFormat(t *testing.T) {
	var receivedRequest map[string]any

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewDecoder(r.Body).Decode(&receivedRequest); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		resp := map[string]any{
			"message": map[string]any{
				"content": "safe",
			},
		}
		if err := json.NewEncoder(w).Encode(resp); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}))
	defer server.Close()

	analyzer := NewLlamaGuardAnalyzer(server.URL, "llama-guard3:1b")
	_, err := analyzer.Analyze(context.Background(), "test content")
	require.NoError(t, err)

	// Verify request format
	assert.Equal(t, "llama-guard3:1b", receivedRequest["model"])
	assert.Equal(t, false, receivedRequest["stream"])

	messages, ok := receivedRequest["messages"].([]any)
	require.True(t, ok)
	require.Len(t, messages, 1)

	msg, ok := messages[0].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, "user", msg["role"])
	assert.Equal(t, "test content", msg["content"])
}

func TestMockAnalyzer_Interface(t *testing.T) {
	var _ Analyzer = (*MockAnalyzer)(nil)
	var _ Analyzer = (*LlamaGuardAnalyzer)(nil)
}

func TestLlamaGuardAnalyzer_HTTPErrorStatusCodes(t *testing.T) {
	tests := []struct {
		name       string
		statusCode int
		body       string
	}{
		{"bad request", http.StatusBadRequest, "invalid request"},
		{"unauthorized", http.StatusUnauthorized, "unauthorized"},
		{"forbidden", http.StatusForbidden, "forbidden"},
		{"not found", http.StatusNotFound, "model not found"},
		{"internal server error", http.StatusInternalServerError, "server error"},
		{"service unavailable", http.StatusServiceUnavailable, "service unavailable"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tc.statusCode)
				if _, err := w.Write([]byte(tc.body)); err != nil {
					return
				}
			}))
			defer server.Close()

			analyzer := NewLlamaGuardAnalyzer(server.URL, "llama-guard3:1b")
			result, err := analyzer.Analyze(context.Background(), "test content")

			assert.Error(t, err)
			assert.Nil(t, result)
			assert.Contains(t, err.Error(), fmt.Sprintf("status %d", tc.statusCode))
		})
	}
}

func TestLlamaGuardAnalyzer_InvalidJSONResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if _, err := w.Write([]byte(`{invalid json`)); err != nil {
			return
		}
	}))
	defer server.Close()

	analyzer := NewLlamaGuardAnalyzer(server.URL, "llama-guard3:1b")
	result, err := analyzer.Analyze(context.Background(), "test content")

	assert.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "decoding response")
}

func TestLlamaGuardAnalyzer_ParseResponse_EdgeCases(t *testing.T) {
	tests := []struct {
		name       string
		content    string
		safe       bool
		categories []string
		confidence float64
	}{
		{"empty content", "", false, nil, 0.0},
		{"safe lowercase", "safe", true, nil, 1.0},
		{"safe with extra whitespace", "  safe  \n", true, nil, 1.0},
		{"unsafe no categories", "unsafe", false, nil, 1.0},
		{"unsafe with single category", "unsafe\nS1", false, []string{"S1"}, 1.0},
		{"unsafe inline category", "unsafe s3", false, []string{"s3"}, 1.0},
		{"unsafe multiple inline", "unsafe s1,s5,s10", false, []string{"s1", "s5", "s10"}, 1.0},
		{"unknown response", "maybe", false, nil, 0.0},
		{"random text", "hello world", false, nil, 0.0},
	}

	analyzer := &LlamaGuardAnalyzer{}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := analyzer.parseResponse(tc.content)
			assert.Equal(t, tc.safe, result.Safe)
			assert.Equal(t, tc.confidence, result.Confidence)
			if tc.categories != nil {
				assert.Equal(t, tc.categories, result.Categories)
			}
		})
	}
}

func TestNewLlamaGuardAnalyzer_Defaults(t *testing.T) {
	// Test with empty strings - should use defaults
	analyzer := NewLlamaGuardAnalyzer("", "")

	assert.Equal(t, "http://localhost:11434", analyzer.endpoint)
	assert.Equal(t, "llama-guard3:latest", analyzer.model)
	assert.NotNil(t, analyzer.client)
	assert.Equal(t, time.Duration(0), analyzer.client.Timeout)
}

func TestNewLlamaGuardAnalyzer_CustomValues(t *testing.T) {
	analyzer := NewLlamaGuardAnalyzer("http://custom:8080", "llama-guard3:8b")

	assert.Equal(t, "http://custom:8080", analyzer.endpoint)
	assert.Equal(t, "llama-guard3:8b", analyzer.model)
}

func TestLlamaGuardAnalyzer_IsAvailable_InvalidJSON(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/tags" {
			if _, err := w.Write([]byte(`{invalid json`)); err != nil {
				return
			}
			return
		}
	}))
	defer server.Close()

	analyzer := NewLlamaGuardAnalyzer(server.URL, "llama-guard3:1b")
	assert.False(t, analyzer.IsAvailable())
}

func TestLlamaGuardAnalyzer_IsAvailable_NonOKStatus(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/tags" {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
	}))
	defer server.Close()

	analyzer := NewLlamaGuardAnalyzer(server.URL, "llama-guard3:1b")
	assert.False(t, analyzer.IsAvailable())
}

func TestMockAnalyzer_Analyze(t *testing.T) {
	mock := &MockAnalyzer{
		SafeResponse: true,
		Categories:   nil,
	}

	result, err := mock.Analyze(context.Background(), "test content")
	require.NoError(t, err)
	assert.True(t, result.Safe)
	assert.Equal(t, 1.0, result.Confidence)
}

func TestMockAnalyzer_Analyze_Unsafe(t *testing.T) {
	mock := &MockAnalyzer{
		SafeResponse: false,
		Categories:   []string{"S1", "S5"},
	}

	result, err := mock.Analyze(context.Background(), "dangerous content")
	require.NoError(t, err)
	assert.False(t, result.Safe)
	assert.Equal(t, []string{"S1", "S5"}, result.Categories)
	assert.Equal(t, 1.0, result.Confidence)
}

func TestMockAnalyzer_Analyze_WithError(t *testing.T) {
	mock := &MockAnalyzer{
		ShouldError: true,
	}

	result, err := mock.Analyze(context.Background(), "test")
	assert.Error(t, err)
	assert.Nil(t, result)
}

func TestMockAnalyzer_IsAvailable(t *testing.T) {
	tests := []struct {
		name      string
		available bool
	}{
		{"available", true},
		{"unavailable", false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			mock := &MockAnalyzer{Available: tc.available}
			assert.Equal(t, tc.available, mock.IsAvailable())
		})
	}
}

func TestLlamaGuardAnalyzer_NoHardcodedTimeout(t *testing.T) {
	analyzer := NewLlamaGuardAnalyzer("http://localhost:11434", "llama-guard3:1b")
	assert.Equal(t, time.Duration(0), analyzer.client.Timeout)
}

func TestLlamaGuardAnalyzer_ContextTimeoutOnly(t *testing.T) {
	// Mock server with 200ms delay
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(200 * time.Millisecond)
		resp := map[string]any{
			"message": map[string]any{
				"content": "safe",
			},
		}
		if err := json.NewEncoder(w).Encode(resp); err != nil {
			return
		}
	}))
	defer server.Close()

	analyzer := NewLlamaGuardAnalyzer(server.URL, "llama-guard3:1b")

	// Use a 50ms context timeout - should timeout before server responds
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	_, err := analyzer.Analyze(ctx, "test content")
	assert.Error(t, err)
}

func TestParseResponse_UnknownDefaultsUnsafe(t *testing.T) {
	tests := []struct {
		name       string
		content    string
		safe       bool
		confidence float64
	}{
		{"empty string", "", false, 0.0},
		{"maybe", "maybe", false, 0.0},
		{"random gibberish", "random gibberish", false, 0.0},
	}

	analyzer := &LlamaGuardAnalyzer{}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := analyzer.parseResponse(tc.content)
			assert.Equal(t, tc.safe, result.Safe)
			assert.Equal(t, tc.confidence, result.Confidence)
		})
	}
}
