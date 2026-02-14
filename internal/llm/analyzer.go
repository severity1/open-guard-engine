// Package llm provides LLM-based content analysis for threat detection.
package llm

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// Result represents the result of an ML analysis.
type Result struct {
	Safe       bool
	Categories []string
	Confidence float64
	Reason     string // Optional reason for the result (used by PromptInjectionAnalyzer)
}

// Analyzer defines the interface for ML-based content analysis.
type Analyzer interface {
	Analyze(ctx context.Context, content string) (*Result, error)
	IsAvailable() bool
}

// LlamaGuardAnalyzer uses llama-guard3 via Ollama for content safety analysis.
type LlamaGuardAnalyzer struct {
	endpoint string
	model    string
	client   *http.Client
}

// NewLlamaGuardAnalyzer creates a new LlamaGuardAnalyzer.
// Default endpoint is http://localhost:11434, default model is llama-guard3:latest.
func NewLlamaGuardAnalyzer(endpoint, model string) *LlamaGuardAnalyzer {
	if endpoint == "" {
		endpoint = "http://localhost:11434"
	}
	if model == "" {
		model = "llama-guard3:latest"
	}

	return &LlamaGuardAnalyzer{
		endpoint: endpoint,
		model:    model,
		client:   &http.Client{},
	}
}

// chatRequest represents the Ollama chat API request.
type chatRequest struct {
	Model    string        `json:"model"`
	Messages []chatMessage `json:"messages"`
	Stream   bool          `json:"stream"`
}

// chatMessage represents a message in the chat.
type chatMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

// chatResponse represents the Ollama chat API response.
type chatResponse struct {
	Message struct {
		Content string `json:"content"`
	} `json:"message"`
}

// Analyze sends content to llama-guard3 for safety analysis.
func (a *LlamaGuardAnalyzer) Analyze(ctx context.Context, content string) (*Result, error) {
	reqBody := chatRequest{
		Model: a.model,
		Messages: []chatMessage{
			{Role: "user", Content: content},
		},
		Stream: false,
	}

	jsonData, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("marshaling request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, a.endpoint+"/api/chat", bytes.NewReader(jsonData))
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := a.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("sending request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20)) // 1MB limit on error body
		return nil, fmt.Errorf("ollama returned status %d: %s", resp.StatusCode, string(body))
	}

	var chatResp chatResponse
	if err := json.NewDecoder(resp.Body).Decode(&chatResp); err != nil {
		return nil, fmt.Errorf("decoding response: %w", err)
	}

	return a.parseResponse(chatResp.Message.Content), nil
}

// parseResponse parses the llama-guard3 response.
// Response format: "safe" or "unsafe\nS1,S2,..."
func (a *LlamaGuardAnalyzer) parseResponse(content string) *Result {
	content = strings.TrimSpace(content)
	lines := strings.Split(content, "\n")

	if len(lines) == 0 {
		return &Result{Safe: false, Confidence: 0.0}
	}

	firstLine := strings.TrimSpace(strings.ToLower(lines[0]))

	if firstLine == "safe" {
		return &Result{Safe: true, Confidence: 1.0}
	}

	if strings.HasPrefix(firstLine, "unsafe") {
		result := &Result{Safe: false, Confidence: 1.0}

		// Parse categories from second line or after "unsafe"
		var categoryStr string
		if len(lines) > 1 {
			categoryStr = strings.TrimSpace(lines[1])
		} else {
			// Categories might be on the same line: "unsafe S1,S2"
			parts := strings.SplitN(firstLine, " ", 2)
			if len(parts) > 1 {
				categoryStr = parts[1]
			}
		}

		if categoryStr != "" {
			categories := strings.Split(categoryStr, ",")
			for _, cat := range categories {
				cat = strings.TrimSpace(cat)
				if cat != "" {
					result.Categories = append(result.Categories, cat)
				}
			}
		}

		return result
	}

	// Unknown response, default to unsafe
	return &Result{Safe: false, Confidence: 0.0}
}

// tagsResponse represents the Ollama tags API response.
type tagsResponse struct {
	Models []struct {
		Name string `json:"name"`
	} `json:"models"`
}

// IsAvailable checks if the Ollama endpoint is available and has the required model.
func (a *LlamaGuardAnalyzer) IsAvailable() bool {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, a.endpoint+"/api/tags", nil)
	if err != nil {
		return false
	}

	resp, err := a.client.Do(req)
	if err != nil {
		return false
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return false
	}

	var tags tagsResponse
	if err := json.NewDecoder(resp.Body).Decode(&tags); err != nil {
		return false
	}

	// Check if our model is available
	for _, model := range tags.Models {
		if model.Name == a.model {
			return true
		}
	}

	return false
}
