package llm

import (
	"context"
	"errors"
)

// MockAnalyzer is a mock implementation of Analyzer for testing.
type MockAnalyzer struct {
	SafeResponse bool
	Categories   []string
	ShouldError  bool
	Available    bool
}

// Analyze returns a mock result based on configuration.
func (m *MockAnalyzer) Analyze(ctx context.Context, content string) (*Result, error) {
	if m.ShouldError {
		return nil, errors.New("mock error")
	}
	return &Result{
		Safe:       m.SafeResponse,
		Categories: m.Categories,
		Confidence: 1.0,
	}, nil
}

// IsAvailable returns the configured availability.
func (m *MockAnalyzer) IsAvailable() bool {
	return m.Available
}
