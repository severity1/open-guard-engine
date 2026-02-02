package integration

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/severity1/open-guard-engine/internal/types"
	"github.com/stretchr/testify/require"
)

// -----------------------------------------------------------------------------
// Binary Helpers
// -----------------------------------------------------------------------------

// getBinaryPath returns the path to the open-guard binary.
func getBinaryPath(t *testing.T) string {
	t.Helper()

	// Try relative path from test directory (tests/integration -> bin)
	binaryPath := filepath.Join("..", "..", "bin", "open-guard")
	if _, err := os.Stat(binaryPath); err == nil {
		return binaryPath
	}

	// Try absolute path from project root
	wd, err := os.Getwd()
	require.NoError(t, err)
	binaryPath = filepath.Join(wd, "..", "..", "bin", "open-guard")
	if _, err := os.Stat(binaryPath); err == nil {
		return binaryPath
	}

	t.Skip("Binary not found. Run 'make build' first.")
	return ""
}

// -----------------------------------------------------------------------------
// Analysis Helpers
// -----------------------------------------------------------------------------

// runWithConfig runs the analyze command with a specific config and returns the result.
func runWithConfig(t *testing.T, prompt string, cfg configMode) *types.HookOutput {
	t.Helper()

	binaryPath := getBinaryPath(t)

	// Create temp directory with config
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, ".open-guard.yaml")
	err := os.WriteFile(configPath, []byte(cfg.yaml), 0644)
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, binaryPath, "analyze", "--project", tmpDir)
	cmd.Stdin = strings.NewReader(prompt)

	output, err := cmd.Output()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			t.Logf("Command stderr: %s", exitErr.Stderr)
		}
	}
	require.NoError(t, err, "analyze command failed")

	var result types.HookOutput
	err = json.Unmarshal(output, &result)
	require.NoError(t, err, "failed to parse output: %s", string(output))

	return &result
}

// -----------------------------------------------------------------------------
// Availability Checks
// -----------------------------------------------------------------------------

func isOllamaAvailable() bool {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost:11434/api/tags", nil)
	if err != nil {
		return false
	}

	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	defer func() { _ = resp.Body.Close() }()

	return resp.StatusCode == http.StatusOK
}

func isClaudeAvailable() bool {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "claude", "--version")
	err := cmd.Run()
	return err == nil
}

func hasOllamaModel(model string) bool {
	if !isOllamaAvailable() {
		return false
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "ollama", "list")
	output, err := cmd.Output()
	if err != nil {
		return false
	}

	return strings.Contains(string(output), model)
}

// skipIfUnavailable checks if the required CLI/model is available and skips if not.
func skipIfUnavailable(t *testing.T, cfg configMode) {
	t.Helper()

	switch cfg.requiresCLI {
	case "ollama":
		if !isOllamaAvailable() {
			t.Skipf("Ollama not available - skipping %s tests", cfg.name)
		}
		if cfg.requireModel != "" && !hasOllamaModel(cfg.requireModel) {
			t.Skipf("Model %s not available - pull with: ollama pull %s:latest", cfg.requireModel, cfg.requireModel)
		}
	case "claude":
		if !isClaudeAvailable() {
			t.Skipf("Claude CLI not available - skipping %s tests", cfg.name)
		}
	}
}

// -----------------------------------------------------------------------------
// Test Result Tracking
// -----------------------------------------------------------------------------

type detectionResult struct {
	configName string
	category   string
	detected   int
	total      int
}

func (r detectionResult) rate() float64 {
	if r.total == 0 {
		return 0
	}
	return float64(r.detected) / float64(r.total) * 100
}
