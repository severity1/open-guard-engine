package audit

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/severity1/open-guard-engine/internal/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewLogger(t *testing.T) {
	tmpDir := t.TempDir()
	logDir := filepath.Join(tmpDir, "logs")

	logger, err := NewLogger(logDir)
	require.NoError(t, err)
	defer func() { _ = logger.Close() }()

	assert.NotNil(t, logger)
	assert.DirExists(t, logDir)
	assert.FileExists(t, filepath.Join(logDir, "audit.log"))
}

func TestLogger_Log(t *testing.T) {
	tmpDir := t.TempDir()
	logDir := filepath.Join(tmpDir, "logs")

	logger, err := NewLogger(logDir)
	require.NoError(t, err)
	defer func() { _ = logger.Close() }()

	entry := &Entry{
		Timestamp:   time.Now().UTC(),
		AuditID:     "test-audit-123",
		Event:       "pre-tool",
		ToolName:    "Bash",
		Decision:    types.DecisionBlock,
		ThreatLevel: types.ThreatLevelHigh,
		ThreatType:  types.ThreatCategoryNetwork,
		Message:     "Test threat detected",
		SessionID:   "session-456",
	}

	err = logger.Log(entry)
	require.NoError(t, err)

	// Close to flush
	logger.Close()

	// Read and verify log file
	logPath := filepath.Join(logDir, "audit.log")
	file, err := os.Open(logPath)
	require.NoError(t, err)
	defer func() { _ = file.Close() }()

	var readEntry Entry
	err = json.NewDecoder(file).Decode(&readEntry)
	require.NoError(t, err)

	assert.Equal(t, "test-audit-123", readEntry.AuditID)
	assert.Equal(t, "pre-tool", readEntry.Event)
	assert.Equal(t, "Bash", readEntry.ToolName)
	assert.Equal(t, types.DecisionBlock, readEntry.Decision)
	assert.Equal(t, types.ThreatLevelHigh, readEntry.ThreatLevel)
}

func TestLogger_LogFromOutput(t *testing.T) {
	tmpDir := t.TempDir()
	logDir := filepath.Join(tmpDir, "logs")

	logger, err := NewLogger(logDir)
	require.NoError(t, err)
	defer func() { _ = logger.Close() }()

	input := &types.HookInput{
		Event:     "pre-tool",
		ToolName:  "Bash",
		SessionID: "session-789",
	}

	output := &types.HookOutput{
		Decision:    types.DecisionConfirm,
		ThreatLevel: types.ThreatLevelMedium,
		ThreatType:  types.ThreatCategoryCredentials,
		Message:     "Credential access detected",
		AuditID:     "audit-xyz",
	}

	err = logger.LogFromOutput(input, output)
	require.NoError(t, err)

	// Close to flush
	logger.Close()

	// Read and verify
	logPath := filepath.Join(logDir, "audit.log")
	file, err := os.Open(logPath)
	require.NoError(t, err)
	defer func() { _ = file.Close() }()

	var readEntry Entry
	err = json.NewDecoder(file).Decode(&readEntry)
	require.NoError(t, err)

	assert.Equal(t, "audit-xyz", readEntry.AuditID)
	assert.Equal(t, "session-789", readEntry.SessionID)
	assert.Equal(t, types.DecisionConfirm, readEntry.Decision)
}

func TestLogger_MultipleEntries(t *testing.T) {
	tmpDir := t.TempDir()
	logDir := filepath.Join(tmpDir, "logs")

	logger, err := NewLogger(logDir)
	require.NoError(t, err)
	defer func() { _ = logger.Close() }()

	// Write multiple entries
	for i := 0; i < 5; i++ {
		entry := &Entry{
			AuditID:  "audit-" + string(rune('A'+i)),
			Event:    "pre-tool",
			Decision: types.DecisionAllow,
		}
		err = logger.Log(entry)
		require.NoError(t, err)
	}

	// Close to flush
	logger.Close()

	// Read and count entries
	logPath := filepath.Join(logDir, "audit.log")
	file, err := os.Open(logPath)
	require.NoError(t, err)
	defer func() { _ = file.Close() }()

	scanner := bufio.NewScanner(file)
	count := 0
	for scanner.Scan() {
		count++
	}
	require.NoError(t, scanner.Err())
	assert.Equal(t, 5, count)
}

func TestLogger_LogPath(t *testing.T) {
	tmpDir := t.TempDir()
	logDir := filepath.Join(tmpDir, "logs")

	logger, err := NewLogger(logDir)
	require.NoError(t, err)
	defer func() { _ = logger.Close() }()

	expected := filepath.Join(logDir, "audit.log")
	assert.Equal(t, expected, logger.LogPath())
}

func TestLogger_Log_SetsTimestamp(t *testing.T) {
	tmpDir := t.TempDir()
	logDir := filepath.Join(tmpDir, "logs")

	logger, err := NewLogger(logDir)
	require.NoError(t, err)
	defer func() { _ = logger.Close() }()

	// Create entry with zero timestamp
	entry := &Entry{
		AuditID:  "test-audit",
		Event:    "pre-tool",
		Decision: types.DecisionAllow,
	}

	before := time.Now().UTC()
	err = logger.Log(entry)
	require.NoError(t, err)
	after := time.Now().UTC()

	// Close to flush
	logger.Close()

	// Read and verify timestamp was set
	logPath := filepath.Join(logDir, "audit.log")
	file, err := os.Open(logPath)
	require.NoError(t, err)
	defer func() { _ = file.Close() }()

	var readEntry Entry
	err = json.NewDecoder(file).Decode(&readEntry)
	require.NoError(t, err)

	// Timestamp should be between before and after
	assert.False(t, readEntry.Timestamp.IsZero(), "Timestamp should be set")
	assert.True(t, !readEntry.Timestamp.Before(before), "Timestamp should be >= before")
	assert.True(t, !readEntry.Timestamp.After(after), "Timestamp should be <= after")
}

func TestLogger_Log_PreservesTimestamp(t *testing.T) {
	tmpDir := t.TempDir()
	logDir := filepath.Join(tmpDir, "logs")

	logger, err := NewLogger(logDir)
	require.NoError(t, err)
	defer func() { _ = logger.Close() }()

	// Create entry with explicit timestamp
	fixedTime := time.Date(2024, 6, 15, 10, 30, 0, 0, time.UTC)
	entry := &Entry{
		Timestamp: fixedTime,
		AuditID:   "test-audit",
		Event:     "pre-tool",
		Decision:  types.DecisionAllow,
	}

	err = logger.Log(entry)
	require.NoError(t, err)

	// Close to flush
	logger.Close()

	// Read and verify timestamp was preserved
	logPath := filepath.Join(logDir, "audit.log")
	file, err := os.Open(logPath)
	require.NoError(t, err)
	defer func() { _ = file.Close() }()

	var readEntry Entry
	err = json.NewDecoder(file).Decode(&readEntry)
	require.NoError(t, err)

	assert.Equal(t, fixedTime, readEntry.Timestamp)
}

func TestNewLogger_CreateDirectoryFails(t *testing.T) {
	// Try to create logger in a path that can't be created
	// Using a file path where we'd try to create a directory
	tmpFile := filepath.Join(t.TempDir(), "file.txt")
	err := os.WriteFile(tmpFile, []byte("content"), 0644)
	require.NoError(t, err)

	// Try to use the file as a directory
	_, err = NewLogger(filepath.Join(tmpFile, "subdir"))
	assert.Error(t, err)
}

func TestLogger_ConcurrentWrites(t *testing.T) {
	tmpDir := t.TempDir()
	logDir := filepath.Join(tmpDir, "logs")

	logger, err := NewLogger(logDir)
	require.NoError(t, err)
	defer func() { _ = logger.Close() }()

	// Write concurrently from multiple goroutines
	numGoroutines := 10
	numEntriesPerGoroutine := 10

	var wg sync.WaitGroup
	wg.Add(numGoroutines)

	for g := 0; g < numGoroutines; g++ {
		go func(goroutineID int) {
			defer wg.Done()
			for i := 0; i < numEntriesPerGoroutine; i++ {
				entry := &Entry{
					AuditID:  fmt.Sprintf("audit-%d-%d", goroutineID, i),
					Event:    "pre-tool",
					Decision: types.DecisionAllow,
				}
				err := logger.Log(entry)
				assert.NoError(t, err)
			}
		}(g)
	}

	wg.Wait()

	// Close to flush
	logger.Close()

	// Count entries
	logPath := filepath.Join(logDir, "audit.log")
	file, err := os.Open(logPath)
	require.NoError(t, err)
	defer func() { _ = file.Close() }()

	scanner := bufio.NewScanner(file)
	count := 0
	for scanner.Scan() {
		count++
	}
	require.NoError(t, scanner.Err())

	expectedEntries := numGoroutines * numEntriesPerGoroutine
	assert.Equal(t, expectedEntries, count, "All entries should be written")
}

func TestLogger_Close_NilFile(t *testing.T) {
	// Create a logger and manually set file to nil to test edge case
	logger := &Logger{
		file: nil,
	}

	err := logger.Close()
	assert.NoError(t, err)
}

func TestLogger_Close_MultipleCalls(t *testing.T) {
	tmpDir := t.TempDir()
	logDir := filepath.Join(tmpDir, "logs")

	logger, err := NewLogger(logDir)
	require.NoError(t, err)

	// First close should work
	err = logger.Close()
	assert.NoError(t, err)

	// Second close should also work (but may error since file is closed)
	// The important thing is it doesn't panic
	_ = logger.Close()
}

func TestNewLogger_DefaultDirectory(t *testing.T) {
	// This test is flaky in CI - skip if running in non-writable home
	homeDir, err := os.UserHomeDir()
	if err != nil {
		t.Skip("Cannot determine home directory")
	}

	logger, err := NewLogger("")
	if err != nil {
		t.Skip("Cannot create logger in home directory")
	}
	defer func() { _ = logger.Close() }()

	expectedPath := filepath.Join(homeDir, ".open-guard", "logs", "audit.log")
	assert.Equal(t, expectedPath, logger.LogPath())
}

func TestEntry_AllFields(t *testing.T) {
	entry := Entry{
		Timestamp:   time.Now().UTC(),
		AuditID:     "audit-123",
		Event:       "pre-tool",
		ToolName:    "Bash",
		Decision:    types.DecisionBlock,
		ThreatLevel: types.ThreatLevelHigh,
		ThreatType:  types.ThreatCategoryNetwork,
		Message:     "Network exfiltration detected",
		SessionID:   "session-456",
	}

	// Marshal to JSON and back to verify all fields
	data, err := json.Marshal(entry)
	require.NoError(t, err)

	var decoded Entry
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	assert.Equal(t, entry.AuditID, decoded.AuditID)
	assert.Equal(t, entry.Event, decoded.Event)
	assert.Equal(t, entry.ToolName, decoded.ToolName)
	assert.Equal(t, entry.Decision, decoded.Decision)
	assert.Equal(t, entry.ThreatLevel, decoded.ThreatLevel)
	assert.Equal(t, entry.ThreatType, decoded.ThreatType)
	assert.Equal(t, entry.Message, decoded.Message)
	assert.Equal(t, entry.SessionID, decoded.SessionID)
}

func TestLogger_LogFromOutput_SanitizesMessage(t *testing.T) {
	tests := []struct {
		name            string
		message         string
		toolName        string
		event           string
		expectMessage   string
		expectToolName  string
		expectEvent     string
	}{
		{
			name:           "control chars stripped",
			message:        "threat\x00detected\x1b[31m",
			toolName:       "Bash",
			event:          "pre-tool",
			expectMessage:  "threat detected",
			expectToolName: "Bash",
			expectEvent:    "pre-tool",
		},
		{
			name:           "newlines replaced with space",
			message:        "line1\nline2\rline3",
			toolName:       "Bash",
			event:          "pre-tool",
			expectMessage:  "line1 line2 line3",
			expectToolName: "Bash",
			expectEvent:    "pre-tool",
		},
		{
			name:           "long message truncated",
			message:        strings.Repeat("a", 5000),
			toolName:       "Bash",
			event:          "pre-tool",
			expectMessage:  strings.Repeat("a", 4096),
			expectToolName: "Bash",
			expectEvent:    "pre-tool",
		},
		{
			name:           "clean message unchanged",
			message:        "Normal threat message",
			toolName:       "Bash",
			event:          "pre-tool",
			expectMessage:  "Normal threat message",
			expectToolName: "Bash",
			expectEvent:    "pre-tool",
		},
		{
			name:           "tool name sanitized",
			message:        "test",
			toolName:       "Bash\x00injected",
			event:          "pre-tool",
			expectMessage:  "test",
			expectToolName: "Bash injected",
			expectEvent:    "pre-tool",
		},
		{
			name:           "event sanitized",
			message:        "test",
			toolName:       "Bash",
			event:          "pre-tool\ninjected",
			expectMessage:  "test",
			expectToolName: "Bash",
			expectEvent:    "pre-tool injected",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tmpDir := t.TempDir()
			logDir := filepath.Join(tmpDir, "logs")

			logger, err := NewLogger(logDir)
			require.NoError(t, err)
			defer func() { _ = logger.Close() }()

			input := &types.HookInput{
				Event:     tc.event,
				ToolName:  tc.toolName,
				SessionID: "session-test",
			}

			output := &types.HookOutput{
				Decision:    types.DecisionBlock,
				ThreatLevel: types.ThreatLevelHigh,
				ThreatType:  types.ThreatCategoryInjection,
				Message:     tc.message,
				AuditID:     "audit-sanitize",
			}

			err = logger.LogFromOutput(input, output)
			require.NoError(t, err)

			// Close to flush
			_ = logger.Close()

			// Read and verify
			logPath := filepath.Join(logDir, "audit.log")
			file, err := os.Open(logPath)
			require.NoError(t, err)
			defer func() { _ = file.Close() }()

			var readEntry Entry
			err = json.NewDecoder(file).Decode(&readEntry)
			require.NoError(t, err)

			assert.Equal(t, tc.expectMessage, readEntry.Message)
			assert.Equal(t, tc.expectToolName, readEntry.ToolName)
			assert.Equal(t, tc.expectEvent, readEntry.Event)
		})
	}
}
