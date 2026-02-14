// Package audit provides audit logging for security events.
package audit

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/severity1/open-guard-engine/internal/types"
)

const maxLogMessageLength = 4096

// Entry represents a single audit log entry.
type Entry struct {
	Timestamp   time.Time            `json:"timestamp"`
	AuditID     string               `json:"audit_id"`
	Event       string               `json:"event"`
	ToolName    string               `json:"tool_name,omitempty"`
	Decision    types.Decision       `json:"decision"`
	ThreatLevel types.ThreatLevel    `json:"threat_level,omitempty"`
	ThreatType  types.ThreatCategory `json:"threat_type,omitempty"`
	Message     string               `json:"message,omitempty"`
	SessionID   string               `json:"session_id,omitempty"`
}

// Logger handles audit logging to file.
type Logger struct {
	logDir  string
	file    *os.File
	encoder *json.Encoder
	mu      sync.Mutex
}

// NewLogger creates a new audit Logger.
// Default log directory is ~/.open-guard/logs/
func NewLogger(logDir string) (*Logger, error) {
	if logDir == "" {
		homeDir, err := os.UserHomeDir()
		if err != nil {
			return nil, fmt.Errorf("getting home directory: %w", err)
		}
		logDir = filepath.Join(homeDir, ".open-guard", "logs")
	}

	// Create log directory if it doesn't exist
	if err := os.MkdirAll(logDir, 0755); err != nil {
		return nil, fmt.Errorf("creating log directory: %w", err)
	}

	logPath := filepath.Join(logDir, "audit.log")
	file, err := os.OpenFile(logPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return nil, fmt.Errorf("opening log file: %w", err)
	}

	return &Logger{
		logDir:  logDir,
		file:    file,
		encoder: json.NewEncoder(file),
	}, nil
}

// Log writes an audit entry to the log file.
func (l *Logger) Log(entry *Entry) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	if entry.Timestamp.IsZero() {
		entry.Timestamp = time.Now().UTC()
	}

	return l.encoder.Encode(entry)
}

// LogFromOutput creates and writes an audit entry from a HookOutput.
func (l *Logger) LogFromOutput(input *types.HookInput, output *types.HookOutput) error {
	entry := &Entry{
		Timestamp:   time.Now().UTC(),
		AuditID:     output.AuditID,
		Event:       sanitizeLogField(input.Event),
		ToolName:    sanitizeLogField(input.ToolName),
		Decision:    output.Decision,
		ThreatLevel: output.ThreatLevel,
		ThreatType:  output.ThreatType,
		Message:     sanitizeLogField(output.Message),
		SessionID:   input.SessionID,
	}

	return l.Log(entry)
}

// ansiEscapePattern matches ANSI escape sequences.
var ansiEscapePattern = regexp.MustCompile(`\x1b\[[0-9;]*[a-zA-Z]`)

// sanitizeLogField strips ANSI escapes and control characters, replaces
// newlines with spaces, and truncates to maxLogMessageLength to prevent
// log injection.
func sanitizeLogField(s string) string {
	// Strip ANSI escape sequences first
	s = ansiEscapePattern.ReplaceAllString(s, "")

	s = strings.Map(func(r rune) rune {
		if r == '\n' || r == '\r' {
			return ' '
		}
		if unicode.IsControl(r) {
			return ' '
		}
		return r
	}, s)

	if len(s) > maxLogMessageLength {
		s = s[:maxLogMessageLength]
	}

	return s
}

// Close closes the log file.
func (l *Logger) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.file != nil {
		return l.file.Close()
	}
	return nil
}

// LogPath returns the path to the audit log file.
func (l *Logger) LogPath() string {
	return filepath.Join(l.logDir, "audit.log")
}
