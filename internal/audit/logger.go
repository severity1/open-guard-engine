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
	"unicode/utf8"

	"github.com/severity1/open-guard-engine/internal/types"
)

const maxLogMessageLength = 4096

// Entry represents a single audit log entry.
type Entry struct {
	Timestamp   time.Time            `json:"timestamp"`
	AuditID     string               `json:"audit_id"`
	Event       string               `json:"event"`
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

	// Work on a copy to avoid mutating the caller's entry
	sanitized := *entry

	if sanitized.Timestamp.IsZero() {
		sanitized.Timestamp = time.Now().UTC()
	}

	// Sanitize user-controllable fields to prevent log injection (#22)
	sanitized.Event = sanitizeLogField(sanitized.Event)
	sanitized.Message = sanitizeLogField(sanitized.Message)
	sanitized.SessionID = sanitizeLogField(sanitized.SessionID)

	return l.encoder.Encode(&sanitized)
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
		// Walk back from the byte limit to find a valid rune boundary,
		// avoiding truncation in the middle of a multi-byte UTF-8 sequence.
		truncLen := maxLogMessageLength
		for truncLen > 0 && !utf8.RuneStart(s[truncLen]) {
			truncLen--
		}
		s = s[:truncLen]
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
