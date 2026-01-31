// Package response handles building hook response decisions.
package response

import (
	"github.com/google/uuid"
	"github.com/severity1/open-guard-engine/internal/config"
	"github.com/severity1/open-guard-engine/internal/types"
)

// Handler builds hook output responses based on configuration.
type Handler struct {
	config *config.Config
}

// NewHandler creates a new response Handler.
func NewHandler(cfg *config.Config) *Handler {
	return &Handler{config: cfg}
}

// Allow returns an allow decision with a message.
func (h *Handler) Allow(message string) *types.HookOutput {
	return &types.HookOutput{
		Decision: types.DecisionAllow,
		Message:  message,
	}
}

// Build creates a HookOutput with the given parameters.
func (h *Handler) Build(decision types.Decision, level types.ThreatLevel, category types.ThreatCategory, message string) *types.HookOutput {
	return &types.HookOutput{
		Decision:    decision,
		ThreatLevel: level,
		ThreatType:  category,
		Message:     message,
		AuditID:     generateAuditID(),
	}
}

// BuildWithSource creates a HookOutput with detection source.
func (h *Handler) BuildWithSource(decision types.Decision, level types.ThreatLevel, category types.ThreatCategory, source types.DetectionSource, message string) *types.HookOutput {
	return &types.HookOutput{
		Decision:    decision,
		ThreatLevel: level,
		ThreatType:  category,
		DetectedBy:  source,
		Message:     message,
		AuditID:     generateAuditID(),
	}
}

// BuildWithModeOverride creates a HookOutput, adjusting the decision based on mode.
func (h *Handler) BuildWithModeOverride(decision types.Decision, level types.ThreatLevel, category types.ThreatCategory, message string) *types.HookOutput {
	// Apply mode overrides
	switch h.config.Mode {
	case config.ModeStrict:
		// In strict mode, confirm becomes block
		if decision == types.DecisionConfirm {
			decision = types.DecisionBlock
		}
	case config.ModePermissive:
		// In permissive mode, block becomes log
		if decision == types.DecisionBlock || decision == types.DecisionConfirm {
			decision = types.DecisionLog
		}
	}

	return h.Build(decision, level, category, message)
}

// BuildWithModeOverrideAndSource creates a HookOutput with detection source, adjusting decision based on mode.
func (h *Handler) BuildWithModeOverrideAndSource(decision types.Decision, level types.ThreatLevel, category types.ThreatCategory, source types.DetectionSource, message string) *types.HookOutput {
	// Apply mode overrides
	switch h.config.Mode {
	case config.ModeStrict:
		if decision == types.DecisionConfirm {
			decision = types.DecisionBlock
		}
	case config.ModePermissive:
		if decision == types.DecisionBlock || decision == types.DecisionConfirm {
			decision = types.DecisionLog
		}
	}

	return h.BuildWithSource(decision, level, category, source, message)
}

// DecisionFromSeverity returns the appropriate decision based on threat severity and mode.
func (h *Handler) DecisionFromSeverity(severity types.ThreatLevel) types.Decision {
	switch severity {
	case types.ThreatLevelCritical:
		return types.DecisionBlock
	case types.ThreatLevelHigh:
		if h.config.Mode == config.ModeStrict {
			return types.DecisionBlock
		}
		return types.DecisionConfirm
	case types.ThreatLevelMedium:
		if h.config.Mode == config.ModeStrict {
			return types.DecisionBlock
		}
		return types.DecisionConfirm
	case types.ThreatLevelLow:
		return types.DecisionLog
	default:
		return types.DecisionAllow
	}
}

// generateAuditID creates a unique audit ID using UUID.
func generateAuditID() string {
	return uuid.New().String()
}
