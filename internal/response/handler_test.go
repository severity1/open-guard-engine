package response

import (
	"testing"

	"github.com/google/uuid"
	"github.com/severity1/open-guard-engine/internal/config"
	"github.com/severity1/open-guard-engine/internal/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHandler_Allow(t *testing.T) {
	cfg := config.DefaultConfig()
	h := NewHandler(cfg)

	output := h.Allow("Command allowed")

	assert.Equal(t, types.DecisionAllow, output.Decision)
	assert.Equal(t, "Command allowed", output.Message)
	assert.Empty(t, output.AuditID) // Allow doesn't need audit ID
}

func TestHandler_Build_Block(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Mode = config.ModeStrict
	h := NewHandler(cfg)

	output := h.Build(
		types.DecisionBlock,
		types.ThreatLevelHigh,
		types.ThreatCategoryNetwork,
		"Network exfiltration detected",
	)

	assert.Equal(t, types.DecisionBlock, output.Decision)
	assert.Equal(t, types.ThreatLevelHigh, output.ThreatLevel)
	assert.Equal(t, types.ThreatCategoryNetwork, output.ThreatType)
	assert.Equal(t, "Network exfiltration detected", output.Message)
	assert.NotEmpty(t, output.AuditID)

	// Verify audit ID is valid UUID
	_, err := uuid.Parse(output.AuditID)
	assert.NoError(t, err)
}

func TestHandler_Build_Confirm(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Mode = config.ModeConfirm
	h := NewHandler(cfg)

	output := h.Build(
		types.DecisionConfirm,
		types.ThreatLevelMedium,
		types.ThreatCategoryCredentials,
		"Confirm credential access",
	)

	assert.Equal(t, types.DecisionConfirm, output.Decision)
	assert.Equal(t, types.ThreatLevelMedium, output.ThreatLevel)
	assert.NotEmpty(t, output.AuditID)
}

func TestHandler_BuildWithModeOverride_StrictMode(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Mode = config.ModeStrict
	h := NewHandler(cfg)

	// In strict mode, confirm should become block
	output := h.BuildWithModeOverride(
		types.DecisionConfirm,
		types.ThreatLevelHigh,
		types.ThreatCategoryInjection,
		"Injection detected",
	)

	assert.Equal(t, types.DecisionBlock, output.Decision)
}

func TestHandler_BuildWithModeOverride_PermissiveMode(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Mode = config.ModePermissive
	h := NewHandler(cfg)

	// In permissive mode, block should become log
	output := h.BuildWithModeOverride(
		types.DecisionBlock,
		types.ThreatLevelCritical,
		types.ThreatCategoryFilesystem,
		"Filesystem attack detected",
	)

	assert.Equal(t, types.DecisionLog, output.Decision)
}

func TestHandler_BuildWithModeOverride_ConfirmMode(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Mode = config.ModeConfirm
	h := NewHandler(cfg)

	// In confirm mode, decisions should pass through
	output := h.BuildWithModeOverride(
		types.DecisionConfirm,
		types.ThreatLevelMedium,
		types.ThreatCategoryRecon,
		"Recon detected",
	)

	assert.Equal(t, types.DecisionConfirm, output.Decision)
}

func TestHandler_AuditID_Unique(t *testing.T) {
	cfg := config.DefaultConfig()
	h := NewHandler(cfg)

	ids := make(map[string]bool)
	for i := 0; i < 100; i++ {
		output := h.Build(
			types.DecisionBlock,
			types.ThreatLevelHigh,
			types.ThreatCategoryNetwork,
			"test",
		)
		require.NotEmpty(t, output.AuditID)
		require.False(t, ids[output.AuditID], "duplicate audit ID: %s", output.AuditID)
		ids[output.AuditID] = true
	}
}

func TestHandler_DecisionFromSeverity(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Mode = config.ModeConfirm
	h := NewHandler(cfg)

	tests := []struct {
		severity types.ThreatLevel
		expected types.Decision
	}{
		{types.ThreatLevelCritical, types.DecisionBlock},
		{types.ThreatLevelHigh, types.DecisionConfirm},
		{types.ThreatLevelMedium, types.DecisionConfirm},
		{types.ThreatLevelLow, types.DecisionLog},
		{types.ThreatLevelNone, types.DecisionAllow},
	}

	for _, tc := range tests {
		t.Run(tc.severity.String(), func(t *testing.T) {
			decision := h.DecisionFromSeverity(tc.severity)
			assert.Equal(t, tc.expected, decision)
		})
	}
}

func TestHandler_DecisionFromSeverity_StrictMode(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Mode = config.ModeStrict
	h := NewHandler(cfg)

	// In strict mode, all threats should block
	tests := []struct {
		severity types.ThreatLevel
		expected types.Decision
	}{
		{types.ThreatLevelCritical, types.DecisionBlock},
		{types.ThreatLevelHigh, types.DecisionBlock},
		{types.ThreatLevelMedium, types.DecisionBlock},
		{types.ThreatLevelLow, types.DecisionLog},
		{types.ThreatLevelNone, types.DecisionAllow},
	}

	for _, tc := range tests {
		t.Run(tc.severity.String(), func(t *testing.T) {
			decision := h.DecisionFromSeverity(tc.severity)
			assert.Equal(t, tc.expected, decision)
		})
	}
}

func TestHandler_BuildWithSource(t *testing.T) {
	cfg := config.DefaultConfig()
	h := NewHandler(cfg)

	sources := []types.DetectionSource{
		types.DetectionSourcePattern,
		types.DetectionSourceLLM,
		types.DetectionSourceAgent,
	}

	for _, source := range sources {
		t.Run(string(source), func(t *testing.T) {
			output := h.BuildWithSource(
				types.DecisionBlock,
				types.ThreatLevelHigh,
				types.ThreatCategoryPromptInjection,
				source,
				"Test message",
			)

			assert.Equal(t, types.DecisionBlock, output.Decision)
			assert.Equal(t, types.ThreatLevelHigh, output.ThreatLevel)
			assert.Equal(t, types.ThreatCategoryPromptInjection, output.ThreatType)
			assert.Equal(t, source, output.DetectedBy)
			assert.Equal(t, "Test message", output.Message)
			assert.NotEmpty(t, output.AuditID)
		})
	}
}

func TestHandler_BuildWithModeOverrideAndSource_AllModes(t *testing.T) {
	tests := []struct {
		mode          config.Mode
		inputDecision types.Decision
		wantDecision  types.Decision
	}{
		// Strict mode: confirm -> block
		{config.ModeStrict, types.DecisionConfirm, types.DecisionBlock},
		{config.ModeStrict, types.DecisionBlock, types.DecisionBlock},
		{config.ModeStrict, types.DecisionAllow, types.DecisionAllow},

		// Confirm mode: no changes
		{config.ModeConfirm, types.DecisionConfirm, types.DecisionConfirm},
		{config.ModeConfirm, types.DecisionBlock, types.DecisionBlock},
		{config.ModeConfirm, types.DecisionAllow, types.DecisionAllow},

		// Permissive mode: block/confirm -> log
		{config.ModePermissive, types.DecisionBlock, types.DecisionLog},
		{config.ModePermissive, types.DecisionConfirm, types.DecisionLog},
		{config.ModePermissive, types.DecisionAllow, types.DecisionAllow},
	}

	for _, tc := range tests {
		name := string(tc.mode) + "_" + string(tc.inputDecision)
		t.Run(name, func(t *testing.T) {
			cfg := config.DefaultConfig()
			cfg.Mode = tc.mode
			h := NewHandler(cfg)

			output := h.BuildWithModeOverrideAndSource(
				tc.inputDecision,
				types.ThreatLevelHigh,
				types.ThreatCategoryNetwork,
				types.DetectionSourcePattern,
				"Test",
			)

			assert.Equal(t, tc.wantDecision, output.Decision)
			assert.Equal(t, types.DetectionSourcePattern, output.DetectedBy)
		})
	}
}

func TestHandler_DecisionFromSeverity_UnknownSeverity(t *testing.T) {
	cfg := config.DefaultConfig()
	h := NewHandler(cfg)

	// Unknown severity should default to allow
	unknown := types.ThreatLevel("unknown")
	decision := h.DecisionFromSeverity(unknown)
	assert.Equal(t, types.DecisionAllow, decision)
}

func TestHandler_Build_AllCategories(t *testing.T) {
	cfg := config.DefaultConfig()
	h := NewHandler(cfg)

	categories := []types.ThreatCategory{
		types.ThreatCategoryNetwork,
		types.ThreatCategoryCredentials,
		types.ThreatCategoryInjection,
		types.ThreatCategoryFilesystem,
		types.ThreatCategoryPromptInjection,
		types.ThreatCategoryPrivilege,
		types.ThreatCategoryPersistence,
		types.ThreatCategoryRecon,
	}

	for _, cat := range categories {
		t.Run(string(cat), func(t *testing.T) {
			output := h.Build(
				types.DecisionBlock,
				types.ThreatLevelHigh,
				cat,
				"Test message",
			)

			assert.Equal(t, cat, output.ThreatType)
			assert.NotEmpty(t, output.AuditID)
		})
	}
}

func TestHandler_NewHandler(t *testing.T) {
	cfg := config.DefaultConfig()
	h := NewHandler(cfg)

	assert.NotNil(t, h)
	assert.Equal(t, cfg, h.config)
}
