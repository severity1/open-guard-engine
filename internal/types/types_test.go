package types

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDecision_String(t *testing.T) {
	tests := []struct {
		decision Decision
		expected string
	}{
		{DecisionBlock, "block"},
		{DecisionConfirm, "confirm"},
		{DecisionScrub, "scrub"},
		{DecisionRemediate, "remediate"},
		{DecisionLog, "log"},
		{DecisionAllow, "allow"},
	}

	for _, tc := range tests {
		t.Run(tc.expected, func(t *testing.T) {
			assert.Equal(t, tc.expected, tc.decision.String())
		})
	}
}

func TestDecision_JSONMarshal(t *testing.T) {
	tests := []struct {
		decision Decision
		expected string
	}{
		{DecisionBlock, `"block"`},
		{DecisionAllow, `"allow"`},
		{DecisionConfirm, `"confirm"`},
	}

	for _, tc := range tests {
		t.Run(tc.decision.String(), func(t *testing.T) {
			data, err := json.Marshal(tc.decision)
			require.NoError(t, err)
			assert.Equal(t, tc.expected, string(data))
		})
	}
}

func TestDecision_JSONUnmarshal(t *testing.T) {
	tests := []struct {
		input    string
		expected Decision
	}{
		{`"block"`, DecisionBlock},
		{`"allow"`, DecisionAllow},
		{`"confirm"`, DecisionConfirm},
		{`"scrub"`, DecisionScrub},
		{`"remediate"`, DecisionRemediate},
		{`"log"`, DecisionLog},
	}

	for _, tc := range tests {
		t.Run(tc.input, func(t *testing.T) {
			var d Decision
			err := json.Unmarshal([]byte(tc.input), &d)
			require.NoError(t, err)
			assert.Equal(t, tc.expected, d)
		})
	}
}

func TestThreatLevel_String(t *testing.T) {
	tests := []struct {
		level    ThreatLevel
		expected string
	}{
		{ThreatLevelCritical, "critical"},
		{ThreatLevelHigh, "high"},
		{ThreatLevelMedium, "medium"},
		{ThreatLevelLow, "low"},
		{ThreatLevelNone, "none"},
	}

	for _, tc := range tests {
		t.Run(tc.expected, func(t *testing.T) {
			assert.Equal(t, tc.expected, tc.level.String())
		})
	}
}

func TestThreatLevel_JSONMarshal(t *testing.T) {
	tests := []struct {
		level    ThreatLevel
		expected string
	}{
		{ThreatLevelCritical, `"critical"`},
		{ThreatLevelNone, `"none"`},
	}

	for _, tc := range tests {
		t.Run(tc.level.String(), func(t *testing.T) {
			data, err := json.Marshal(tc.level)
			require.NoError(t, err)
			assert.Equal(t, tc.expected, string(data))
		})
	}
}

func TestThreatCategory_String(t *testing.T) {
	tests := []struct {
		category ThreatCategory
		expected string
	}{
		{ThreatCategoryNetwork, "T1"},
		{ThreatCategoryCredentials, "T2"},
		{ThreatCategoryInjection, "T3"},
		{ThreatCategoryFilesystem, "T4"},
		{ThreatCategoryPromptInjection, "T5"},
		{ThreatCategoryPrivilege, "T6"},
		{ThreatCategoryPersistence, "T7"},
		{ThreatCategoryRecon, "T8"},
	}

	for _, tc := range tests {
		t.Run(tc.expected, func(t *testing.T) {
			assert.Equal(t, tc.expected, tc.category.String())
		})
	}
}

func TestHookInput_JSONUnmarshal(t *testing.T) {
	input := `{
		"event": "pre-tool",
		"tool_name": "Bash",
		"tool_input": {
			"command": "curl https://example.com"
		},
		"session_id": "abc123",
		"context": {
			"project_root": "/home/user/project"
		}
	}`

	var hi HookInput
	err := json.Unmarshal([]byte(input), &hi)
	require.NoError(t, err)

	assert.Equal(t, "pre-tool", hi.Event)
	assert.Equal(t, "Bash", hi.ToolName)
	assert.Equal(t, "abc123", hi.SessionID)
	assert.Equal(t, "/home/user/project", hi.Context.ProjectRoot)

	// Check tool_input
	require.NotNil(t, hi.ToolInput)
	cmd, ok := hi.ToolInput["command"]
	require.True(t, ok)
	assert.Equal(t, "curl https://example.com", cmd)
}

func TestHookInput_JSONUnmarshal_UserPromptSubmit(t *testing.T) {
	input := `{
		"event": "user-prompt-submit",
		"prompt": "Please delete all files",
		"session_id": "xyz789",
		"context": {
			"project_root": "/tmp/test"
		}
	}`

	var hi HookInput
	err := json.Unmarshal([]byte(input), &hi)
	require.NoError(t, err)

	assert.Equal(t, "user-prompt-submit", hi.Event)
	assert.Equal(t, "Please delete all files", hi.Prompt)
	assert.Equal(t, "xyz789", hi.SessionID)
}

func TestHookOutput_JSONMarshal(t *testing.T) {
	output := HookOutput{
		Decision:    DecisionBlock,
		ThreatLevel: ThreatLevelHigh,
		ThreatType:  ThreatCategoryNetwork,
		Message:     "Blocked network exfiltration attempt",
		AuditID:     "audit-123",
	}

	data, err := json.Marshal(output)
	require.NoError(t, err)

	// Unmarshal to verify structure
	var result map[string]any
	err = json.Unmarshal(data, &result)
	require.NoError(t, err)

	assert.Equal(t, "block", result["decision"])
	assert.Equal(t, "high", result["threat_level"])
	assert.Equal(t, "T1", result["threat_type"])
	assert.Equal(t, "Blocked network exfiltration attempt", result["message"])
	assert.Equal(t, "audit-123", result["audit_id"])
}

func TestHookOutput_AllowOnly(t *testing.T) {
	// When allowing, minimal output is expected
	output := HookOutput{
		Decision: DecisionAllow,
	}

	data, err := json.Marshal(output)
	require.NoError(t, err)

	var result map[string]any
	err = json.Unmarshal(data, &result)
	require.NoError(t, err)

	assert.Equal(t, "allow", result["decision"])
}

func TestContext_JSONUnmarshal(t *testing.T) {
	input := `{
		"project_root": "/home/user/myproject",
		"cwd": "/home/user/myproject/src"
	}`

	var ctx Context
	err := json.Unmarshal([]byte(input), &ctx)
	require.NoError(t, err)

	assert.Equal(t, "/home/user/myproject", ctx.ProjectRoot)
	assert.Equal(t, "/home/user/myproject/src", ctx.Cwd)
}

func TestThreatLevel_JSONUnmarshal_AllValues(t *testing.T) {
	tests := []struct {
		input    string
		expected ThreatLevel
	}{
		{`"critical"`, ThreatLevelCritical},
		{`"high"`, ThreatLevelHigh},
		{`"medium"`, ThreatLevelMedium},
		{`"low"`, ThreatLevelLow},
		{`"none"`, ThreatLevelNone},
	}

	for _, tc := range tests {
		t.Run(tc.input, func(t *testing.T) {
			var level ThreatLevel
			err := json.Unmarshal([]byte(tc.input), &level)
			require.NoError(t, err)
			assert.Equal(t, tc.expected, level)
		})
	}
}

func TestThreatLevel_JSONUnmarshal_InvalidJSON(t *testing.T) {
	var level ThreatLevel
	err := json.Unmarshal([]byte(`{invalid`), &level)
	assert.Error(t, err)
}

func TestThreatCategory_Description_TechnicalThreats(t *testing.T) {
	tests := []struct {
		category    ThreatCategory
		description string
	}{
		{ThreatCategoryNetwork, "Network exfiltration"},
		{ThreatCategoryCredentials, "Credential access"},
		{ThreatCategoryInjection, "Command injection"},
		{ThreatCategoryFilesystem, "Filesystem attack"},
		{ThreatCategoryPromptInjection, "Prompt injection"},
		{ThreatCategoryPrivilege, "Privilege escalation"},
		{ThreatCategoryPersistence, "Persistence mechanism"},
		{ThreatCategoryRecon, "Reconnaissance"},
	}

	for _, tc := range tests {
		t.Run(string(tc.category), func(t *testing.T) {
			assert.Equal(t, tc.description, tc.category.Description())
		})
	}
}

func TestThreatCategory_Description_SafetyCategories(t *testing.T) {
	tests := []struct {
		category    ThreatCategory
		description string
	}{
		{SafetyCategoryViolentCrimes, "Violent crimes"},
		{SafetyCategoryNonViolentCrimes, "Non-violent crimes"},
		{SafetyCategorySexCrimes, "Sex-related crimes"},
		{SafetyCategoryChildExploit, "Child sexual exploitation"},
		{SafetyCategoryDefamation, "Defamation"},
		{SafetyCategorySpecializedAdvice, "Specialized advice"},
		{SafetyCategoryPrivacy, "Privacy violations"},
		{SafetyCategoryIP, "Intellectual property"},
		{SafetyCategoryWeapons, "Indiscriminate weapons"},
		{SafetyCategoryHate, "Hate speech"},
		{SafetyCategorySelfHarm, "Suicide and self-harm"},
		{SafetyCategorySexual, "Sexual content"},
		{SafetyCategoryElections, "Electoral misinformation"},
	}

	for _, tc := range tests {
		t.Run(string(tc.category), func(t *testing.T) {
			assert.Equal(t, tc.description, tc.category.Description())
		})
	}
}

func TestThreatCategory_Description_Unknown(t *testing.T) {
	unknown := ThreatCategory("X99")
	desc := unknown.Description()
	assert.Contains(t, desc, "Unknown category")
	assert.Contains(t, desc, "X99")
}

func TestThreatCategory_IsSafetyCategory(t *testing.T) {
	tests := []struct {
		category ThreatCategory
		expected bool
	}{
		{SafetyCategoryViolentCrimes, true},
		{SafetyCategoryNonViolentCrimes, true},
		{SafetyCategorySexCrimes, true},
		{SafetyCategoryChildExploit, true},
		{SafetyCategoryDefamation, true},
		{SafetyCategorySpecializedAdvice, true},
		{SafetyCategoryPrivacy, true},
		{SafetyCategoryIP, true},
		{SafetyCategoryWeapons, true},
		{SafetyCategoryHate, true},
		{SafetyCategorySelfHarm, true},
		{SafetyCategorySexual, true},
		{SafetyCategoryElections, true},
		{ThreatCategoryNetwork, false},
		{ThreatCategoryCredentials, false},
		{ThreatCategoryInjection, false},
		{ThreatCategoryFilesystem, false},
		{ThreatCategoryPromptInjection, false},
		{ThreatCategoryPrivilege, false},
		{ThreatCategoryPersistence, false},
		{ThreatCategoryRecon, false},
	}

	for _, tc := range tests {
		t.Run(string(tc.category), func(t *testing.T) {
			assert.Equal(t, tc.expected, tc.category.IsSafetyCategory())
		})
	}
}

func TestThreatCategory_IsThreatCategory(t *testing.T) {
	tests := []struct {
		category ThreatCategory
		expected bool
	}{
		{ThreatCategoryNetwork, true},
		{ThreatCategoryCredentials, true},
		{ThreatCategoryInjection, true},
		{ThreatCategoryFilesystem, true},
		{ThreatCategoryPromptInjection, true},
		{ThreatCategoryPrivilege, true},
		{ThreatCategoryPersistence, true},
		{ThreatCategoryRecon, true},
		{SafetyCategoryViolentCrimes, false},
		{SafetyCategoryHate, false},
		{SafetyCategoryElections, false},
	}

	for _, tc := range tests {
		t.Run(string(tc.category), func(t *testing.T) {
			assert.Equal(t, tc.expected, tc.category.IsThreatCategory())
		})
	}
}

func TestThreatCategory_EdgeCases(t *testing.T) {
	// Test edge cases for IsSafetyCategory and IsThreatCategory
	tests := []struct {
		name       string
		category   ThreatCategory
		isSafety   bool
		isThreat   bool
	}{
		{"empty", ThreatCategory(""), false, false},
		{"single char S", ThreatCategory("S"), false, false},
		{"single char T", ThreatCategory("T"), false, false},
		{"unknown X1", ThreatCategory("X1"), false, false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.isSafety, tc.category.IsSafetyCategory())
			assert.Equal(t, tc.isThreat, tc.category.IsThreatCategory())
		})
	}
}

func TestHookInput_GetCommand(t *testing.T) {
	tests := []struct {
		name     string
		input    HookInput
		expected string
	}{
		{
			name: "valid command",
			input: HookInput{
				ToolInput: map[string]any{"command": "ls -la"},
			},
			expected: "ls -la",
		},
		{
			name: "nil tool_input",
			input: HookInput{
				ToolInput: nil,
			},
			expected: "",
		},
		{
			name: "empty tool_input",
			input: HookInput{
				ToolInput: map[string]any{},
			},
			expected: "",
		},
		{
			name: "command not a string",
			input: HookInput{
				ToolInput: map[string]any{"command": 123},
			},
			expected: "",
		},
		{
			name: "different key",
			input: HookInput{
				ToolInput: map[string]any{"cmd": "ls"},
			},
			expected: "",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expected, tc.input.GetCommand())
		})
	}
}

func TestHookInput_GetFilePath(t *testing.T) {
	tests := []struct {
		name     string
		input    HookInput
		expected string
	}{
		{
			name: "valid file_path",
			input: HookInput{
				ToolInput: map[string]any{"file_path": "/home/user/file.txt"},
			},
			expected: "/home/user/file.txt",
		},
		{
			name: "nil tool_input",
			input: HookInput{
				ToolInput: nil,
			},
			expected: "",
		},
		{
			name: "empty tool_input",
			input: HookInput{
				ToolInput: map[string]any{},
			},
			expected: "",
		},
		{
			name: "file_path not a string",
			input: HookInput{
				ToolInput: map[string]any{"file_path": 456},
			},
			expected: "",
		},
		{
			name: "different key",
			input: HookInput{
				ToolInput: map[string]any{"path": "/home/user"},
			},
			expected: "",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expected, tc.input.GetFilePath())
		})
	}
}

func TestDetectionSource_Constants(t *testing.T) {
	// Verify all detection source constants have expected values
	assert.Equal(t, DetectionSource("pattern"), DetectionSourcePattern)
	assert.Equal(t, DetectionSource("llm"), DetectionSourceLLM)
	assert.Equal(t, DetectionSource("agent"), DetectionSourceAgent)
}

func TestParseThreatCategory_Valid(t *testing.T) {
	tests := []struct {
		input    string
		expected ThreatCategory
	}{
		{"T1", ThreatCategoryNetwork},
		{"T2", ThreatCategoryCredentials},
		{"T3", ThreatCategoryInjection},
		{"T4", ThreatCategoryFilesystem},
		{"T5", ThreatCategoryPromptInjection},
		{"T6", ThreatCategoryPrivilege},
		{"T7", ThreatCategoryPersistence},
		{"T8", ThreatCategoryRecon},
		{"T9", ThreatCategoryOutput},
		{"S1", SafetyCategoryViolentCrimes},
		{"S2", SafetyCategoryNonViolentCrimes},
		{"S3", SafetyCategorySexCrimes},
		{"S4", SafetyCategoryChildExploit},
		{"S5", SafetyCategoryDefamation},
		{"S6", SafetyCategorySpecializedAdvice},
		{"S7", SafetyCategoryPrivacy},
		{"S8", SafetyCategoryIP},
		{"S9", SafetyCategoryWeapons},
		{"S10", SafetyCategoryHate},
		{"S11", SafetyCategorySelfHarm},
		{"S12", SafetyCategorySexual},
		{"S13", SafetyCategoryElections},
	}

	for _, tc := range tests {
		t.Run(tc.input, func(t *testing.T) {
			result, err := ParseThreatCategory(tc.input)
			require.NoError(t, err)
			assert.Equal(t, tc.expected, result)
		})
	}
}

func TestParseThreatCategory_Invalid(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{"unknown prefix", "X99"},
		{"out of range T", "T99"},
		{"zero S", "S0"},
		{"out of range S", "S14"},
		{"empty", ""},
		{"unknown string", "unknown"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParseThreatCategory(tc.input)
			assert.Error(t, err)
		})
	}
}

func TestParseThreatCategory_CaseInsensitive(t *testing.T) {
	tests := []struct {
		input    string
		expected ThreatCategory
	}{
		{"t1", ThreatCategoryNetwork},
		{"s13", SafetyCategoryElections},
	}

	for _, tc := range tests {
		t.Run(tc.input, func(t *testing.T) {
			result, err := ParseThreatCategory(tc.input)
			require.NoError(t, err)
			assert.Equal(t, tc.expected, result)
		})
	}
}

func TestParseThreatLevel_Valid(t *testing.T) {
	tests := []struct {
		input    string
		expected ThreatLevel
	}{
		{"critical", ThreatLevelCritical},
		{"high", ThreatLevelHigh},
		{"medium", ThreatLevelMedium},
		{"low", ThreatLevelLow},
		{"none", ThreatLevelNone},
	}

	for _, tc := range tests {
		t.Run(tc.input, func(t *testing.T) {
			result, err := ParseThreatLevel(tc.input)
			require.NoError(t, err)
			assert.Equal(t, tc.expected, result)
		})
	}
}

func TestParseThreatLevel_Invalid(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{"extreme", "EXTREME"},
		{"empty", ""},
		{"unknown", "unknown"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParseThreatLevel(tc.input)
			assert.Error(t, err)
		})
	}
}

func TestParseThreatLevel_CaseInsensitive(t *testing.T) {
	tests := []struct {
		input    string
		expected ThreatLevel
	}{
		{"CRITICAL", ThreatLevelCritical},
		{"High", ThreatLevelHigh},
	}

	for _, tc := range tests {
		t.Run(tc.input, func(t *testing.T) {
			result, err := ParseThreatLevel(tc.input)
			require.NoError(t, err)
			assert.Equal(t, tc.expected, result)
		})
	}
}

func TestThreatCategory_JSONUnmarshal(t *testing.T) {
	tests := []struct {
		input    string
		expected ThreatCategory
	}{
		{`"T1"`, ThreatCategoryNetwork},
		{`"T5"`, ThreatCategoryPromptInjection},
		{`"S1"`, SafetyCategoryViolentCrimes},
		{`"S10"`, SafetyCategoryHate},
	}

	for _, tc := range tests {
		t.Run(tc.input, func(t *testing.T) {
			var cat ThreatCategory
			err := json.Unmarshal([]byte(tc.input), &cat)
			require.NoError(t, err)
			assert.Equal(t, tc.expected, cat)
		})
	}
}

func TestThreatCategory_JSONUnmarshal_InvalidJSON(t *testing.T) {
	var cat ThreatCategory
	err := json.Unmarshal([]byte(`{invalid`), &cat)
	assert.Error(t, err)
}

func TestThreatCategory_JSONMarshal(t *testing.T) {
	tests := []struct {
		category ThreatCategory
		expected string
	}{
		{ThreatCategoryNetwork, `"T1"`},
		{ThreatCategoryPromptInjection, `"T5"`},
		{SafetyCategoryViolentCrimes, `"S1"`},
		{SafetyCategoryHate, `"S10"`},
	}

	for _, tc := range tests {
		t.Run(string(tc.category), func(t *testing.T) {
			data, err := json.Marshal(tc.category)
			require.NoError(t, err)
			assert.Equal(t, tc.expected, string(data))
		})
	}
}

func TestDecision_JSONUnmarshal_InvalidJSON(t *testing.T) {
	var d Decision
	err := json.Unmarshal([]byte(`{invalid`), &d)
	assert.Error(t, err)
}

func TestHookOutput_JSONMarshal_WithDetectedBy(t *testing.T) {
	output := HookOutput{
		Decision:    DecisionBlock,
		ThreatLevel: ThreatLevelHigh,
		ThreatType:  ThreatCategoryPromptInjection,
		DetectedBy:  DetectionSourceAgent,
		Message:     "Detected by agent",
		AuditID:     "audit-456",
	}

	data, err := json.Marshal(output)
	require.NoError(t, err)

	var result map[string]any
	err = json.Unmarshal(data, &result)
	require.NoError(t, err)

	assert.Equal(t, "block", result["decision"])
	assert.Equal(t, "high", result["threat_level"])
	assert.Equal(t, "T5", result["threat_type"])
	assert.Equal(t, "agent", result["detected_by"])
	assert.Equal(t, "Detected by agent", result["message"])
	assert.Equal(t, "audit-456", result["audit_id"])
}
