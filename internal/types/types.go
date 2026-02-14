// Package types defines shared types for the open-guard security engine.
package types

import (
	"encoding/json"
	"fmt"
	"strings"
)

// Decision represents the action to take for a hook event.
type Decision string

const (
	DecisionBlock     Decision = "block"
	DecisionConfirm   Decision = "confirm"
	DecisionScrub     Decision = "scrub"
	DecisionRemediate Decision = "remediate"
	DecisionLog       Decision = "log"
	DecisionAllow     Decision = "allow"
)

func (d Decision) String() string {
	return string(d)
}

func (d Decision) MarshalJSON() ([]byte, error) {
	return json.Marshal(string(d))
}

func (d *Decision) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}
	*d = Decision(s)
	return nil
}

// ThreatLevel indicates the severity of a detected threat.
type ThreatLevel string

const (
	ThreatLevelCritical ThreatLevel = "critical"
	ThreatLevelHigh     ThreatLevel = "high"
	ThreatLevelMedium   ThreatLevel = "medium"
	ThreatLevelLow      ThreatLevel = "low"
	ThreatLevelNone     ThreatLevel = "none"
)

func (t ThreatLevel) String() string {
	return string(t)
}

func (t ThreatLevel) MarshalJSON() ([]byte, error) {
	return json.Marshal(string(t))
}

func (t *ThreatLevel) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}
	*t = ThreatLevel(s)
	return nil
}

// ThreatCategory represents the type of threat (T1-T8 technical, S1-S13 content safety).
type ThreatCategory string

// Technical security threats (detected via pattern matching)
const (
	ThreatCategoryNetwork         ThreatCategory = "T1" // Network exfiltration
	ThreatCategoryCredentials     ThreatCategory = "T2" // Credential access
	ThreatCategoryInjection       ThreatCategory = "T3" // Command injection
	ThreatCategoryFilesystem      ThreatCategory = "T4" // Filesystem attacks
	ThreatCategoryPromptInjection ThreatCategory = "T5" // Prompt injection
	ThreatCategoryPrivilege       ThreatCategory = "T6" // Privilege escalation
	ThreatCategoryPersistence     ThreatCategory = "T7" // Persistence mechanisms
	ThreatCategoryRecon           ThreatCategory = "T8" // Reconnaissance
	ThreatCategoryOutput          ThreatCategory = "T9" // Output monitoring (leaked prompts, credentials)
)

// Content safety categories (detected via llama-guard3)
const (
	SafetyCategoryViolentCrimes    ThreatCategory = "S1"  // Violent crimes
	SafetyCategoryNonViolentCrimes ThreatCategory = "S2"  // Non-violent crimes
	SafetyCategorySexCrimes        ThreatCategory = "S3"  // Sex-related crimes
	SafetyCategoryChildExploit     ThreatCategory = "S4"  // Child sexual exploitation
	SafetyCategoryDefamation       ThreatCategory = "S5"  // Defamation
	SafetyCategorySpecializedAdvice ThreatCategory = "S6" // Specialized advice
	SafetyCategoryPrivacy          ThreatCategory = "S7"  // Privacy violations
	SafetyCategoryIP               ThreatCategory = "S8"  // Intellectual property
	SafetyCategoryWeapons          ThreatCategory = "S9"  // Indiscriminate weapons
	SafetyCategoryHate             ThreatCategory = "S10" // Hate speech
	SafetyCategorySelfHarm         ThreatCategory = "S11" // Suicide and self-harm
	SafetyCategorySexual           ThreatCategory = "S12" // Sexual content
	SafetyCategoryElections        ThreatCategory = "S13" // Electoral misinformation
)

func (t ThreatCategory) String() string {
	return string(t)
}

func (t ThreatCategory) MarshalJSON() ([]byte, error) {
	return json.Marshal(string(t))
}

func (t *ThreatCategory) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}
	*t = ThreatCategory(s)
	return nil
}

// Description returns a human-readable description of the threat category.
func (t ThreatCategory) Description() string {
	descriptions := map[ThreatCategory]string{
		// Technical security (T1-T9)
		ThreatCategoryNetwork:         "Network exfiltration",
		ThreatCategoryCredentials:     "Credential access",
		ThreatCategoryInjection:       "Command injection",
		ThreatCategoryFilesystem:      "Filesystem attack",
		ThreatCategoryPromptInjection: "Prompt injection",
		ThreatCategoryPrivilege:       "Privilege escalation",
		ThreatCategoryPersistence:     "Persistence mechanism",
		ThreatCategoryRecon:           "Reconnaissance",
		ThreatCategoryOutput:          "Output monitoring",
		// Content safety (S1-S13)
		SafetyCategoryViolentCrimes:     "Violent crimes",
		SafetyCategoryNonViolentCrimes:  "Non-violent crimes",
		SafetyCategorySexCrimes:         "Sex-related crimes",
		SafetyCategoryChildExploit:      "Child sexual exploitation",
		SafetyCategoryDefamation:        "Defamation",
		SafetyCategorySpecializedAdvice: "Specialized advice",
		SafetyCategoryPrivacy:           "Privacy violations",
		SafetyCategoryIP:                "Intellectual property",
		SafetyCategoryWeapons:           "Indiscriminate weapons",
		SafetyCategoryHate:              "Hate speech",
		SafetyCategorySelfHarm:          "Suicide and self-harm",
		SafetyCategorySexual:            "Sexual content",
		SafetyCategoryElections:         "Electoral misinformation",
	}
	if desc, ok := descriptions[t]; ok {
		return desc
	}
	return fmt.Sprintf("Unknown category: %s", t)
}

// IsSafetyCategory returns true if this is a content safety category (S1-S13).
func (t ThreatCategory) IsSafetyCategory() bool {
	return len(t) >= 2 && t[0] == 'S'
}

// IsThreatCategory returns true if this is a technical threat category (T1-T9).
func (t ThreatCategory) IsThreatCategory() bool {
	return len(t) >= 2 && t[0] == 'T'
}

// validThreatCategories maps uppercase category strings to their ThreatCategory constants.
var validThreatCategories = map[string]ThreatCategory{
	"T1":  ThreatCategoryNetwork,
	"T2":  ThreatCategoryCredentials,
	"T3":  ThreatCategoryInjection,
	"T4":  ThreatCategoryFilesystem,
	"T5":  ThreatCategoryPromptInjection,
	"T6":  ThreatCategoryPrivilege,
	"T7":  ThreatCategoryPersistence,
	"T8":  ThreatCategoryRecon,
	"T9":  ThreatCategoryOutput,
	"S1":  SafetyCategoryViolentCrimes,
	"S2":  SafetyCategoryNonViolentCrimes,
	"S3":  SafetyCategorySexCrimes,
	"S4":  SafetyCategoryChildExploit,
	"S5":  SafetyCategoryDefamation,
	"S6":  SafetyCategorySpecializedAdvice,
	"S7":  SafetyCategoryPrivacy,
	"S8":  SafetyCategoryIP,
	"S9":  SafetyCategoryWeapons,
	"S10": SafetyCategoryHate,
	"S11": SafetyCategorySelfHarm,
	"S12": SafetyCategorySexual,
	"S13": SafetyCategoryElections,
}

// ParseThreatCategory parses a string into a ThreatCategory.
// Case-insensitive. Returns an error for unknown values.
func ParseThreatCategory(s string) (ThreatCategory, error) {
	if cat, ok := validThreatCategories[strings.ToUpper(s)]; ok {
		return cat, nil
	}
	return "", fmt.Errorf("invalid threat category: %q", s)
}

// validThreatLevels maps lowercase level strings to their ThreatLevel constants.
var validThreatLevels = map[string]ThreatLevel{
	"critical": ThreatLevelCritical,
	"high":     ThreatLevelHigh,
	"medium":   ThreatLevelMedium,
	"low":      ThreatLevelLow,
	"none":     ThreatLevelNone,
}

// ParseThreatLevel parses a string into a ThreatLevel.
// Case-insensitive. Returns an error for unknown values.
func ParseThreatLevel(s string) (ThreatLevel, error) {
	if level, ok := validThreatLevels[strings.ToLower(s)]; ok {
		return level, nil
	}
	return "", fmt.Errorf("invalid threat level: %q", s)
}

// DetectionSource indicates which layer detected the threat.
type DetectionSource string

const (
	DetectionSourcePattern DetectionSource = "pattern" // Regex pattern matching
	DetectionSourceLLM     DetectionSource = "llm"     // Ollama LLM (llama3, llama-guard)
	DetectionSourceAgent   DetectionSource = "agent"   // Claude agent SDK
)

// HookOutput represents the JSON response returned to Claude Code.
type HookOutput struct {
	Decision    Decision        `json:"decision"`
	ThreatLevel ThreatLevel     `json:"threat_level,omitempty"`
	ThreatType  ThreatCategory  `json:"threat_type,omitempty"`
	DetectedBy  DetectionSource `json:"detected_by,omitempty"`
	Message     string          `json:"message,omitempty"`
	AuditID     string          `json:"audit_id,omitempty"`
}
