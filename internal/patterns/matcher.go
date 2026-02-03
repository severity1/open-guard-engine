// Package patterns provides regex-based threat pattern matching.
package patterns

import (
	_ "embed"
	"regexp"
	"strings"

	"github.com/severity1/open-guard-engine/internal/types"
	"gopkg.in/yaml.v3"
)

//go:embed patterns.yaml
var patternsYAML []byte

// PatternDef defines a single threat pattern from the YAML file.
type PatternDef struct {
	ID          string            `yaml:"id"`
	Category    string            `yaml:"category"`
	Name        string            `yaml:"name"`
	Description string            `yaml:"description"`
	Severity    string            `yaml:"severity"`
	Pattern     string            `yaml:"pattern"`
	Extract     map[string]string `yaml:"extract,omitempty"`
}

// PatternsFile represents the structure of patterns.yaml.
type PatternsFile struct {
	Patterns []PatternDef `yaml:"patterns"`
}

// CompiledPattern is a pattern with pre-compiled regex.
type CompiledPattern struct {
	PatternDef
	Regex        *regexp.Regexp
	ExtractRegex map[string]*regexp.Regexp
}

// MatchResult represents a pattern match.
type MatchResult struct {
	PatternID   string
	PatternName string
	Category    types.ThreatCategory
	Severity    types.ThreatLevel
	Description string
	Extracted   map[string]string
}

// Matcher performs pattern matching against content.
type Matcher struct {
	patterns []CompiledPattern
}

// NewMatcher creates a new Matcher with embedded patterns.
func NewMatcher() (*Matcher, error) {
	var pf PatternsFile
	if err := yaml.Unmarshal(patternsYAML, &pf); err != nil {
		return nil, err
	}

	m := &Matcher{
		patterns: make([]CompiledPattern, 0, len(pf.Patterns)),
	}

	for _, p := range pf.Patterns {
		re, err := regexp.Compile(p.Pattern)
		if err != nil {
			return nil, err
		}

		cp := CompiledPattern{
			PatternDef:   p,
			Regex:        re,
			ExtractRegex: make(map[string]*regexp.Regexp),
		}

		// Compile extraction patterns
		for name, pattern := range p.Extract {
			extractRe, err := regexp.Compile(pattern)
			if err != nil {
				return nil, err
			}
			cp.ExtractRegex[name] = extractRe
		}

		m.patterns = append(m.patterns, cp)
	}

	return m, nil
}

// Match checks content against all patterns.
func (m *Matcher) Match(content string) []MatchResult {
	var results []MatchResult

	for _, p := range m.patterns {
		if p.Regex.MatchString(content) {
			result := MatchResult{
				PatternID:   p.ID,
				PatternName: p.Name,
				Category:    categoryFromString(p.Category),
				Severity:    severityFromString(p.Severity),
				Description: p.Description,
				Extracted:   make(map[string]string),
			}

			// Extract values
			for name, re := range p.ExtractRegex {
				if matches := re.FindStringSubmatch(content); len(matches) > 1 {
					result.Extracted[name] = matches[1]
				}
			}

			results = append(results, result)
		}
	}

	return results
}

// categoryFromString converts a category string to ThreatCategory.
func categoryFromString(s string) types.ThreatCategory {
	switch strings.ToUpper(s) {
	case "T1":
		return types.ThreatCategoryNetwork
	case "T2":
		return types.ThreatCategoryCredentials
	case "T3":
		return types.ThreatCategoryInjection
	case "T4":
		return types.ThreatCategoryFilesystem
	case "T5":
		return types.ThreatCategoryPromptInjection
	case "T6":
		return types.ThreatCategoryPrivilege
	case "T7":
		return types.ThreatCategoryPersistence
	case "T8":
		return types.ThreatCategoryRecon
	case "T9":
		return types.ThreatCategoryOutput
	default:
		return types.ThreatCategory(s)
	}
}

// severityFromString converts a severity string to ThreatLevel.
func severityFromString(s string) types.ThreatLevel {
	switch strings.ToLower(s) {
	case "critical":
		return types.ThreatLevelCritical
	case "high":
		return types.ThreatLevelHigh
	case "medium":
		return types.ThreatLevelMedium
	case "low":
		return types.ThreatLevelLow
	default:
		return types.ThreatLevelNone
	}
}

// HighestSeverity returns the highest severity from a list of results.
func HighestSeverity(results []MatchResult) types.ThreatLevel {
	if len(results) == 0 {
		return types.ThreatLevelNone
	}

	severityOrder := map[types.ThreatLevel]int{
		types.ThreatLevelCritical: 4,
		types.ThreatLevelHigh:     3,
		types.ThreatLevelMedium:   2,
		types.ThreatLevelLow:      1,
		types.ThreatLevelNone:     0,
	}

	highest := types.ThreatLevelNone
	for _, r := range results {
		if severityOrder[r.Severity] > severityOrder[highest] {
			highest = r.Severity
		}
	}
	return highest
}
