// Package encoding provides detection and decoding of obfuscated content.
package encoding

import (
	"encoding/base64"
	"encoding/hex"
	"regexp"
	"strings"
	"unicode"

	"golang.org/x/text/unicode/norm"
)

// DetectionResult contains the results of encoding detection.
type DetectionResult struct {
	HasObfuscation bool
	DecodedContent string
	EncodingTypes  []string
	Suspicious     bool
}

// maxDecodeDepth limits recursive decoding to prevent infinite loops.
const maxDecodeDepth = 3

// Detector detects and decodes obfuscated content (base64, hex, ROT13, Unicode tricks).
type Detector struct {
	// Patterns for detecting encoded content
	base64Pattern   *regexp.Regexp
	hexPattern      *regexp.Regexp
	injectionKeywords *regexp.Regexp
}

// NewDetector creates a new encoding detector.
func NewDetector() *Detector {
	return &Detector{
		// Match base64 strings (at least 6 base64 chars + optional padding, minimum 8 total)
		base64Pattern: regexp.MustCompile(`[A-Za-z0-9+/]{6,}={0,2}`),
		// Match hex strings (0x prefix or \x sequences)
		hexPattern: regexp.MustCompile(`(?i)(?:0x|\\x)?([0-9a-f]{2}){10,}`),
		// Keywords that indicate injection in decoded content
		injectionKeywords: regexp.MustCompile(`(?i)(ignore|forget|disregard|override|bypass|system|instruction|prompt|jailbreak|DAN|admin|developer)`),
	}
}

// Detect analyzes content for obfuscation and returns decoded content if suspicious.
func (d *Detector) Detect(content string) *DetectionResult {
	result := &DetectionResult{
		DecodedContent: content,
		EncodingTypes:  make([]string, 0),
	}

	// Check for base64 encoded content
	if decoded, found := d.decodeBase64Suspicious(content); found {
		result.HasObfuscation = true
		result.EncodingTypes = append(result.EncodingTypes, "base64")
		result.DecodedContent = content + "\n[DECODED BASE64]: " + decoded
		if d.injectionKeywords.MatchString(decoded) {
			result.Suspicious = true
		}
	}

	// Check for hex encoded content
	if decoded, found := d.decodeHexSuspicious(content); found {
		result.HasObfuscation = true
		result.EncodingTypes = append(result.EncodingTypes, "hex")
		result.DecodedContent = result.DecodedContent + "\n[DECODED HEX]: " + decoded
		if d.injectionKeywords.MatchString(decoded) {
			result.Suspicious = true
		}
	}

	// Check for ROT13 content (if ROT13 keyword is present)
	if strings.Contains(strings.ToLower(content), "rot13") ||
	   strings.Contains(strings.ToLower(content), "caesar") {
		decoded := d.decodeROT13(content)
		result.HasObfuscation = true
		result.EncodingTypes = append(result.EncodingTypes, "rot13")
		result.DecodedContent = result.DecodedContent + "\n[DECODED ROT13]: " + decoded
		if d.injectionKeywords.MatchString(decoded) {
			result.Suspicious = true
		}
	}

	// Check for zero-width characters (invisible unicode)
	if d.hasZeroWidthChars(content) {
		result.HasObfuscation = true
		result.EncodingTypes = append(result.EncodingTypes, "zero-width")
		cleaned := d.removeZeroWidthChars(content)
		if cleaned != content {
			result.DecodedContent = result.DecodedContent + "\n[CLEANED ZERO-WIDTH]: " + cleaned
		}
	}

	// Check for Unicode homoglyphs (Cyrillic lookalikes)
	if d.hasHomoglyphs(content) {
		result.HasObfuscation = true
		result.EncodingTypes = append(result.EncodingTypes, "homoglyph")
		normalized := d.normalizeHomoglyphs(content)
		result.DecodedContent = result.DecodedContent + "\n[NORMALIZED HOMOGLYPHS]: " + normalized
		if d.injectionKeywords.MatchString(normalized) {
			result.Suspicious = true
		}
	}

	// Check for reversed text
	if strings.Contains(strings.ToLower(content), "reversed") ||
	   strings.Contains(strings.ToLower(content), "backwards") {
		reversed := d.reverseString(content)
		if d.injectionKeywords.MatchString(reversed) {
			result.HasObfuscation = true
			result.EncodingTypes = append(result.EncodingTypes, "reversed")
			result.DecodedContent = result.DecodedContent + "\n[REVERSED]: " + reversed
			result.Suspicious = true
		}
	}

	return result
}

// decodeBase64Suspicious attempts to decode base64 content recursively up to maxDecodeDepth.
func (d *Detector) decodeBase64Suspicious(content string) (string, bool) {
	return d.decodeBase64Recursive(content, 0)
}

// decodeBase64Recursive decodes base64 content up to maxDecodeDepth layers.
func (d *Detector) decodeBase64Recursive(content string, depth int) (string, bool) {
	if depth >= maxDecodeDepth {
		return "", false
	}

	matches := d.base64Pattern.FindAllString(content, -1)
	var decodedParts []string

	for _, match := range matches {
		decoded, err := base64.StdEncoding.DecodeString(match)
		if err != nil {
			decoded, err = base64.URLEncoding.DecodeString(match)
			if err != nil {
				continue
			}
		}

		decodedStr := string(decoded)
		if !isPrintableASCII(decodedStr) {
			continue
		}

		// Recursively decode if the decoded content itself contains base64
		if innerDecoded, found := d.decodeBase64Recursive(decodedStr, depth+1); found {
			decodedParts = append(decodedParts, innerDecoded)
		} else {
			decodedParts = append(decodedParts, decodedStr)
		}
	}

	if len(decodedParts) > 0 {
		return strings.Join(decodedParts, " "), true
	}
	return "", false
}

// decodeHexSuspicious attempts to decode hex content.
func (d *Detector) decodeHexSuspicious(content string) (string, bool) {
	// Remove 0x prefixes and \x sequences
	cleaned := strings.ReplaceAll(content, "0x", "")
	cleaned = strings.ReplaceAll(cleaned, "\\x", "")

	matches := d.hexPattern.FindAllString(cleaned, -1)
	var decodedParts []string

	for _, match := range matches {
		// Clean the match
		match = strings.ReplaceAll(match, "0x", "")
		match = strings.ReplaceAll(match, "\\x", "")
		match = strings.ReplaceAll(match, " ", "")

		decoded, err := hex.DecodeString(match)
		if err != nil {
			continue
		}

		decodedStr := string(decoded)
		if isPrintableASCII(decodedStr) {
			decodedParts = append(decodedParts, decodedStr)
		}
	}

	if len(decodedParts) > 0 {
		return strings.Join(decodedParts, " "), true
	}
	return "", false
}

// decodeROT13 applies ROT13 transformation to alphabetic characters.
func (d *Detector) decodeROT13(content string) string {
	result := make([]rune, len(content))
	for i, r := range content {
		switch {
		case r >= 'a' && r <= 'z':
			result[i] = 'a' + (r-'a'+13)%26
		case r >= 'A' && r <= 'Z':
			result[i] = 'A' + (r-'A'+13)%26
		default:
			result[i] = r
		}
	}
	return string(result)
}

// hasZeroWidthChars checks for invisible Unicode characters.
func (d *Detector) hasZeroWidthChars(content string) bool {
	zeroWidthChars := []rune{
		'\u200B', // Zero-width space
		'\u200C', // Zero-width non-joiner
		'\u200D', // Zero-width joiner
		'\uFEFF', // Zero-width no-break space (BOM)
		'\u2060', // Word joiner
		'\u180E', // Mongolian vowel separator
	}

	for _, r := range content {
		for _, zwc := range zeroWidthChars {
			if r == zwc {
				return true
			}
		}
	}
	return false
}

// removeZeroWidthChars removes invisible Unicode characters.
func (d *Detector) removeZeroWidthChars(content string) string {
	zeroWidthChars := []rune{
		'\u200B', '\u200C', '\u200D', '\uFEFF', '\u2060', '\u180E',
	}

	result := strings.Builder{}
	for _, r := range content {
		isZeroWidth := false
		for _, zwc := range zeroWidthChars {
			if r == zwc {
				isZeroWidth = true
				break
			}
		}
		if !isZeroWidth {
			result.WriteRune(r)
		}
	}
	return result.String()
}

// hasHomoglyphs checks for Cyrillic, Greek, or fullwidth lookalike characters.
func (d *Detector) hasHomoglyphs(content string) bool {
	for _, r := range content {
		// Check fullwidth Latin characters (U+FF01 to U+FF5E)
		if r >= '\uFF01' && r <= '\uFF5E' {
			return true
		}
		if unicode.Is(unicode.Cyrillic, r) || unicode.Is(unicode.Greek, r) {
			if isHomoglyph(r) {
				return true
			}
		}
	}
	return false
}

// normalizeHomoglyphs replaces lookalike characters with their Latin equivalents.
// Applies NFKC normalization first (handles fullwidth chars), then manual Cyrillic/Greek mappings.
func (d *Detector) normalizeHomoglyphs(content string) string {
	// NFKC normalization converts fullwidth and other compatibility forms to their canonical equivalents
	content = norm.NFKC.String(content)

	// Common Cyrillic to Latin mappings
	homoglyphMap := map[rune]rune{
		'а': 'a', 'А': 'A', // Cyrillic a
		'е': 'e', 'Е': 'E', // Cyrillic e
		'о': 'o', 'О': 'O', // Cyrillic o
		'р': 'p', 'Р': 'P', // Cyrillic r -> p
		'с': 'c', 'С': 'C', // Cyrillic s -> c
		'у': 'y', 'У': 'Y', // Cyrillic u -> y
		'х': 'x', 'Х': 'X', // Cyrillic kh -> x
		'і': 'i', 'І': 'I', // Ukrainian i
		'ј': 'j', 'Ј': 'J', // Serbian j
		'ѕ': 's', 'Ѕ': 'S', // Macedonian dze
		// Greek
		'α': 'a', 'Α': 'A',
		'ε': 'e', 'Ε': 'E',
		'ο': 'o', 'Ο': 'O',
		'ρ': 'p', 'Ρ': 'P',
		'τ': 't', 'Τ': 'T',
	}

	result := strings.Builder{}
	for _, r := range content {
		if replacement, ok := homoglyphMap[r]; ok {
			result.WriteRune(replacement)
		} else {
			result.WriteRune(r)
		}
	}
	return result.String()
}

// reverseString reverses a string.
func (d *Detector) reverseString(s string) string {
	runes := []rune(s)
	for i, j := 0, len(runes)-1; i < j; i, j = i+1, j-1 {
		runes[i], runes[j] = runes[j], runes[i]
	}
	return string(runes)
}

// isHomoglyph checks if a rune is a known homoglyph.
func isHomoglyph(r rune) bool {
	homoglyphs := []rune{
		'а', 'А', 'е', 'Е', 'о', 'О', 'р', 'Р', 'с', 'С',
		'у', 'У', 'х', 'Х', 'і', 'І', 'ј', 'Ј', 'ѕ', 'Ѕ',
		'α', 'Α', 'ε', 'Ε', 'ο', 'Ο', 'ρ', 'Ρ', 'τ', 'Τ',
	}
	for _, h := range homoglyphs {
		if r == h {
			return true
		}
	}
	return false
}

// isPrintableASCII checks if a string contains mostly printable ASCII.
// Uses a stricter 90% threshold for short strings (under 15 bytes) to reduce
// false positives from the lowered base64 minimum length.
func isPrintableASCII(s string) bool {
	printable := 0
	for _, r := range s {
		if r >= 32 && r <= 126 {
			printable++
		}
	}
	if len(s) == 0 {
		return false
	}
	threshold := 0.8
	if len(s) < 15 {
		threshold = 0.9
	}
	return float64(printable)/float64(len(s)) >= threshold
}
