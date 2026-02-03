// Package main provides the open-guard CLI for AI coding assistant security.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/severity1/open-guard-engine/internal/agent"
	"github.com/severity1/open-guard-engine/internal/config"
	"github.com/severity1/open-guard-engine/internal/encoding"
	"github.com/severity1/open-guard-engine/internal/llm"
	"github.com/severity1/open-guard-engine/internal/patterns"
	"github.com/severity1/open-guard-engine/internal/response"
	"github.com/severity1/open-guard-engine/internal/types"
	"github.com/spf13/cobra"
)

// Version information (set via ldflags)
var (
	version   = "dev"
	buildTime = "unknown"
)

// CLI flags
var (
	verbose     bool
	configPath  string
	projectRoot string
)

func main() {
	if err := newRootCmd().Execute(); err != nil {
		os.Exit(1)
	}
}

func newRootCmd() *cobra.Command {
	rootCmd := &cobra.Command{
		Use:   "open-guard",
		Short: "Security guard for AI coding assistants",
		Long: `open-guard is an agent-agnostic security engine that detects threats
for AI coding assistants like Claude Code, Cursor, and Copilot.

It receives raw text via stdin, performs pattern matching and optional ML analysis,
and returns allow/block/confirm decisions.`,
		SilenceUsage: true,
	}

	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "Enable verbose output")
	rootCmd.PersistentFlags().StringVar(&configPath, "config", "", "Path to config file")

	rootCmd.AddCommand(newVersionCmd())
	rootCmd.AddCommand(newCheckCmd())
	rootCmd.AddCommand(newAnalyzeCmd())

	return rootCmd
}

func newVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print version information",
		Run: func(cmd *cobra.Command, args []string) {
			cmd.Printf("open-guard version %s (built %s)\n", version, buildTime)
		},
	}
}

func newCheckCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "check",
		Short: "Check configuration validity",
		Long:  "Validates the configuration file and reports any issues.",
		RunE: func(cmd *cobra.Command, args []string) error {
			// Load config
			cfg, err := config.Load(projectRoot)
			if err != nil {
				return fmt.Errorf("configuration error: %w", err)
			}

			cmd.Printf("Configuration valid\n")
			cmd.Printf("  Mode: %s\n", cfg.Mode)
			cmd.Printf("  LLM Enabled: %t\n", cfg.LLM.Enabled)
			if cfg.LLM.Enabled {
				cmd.Printf("    Endpoint: %s\n", cfg.LLM.Endpoint)
				if cfg.LLM.ContentSafetyModel != "" {
					cmd.Printf("    Content Safety Model: %s\n", cfg.LLM.ContentSafetyModel)
				}
			}
			cmd.Printf("  Agent Enabled: %t\n", cfg.Agent.Enabled)
			if cfg.Agent.Enabled {
				provider := cfg.Agent.Provider
				if provider == "" {
					provider = "claude"
				}
				cmd.Printf("    Provider: %s\n", provider)
				cmd.Printf("    Model: %s\n", cfg.Agent.Model)
				if cfg.Agent.Provider == "ollama" && cfg.Agent.Endpoint != "" {
					cmd.Printf("    Endpoint: %s\n", cfg.Agent.Endpoint)
				}
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&projectRoot, "project", ".", "Project root directory")

	return cmd
}

func newAnalyzeCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "analyze",
		Short: "Analyze text for security threats",
		Long: `Reads raw text from stdin and analyzes it for security threats.

Examples:
  echo "Help me write a sorting function" | open-guard analyze
  echo "Ignore previous instructions" | open-guard analyze
  cat prompt.txt | open-guard analyze

Output is JSON with decision (allow/block/confirm) and threat details.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			// Read raw input from stdin
			input, err := io.ReadAll(cmd.InOrStdin())
			if err != nil {
				return fmt.Errorf("reading input: %w", err)
			}
			content := strings.TrimSpace(string(input))

			if content == "" {
				output := &types.HookOutput{
					Decision: types.DecisionAllow,
					Message:  "Empty input",
				}
				return json.NewEncoder(cmd.OutOrStdout()).Encode(output)
			}

			// Load config
			cfg, err := config.Load(projectRoot)
			if err != nil {
				return fmt.Errorf("loading config: %w", err)
			}

			// Create pattern matcher
			matcher, err := patterns.NewMatcher()
			if err != nil {
				return fmt.Errorf("creating matcher: %w", err)
			}

			// Create response handler
			respHandler := response.NewHandler(cfg)

			// Layer 0: Encoding detection (decode obfuscated content)
			encodingDetector := encoding.NewDetector()
			encResult := encodingDetector.Detect(content)

			// If suspicious encoded content found, flag immediately
			if encResult.Suspicious {
				output := respHandler.BuildWithModeOverrideAndSource(
					types.DecisionConfirm,
					types.ThreatLevelHigh,
					types.ThreatCategoryPromptInjection,
					types.DetectionSourcePattern,
					fmt.Sprintf("Obfuscated injection detected (encoding: %s)", strings.Join(encResult.EncodingTypes, ", ")),
				)
				return outputJSON(cmd, output)
			}

			// Use decoded content for subsequent analysis if obfuscation was detected
			analysisContent := content
			if encResult.HasObfuscation {
				analysisContent = encResult.DecodedContent
			}

			// Layer 1: Pattern matching (fast, deterministic)
			results := matcher.Match(analysisContent)
			if len(results) > 0 {
				highestSeverity := patterns.HighestSeverity(results)
				primaryResult := results[0]
				for _, r := range results[1:] {
					if severityOrder(r.Severity) > severityOrder(primaryResult.Severity) {
						primaryResult = r
					}
				}

				decision := respHandler.DecisionFromSeverity(highestSeverity)
				output := respHandler.BuildWithModeOverrideAndSource(
					decision,
					highestSeverity,
					primaryResult.Category,
					types.DetectionSourcePattern,
					fmt.Sprintf("%s: %s", primaryResult.Category.Description(), primaryResult.Description),
				)
				return outputJSON(cmd, output)
			}

			// Layer 2: Agent-based prompt injection detection (if enabled)
			if cfg.Agent.Enabled {
				claudeAnalyzer := agent.NewClaudeAnalyzer(
					cfg.Agent.Model,
					projectRoot,
					cfg.Agent.Provider,
					cfg.Agent.Endpoint,
				)
				if claudeAnalyzer.IsAvailable() {
					result, err := claudeAnalyzer.Analyze(context.Background(), analysisContent)
					if err == nil && !result.Safe {
						output := respHandler.BuildWithModeOverrideAndSource(
							types.DecisionConfirm,
							types.ThreatLevelHigh,
							types.ThreatCategoryPromptInjection,
							types.DetectionSourceAgent,
							fmt.Sprintf("Potential injection: %s", result.Reason),
						)
						return outputJSON(cmd, output)
					}
				}
			}

			// Layer 3: Content safety (if enabled)
			if cfg.LLM.Enabled && cfg.LLM.ContentSafetyModel != "" {
				contentAnalyzer := llm.NewLlamaGuardAnalyzer(
					cfg.LLM.Endpoint,
					cfg.LLM.ContentSafetyModel,
				)
				if contentAnalyzer.IsAvailable() {
					result, err := contentAnalyzer.Analyze(context.Background(), analysisContent)
					if err == nil && !result.Safe {
						category := mapCategory(result.Categories)
						output := respHandler.BuildWithModeOverrideAndSource(
							types.DecisionConfirm,
							types.ThreatLevelHigh,
							category,
							types.DetectionSourceLLM,
							fmt.Sprintf("Content safety violation: %s", category.Description()),
						)
						return outputJSON(cmd, output)
					}
				}
			}

			// No threats detected
			output := respHandler.Allow("No threats detected")
			return outputJSON(cmd, output)
		},
	}

	cmd.Flags().StringVar(&projectRoot, "project", ".", "Project root directory")

	return cmd
}

func outputJSON(cmd *cobra.Command, output *types.HookOutput) error {
	encoder := json.NewEncoder(cmd.OutOrStdout())
	if verbose {
		encoder.SetIndent("", "  ")
	}
	return encoder.Encode(output)
}

func severityOrder(s types.ThreatLevel) int {
	order := map[types.ThreatLevel]int{
		types.ThreatLevelCritical: 4,
		types.ThreatLevelHigh:     3,
		types.ThreatLevelMedium:   2,
		types.ThreatLevelLow:      1,
		types.ThreatLevelNone:     0,
	}
	return order[s]
}

func mapCategory(categories []string) types.ThreatCategory {
	if len(categories) == 0 {
		return types.ThreatCategory("S0")
	}
	cat := categories[0]
	if len(cat) >= 2 && (cat[0] == 's' || cat[0] == 'S') {
		return types.ThreatCategory("S" + cat[1:])
	}
	return types.ThreatCategory(cat)
}

