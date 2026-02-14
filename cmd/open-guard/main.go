// Package main provides the open-guard CLI for AI coding assistant security.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/severity1/open-guard-engine/internal/agent"
	"github.com/severity1/open-guard-engine/internal/config"
	"github.com/severity1/open-guard-engine/internal/encoding"
	"github.com/severity1/open-guard-engine/internal/llm"
	"github.com/severity1/open-guard-engine/internal/patterns"
	"github.com/severity1/open-guard-engine/internal/response"
	"github.com/severity1/open-guard-engine/internal/types"
	"github.com/spf13/cobra"
)

// defaultMaxInputSize is the hardcoded safety limit applied before config is loaded.
// Config's MaxInputSize can override this once loaded, but this prevents unbounded
// reads during the initial stdin consumption.
const defaultMaxInputSize int64 = 10 * 1024 * 1024 // 10MB

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
			var cfg *config.Config
			var err error
			if configPath != "" {
				cfg, err = config.LoadFromPath(configPath)
			} else {
				cfg, err = config.Load(projectRoot)
			}
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
			// Read raw input from stdin with size limit to prevent OOM.
			// Uses hardcoded default since config is loaded after stdin read.
			limitedReader := io.LimitReader(cmd.InOrStdin(), defaultMaxInputSize+1)
			input, err := io.ReadAll(limitedReader)
			if err != nil {
				return fmt.Errorf("reading input: %w", err)
			}
			if int64(len(input)) > defaultMaxInputSize {
				return fmt.Errorf("input exceeds maximum size of %d bytes", defaultMaxInputSize)
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
			var cfg *config.Config
			if configPath != "" {
				cfg, err = config.LoadFromPath(configPath)
			} else {
				cfg, err = config.Load(projectRoot)
			}
			if err != nil {
				return fmt.Errorf("loading config: %w", err)
			}

			// Validate input size against config (may be stricter than hardcoded default)
			if cfg.MaxInputSize > 0 && int64(len(input)) > cfg.MaxInputSize {
				return fmt.Errorf("input exceeds maximum size of %d bytes", cfg.MaxInputSize)
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
					agentTimeout := time.Duration(cfg.Agent.TimeoutSeconds) * time.Second
					if agentTimeout == 0 {
						agentTimeout = 60 * time.Second
					}
					agentCtx, agentCancel := context.WithTimeout(context.Background(), agentTimeout)
					defer agentCancel()

					result, err := claudeAnalyzer.Analyze(agentCtx, analysisContent)
					if err != nil {
						if output := handleAnalysisError(cfg, respHandler, types.DetectionSourceAgent, types.ThreatCategoryPromptInjection, err); output != nil {
							return outputJSON(cmd, output)
						}
					} else if !result.Safe {
						reason := result.Reason
						if reason == "" {
							reason = "detected by semantic analysis"
						}
						output := respHandler.BuildWithModeOverrideAndSource(
							types.DecisionConfirm,
							types.ThreatLevelHigh,
							types.ThreatCategoryPromptInjection,
							types.DetectionSourceAgent,
							fmt.Sprintf("Potential injection: %s", reason),
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
					llmTimeout := time.Duration(cfg.LLM.TimeoutSeconds) * time.Second
					if llmTimeout == 0 {
						llmTimeout = 30 * time.Second
					}
					llmCtx, llmCancel := context.WithTimeout(context.Background(), llmTimeout)
					defer llmCancel()

					result, err := contentAnalyzer.Analyze(llmCtx, analysisContent)
					if err != nil {
						if output := handleAnalysisError(cfg, respHandler, types.DetectionSourceLLM, types.SafetyCategoryViolentCrimes, err); output != nil {
							return outputJSON(cmd, output)
						}
					} else if !result.Safe {
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

// handleAnalysisError handles errors from agent/LLM analysis layers.
// In permissive mode, errors are ignored and the pipeline continues (returns nil).
// In other modes, errors produce a confirm decision (mode override transforms: strict -> block).
func handleAnalysisError(cfg *config.Config, respHandler *response.Handler, source types.DetectionSource, category types.ThreatCategory, analysisErr error) *types.HookOutput {
	if cfg.Mode == config.ModePermissive {
		return nil
	}
	return respHandler.BuildWithModeOverrideAndSource(
		types.DecisionConfirm,
		types.ThreatLevelMedium,
		category,
		source,
		fmt.Sprintf("Analysis error: %s", analysisErr.Error()),
	)
}

func mapCategory(categories []string) types.ThreatCategory {
	if len(categories) == 0 {
		return types.SafetyCategoryViolentCrimes // S1 default for unknown LLM output
	}
	cat := categories[0]
	parsed, err := types.ParseThreatCategory(cat)
	if err != nil {
		return types.SafetyCategoryViolentCrimes // S1 fallback for unrecognized categories
	}
	return parsed
}

