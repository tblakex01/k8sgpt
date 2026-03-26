/*
Copyright 2023 The K8sGPT Authors.
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at
    http://www.apache.org/licenses/LICENSE-2.0
Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package analyze

import (
	"database/sql"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/fatih/color"
	"github.com/k8sgpt-ai/k8sgpt/pkg/ai/interactive"
	"github.com/k8sgpt-ai/k8sgpt/pkg/analysis"
	"github.com/k8sgpt-ai/k8sgpt/pkg/common"
	"github.com/k8sgpt-ai/k8sgpt/pkg/policy"
	"github.com/k8sgpt-ai/k8sgpt/pkg/store"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var (
	explain         bool
	backend         string
	output          string
	filters         []string
	language        string
	nocache         bool
	namespace       string
	labelSelector   string
	anonymize       bool
	maxConcurrency  int
	withDoc         bool
	interactiveMode bool
	customAnalysis  bool
	customHeaders     []string
	withStats         bool
	severityThreshold string
	remediate         bool
	dryRun            bool
	noStore           bool
	policyMode        string
)

// AnalyzeCmd represents the problems command
var AnalyzeCmd = &cobra.Command{
	Use:     "analyze",
	Aliases: []string{"analyse"},
	Short:   "This command will find problems within your Kubernetes cluster",
	Long: `This command will find problems within your Kubernetes cluster and
	provide you with a list of issues that need to be resolved`,
	Run: func(cmd *cobra.Command, args []string) {
		// Create analysis configuration first.
		config, err := analysis.NewAnalysis(
			backend,
			language,
			filters,
			namespace,
			labelSelector,
			nocache,
			explain,
			maxConcurrency,
			withDoc,
			interactiveMode,
			customHeaders,
			withStats,
		)

		verbose := viper.GetBool("verbose")
		if verbose {
			fmt.Println("Debug: Checking analysis configuration.")
		}
		if err != nil {
			color.Red("Error: %v", err)
			os.Exit(1)
		}
		if verbose {
			fmt.Println("Debug: Analysis initialized.")
		}
		defer config.Close()

		if dryRun && !remediate {
			color.Red("Error: --dry-run requires --remediate")
			os.Exit(1)
		}
		if remediate && !dryRun {
			fi, err := os.Stdin.Stat()
			if err != nil || fi.Mode()&os.ModeCharDevice == 0 {
				color.Red("Error: --remediate requires an interactive terminal; use --dry-run to preview")
				os.Exit(1)
			}
		}
		if severityThreshold != "" && !common.Severity(severityThreshold).IsValid() {
			color.Red("Error: invalid severity threshold %q (valid: critical, high, medium, low)", severityThreshold)
			os.Exit(1)
		}
		config.SeverityThreshold = severityThreshold

		storePath := viper.GetString("store.path")
		if storePath == "" {
			homeDir, _ := os.UserHomeDir()
			storePath = filepath.Join(homeDir, ".k8sgpt", "history.db")
		}
		if !noStore {
			resultStore, storeErr := store.NewSQLiteStore(storePath)
			if storeErr != nil {
				color.Yellow("Warning: could not initialize store: %v", storeErr)
			} else {
				config.Store = resultStore
				defer resultStore.Close()
			}
		}
		config.NoStore = noStore

		if customAnalysis {
			config.RunCustomAnalysis()
			if verbose {
				fmt.Println("Debug: All custom analyzers completed.")
			}
		}
		config.RunAnalysis()
		if verbose {
			fmt.Println("Debug: All core analyzers completed.")
		}

		config.FilterBySeverity()
		config.SortBySeverity()

		config.ComputeScore()
		kubecontext := viper.GetString("kubecontext")
		if kubecontext == "" {
			kubecontext = "default"
		}
		if err := config.SaveToStore(kubecontext); err != nil {
			color.Yellow("Warning: failed to save results to store: %v", err)
		}
		if config.Store != nil {
			retention := viper.GetString("store.retention")
			if retention != "" {
				if d, parseErr := time.ParseDuration(retention); parseErr == nil {
					config.Store.Prune(d) //nolint:errcheck
				}
			}
		}

		if explain {
			err := config.GetAIResults(output, anonymize)
			if verbose {
				fmt.Println("Debug: Checking AI results.")
			}
			if err != nil {
				color.Red("Error: %v", err)
				os.Exit(1)
			}
		}

		// print results
		output_data, err := config.PrintOutput(output)
		if verbose {
			fmt.Println("Debug: Checking output.")
		}
		if err != nil {
			color.Red("Error: %v", err)
			os.Exit(1)
		}

		if withStats {
			statsData := config.PrintStats()
			fmt.Println(string(statsData))
		}

		fmt.Println(string(output_data))

		if remediate {
			policies := policy.LoadPolicies()
			if len(policies) > 0 {
				var db *sql.DB
				if config.Store != nil {
					if sqlStore, ok := config.Store.(*store.SQLiteStore); ok {
						db = sqlStore.DB()
					}
				}
				engine := &policy.Engine{
					Policies:   policies,
					DB:         db,
					PolicyMode: policyMode,
				}
				outcomes := engine.Evaluate(config.Results, namespace)
				if verbose {
					fmt.Printf("Debug: Policy engine evaluated %d outcomes.\n", len(outcomes))
				}
			} else {
				// Fallback to legacy interactive remediation
				if err := config.RunRemediation(dryRun); err != nil {
					color.Red("Error during remediation: %v", err)
					os.Exit(1)
				}
			}
		}

		if interactiveMode && explain {
			if output == "json" {
				color.Yellow("Caution: interactive mode using --json enabled may use additional tokens.")
			}
			sigs := make(chan os.Signal, 1)
			signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
			interactiveClient := interactive.NewInteractionRunner(config, output_data)

			go interactiveClient.StartInteraction()
			for {
				select {
				case res := <-sigs:
					switch res {
					default:
						os.Exit(0)
					}
				case res := <-interactiveClient.State:
					switch res {
					case interactive.E_EXITED:
						os.Exit(0)
					}
				}
			}
		}
	},
}

func init() {
	// namespace flag
	AnalyzeCmd.Flags().StringVarP(&namespace, "namespace", "n", "", "Namespace to analyze")
	// no cache flag
	AnalyzeCmd.Flags().BoolVarP(&nocache, "no-cache", "c", false, "Do not use cached data")
	// anonymize flag
	AnalyzeCmd.Flags().BoolVarP(&anonymize, "anonymize", "a", false, "Anonymize data before sending it to the AI backend. This flag masks sensitive data, such as Kubernetes object names and labels, by replacing it with a key. However, please note that this flag does not currently apply to events.")
	// array of strings flag
	AnalyzeCmd.Flags().StringSliceVarP(&filters, "filter", "f", []string{}, "Filter for these analyzers (e.g. Pod, PersistentVolumeClaim, Service, ReplicaSet)")
	// explain flag
	AnalyzeCmd.Flags().BoolVarP(&explain, "explain", "e", false, "Explain the problem to me")
	// add flag for backend
	AnalyzeCmd.Flags().StringVarP(&backend, "backend", "b", "", "Backend AI provider")
	// output as json
	AnalyzeCmd.Flags().StringVarP(&output, "output", "o", "text", "Output format (text, json)")
	// add language options for output
	AnalyzeCmd.Flags().StringVarP(&language, "language", "l", "english", "Languages to use for AI (e.g. 'English', 'Spanish', 'French', 'German', 'Italian', 'Portuguese', 'Dutch', 'Russian', 'Chinese', 'Japanese', 'Korean')")
	// add max concurrency
	AnalyzeCmd.Flags().IntVarP(&maxConcurrency, "max-concurrency", "m", 10, "Maximum number of concurrent requests to the Kubernetes API server")
	// kubernetes doc flag
	AnalyzeCmd.Flags().BoolVarP(&withDoc, "with-doc", "d", false, "Give me the official documentation of the involved field")
	// interactive mode flag
	AnalyzeCmd.Flags().BoolVarP(&interactiveMode, "interactive", "i", false, "Enable interactive mode that allows further conversation with LLM about the problem. Works only with --explain flag")
	// custom analysis flag
	AnalyzeCmd.Flags().BoolVarP(&customAnalysis, "custom-analysis", "z", false, "Enable custom analyzers")
	// add custom headers flag
	AnalyzeCmd.Flags().StringSliceVarP(&customHeaders, "custom-headers", "r", []string{}, "Custom Headers, <key>:<value> (e.g CustomHeaderKey:CustomHeaderValue AnotherHeader:AnotherValue)")
	// label selector flag
	AnalyzeCmd.Flags().StringVarP(&labelSelector, "selector", "L", "", "Label selector (label query) to filter on, supports '=', '==', and '!='. (e.g. -L key1=value1,key2=value2). Matching objects must satisfy all of the specified label constraints.")
	// print stats
	AnalyzeCmd.Flags().BoolVarP(&withStats, "with-stat", "s", false, "Print analysis stats. This option disables errors display.")
	// severity threshold flag
	AnalyzeCmd.Flags().StringVarP(&severityThreshold, "severity-threshold", "S", "", "Filter results by minimum severity (critical, high, medium, low)")
	// remediate flag
	AnalyzeCmd.Flags().BoolVar(&remediate, "remediate", false, "Apply suggested remediations interactively")
	// dry-run flag
	AnalyzeCmd.Flags().BoolVar(&dryRun, "dry-run", false, "Preview remediations without applying (requires --remediate)")
	// no-store flag
	AnalyzeCmd.Flags().BoolVar(&noStore, "no-store", false, "Do not save results to history store")
	// policy-mode flag
	AnalyzeCmd.Flags().StringVar(&policyMode, "policy-mode", "", "Override all policy actions to this mode (e.g. dry-run)")
}
