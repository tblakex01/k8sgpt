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

package policy

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/fatih/color"
	"github.com/k8sgpt-ai/k8sgpt/pkg/analysis"
	"github.com/k8sgpt-ai/k8sgpt/pkg/policy"
	"github.com/k8sgpt-ai/k8sgpt/pkg/store"
	"github.com/spf13/cobra"
)

// PolicyCmd is the parent command for policy subcommands.
var PolicyCmd = &cobra.Command{
	Use:   "policy",
	Short: "Manage and inspect remediation policies",
	Long:  `List configured policies, test what policies would fire, and view the audit log.`,
}

// Per-subcommand flag variables — kept separate to avoid shared state across subcommands.
var (
	listOutput string
)

var (
	testNamespace     string
	testFilters       []string
	testLabelSelector string
	testOutput        string
)

var (
	auditPolicy string
	auditSince  string
	auditLimit  int
	auditOutput string
)

func getStore() (*store.SQLiteStore, error) {
	return store.GetDefaultStore()
}

var listCmd = &cobra.Command{
	Use:   "list",
	Short: "List configured remediation policies",
	Run: func(cmd *cobra.Command, args []string) {
		policies := policy.LoadPolicies()

		if listOutput == "json" {
			data, _ := json.MarshalIndent(policies, "", "  ")
			fmt.Println(string(data))
			return
		}

		if len(policies) == 0 {
			fmt.Println("No policies configured.")
			fmt.Println("Add policies under 'remediationPolicies' in your k8sgpt config.")
			return
		}

		fmt.Printf("%-20s %-12s %-10s %-12s %s\n", "NAME", "ACTION", "COOLDOWN", "MAX-RETRIES", "MATCH")
		fmt.Println(strings.Repeat("-", 80))
		for _, p := range policies {
			matchParts := []string{}
			if p.Match.Kind != "" {
				matchParts = append(matchParts, "kind="+p.Match.Kind)
			}
			if len(p.Match.Kinds) > 0 {
				matchParts = append(matchParts, "kinds=["+strings.Join(p.Match.Kinds, ",")+"]")
			}
			if len(p.Match.Severity) > 0 {
				matchParts = append(matchParts, "severity=["+strings.Join(p.Match.Severity, ",")+"]")
			}
			if p.Match.Namespace != "" {
				matchParts = append(matchParts, "namespace="+p.Match.Namespace)
			}
			if p.Match.TextPattern != "" {
				matchParts = append(matchParts, "pattern="+p.Match.TextPattern)
			}
			if p.Match.HasRemediation != nil {
				matchParts = append(matchParts, fmt.Sprintf("hasRemediation=%v", *p.Match.HasRemediation))
			}
			matchStr := strings.Join(matchParts, ", ")
			if matchStr == "" {
				matchStr = "(all)"
			}

			cooldownStr := "-"
			if p.Cooldown > 0 {
				cooldownStr = p.Cooldown.String()
			}

			fmt.Printf("%-20s %-12s %-10s %-12d %s\n",
				p.Name, p.Action, cooldownStr, p.MaxRetries, matchStr)
		}
	},
}

var testCmd = &cobra.Command{
	Use:   "test",
	Short: "Run analysis in dry-run mode and show which policies would fire",
	Run: func(cmd *cobra.Command, args []string) {
		policies := policy.LoadPolicies()
		if len(policies) == 0 {
			fmt.Println("No policies configured — nothing to test.")
			return
		}

		config, err := analysis.NewAnalysis(
			"", "", testFilters, testNamespace, testLabelSelector,
			true, false, 10, false, false, nil, false,
		)
		if err != nil {
			color.Red("Error initializing analysis: %v", err)
			os.Exit(1)
		}
		defer config.Close()

		config.RunAnalysis()

		engine := &policy.Engine{
			Policies:   policies,
			PolicyMode: "dry-run",
		}

		outcomes := engine.Evaluate(config.Results, testNamespace)

		if testOutput == "json" {
			data, _ := json.MarshalIndent(outcomes, "", "  ")
			fmt.Println(string(data))
			return
		}

		if len(outcomes) == 0 {
			fmt.Println("No policy matches found.")
			return
		}

		fmt.Printf("%-20s %-12s %-30s %-12s %s\n", "POLICY", "KIND", "RESOURCE", "SEVERITY", "OUTCOME")
		fmt.Println(strings.Repeat("-", 90))
		for _, o := range outcomes {
			resource := o.Resource
			if o.Namespace != "" {
				resource = o.Namespace + "/" + o.Resource
			}
			fmt.Printf("%-20s %-12s %-30s %-12s %s\n",
				o.PolicyName, o.Kind, resource, o.Severity, o.Outcome)
		}
		fmt.Printf("\n%d match(es) found (dry-run — no actions executed).\n", len(outcomes))
	},
}

var auditCmd = &cobra.Command{
	Use:   "audit",
	Short: "Show policy audit log entries from the SQLite store",
	Run: func(cmd *cobra.Command, args []string) {
		s, err := getStore()
		if err != nil {
			color.Red("Error opening store: %v", err)
			os.Exit(1)
		}
		defer s.Close() //nolint:errcheck

		opts := policy.AuditOpts{
			PolicyName: auditPolicy,
			Limit:      auditLimit,
		}
		if auditSince != "" {
			d, err := time.ParseDuration(auditSince)
			if err != nil {
				color.Red("Error parsing --since: %v", err)
				os.Exit(1)
			}
			opts.Since = time.Now().Add(-d)
		}

		entries, err := policy.QueryAuditLog(s.DB(), opts)
		if err != nil {
			color.Red("Error querying audit log: %v", err)
			os.Exit(1)
		}

		if auditOutput == "json" {
			data, _ := json.MarshalIndent(entries, "", "  ")
			fmt.Println(string(data))
			return
		}

		if len(entries) == 0 {
			fmt.Println("No audit log entries found.")
			return
		}

		fmt.Printf("%-20s %-12s %-30s %-12s %-14s %s\n",
			"POLICY", "KIND", "RESOURCE", "SEVERITY", "OUTCOME", "TIME")
		fmt.Println(strings.Repeat("-", 100))
		for _, e := range entries {
			resource := e.Resource
			if e.Namespace != "" {
				resource = e.Namespace + "/" + e.Resource
			}
			fmt.Printf("%-20s %-12s %-30s %-12s %-14s %s\n",
				e.PolicyName, e.Kind, resource, e.Severity, e.Outcome,
				e.CreatedAt.Local().Format("2006-01-02 15:04:05"))
		}
	},
}

func init() {
	// List flags
	listCmd.Flags().StringVarP(&listOutput, "output", "o", "text", "Output format (text, json)")

	// Test flags
	testCmd.Flags().StringVarP(&testNamespace, "namespace", "n", "", "Namespace to analyze")
	testCmd.Flags().StringSliceVarP(&testFilters, "filter", "f", []string{}, "Filter for specific analyzers")
	testCmd.Flags().StringVarP(&testLabelSelector, "selector", "L", "", "Label selector to filter resources")
	testCmd.Flags().StringVarP(&testOutput, "output", "o", "text", "Output format (text, json)")

	// Audit flags
	auditCmd.Flags().StringVar(&auditPolicy, "policy", "", "Filter by policy name")
	auditCmd.Flags().StringVar(&auditSince, "since", "", "Show entries since duration (e.g. 24h, 168h)")
	auditCmd.Flags().IntVar(&auditLimit, "limit", 50, "Maximum number of entries to show")
	auditCmd.Flags().StringVarP(&auditOutput, "output", "o", "text", "Output format (text, json)")

	PolicyCmd.AddCommand(listCmd)
	PolicyCmd.AddCommand(testCmd)
	PolicyCmd.AddCommand(auditCmd)
}
