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

package history

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/fatih/color"
	"github.com/k8sgpt-ai/k8sgpt/pkg/store"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func getStore() (*store.SQLiteStore, error) {
	storePath := viper.GetString("store.path")
	if storePath == "" {
		homeDir, _ := os.UserHomeDir()
		storePath = filepath.Join(homeDir, ".k8sgpt", "history.db")
	}
	return store.NewSQLiteStore(storePath)
}

// HistoryCmd is the parent command for history subcommands.
var HistoryCmd = &cobra.Command{
	Use:   "history",
	Short: "Query analysis result history",
	Long:  `View, compare, and analyze trends in historical analysis results.`,
}

// Per-subcommand flag variables — kept separate to avoid shared state across subcommands.
var (
	listSince  string
	listLimit  int
	listOutput string
)

var (
	diffLastN  int
	diffOutput string
)

var (
	trendSince  string
	trendOutput string
)

var olderThan string

var listCmd = &cobra.Command{
	Use:   "list",
	Short: "List recent analysis runs",
	Run: func(cmd *cobra.Command, args []string) {
		s, err := getStore()
		if err != nil {
			color.Red("Error: %v", err)
			os.Exit(1)
		}
		defer s.Close() //nolint:errcheck

		opts := store.ListOpts{Limit: listLimit}
		if listSince != "" {
			d, err := time.ParseDuration(listSince)
			if err != nil {
				color.Red("Error parsing --since: %v", err)
				os.Exit(1)
			}
			opts.Since = time.Now().Add(-d)
		}

		runs, err := s.ListRuns(opts)
		if err != nil {
			color.Red("Error: %v", err)
			os.Exit(1)
		}

		if listOutput == "json" {
			data, _ := json.MarshalIndent(runs, "", "  ")
			fmt.Println(string(data))
			return
		}

		if len(runs) == 0 {
			fmt.Println("No runs found.")
			return
		}

		fmt.Printf("%-28s %-8s %-6s %-10s %s\n", "ID", "Score", "Grade", "Failures", "Time")
		fmt.Println("------------------------------------------------------------------------------------")
		for _, r := range runs {
			fmt.Printf("%-28s %-8d %-6s %-10d %s\n",
				r.ID, r.Score, r.Grade, r.FailureCount,
				r.CreatedAt.Local().Format("2006-01-02 15:04:05"))
		}
	},
}

var diffCmd = &cobra.Command{
	Use:   "diff [run1] [run2]",
	Short: "Compare two analysis runs",
	Run: func(cmd *cobra.Command, args []string) {
		s, err := getStore()
		if err != nil {
			color.Red("Error: %v", err)
			os.Exit(1)
		}
		defer s.Close() //nolint:errcheck

		var runID1, runID2 string
		if diffLastN > 0 {
			runs, err := s.ListRuns(store.ListOpts{Limit: diffLastN})
			if err != nil || len(runs) < 2 {
				color.Red("Error: need at least 2 runs for diff (found %d)", len(runs))
				os.Exit(1)
			}
			runID1 = runs[1].ID // older
			runID2 = runs[0].ID // newer
		} else if len(args) >= 2 {
			runID1 = args[0]
			runID2 = args[1]
		} else {
			color.Red("Error: provide two run IDs or use --last 2")
			os.Exit(1)
		}

		diff, err := s.Diff(runID1, runID2)
		if err != nil {
			color.Red("Error: %v", err)
			os.Exit(1)
		}

		if diffOutput == "json" {
			data, _ := json.MarshalIndent(diff, "", "  ")
			fmt.Println(string(data))
			return
		}

		fmt.Printf("Diff: %s → %s\n", runID1[:8], runID2[:8])
		fmt.Printf("Score delta: %+d\n\n", diff.ScoreDelta)

		if len(diff.NewFailures) > 0 {
			color.Red("New failures (%d):\n", len(diff.NewFailures))
			for _, f := range diff.NewFailures {
				fmt.Printf("  + [%s] %s/%s: %s\n", f.Severity, f.Kind, f.Name, f.Text)
			}
		}
		if len(diff.ResolvedFailures) > 0 {
			color.Green("\nResolved failures (%d):\n", len(diff.ResolvedFailures))
			for _, f := range diff.ResolvedFailures {
				fmt.Printf("  - [%s] %s/%s: %s\n", f.Severity, f.Kind, f.Name, f.Text)
			}
		}
		if len(diff.NewFailures) == 0 && len(diff.ResolvedFailures) == 0 {
			fmt.Println("No changes between runs.")
		}
	},
}

var trendCmd = &cobra.Command{
	Use:   "trend",
	Short: "Show health score trends over time",
	Run: func(cmd *cobra.Command, args []string) {
		s, err := getStore()
		if err != nil {
			color.Red("Error: %v", err)
			os.Exit(1)
		}
		defer s.Close() //nolint:errcheck

		opts := store.TrendOpts{}
		if trendSince != "" {
			d, err := time.ParseDuration(trendSince)
			if err != nil {
				color.Red("Error parsing --since: %v", err)
				os.Exit(1)
			}
			opts.Since = time.Now().Add(-d)
		}

		trend, err := s.Trend(opts)
		if err != nil {
			color.Red("Error: %v", err)
			os.Exit(1)
		}

		if trendOutput == "json" {
			data, _ := json.MarshalIndent(trend, "", "  ")
			fmt.Println(string(data))
			return
		}

		if len(trend.ScoreOverTime) == 0 {
			fmt.Println("No data points found.")
			return
		}

		fmt.Println("Score Over Time:")
		for _, p := range trend.ScoreOverTime {
			fmt.Printf("  %s  %d (%s)\n",
				p.Timestamp.Local().Format("2006-01-02 15:04"), p.Score, p.Grade)
		}

		if len(trend.PersistentFailures) > 0 {
			fmt.Printf("\nPersistent Failures (>50%% of runs):\n")
			for _, pf := range trend.PersistentFailures {
				fmt.Printf("  [%s] %s/%s: %s (%.0f%%)\n",
					pf.Severity, pf.Kind, pf.Name, pf.Text, pf.OccurrenceRate*100)
			}
		}

		if len(trend.Regressions) > 0 {
			color.Yellow("\nRegressions (resolved then reappeared):\n")
			for _, r := range trend.Regressions {
				fmt.Printf("  [%s] %s/%s: %s\n", r.Severity, r.Kind, r.Name, r.Text)
			}
		}
	},
}

var pruneCmd = &cobra.Command{
	Use:   "prune",
	Short: "Remove old analysis runs",
	Run: func(cmd *cobra.Command, args []string) {
		s, err := getStore()
		if err != nil {
			color.Red("Error: %v", err)
			os.Exit(1)
		}
		defer s.Close() //nolint:errcheck

		if olderThan == "" {
			color.Red("Error: --older-than is required")
			os.Exit(1)
		}

		d, err := time.ParseDuration(olderThan)
		if err != nil {
			color.Red("Error parsing --older-than: %v", err)
			os.Exit(1)
		}

		pruned, err := s.Prune(d)
		if err != nil {
			color.Red("Error: %v", err)
			os.Exit(1)
		}
		fmt.Printf("Pruned %d run(s).\n", pruned)
	},
}

func init() {
	// List flags
	listCmd.Flags().StringVar(&listSince, "since", "", "Show runs since duration (e.g. 7d=168h, 24h)")
	listCmd.Flags().IntVar(&listLimit, "limit", 20, "Maximum number of runs to show")
	listCmd.Flags().StringVarP(&listOutput, "output", "o", "text", "Output format (text, json)")

	// Diff flags
	diffCmd.Flags().IntVar(&diffLastN, "last", 0, "Compare last N runs (e.g. --last 2)")
	diffCmd.Flags().StringVarP(&diffOutput, "output", "o", "text", "Output format (text, json)")

	// Trend flags
	trendCmd.Flags().StringVar(&trendSince, "since", "", "Show trends since duration (e.g. 168h)")
	trendCmd.Flags().StringVarP(&trendOutput, "output", "o", "text", "Output format (text, json)")

	// Prune flags
	pruneCmd.Flags().StringVar(&olderThan, "older-than", "", "Remove runs older than duration (e.g. 2160h for 90 days)")

	HistoryCmd.AddCommand(listCmd)
	HistoryCmd.AddCommand(diffCmd)
	HistoryCmd.AddCommand(trendCmd)
	HistoryCmd.AddCommand(pruneCmd)
}
