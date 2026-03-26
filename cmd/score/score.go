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

package score

import (
	"fmt"
	"os"

	"github.com/fatih/color"
	"github.com/k8sgpt-ai/k8sgpt/pkg/analysis"
	"github.com/k8sgpt-ai/k8sgpt/pkg/common"
	"github.com/spf13/cobra"
)

var (
	namespace     string
	filters       []string
	labelSelector string
	output        string
)

var ScoreCmd = &cobra.Command{
	Use:   "score",
	Short: "Compute and display the cluster health score",
	Long:  `Runs analysis and computes a weighted health score (0-100) based on failure severity and resource criticality.`,
	Run: func(cmd *cobra.Command, args []string) {
		config, err := analysis.NewAnalysis(
			"", "", filters, namespace, labelSelector,
			true, false, 10, false, false, nil, false,
		)
		if err != nil {
			color.Red("Error: %v", err)
			os.Exit(1)
		}
		defer config.Close()

		config.RunAnalysis()
		config.ComputeScore()

		if config.Score == nil {
			color.Red("Error: score computation failed")
			os.Exit(1)
		}

		hs := config.Score

		if output == "json" {
			data, err := config.PrintOutput("json")
			if err != nil {
				color.Red("Error: %v", err)
				os.Exit(1)
			}
			fmt.Println(string(data))
			return
		}

		gradeColor := color.GreenString
		switch hs.Grade {
		case "C":
			gradeColor = color.YellowString
		case "D", "F":
			gradeColor = color.RedString
		}

		fmt.Printf("Cluster Health Score: %s (%d/100)\n\n", gradeColor(hs.Grade), hs.Score)
		fmt.Printf("Failures: %d total\n", hs.FailureCount)

		if hs.SeverityCounts != nil {
			for _, sev := range []common.Severity{
				common.SeverityCritical,
				common.SeverityHigh,
				common.SeverityMedium,
				common.SeverityLow,
			} {
				if count, ok := hs.SeverityCounts[sev]; ok && count > 0 {
					fmt.Printf("  %-10s %d\n", string(sev)+":", count)
				}
			}
		}

		if len(hs.TopContributors) > 0 {
			fmt.Printf("\nTop Contributors:\n")
			for i, c := range hs.TopContributors {
				fmt.Printf("  %d. %s/%s [%s] (penalty: %.1f)\n",
					i+1, c.Kind, c.Name, c.Severity, c.Penalty)
			}
		}
	},
}

func init() {
	ScoreCmd.Flags().StringVarP(&namespace, "namespace", "n", "", "Namespace to analyze")
	ScoreCmd.Flags().StringSliceVarP(&filters, "filter", "f", []string{}, "Filter for specific analyzers")
	ScoreCmd.Flags().StringVarP(&labelSelector, "selector", "L", "", "Label selector to filter resources")
	ScoreCmd.Flags().StringVarP(&output, "output", "o", "text", "Output format (text, json)")
}
