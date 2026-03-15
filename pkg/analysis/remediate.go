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

package analysis

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/fatih/color"
	"github.com/k8sgpt-ai/k8sgpt/pkg/common"
)

func isTerminal() bool {
	fi, err := os.Stdin.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice != 0
}

func (a *Analysis) RunRemediation(dryRun bool) error {
	for _, result := range a.Results {
		for _, failure := range result.Error {
			if failure.Remediation == nil {
				continue
			}
			if failure.Remediation.Type != common.RemediationTypeCommand {
				continue
			}
			if len(failure.Remediation.CommandArgs) == 0 {
				continue
			}

			if dryRun {
				args := make([]string, len(failure.Remediation.CommandArgs))
				copy(args, failure.Remediation.CommandArgs)

				// Only append --dry-run=client for mutating kubectl commands
				mutatingVerbs := map[string]bool{"create": true, "delete": true, "patch": true, "apply": true, "replace": true, "run": true}
				if len(args) > 1 && mutatingVerbs[args[1]] {
					args = append(args, "--dry-run=client")
				}

				fmt.Printf("\n%s %s\n", color.YellowString("[DRY-RUN]"), failure.Text)
				fmt.Printf("  Command: %s\n", strings.Join(args, " "))

				cmd := exec.Command(args[0], args[1:]...) // #nosec G204
				output, err := cmd.CombinedOutput()
				if err != nil {
					color.Red("  Dry-run failed: %v\n%s", err, string(output))
				} else {
					fmt.Printf("  Dry-run output:\n%s\n", string(output))
				}
				continue
			}

			// Non-dry-run: require interactive terminal
			if !isTerminal() {
				color.Yellow("Skipping remediation (non-interactive terminal): %s", failure.Text)
				continue
			}

			fmt.Printf("\n%s %s\n", color.CyanString("[FIX]"), failure.Text)
			fmt.Printf("  Command: %s\n", failure.Remediation.Command)
			fmt.Printf("  Risk: %s\n", failure.Remediation.Risk)
			fmt.Printf("  Apply fix? [y/N] ")

			reader := bufio.NewReader(os.Stdin)
			answer, _ := reader.ReadString('\n')
			answer = strings.TrimSpace(strings.ToLower(answer))

			if answer != "y" && answer != "yes" {
				fmt.Println("  Skipped.")
				continue
			}

			args := failure.Remediation.CommandArgs
			cmd := exec.Command(args[0], args[1:]...) // #nosec G204
			output, err := cmd.CombinedOutput()
			if err != nil {
				color.Red("  Fix failed: %v\n%s", err, string(output))
			} else {
				color.Green("  Fix applied successfully.\n%s", string(output))
			}
		}
	}
	return nil
}
