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
	"bufio"
	"database/sql"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/k8sgpt-ai/k8sgpt/pkg/common"
)

// Engine evaluates analysis results against a set of policies and executes
// the appropriate remediation actions.
type Engine struct {
	Policies   []Policy
	DB         *sql.DB // shared SQLite database for audit + cooldown tracking
	RunID      string
	PolicyMode string // "" (normal) or "dry-run" (global override)
}

// EvaluateResult holds the outcome of evaluating a single failure against a policy.
type EvaluateResult struct {
	PolicyName string
	Kind       string
	Resource   string
	Namespace  string
	Severity   string
	Action     string
	Command    string
	Outcome    string // executed, skipped-cooldown, skipped-max-retries, dry-run, logged
	Error      string
}

// Evaluate iterates over results and failures, matches policies, and executes actions.
func (e *Engine) Evaluate(results []common.Result, namespace string) []EvaluateResult {
	var evalResults []EvaluateResult

	for _, result := range results {
		for _, failure := range result.Error {
			hasRemediation := failure.Remediation != nil

			policy := FindFirstMatch(
				e.Policies,
				result.Kind,
				namespace,
				failure.Severity,
				failure.Text,
				hasRemediation,
			)
			if policy == nil {
				continue
			}

			if !policy.IsEligibleForExecution(hasRemediation) {
				continue
			}

			er := EvaluateResult{
				PolicyName: policy.Name,
				Kind:       result.Kind,
				Resource:   result.Name,
				Namespace:  namespace,
				Severity:   string(failure.Severity),
				Action:     policy.Action,
			}

			// Resolve command string for display/audit.
			if failure.Remediation != nil && len(failure.Remediation.CommandArgs) > 0 {
				er.Command = strings.Join(failure.Remediation.CommandArgs, " ")
			}

			// Global dry-run override.
			effectiveAction := policy.Action
			if e.PolicyMode == ActionDryRun {
				effectiveAction = ActionDryRun
			}

			switch effectiveAction {
			case ActionLogOnly:
				er.Outcome = OutcomeLogged

			case ActionDryRun:
				er.Outcome = OutcomeDryRun

			case ActionInteractive:
				outcome, errStr := e.executeInteractive(failure.Remediation)
				er.Outcome = outcome
				er.Error = errStr

			case ActionAuto:
				outcome, errStr := e.executeAuto(policy, er.Kind, er.Resource, failure.Remediation)
				er.Outcome = outcome
				er.Error = errStr

			default:
				er.Outcome = OutcomeLogged
			}

			e.writeAudit(er)
			evalResults = append(evalResults, er)
		}
	}

	return evalResults
}

// executeAuto runs the remediation command automatically after checking cooldown and
// max-retries constraints.
func (e *Engine) executeAuto(policy *Policy, kind, resource string, rem *common.Remediation) (outcome, errStr string) {
	if rem == nil || rem.Type != common.RemediationTypeCommand {
		return OutcomeLogged, ""
	}
	if len(rem.CommandArgs) == 0 || rem.CommandArgs[0] != "kubectl" {
		return OutcomeLogged, "auto execution only allowed for kubectl commands"
	}

	// Check cooldown.
	if policy.Cooldown > 0 && e.DB != nil {
		cutoff := time.Now().Add(-policy.Cooldown).UTC().Format(time.RFC3339Nano)
		var count int
		err := e.DB.QueryRow(
			`SELECT COUNT(*) FROM policy_audit WHERE policy_name=? AND kind=? AND resource=? AND outcome='executed' AND created_at > ?`,
			policy.Name, kind, resource, cutoff,
		).Scan(&count)
		if err == nil && count > 0 {
			return OutcomeSkippedCooldown, ""
		}
	}

	// Check max retries.
	if policy.MaxRetries > 0 && e.DB != nil {
		var count int
		err := e.DB.QueryRow(
			`SELECT COUNT(*) FROM policy_audit WHERE policy_name=? AND kind=? AND resource=? AND outcome='executed'`,
			policy.Name, kind, resource,
		).Scan(&count)
		if err == nil && count >= policy.MaxRetries {
			return OutcomeSkippedMaxRetries, ""
		}
	}

	// Execute the command.
	args := rem.CommandArgs
	cmd := exec.Command(args[0], args[1:]...) // #nosec G204
	out, err := cmd.CombinedOutput()
	if err != nil {
		return OutcomeExecuted, fmt.Sprintf("command error: %s; output: %s", err.Error(), strings.TrimSpace(string(out)))
	}
	return OutcomeExecuted, ""
}

// executeInteractive prompts the user to approve the command before executing it.
func (e *Engine) executeInteractive(rem *common.Remediation) (outcome, errStr string) {
	if rem == nil || rem.Type != common.RemediationTypeCommand {
		return OutcomeLogged, ""
	}
	if len(rem.CommandArgs) == 0 {
		return OutcomeLogged, "no command args provided"
	}

	cmdStr := strings.Join(rem.CommandArgs, " ")
	fmt.Printf("Policy remediation — run command? %s [y/N]: ", cmdStr)

	reader := bufio.NewReader(os.Stdin)
	line, _ := reader.ReadString('\n')
	line = strings.TrimSpace(strings.ToLower(line))

	if line != "y" {
		return "skipped-interactive", ""
	}

	args := rem.CommandArgs
	cmd := exec.Command(args[0], args[1:]...) // #nosec G204
	out, err := cmd.CombinedOutput()
	if err != nil {
		return OutcomeExecuted, fmt.Sprintf("command error: %s; output: %s", err.Error(), strings.TrimSpace(string(out)))
	}
	return OutcomeExecuted, ""
}

// writeAudit inserts an audit record for the evaluated result if a DB is configured.
func (e *Engine) writeAudit(er EvaluateResult) {
	if e.DB == nil {
		return
	}

	id := fmt.Sprintf("%d", time.Now().UnixNano())
	createdAt := time.Now().UTC().Format(time.RFC3339Nano)

	_, _ = e.DB.Exec(
		`INSERT INTO policy_audit (id, run_id, policy_name, kind, resource, namespace, severity, action, command, outcome, error, created_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		id,
		e.RunID,
		er.PolicyName,
		er.Kind,
		er.Resource,
		er.Namespace,
		er.Severity,
		er.Action,
		er.Command,
		er.Outcome,
		er.Error,
		createdAt,
	)
}
