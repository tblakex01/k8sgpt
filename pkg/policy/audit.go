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
	"database/sql"
	"fmt"
	"time"
)

type AuditEntry struct {
	ID         string    `json:"id"`
	RunID      string    `json:"runId"`
	PolicyName string    `json:"policyName"`
	Kind       string    `json:"kind"`
	Resource   string    `json:"resource"`
	Namespace  string    `json:"namespace"`
	Severity   string    `json:"severity"`
	Action     string    `json:"action"`
	Command    string    `json:"command"`
	Outcome    string    `json:"outcome"`
	Error      string    `json:"error,omitempty"`
	CreatedAt  time.Time `json:"createdAt"`
}

type AuditOpts struct {
	PolicyName string
	Since      time.Time
	Limit      int
}

func QueryAuditLog(db *sql.DB, opts AuditOpts) ([]AuditEntry, error) {
	query := `SELECT id, run_id, policy_name, kind, resource, namespace, severity,
		action, command, outcome, error, created_at
		FROM policy_audit WHERE 1=1`
	var args []interface{}

	if opts.PolicyName != "" {
		query += " AND policy_name = ?"
		args = append(args, opts.PolicyName)
	}
	if !opts.Since.IsZero() {
		query += " AND created_at >= ?"
		args = append(args, opts.Since.UTC().Format(time.RFC3339Nano))
	}

	query += " ORDER BY created_at DESC"

	limit := opts.Limit
	if limit <= 0 {
		limit = 50
	}
	query += fmt.Sprintf(" LIMIT %d", limit)

	rows, err := db.Query(query, args...)
	if err != nil {
		return nil, fmt.Errorf("querying audit log: %w", err)
	}
	defer rows.Close() //nolint:errcheck

	var entries []AuditEntry
	for rows.Next() {
		var e AuditEntry
		var createdAtStr string
		var runID, ns, cmd, errStr sql.NullString
		if err := rows.Scan(&e.ID, &runID, &e.PolicyName, &e.Kind, &e.Resource,
			&ns, &e.Severity, &e.Action, &cmd, &e.Outcome, &errStr, &createdAtStr); err != nil {
			return nil, fmt.Errorf("scanning audit entry: %w", err)
		}
		e.RunID = runID.String
		e.Namespace = ns.String
		e.Command = cmd.String
		e.Error = errStr.String
		e.CreatedAt, _ = time.Parse(time.RFC3339Nano, createdAtStr)
		entries = append(entries, e)
	}
	return entries, nil
}
