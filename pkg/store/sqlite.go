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

package store

import (
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"time"

	"github.com/k8sgpt-ai/k8sgpt/pkg/common"
	"github.com/k8sgpt-ai/k8sgpt/pkg/score"
	"github.com/oklog/ulid/v2"
	"github.com/spf13/viper"
	_ "modernc.org/sqlite"
)

// SQLiteStore is a SQLite-backed implementation of IStore.
type SQLiteStore struct {
	db *sql.DB
}

// DB returns the underlying *sql.DB for advanced use (e.g., policy audit).
func (s *SQLiteStore) DB() *sql.DB {
	return s.db
}

// NewSQLiteStore opens (or creates) a SQLite database at dbPath and runs
// schema migrations. Parent directories are created as needed.
func NewSQLiteStore(dbPath string) (*SQLiteStore, error) {
	if err := os.MkdirAll(filepath.Dir(dbPath), 0o755); err != nil {
		return nil, fmt.Errorf("store: create dirs: %w", err)
	}

	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, fmt.Errorf("store: open sqlite: %w", err)
	}

	// Recommended pragmas for performance and correctness.
	for _, pragma := range []string{
		"PRAGMA journal_mode=WAL;",
		"PRAGMA foreign_keys=ON;",
	} {
		if _, err := db.Exec(pragma); err != nil {
			_ = db.Close()
			return nil, fmt.Errorf("store: pragma %q: %w", pragma, err)
		}
	}

	st := &SQLiteStore{db: db}
	if err := st.migrate(); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("store: migrate: %w", err)
	}
	return st, nil
}

// GetDefaultStore creates a SQLiteStore using the configured path or default.
func GetDefaultStore() (*SQLiteStore, error) {
	storePath := viper.GetString("store.path")
	if storePath == "" {
		homeDir, _ := os.UserHomeDir()
		storePath = filepath.Join(homeDir, ".k8sgpt", "history.db")
	}
	return NewSQLiteStore(storePath)
}

// migrate creates the schema if it does not already exist.
func (s *SQLiteStore) migrate() error {
	schema := `
CREATE TABLE IF NOT EXISTS runs (
    id          TEXT PRIMARY KEY,
    cluster     TEXT NOT NULL,
    namespace   TEXT NOT NULL,
    score       INTEGER NOT NULL,
    grade       TEXT NOT NULL,
    failure_count   INTEGER NOT NULL DEFAULT 0,
    severity_counts TEXT NOT NULL DEFAULT '{}',
    filters     TEXT NOT NULL DEFAULT '[]',
    created_at  TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_runs_cluster     ON runs(cluster);
CREATE INDEX IF NOT EXISTS idx_runs_created_at  ON runs(created_at);

CREATE TABLE IF NOT EXISTS results (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id      TEXT NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
    kind        TEXT NOT NULL,
    name        TEXT NOT NULL,
    details     TEXT NOT NULL DEFAULT '',
    parent_object TEXT NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_results_run_id ON results(run_id);

CREATE TABLE IF NOT EXISTS failures (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    result_id       INTEGER NOT NULL REFERENCES results(id) ON DELETE CASCADE,
    text            TEXT NOT NULL,
    severity        TEXT NOT NULL,
    kubernetes_doc  TEXT NOT NULL DEFAULT '',
    remediation     TEXT
);

CREATE INDEX IF NOT EXISTS idx_failures_result_id ON failures(result_id);

CREATE TABLE IF NOT EXISTS policy_audit (
    id          TEXT PRIMARY KEY,
    run_id      TEXT NOT NULL,
    policy_name TEXT NOT NULL,
    kind        TEXT NOT NULL DEFAULT '',
    resource    TEXT NOT NULL DEFAULT '',
    namespace   TEXT NOT NULL DEFAULT '',
    severity    TEXT NOT NULL DEFAULT '',
    action      TEXT NOT NULL DEFAULT '',
    command     TEXT NOT NULL DEFAULT '',
    outcome     TEXT NOT NULL DEFAULT '',
    error       TEXT NOT NULL DEFAULT '',
    created_at  TEXT NOT NULL
);
`
	_, err := s.db.Exec(schema)
	return err
}

// newULID generates a new monotonic ULID using crypto/rand entropy.
func newULID() (string, error) {
	// Use crypto/rand as entropy source, wrapped in a monotonic reader.
	entropy := ulid.Monotonic(rand.Reader, 0)
	id, err := ulid.New(ulid.Timestamp(time.Now()), entropy)
	if err != nil {
		// fallback: use non-monotonic rand
		n, rerr := rand.Int(rand.Reader, new(big.Int).SetBit(new(big.Int), 80, 1))
		if rerr != nil {
			return "", fmt.Errorf("store: ulid entropy: %w", rerr)
		}
		_ = n
		return "", fmt.Errorf("store: ulid: %w", err)
	}
	return id.String(), nil
}

// Save inserts a RunRecord into the database. It assigns run.ID on success.
func (s *SQLiteStore) Save(run *RunRecord) error {
	id, err := newULID()
	if err != nil {
		return err
	}
	run.ID = id

	severityJSON, err := json.Marshal(run.Score.SeverityCounts)
	if err != nil {
		return fmt.Errorf("store: marshal severity counts: %w", err)
	}
	filtersJSON, err := json.Marshal(run.Filters)
	if err != nil {
		return fmt.Errorf("store: marshal filters: %w", err)
	}

	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("store: begin tx: %w", err)
	}
	defer func() {
		if err != nil {
			_ = tx.Rollback()
		}
	}()

	_, err = tx.Exec(`
		INSERT INTO runs (id, cluster, namespace, score, grade, failure_count, severity_counts, filters, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		run.ID,
		run.Cluster,
		run.Namespace,
		run.Score.Score,
		run.Score.Grade,
		run.Score.FailureCount,
		string(severityJSON),
		string(filtersJSON),
		run.CreatedAt.UTC().Format(time.RFC3339Nano),
	)
	if err != nil {
		return fmt.Errorf("store: insert run: %w", err)
	}

	for _, result := range run.Results {
		res, err := tx.Exec(`
			INSERT INTO results (run_id, kind, name, details, parent_object)
			VALUES (?, ?, ?, ?, ?)`,
			run.ID, result.Kind, result.Name, result.Details, result.ParentObject,
		)
		if err != nil {
			return fmt.Errorf("store: insert result: %w", err)
		}
		resultID, err := res.LastInsertId()
		if err != nil {
			return fmt.Errorf("store: last insert id: %w", err)
		}

		for _, f := range result.Error {
			var remJSON *string
			if f.Remediation != nil {
				b, err := json.Marshal(f.Remediation)
				if err != nil {
					return fmt.Errorf("store: marshal remediation: %w", err)
				}
				s := string(b)
				remJSON = &s
			}
			_, err = tx.Exec(`
				INSERT INTO failures (result_id, text, severity, kubernetes_doc, remediation)
				VALUES (?, ?, ?, ?, ?)`,
				resultID, f.Text, string(f.Severity), f.KubernetesDoc, remJSON,
			)
			if err != nil {
				return fmt.Errorf("store: insert failure: %w", err)
			}
		}
	}

	return tx.Commit()
}

// GetRun loads a full RunRecord (with results and failures) by ID.
func (s *SQLiteStore) GetRun(id string) (*RunRecord, error) {
	row := s.db.QueryRow(`
		SELECT id, cluster, namespace, score, grade, failure_count, severity_counts, filters, created_at
		FROM runs WHERE id = ?`, id)

	run, err := scanRun(row)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("store: run %q not found", id)
	}
	if err != nil {
		return nil, fmt.Errorf("store: scan run: %w", err)
	}

	run.Results, err = s.loadResults(id)
	if err != nil {
		return nil, err
	}
	return run, nil
}

// ListRuns returns run summaries matching the given options, ordered newest first.
func (s *SQLiteStore) ListRuns(opts ListOpts) ([]RunSummary, error) {
	query := `SELECT id, cluster, namespace, score, grade, failure_count, severity_counts, created_at FROM runs WHERE 1=1`
	args := []interface{}{}

	if opts.Cluster != "" {
		query += " AND cluster = ?"
		args = append(args, opts.Cluster)
	}
	if !opts.Since.IsZero() {
		query += " AND created_at >= ?"
		args = append(args, opts.Since.UTC().Format(time.RFC3339Nano))
	}
	if !opts.Until.IsZero() {
		query += " AND created_at <= ?"
		args = append(args, opts.Until.UTC().Format(time.RFC3339Nano))
	}

	query += " ORDER BY created_at DESC"

	if opts.Limit > 0 {
		query += fmt.Sprintf(" LIMIT %d", opts.Limit)
	}

	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, fmt.Errorf("store: list runs: %w", err)
	}
	defer rows.Close() //nolint:errcheck

	var summaries []RunSummary
	for rows.Next() {
		var s RunSummary
		var severityJSON string
		var createdAt string
		if err := rows.Scan(&s.ID, &s.Cluster, &s.Namespace, &s.Score, &s.Grade,
			&s.FailureCount, &severityJSON, &createdAt); err != nil {
			return nil, fmt.Errorf("store: scan summary: %w", err)
		}
		s.CreatedAt, err = time.Parse(time.RFC3339Nano, createdAt)
		if err != nil {
			return nil, fmt.Errorf("store: parse created_at: %w", err)
		}
		var counts map[common.Severity]int
		if err := json.Unmarshal([]byte(severityJSON), &counts); err == nil {
			s.CriticalCount = counts[common.SeverityCritical]
			s.HighCount = counts[common.SeverityHigh]
			s.MediumCount = counts[common.SeverityMedium]
			s.LowCount = counts[common.SeverityLow]
		}
		summaries = append(summaries, s)
	}
	return summaries, rows.Err()
}

// Diff computes the difference between two runs: new failures and resolved failures.
func (s *SQLiteStore) Diff(runID1, runID2 string) (*DiffResult, error) {
	run1, err := s.GetRun(runID1)
	if err != nil {
		return nil, fmt.Errorf("store: diff get run1: %w", err)
	}
	run2, err := s.GetRun(runID2)
	if err != nil {
		return nil, fmt.Errorf("store: diff get run2: %w", err)
	}

	// Build failure sets keyed by kind+name+text.
	type key struct{ kind, name, text string }

	set1 := make(map[key]FailureSummary)
	for _, r := range run1.Results {
		for _, f := range r.Error {
			k := key{r.Kind, r.Name, f.Text}
			set1[k] = FailureSummary{Kind: r.Kind, Name: r.Name, Text: f.Text, Severity: f.Severity}
		}
	}

	set2 := make(map[key]FailureSummary)
	for _, r := range run2.Results {
		for _, f := range r.Error {
			k := key{r.Kind, r.Name, f.Text}
			set2[k] = FailureSummary{Kind: r.Kind, Name: r.Name, Text: f.Text, Severity: f.Severity}
		}
	}

	var newFailures, resolvedFailures []FailureSummary
	for k, fs := range set2 {
		if _, exists := set1[k]; !exists {
			newFailures = append(newFailures, fs)
		}
	}
	for k, fs := range set1 {
		if _, exists := set2[k]; !exists {
			resolvedFailures = append(resolvedFailures, fs)
		}
	}

	return &DiffResult{
		Run1ID:           runID1,
		Run2ID:           runID2,
		ScoreDelta:       run2.Score.Score - run1.Score.Score,
		NewFailures:      newFailures,
		ResolvedFailures: resolvedFailures,
	}, nil
}

// Trend returns score-over-time and persistent failure analysis for a time window.
func (s *SQLiteStore) Trend(opts TrendOpts) (*TrendResult, error) {
	listOpts := ListOpts{
		Cluster: opts.Cluster,
		Since:   opts.Since,
		Until:   opts.Until,
		Limit:   1000, // Reasonable cap for trend analysis
	}

	summaries, err := s.ListRuns(listOpts)
	if err != nil {
		return nil, err
	}

	// ScoreOverTime — ordered oldest-first for charting.
	scoreOverTime := make([]ScorePoint, len(summaries))
	for i, sm := range summaries {
		scoreOverTime[len(summaries)-1-i] = ScorePoint{
			Timestamp: sm.CreatedAt,
			Score:     sm.Score,
			Grade:     sm.Grade,
		}
	}

	if len(summaries) == 0 {
		return &TrendResult{
			ScoreOverTime:      scoreOverTime,
			PersistentFailures: []PersistentIssue{},
			Regressions:        []FailureSummary{},
		}, nil
	}

	// Count how many runs each failure (kind+name+text) appears in.
	type fkey struct{ kind, name, text string }
	type fval struct {
		FailureSummary
		count int
	}
	failureCounts := make(map[fkey]*fval)

	for _, sm := range summaries {
		run, err := s.GetRun(sm.ID)
		if err != nil {
			return nil, err
		}
		// Use a set per run to avoid double-counting the same failure in the same run.
		seen := make(map[fkey]struct{})
		for _, r := range run.Results {
			for _, f := range r.Error {
				k := fkey{r.Kind, r.Name, f.Text}
				if _, already := seen[k]; already {
					continue
				}
				seen[k] = struct{}{}
				if _, ok := failureCounts[k]; !ok {
					failureCounts[k] = &fval{
						FailureSummary: FailureSummary{Kind: r.Kind, Name: r.Name, Text: f.Text, Severity: f.Severity},
					}
				}
				failureCounts[k].count++
			}
		}
	}

	total := len(summaries)
	var persistentFailures []PersistentIssue
	for _, fv := range failureCounts {
		rate := float64(fv.count) / float64(total)
		if rate > 0.5 {
			persistentFailures = append(persistentFailures, PersistentIssue{
				FailureSummary: fv.FailureSummary,
				OccurrenceRate: rate,
			})
		}
	}

	// Regressions: failures in the most recent run that were NOT in the second-most-recent run.
	var regressions []FailureSummary
	if len(summaries) >= 2 {
		newest, err := s.GetRun(summaries[0].ID)
		if err != nil {
			return nil, err
		}
		secondNewest, err := s.GetRun(summaries[1].ID)
		if err != nil {
			return nil, err
		}

		prevSet := make(map[fkey]struct{})
		for _, r := range secondNewest.Results {
			for _, f := range r.Error {
				prevSet[fkey{r.Kind, r.Name, f.Text}] = struct{}{}
			}
		}
		for _, r := range newest.Results {
			for _, f := range r.Error {
				k := fkey{r.Kind, r.Name, f.Text}
				if _, exists := prevSet[k]; !exists {
					regressions = append(regressions, FailureSummary{
						Kind:     r.Kind,
						Name:     r.Name,
						Text:     f.Text,
						Severity: f.Severity,
					})
				}
			}
		}
	}

	if persistentFailures == nil {
		persistentFailures = []PersistentIssue{}
	}
	if regressions == nil {
		regressions = []FailureSummary{}
	}

	return &TrendResult{
		ScoreOverTime:      scoreOverTime,
		PersistentFailures: persistentFailures,
		Regressions:        regressions,
	}, nil
}

// Prune deletes runs older than the given duration and returns the count deleted.
func (s *SQLiteStore) Prune(olderThan time.Duration) (int, error) {
	cutoff := time.Now().UTC().Add(-olderThan).Format(time.RFC3339Nano)
	res, err := s.db.Exec(`DELETE FROM runs WHERE created_at < ?`, cutoff)
	if err != nil {
		return 0, fmt.Errorf("store: prune: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("store: prune rows affected: %w", err)
	}
	return int(n), nil
}

// Close closes the underlying database connection.
func (s *SQLiteStore) Close() error {
	return s.db.Close()
}

// --- helpers ---

type scannable interface {
	Scan(dest ...interface{}) error
}

func scanRun(row scannable) (*RunRecord, error) {
	var run RunRecord
	var scoreVal int
	var grade string
	var failureCount int
	var severityJSON string
	var filtersJSON string
	var createdAt string

	if err := row.Scan(&run.ID, &run.Cluster, &run.Namespace,
		&scoreVal, &grade, &failureCount, &severityJSON, &filtersJSON, &createdAt); err != nil {
		return nil, err
	}

	run.Score = score.HealthScore{
		Score:        scoreVal,
		Grade:        grade,
		FailureCount: failureCount,
	}

	var severityCounts map[common.Severity]int
	if err := json.Unmarshal([]byte(severityJSON), &severityCounts); err == nil {
		run.Score.SeverityCounts = severityCounts
	}

	if err := json.Unmarshal([]byte(filtersJSON), &run.Filters); err != nil {
		run.Filters = []string{}
	}

	var err error
	run.CreatedAt, err = time.Parse(time.RFC3339Nano, createdAt)
	if err != nil {
		return nil, fmt.Errorf("store: parse created_at: %w", err)
	}
	return &run, nil
}

func (s *SQLiteStore) loadResults(runID string) ([]common.Result, error) {
	rows, err := s.db.Query(`
		SELECT id, kind, name, details, parent_object FROM results WHERE run_id = ?`, runID)
	if err != nil {
		return nil, fmt.Errorf("store: load results: %w", err)
	}
	defer rows.Close() //nolint:errcheck

	var results []common.Result
	for rows.Next() {
		var resultID int64
		var r common.Result
		if err := rows.Scan(&resultID, &r.Kind, &r.Name, &r.Details, &r.ParentObject); err != nil {
			return nil, fmt.Errorf("store: scan result: %w", err)
		}
		r.Error, err = s.loadFailures(resultID)
		if err != nil {
			return nil, err
		}
		results = append(results, r)
	}
	return results, rows.Err()
}

func (s *SQLiteStore) loadFailures(resultID int64) ([]common.Failure, error) {
	rows, err := s.db.Query(`
		SELECT text, severity, kubernetes_doc, remediation FROM failures WHERE result_id = ?`, resultID)
	if err != nil {
		return nil, fmt.Errorf("store: load failures: %w", err)
	}
	defer rows.Close() //nolint:errcheck

	var failures []common.Failure
	for rows.Next() {
		var f common.Failure
		var severity string
		var remJSON *string
		if err := rows.Scan(&f.Text, &severity, &f.KubernetesDoc, &remJSON); err != nil {
			return nil, fmt.Errorf("store: scan failure: %w", err)
		}
		f.Severity = common.Severity(severity)
		if remJSON != nil {
			var rem common.Remediation
			if err := json.Unmarshal([]byte(*remJSON), &rem); err == nil {
				f.Remediation = &rem
			}
		}
		failures = append(failures, f)
	}
	return failures, rows.Err()
}
