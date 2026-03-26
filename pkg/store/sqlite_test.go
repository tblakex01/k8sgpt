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
	"path/filepath"
	"testing"
	"time"

	"github.com/k8sgpt-ai/k8sgpt/pkg/common"
	"github.com/k8sgpt-ai/k8sgpt/pkg/score"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// makeRun creates a RunRecord with the given cluster and list of failure texts.
func makeRun(cluster string, failures []string) *RunRecord {
	results := make([]common.Result, 0, len(failures))
	for i, f := range failures {
		results = append(results, common.Result{
			Kind:  "Pod",
			Name:  "pod-" + cluster + "-" + string(rune('a'+i)),
			Error: []common.Failure{{Text: f, Severity: common.SeverityMedium}},
		})
	}
	return &RunRecord{
		Cluster:   cluster,
		Namespace: "default",
		Score: score.HealthScore{
			Score:        80,
			Grade:        "B",
			FailureCount: len(failures),
			SeverityCounts: map[common.Severity]int{
				common.SeverityMedium: len(failures),
			},
		},
		Filters:   []string{},
		Results:   results,
		CreatedAt: time.Now().UTC(),
	}
}

func TestNewSQLiteStore_CreatesFile(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "subdir", "test.db")

	store, err := NewSQLiteStore(dbPath)
	require.NoError(t, err)
	defer store.Close() //nolint:errcheck

	// Verify we can ping the DB
	err = store.DB().Ping()
	require.NoError(t, err)
}

func TestSaveAndGetRun(t *testing.T) {
	dir := t.TempDir()
	st, err := NewSQLiteStore(filepath.Join(dir, "test.db"))
	require.NoError(t, err)
	defer st.Close() //nolint:errcheck

	run := makeRun("prod", []string{"CrashLoopBackOff", "OOMKilled"})
	run.CreatedAt = time.Now().UTC().Truncate(time.Second)

	err = st.Save(run)
	require.NoError(t, err)
	assert.NotEmpty(t, run.ID, "ID should be assigned after Save")

	got, err := st.GetRun(run.ID)
	require.NoError(t, err)
	require.NotNil(t, got)

	assert.Equal(t, run.ID, got.ID)
	assert.Equal(t, "prod", got.Cluster)
	assert.Equal(t, "default", got.Namespace)
	assert.Equal(t, 80, got.Score.Score)
	assert.Equal(t, "B", got.Score.Grade)
	assert.Equal(t, 2, got.Score.FailureCount)
	assert.Equal(t, run.CreatedAt.UTC(), got.CreatedAt.UTC())
	assert.Len(t, got.Results, 2)

	texts := make([]string, 0)
	for _, r := range got.Results {
		for _, f := range r.Error {
			texts = append(texts, f.Text)
		}
	}
	assert.Contains(t, texts, "CrashLoopBackOff")
	assert.Contains(t, texts, "OOMKilled")
}

func TestListRuns(t *testing.T) {
	dir := t.TempDir()
	st, err := NewSQLiteStore(filepath.Join(dir, "test.db"))
	require.NoError(t, err)
	defer st.Close() //nolint:errcheck

	// Create 5 runs with slight time differences
	base := time.Now().UTC().Add(-5 * time.Minute)
	for i := 0; i < 5; i++ {
		run := makeRun("cluster1", []string{"error"})
		run.CreatedAt = base.Add(time.Duration(i) * time.Minute)
		err = st.Save(run)
		require.NoError(t, err)
	}

	summaries, err := st.ListRuns(ListOpts{Limit: 3})
	require.NoError(t, err)
	assert.Len(t, summaries, 3)

	// Verify ordering: newest first
	for i := 1; i < len(summaries); i++ {
		assert.True(t, summaries[i-1].CreatedAt.After(summaries[i].CreatedAt) ||
			summaries[i-1].CreatedAt.Equal(summaries[i].CreatedAt),
			"Results should be ordered newest first")
	}
}

func TestListRunsWithTimeFilter(t *testing.T) {
	dir := t.TempDir()
	st, err := NewSQLiteStore(filepath.Join(dir, "test.db"))
	require.NoError(t, err)
	defer st.Close() //nolint:errcheck

	// Old run: 48 hours ago
	oldRun := makeRun("cluster1", []string{"old error"})
	oldRun.CreatedAt = time.Now().UTC().Add(-48 * time.Hour)
	err = st.Save(oldRun)
	require.NoError(t, err)

	// Recent run: 1 hour ago
	recentRun := makeRun("cluster1", []string{"recent error"})
	recentRun.CreatedAt = time.Now().UTC().Add(-1 * time.Hour)
	err = st.Save(recentRun)
	require.NoError(t, err)

	since := time.Now().UTC().Add(-24 * time.Hour)
	summaries, err := st.ListRuns(ListOpts{Since: since})
	require.NoError(t, err)
	require.Len(t, summaries, 1)
	assert.Equal(t, recentRun.ID, summaries[0].ID)
}

func TestDiff(t *testing.T) {
	dir := t.TempDir()
	st, err := NewSQLiteStore(filepath.Join(dir, "test.db"))
	require.NoError(t, err)
	defer st.Close() //nolint:errcheck

	// run1 has {crash, warning}
	run1 := &RunRecord{
		Cluster:   "cluster1",
		Namespace: "default",
		Score:     score.HealthScore{Score: 70, Grade: "C"},
		Filters:   []string{},
		Results: []common.Result{
			{Kind: "Pod", Name: "pod-a", Error: []common.Failure{{Text: "crash", Severity: common.SeverityCritical}}},
			{Kind: "Pod", Name: "pod-b", Error: []common.Failure{{Text: "warning", Severity: common.SeverityLow}}},
		},
		CreatedAt: time.Now().UTC().Add(-10 * time.Minute),
	}
	err = st.Save(run1)
	require.NoError(t, err)

	// run2 has {crash, new_issue}
	run2 := &RunRecord{
		Cluster:   "cluster1",
		Namespace: "default",
		Score:     score.HealthScore{Score: 60, Grade: "C"},
		Filters:   []string{},
		Results: []common.Result{
			{Kind: "Pod", Name: "pod-a", Error: []common.Failure{{Text: "crash", Severity: common.SeverityCritical}}},
			{Kind: "Pod", Name: "pod-c", Error: []common.Failure{{Text: "new_issue", Severity: common.SeverityHigh}}},
		},
		CreatedAt: time.Now().UTC(),
	}
	err = st.Save(run2)
	require.NoError(t, err)

	diff, err := st.Diff(run1.ID, run2.ID)
	require.NoError(t, err)
	require.NotNil(t, diff)

	assert.Equal(t, run1.ID, diff.Run1ID)
	assert.Equal(t, run2.ID, diff.Run2ID)
	assert.Equal(t, -10, diff.ScoreDelta) // 60 - 70 = -10

	// New failure: new_issue (in run2 but not run1)
	require.Len(t, diff.NewFailures, 1)
	assert.Equal(t, "new_issue", diff.NewFailures[0].Text)

	// Resolved failure: warning (in run1 but not run2)
	require.Len(t, diff.ResolvedFailures, 1)
	assert.Equal(t, "warning", diff.ResolvedFailures[0].Text)
}

func TestTrend(t *testing.T) {
	dir := t.TempDir()
	st, err := NewSQLiteStore(filepath.Join(dir, "test.db"))
	require.NoError(t, err)
	defer st.Close() //nolint:errcheck

	// 3 runs each with the same failure
	base := time.Now().UTC().Add(-3 * time.Hour)
	for i := 0; i < 3; i++ {
		run := &RunRecord{
			Cluster:   "cluster1",
			Namespace: "default",
			Score:     score.HealthScore{Score: 80, Grade: "B"},
			Filters:   []string{},
			Results: []common.Result{
				{Kind: "Pod", Name: "pod-a", Error: []common.Failure{
					{Text: "persistent crash", Severity: common.SeverityCritical},
				}},
			},
			CreatedAt: base.Add(time.Duration(i) * time.Hour),
		}
		err = st.Save(run)
		require.NoError(t, err)
	}

	trend, err := st.Trend(TrendOpts{
		Cluster: "cluster1",
		Since:   base.Add(-1 * time.Hour),
	})
	require.NoError(t, err)
	require.NotNil(t, trend)

	assert.Len(t, trend.ScoreOverTime, 3)

	require.Len(t, trend.PersistentFailures, 1)
	assert.Equal(t, "persistent crash", trend.PersistentFailures[0].Text)
	assert.InDelta(t, 1.0, trend.PersistentFailures[0].OccurrenceRate, 0.001)
}

func TestGetRunNotFound(t *testing.T) {
	dir := t.TempDir()
	st, err := NewSQLiteStore(filepath.Join(dir, "test.db"))
	require.NoError(t, err)
	defer st.Close() //nolint:errcheck

	_, err = st.GetRun("01NONEXISTENT000000000000")
	require.Error(t, err)
}

func TestListRunsClusterFilter(t *testing.T) {
	dir := t.TempDir()
	st, err := NewSQLiteStore(filepath.Join(dir, "test.db"))
	require.NoError(t, err)
	defer st.Close() //nolint:errcheck

	run1 := makeRun("cluster-a", []string{"err1"})
	run2 := makeRun("cluster-b", []string{"err2"})
	require.NoError(t, st.Save(run1))
	require.NoError(t, st.Save(run2))

	summaries, err := st.ListRuns(ListOpts{Cluster: "cluster-a"})
	require.NoError(t, err)
	require.Len(t, summaries, 1)
	assert.Equal(t, "cluster-a", summaries[0].Cluster)
}

func TestListRunsUntilFilter(t *testing.T) {
	dir := t.TempDir()
	st, err := NewSQLiteStore(filepath.Join(dir, "test.db"))
	require.NoError(t, err)
	defer st.Close() //nolint:errcheck

	recent := makeRun("cluster1", []string{"new error"})
	recent.CreatedAt = time.Now().UTC().Add(-1 * time.Hour)
	require.NoError(t, st.Save(recent))

	future := makeRun("cluster1", []string{"future error"})
	future.CreatedAt = time.Now().UTC().Add(1 * time.Hour)
	require.NoError(t, st.Save(future))

	until := time.Now().UTC()
	summaries, err := st.ListRuns(ListOpts{Until: until})
	require.NoError(t, err)
	require.Len(t, summaries, 1)
	assert.Equal(t, recent.ID, summaries[0].ID)
}

func TestSaveRunWithRemediation(t *testing.T) {
	dir := t.TempDir()
	st, err := NewSQLiteStore(filepath.Join(dir, "test.db"))
	require.NoError(t, err)
	defer st.Close() //nolint:errcheck

	run := &RunRecord{
		Cluster:   "prod",
		Namespace: "default",
		Score:     score.HealthScore{Score: 50, Grade: "D", FailureCount: 1},
		Filters:   []string{"Pod"},
		Results: []common.Result{
			{
				Kind: "Pod",
				Name: "pod-x",
				Error: []common.Failure{
					{
						Text:          "OOMKilled",
						Severity:      common.SeverityHigh,
						KubernetesDoc: "https://kubernetes.io/docs",
						Remediation: &common.Remediation{
							Type:        common.RemediationTypeCommand,
							Command:     "kubectl",
							CommandArgs: []string{"describe", "pod", "pod-x"},
							Description: "Inspect the pod",
							Risk:        "low",
						},
					},
				},
			},
		},
		CreatedAt: time.Now().UTC(),
	}

	err = st.Save(run)
	require.NoError(t, err)

	got, err := st.GetRun(run.ID)
	require.NoError(t, err)
	require.Len(t, got.Results, 1)
	require.Len(t, got.Results[0].Error, 1)
	f := got.Results[0].Error[0]
	assert.Equal(t, "OOMKilled", f.Text)
	assert.NotNil(t, f.Remediation)
	assert.Equal(t, "kubectl", f.Remediation.Command)
	assert.Equal(t, "https://kubernetes.io/docs", f.KubernetesDoc)
}

func TestTrendWithSingleRun(t *testing.T) {
	dir := t.TempDir()
	st, err := NewSQLiteStore(filepath.Join(dir, "test.db"))
	require.NoError(t, err)
	defer st.Close() //nolint:errcheck

	run := makeRun("cluster1", []string{"some error"})
	run.CreatedAt = time.Now().UTC().Add(-1 * time.Hour)
	require.NoError(t, st.Save(run))

	trend, err := st.Trend(TrendOpts{
		Cluster: "cluster1",
		Since:   time.Now().UTC().Add(-2 * time.Hour),
	})
	require.NoError(t, err)
	require.NotNil(t, trend)
	assert.Len(t, trend.ScoreOverTime, 1)
	// Single run: no regressions (need >=2 runs)
	assert.Empty(t, trend.Regressions)
}

func TestTrendEmpty(t *testing.T) {
	dir := t.TempDir()
	st, err := NewSQLiteStore(filepath.Join(dir, "test.db"))
	require.NoError(t, err)
	defer st.Close() //nolint:errcheck

	trend, err := st.Trend(TrendOpts{
		Cluster: "no-such-cluster",
		Since:   time.Now().UTC().Add(-24 * time.Hour),
	})
	require.NoError(t, err)
	require.NotNil(t, trend)
	assert.Empty(t, trend.ScoreOverTime)
	assert.Empty(t, trend.PersistentFailures)
	assert.Empty(t, trend.Regressions)
}

func TestPrune(t *testing.T) {
	dir := t.TempDir()
	st, err := NewSQLiteStore(filepath.Join(dir, "test.db"))
	require.NoError(t, err)
	defer st.Close() //nolint:errcheck

	// Old run: 72 hours ago
	oldRun := makeRun("cluster1", []string{"old error"})
	oldRun.CreatedAt = time.Now().UTC().Add(-72 * time.Hour)
	err = st.Save(oldRun)
	require.NoError(t, err)

	// Recent run: 1 hour ago
	recentRun := makeRun("cluster1", []string{"recent error"})
	recentRun.CreatedAt = time.Now().UTC().Add(-1 * time.Hour)
	err = st.Save(recentRun)
	require.NoError(t, err)

	// Prune runs older than 48 hours
	deleted, err := st.Prune(48 * time.Hour)
	require.NoError(t, err)
	assert.Equal(t, 1, deleted)

	// Only recent run should remain
	summaries, err := st.ListRuns(ListOpts{})
	require.NoError(t, err)
	require.Len(t, summaries, 1)
	assert.Equal(t, recentRun.ID, summaries[0].ID)
}
