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
	"time"

	"github.com/k8sgpt-ai/k8sgpt/pkg/common"
	"github.com/k8sgpt-ai/k8sgpt/pkg/score"
)

type IStore interface {
	Save(run *RunRecord) error
	GetRun(id string) (*RunRecord, error)
	ListRuns(opts ListOpts) ([]RunSummary, error)
	Diff(runID1, runID2 string) (*DiffResult, error)
	Trend(opts TrendOpts) (*TrendResult, error)
	Prune(olderThan time.Duration) (int, error)
	Close() error
}

type RunRecord struct {
	ID        string
	Cluster   string
	Namespace string
	Score     score.HealthScore
	Filters   []string
	Results   []common.Result
	CreatedAt time.Time
}

type RunSummary struct {
	ID            string    `json:"id"`
	Cluster       string    `json:"cluster"`
	Namespace     string    `json:"namespace"`
	Score         int       `json:"score"`
	Grade         string    `json:"grade"`
	FailureCount  int       `json:"failureCount"`
	CriticalCount int       `json:"criticalCount"`
	HighCount     int       `json:"highCount"`
	MediumCount   int       `json:"mediumCount"`
	LowCount      int       `json:"lowCount"`
	CreatedAt     time.Time `json:"createdAt"`
}

type ListOpts struct {
	Cluster string
	Since   time.Time
	Until   time.Time
	Limit   int
}

type TrendOpts struct {
	Cluster string
	Since   time.Time
	Until   time.Time
}

type DiffResult struct {
	Run1ID           string           `json:"run1Id"`
	Run2ID           string           `json:"run2Id"`
	ScoreDelta       int              `json:"scoreDelta"`
	NewFailures      []FailureSummary `json:"newFailures"`
	ResolvedFailures []FailureSummary `json:"resolvedFailures"`
}

type FailureSummary struct {
	Kind     string          `json:"kind"`
	Name     string          `json:"name"`
	Text     string          `json:"text"`
	Severity common.Severity `json:"severity"`
}

type TrendResult struct {
	ScoreOverTime      []ScorePoint      `json:"scoreOverTime"`
	PersistentFailures []PersistentIssue `json:"persistentFailures"`
	Regressions        []FailureSummary  `json:"regressions"`
}

type ScorePoint struct {
	Timestamp time.Time `json:"timestamp"`
	Score     int       `json:"score"`
	Grade     string    `json:"grade"`
}

type PersistentIssue struct {
	FailureSummary
	OccurrenceRate float64 `json:"occurrenceRate"`
}
