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
	"testing"

	"github.com/k8sgpt-ai/k8sgpt/pkg/common"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
)

func TestCompute_NoFailures(t *testing.T) {
	results := []common.Result{}
	cfg := DefaultConfig()
	hs := Compute(results, cfg)
	assert.Equal(t, 100, hs.Score)
	assert.Equal(t, "A", hs.Grade)
	assert.Equal(t, 0, hs.FailureCount)
}

func TestCompute_SingleCriticalNode(t *testing.T) {
	results := []common.Result{
		{
			Kind: "Node",
			Name: "node-1",
			Error: []common.Failure{
				{Text: "node not ready", Severity: common.SeverityCritical},
			},
		},
	}
	cfg := DefaultConfig()
	hs := Compute(results, cfg)
	assert.Equal(t, 70, hs.Score)
	assert.Equal(t, "C", hs.Grade)
	assert.Equal(t, 1, hs.FailureCount)
	assert.Equal(t, 1, hs.SeverityCounts[common.SeverityCritical])
}

func TestCompute_FloorAtZero(t *testing.T) {
	results := []common.Result{
		{
			Kind: "Node",
			Name: "node-1",
			Error: []common.Failure{
				{Text: "not ready", Severity: common.SeverityCritical},
				{Text: "disk pressure", Severity: common.SeverityCritical},
				{Text: "memory pressure", Severity: common.SeverityCritical},
				{Text: "pid pressure", Severity: common.SeverityCritical},
			},
		},
	}
	cfg := DefaultConfig()
	hs := Compute(results, cfg)
	assert.Equal(t, 0, hs.Score)
	assert.Equal(t, "F", hs.Grade)
}

func TestCompute_AllGradeThresholds(t *testing.T) {
	cfg := DefaultConfig()
	tests := []struct {
		name          string
		score         int
		expectedGrade string
	}{
		{"A grade", 95, "A"},
		{"B grade", 80, "B"},
		{"C grade", 65, "C"},
		{"D grade", 45, "D"},
		{"F grade", 30, "F"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			grade := gradeFromScore(tt.score)
			_ = cfg
			assert.Equal(t, tt.expectedGrade, grade)
		})
	}
}

func TestCompute_CustomWeights(t *testing.T) {
	results := []common.Result{
		{
			Kind: "Pod",
			Name: "pod-1",
			Error: []common.Failure{
				{Text: "crash", Severity: common.SeverityCritical},
			},
		},
	}
	cfg := DefaultConfig()
	cfg.SeverityWeights[common.SeverityCritical] = 20
	hs := Compute(results, cfg)
	assert.Equal(t, 80, hs.Score)
	assert.Equal(t, "B", hs.Grade)
}

func TestCompute_ResourceMultipliers(t *testing.T) {
	cfg := DefaultConfig()
	tests := []struct {
		kind               string
		expectedMultiplier float64
	}{
		{"Node", 3.0},
		{"Deployment", 2.0},
		{"StatefulSet", 2.0},
		{"DaemonSet", 2.0},
		{"Service", 1.5},
		{"Ingress", 1.5},
		{"ValidatingWebhookConfiguration", 1.5},
		{"MutatingWebhookConfiguration", 1.5},
		{"Pod", 1.0},
		{"Job", 1.0},
		{"CronJob", 1.0},
		{"PersistentVolumeClaim", 1.0},
		{"ConfigMap", 1.0},
		{"Secret", 1.0},
		{"UnknownResource", 1.0},
	}
	for _, tt := range tests {
		t.Run(tt.kind, func(t *testing.T) {
			m := cfg.ResourceMultiplier(tt.kind)
			assert.InDelta(t, tt.expectedMultiplier, m, 1e-9)
		})
	}
}

func TestCompute_TopContributors(t *testing.T) {
	results := []common.Result{
		{Kind: "Node", Name: "node-1", Error: []common.Failure{
			{Text: "not ready", Severity: common.SeverityCritical},
		}},
		{Kind: "Pod", Name: "pod-1", Error: []common.Failure{
			{Text: "crash", Severity: common.SeverityLow},
		}},
		{Kind: "Deployment", Name: "deploy-1", Error: []common.Failure{
			{Text: "unavailable", Severity: common.SeverityHigh},
		}},
	}
	cfg := DefaultConfig()
	hs := Compute(results, cfg)
	assert.Len(t, hs.TopContributors, 3)
	assert.Equal(t, "Node", hs.TopContributors[0].Kind)
	assert.Equal(t, "Deployment", hs.TopContributors[1].Kind)
	assert.Equal(t, "Pod", hs.TopContributors[2].Kind)
}

func TestConfigFromViper_Defaults(t *testing.T) {
	// With no viper values set, ConfigFromViper should return the same weights as DefaultConfig
	cfg := ConfigFromViper()
	defaults := DefaultConfig()
	assert.InDelta(t, defaults.SeverityWeights[common.SeverityCritical], cfg.SeverityWeights[common.SeverityCritical], 1e-9)
	assert.InDelta(t, defaults.SeverityWeights[common.SeverityHigh], cfg.SeverityWeights[common.SeverityHigh], 1e-9)
	assert.InDelta(t, defaults.SeverityWeights[common.SeverityMedium], cfg.SeverityWeights[common.SeverityMedium], 1e-9)
	assert.InDelta(t, defaults.SeverityWeights[common.SeverityLow], cfg.SeverityWeights[common.SeverityLow], 1e-9)
}

func TestConfigFromViper_CustomWeights(t *testing.T) {
	viper.Set("score.weights.critical", 15.0)
	viper.Set("score.weights.high", 8.0)
	viper.Set("score.weights.medium", 3.0)
	viper.Set("score.weights.low", 2.0)
	defer func() {
		viper.Set("score.weights.critical", 0.0)
		viper.Set("score.weights.high", 0.0)
		viper.Set("score.weights.medium", 0.0)
		viper.Set("score.weights.low", 0.0)
	}()

	cfg := ConfigFromViper()
	assert.InDelta(t, 15.0, cfg.SeverityWeights[common.SeverityCritical], 1e-9)
	assert.InDelta(t, 8.0, cfg.SeverityWeights[common.SeverityHigh], 1e-9)
	assert.InDelta(t, 3.0, cfg.SeverityWeights[common.SeverityMedium], 1e-9)
	assert.InDelta(t, 2.0, cfg.SeverityWeights[common.SeverityLow], 1e-9)
}

func TestCompute_MixedSeverities(t *testing.T) {
	results := []common.Result{
		{Kind: "Pod", Name: "pod-1", Error: []common.Failure{
			{Text: "crash", Severity: common.SeverityCritical},
			{Text: "warning", Severity: common.SeverityLow},
		}},
		{Kind: "Service", Name: "svc-1", Error: []common.Failure{
			{Text: "no endpoints", Severity: common.SeverityMedium},
		}},
	}
	cfg := DefaultConfig()
	hs := Compute(results, cfg)
	assert.Equal(t, 86, hs.Score)
	assert.Equal(t, "B", hs.Grade)
	assert.Equal(t, 3, hs.FailureCount)
	assert.Equal(t, 1, hs.SeverityCounts[common.SeverityCritical])
	assert.Equal(t, 1, hs.SeverityCounts[common.SeverityMedium])
	assert.Equal(t, 1, hs.SeverityCounts[common.SeverityLow])
}
