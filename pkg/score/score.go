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
	"math"
	"sort"
	"time"

	"github.com/k8sgpt-ai/k8sgpt/pkg/common"
	"github.com/spf13/viper"
)

type HealthScore struct {
	Score           int                     `json:"score"`
	Grade           string                  `json:"grade"`
	TotalPenalty    float64                 `json:"totalPenalty"`
	FailureCount    int                     `json:"failureCount"`
	SeverityCounts  map[common.Severity]int `json:"severityCounts"`
	TopContributors []ScoreContributor      `json:"topContributors"`
	ComputedAt      time.Time               `json:"computedAt"`
}

type ScoreContributor struct {
	Kind     string          `json:"kind"`
	Name     string          `json:"name"`
	Severity common.Severity `json:"severity"`
	Penalty  float64         `json:"penalty"`
}

type Config struct {
	SeverityWeights     map[common.Severity]float64
	ResourceMultipliers map[string]float64
}

func DefaultConfig() Config {
	return Config{
		SeverityWeights: map[common.Severity]float64{
			common.SeverityCritical: 10,
			common.SeverityHigh:     5,
			common.SeverityMedium:   2,
			common.SeverityLow:      1,
		},
		ResourceMultipliers: map[string]float64{
			"Node":                           3.0,
			"Deployment":                     2.0,
			"StatefulSet":                    2.0,
			"DaemonSet":                      2.0,
			"Service":                        1.5,
			"Ingress":                        1.5,
			"ValidatingWebhookConfiguration": 1.5,
			"MutatingWebhookConfiguration":   1.5,
		},
	}
}

func ConfigFromViper() Config {
	cfg := DefaultConfig()
	if v := viper.GetFloat64("score.weights.critical"); v > 0 {
		cfg.SeverityWeights[common.SeverityCritical] = v
	}
	if v := viper.GetFloat64("score.weights.high"); v > 0 {
		cfg.SeverityWeights[common.SeverityHigh] = v
	}
	if v := viper.GetFloat64("score.weights.medium"); v > 0 {
		cfg.SeverityWeights[common.SeverityMedium] = v
	}
	if v := viper.GetFloat64("score.weights.low"); v > 0 {
		cfg.SeverityWeights[common.SeverityLow] = v
	}
	return cfg
}

func (c Config) ResourceMultiplier(kind string) float64 {
	if m, ok := c.ResourceMultipliers[kind]; ok {
		return m
	}
	return 1.0
}

func Compute(results []common.Result, cfg Config) HealthScore {
	now := time.Now()
	severityCounts := make(map[common.Severity]int)
	var contributors []ScoreContributor
	var totalPenalty float64
	failureCount := 0

	for _, result := range results {
		for _, f := range result.Error {
			failureCount++
			severityCounts[f.Severity]++
			weight := cfg.SeverityWeights[f.Severity]
			multiplier := cfg.ResourceMultiplier(result.Kind)
			penalty := weight * multiplier
			totalPenalty += penalty
			contributors = append(contributors, ScoreContributor{
				Kind:     result.Kind,
				Name:     result.Name,
				Severity: f.Severity,
				Penalty:  penalty,
			})
		}
	}

	sort.Slice(contributors, func(i, j int) bool {
		return contributors[i].Penalty > contributors[j].Penalty
	})
	if len(contributors) > 5 {
		contributors = contributors[:5]
	}

	rawScore := 100.0 - totalPenalty
	finalScore := int(math.Max(0, math.Round(rawScore)))

	return HealthScore{
		Score:           finalScore,
		Grade:           gradeFromScore(finalScore),
		TotalPenalty:    totalPenalty,
		FailureCount:    failureCount,
		SeverityCounts:  severityCounts,
		TopContributors: contributors,
		ComputedAt:      now,
	}
}

func gradeFromScore(score int) string {
	switch {
	case score >= 90:
		return "A"
	case score >= 75:
		return "B"
	case score >= 60:
		return "C"
	case score >= 40:
		return "D"
	default:
		return "F"
	}
}
