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
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	ClusterHealthScoreGauge = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "k8sgpt_cluster_health_score",
		Help: "Current cluster health score (0-100)",
	})

	FailureCountBySeverity = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "k8sgpt_failure_count_by_severity",
		Help: "Number of failures by severity level",
	}, []string{"severity"})
)

func UpdateMetrics(hs *HealthScore) {
	if hs == nil {
		return
	}
	ClusterHealthScoreGauge.Set(float64(hs.Score))
	for sev, count := range hs.SeverityCounts {
		FailureCountBySeverity.WithLabelValues(string(sev)).Set(float64(count))
	}
}
