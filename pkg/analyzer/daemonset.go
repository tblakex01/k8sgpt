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

package analyzer

import (
	"fmt"

	"github.com/k8sgpt-ai/k8sgpt/pkg/common"
	"github.com/k8sgpt-ai/k8sgpt/pkg/kubernetes"
	"github.com/k8sgpt-ai/k8sgpt/pkg/util"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

type DaemonSetAnalyzer struct{}

func (DaemonSetAnalyzer) Analyze(a common.Analyzer) ([]common.Result, error) {

	kind := "DaemonSet"
	apiDoc := kubernetes.K8sApiReference{
		Kind: kind,
		ApiVersion: schema.GroupVersion{
			Group:   "apps",
			Version: "v1",
		},
		OpenapiSchema: a.OpenapiSchema,
	}

	AnalyzerErrorsMetric.DeletePartialMatch(map[string]string{
		"analyzer_name": kind,
	})

	list, err := a.Client.GetClient().AppsV1().DaemonSets(a.Namespace).List(a.Context, metav1.ListOptions{LabelSelector: a.LabelSelector})
	if err != nil {
		return nil, err
	}

	var preAnalysis = map[string]common.PreAnalysis{}

	for _, ds := range list.Items {
		var failures []common.Failure

		if ds.Status.DesiredNumberScheduled != ds.Status.CurrentNumberScheduled {
			doc := apiDoc.GetApiDocV2("status.desiredNumberScheduled")
			failures = append(failures, common.Failure{
				Text: fmt.Sprintf(
					"DaemonSet has %d desired pods but only %d currently scheduled.",
					ds.Status.DesiredNumberScheduled,
					ds.Status.CurrentNumberScheduled,
				),
				KubernetesDoc: doc,
				Sensitive: []common.Sensitive{
					{
						Unmasked: ds.Name,
						Masked:   util.MaskString(ds.Name),
					},
					{
						Unmasked: ds.Namespace,
						Masked:   util.MaskString(ds.Namespace),
					},
				},
			})
		}

		if ds.Status.NumberUnavailable > 0 {
			doc := apiDoc.GetApiDocV2("status.numberUnavailable")
			failures = append(failures, common.Failure{
				Text: fmt.Sprintf(
					"DaemonSet has %d unavailable pods.",
					ds.Status.NumberUnavailable,
				),
				KubernetesDoc: doc,
				Sensitive: []common.Sensitive{
					{
						Unmasked: ds.Name,
						Masked:   util.MaskString(ds.Name),
					},
					{
						Unmasked: ds.Namespace,
						Masked:   util.MaskString(ds.Namespace),
					},
				},
			})
		}

		if ds.Status.NumberMisscheduled > 0 {
			doc := apiDoc.GetApiDocV2("status.numberMisscheduled")
			failures = append(failures, common.Failure{
				Text: fmt.Sprintf(
					"DaemonSet has %d pods running on unexpected nodes.",
					ds.Status.NumberMisscheduled,
				),
				KubernetesDoc: doc,
				Sensitive: []common.Sensitive{
					{
						Unmasked: ds.Name,
						Masked:   util.MaskString(ds.Name),
					},
					{
						Unmasked: ds.Namespace,
						Masked:   util.MaskString(ds.Namespace),
					},
				},
			})
		}

		// Check for warning events
		events, err := a.Client.GetClient().CoreV1().Events(ds.Namespace).List(a.Context, metav1.ListOptions{
			FieldSelector: "involvedObject.name=" + ds.Name,
		})
		if err == nil {
			for _, event := range events.Items {
				if event.Type != "Normal" {
					failures = append(failures, common.Failure{
						Text: fmt.Sprintf("DaemonSet %s/%s has event: %s", ds.Namespace, ds.Name, event.Message),
						Sensitive: []common.Sensitive{
							{
								Unmasked: ds.Name,
								Masked:   util.MaskString(ds.Name),
							},
							{
								Unmasked: ds.Namespace,
								Masked:   util.MaskString(ds.Namespace),
							},
						},
					})
				}
			}
		}

		if len(failures) > 0 {
			preAnalysis[fmt.Sprintf("%s/%s", ds.Namespace, ds.Name)] = common.PreAnalysis{
				DaemonSet:      ds,
				FailureDetails: failures,
			}
			AnalyzerErrorsMetric.WithLabelValues(kind, ds.Name, ds.Namespace).Set(float64(len(failures)))
		}
	}

	for key, value := range preAnalysis {
		var currentAnalysis = common.Result{
			Kind:  kind,
			Name:  key,
			Error: value.FailureDetails,
		}

		parent, found := util.GetParent(a.Client, value.DaemonSet.ObjectMeta)
		if found {
			currentAnalysis.ParentObject = parent
		}
		a.Results = append(a.Results, currentAnalysis)
	}

	return a.Results, nil
}
