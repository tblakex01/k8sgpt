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
	"context"
	"fmt"

	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/k8sgpt-ai/k8sgpt/pkg/common"
	"github.com/k8sgpt-ai/k8sgpt/pkg/kubernetes"
	"github.com/k8sgpt-ai/k8sgpt/pkg/util"
)

// DeploymentAnalyzer is an analyzer that checks for misconfigured Deployments
type DeploymentAnalyzer struct {
}

// Analyze scans all namespaces for Deployments with misconfigurations
func (d DeploymentAnalyzer) Analyze(a common.Analyzer) ([]common.Result, error) {

	kind := "Deployment"
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

	deployments, err := a.Client.GetClient().AppsV1().Deployments(a.Namespace).List(context.Background(), v1.ListOptions{LabelSelector: a.LabelSelector})
	if err != nil {
		return nil, err
	}
	var preAnalysis = map[string]common.PreAnalysis{}

	for _, deployment := range deployments.Items {
		var failures []common.Failure

		// Derive the label selector string from the Deployment's spec selector
		labelSelector := ""
		if deployment.Spec.Selector != nil {
			labelSelector = v1.FormatLabelSelector(deployment.Spec.Selector)
		}
		if *deployment.Spec.Replicas != deployment.Status.ReadyReplicas {
			if  deployment.Status.Replicas > *deployment.Spec.Replicas {
				doc := apiDoc.GetApiDocV2("spec.replicas")

				failures = append(failures, common.Failure{
					Text:          fmt.Sprintf("Deployment %s/%s has %d replicas in spec but %d replicas in status because status field is not updated yet after scaling and %d replicas are available with status running", deployment.Namespace, deployment.Name, *deployment.Spec.Replicas, deployment.Status.Replicas, deployment.Status.ReadyReplicas),
					KubernetesDoc: doc,
					Sensitive: []common.Sensitive{
						{
							Unmasked: deployment.Namespace,
							Masked:   util.MaskString(deployment.Namespace),
						},
						{
							Unmasked: deployment.Name,
							Masked:   util.MaskString(deployment.Name),
						},
					},
					Severity: common.SeverityMedium,
					Remediation: &common.Remediation{
						Type:        common.RemediationTypeInvestigation,
						Description: "Deployment status has not been updated yet after scaling. Wait for the controller to reconcile or check events.",
						Steps: []string{
							fmt.Sprintf("kubectl describe deployment %s -n %s", deployment.Name, deployment.Namespace),
							fmt.Sprintf("kubectl get events -n %s --field-selector involvedObject.name=%s", deployment.Namespace, deployment.Name),
						},
						Risk: "No changes made; investigation only",
					},
				})

			} else {
				doc := apiDoc.GetApiDocV2("spec.replicas")

				failures = append(failures, common.Failure{
					Text:          fmt.Sprintf("Deployment %s/%s has %d replicas but %d are available with status running", deployment.Namespace, deployment.Name, *deployment.Spec.Replicas, deployment.Status.ReadyReplicas),
					KubernetesDoc: doc,
					Sensitive: []common.Sensitive{
						{
							Unmasked: deployment.Namespace,
							Masked:   util.MaskString(deployment.Namespace),
						},
						{
							Unmasked: deployment.Name,
							Masked:   util.MaskString(deployment.Name),
						},
					},
					Severity: common.SeverityHigh,
					Remediation: &common.Remediation{
						Type:        common.RemediationTypeInvestigation,
						Description: "Deployment has fewer available replicas than desired. Check pod status and events.",
						Steps: []string{
							fmt.Sprintf("kubectl describe deployment %s -n %s", deployment.Name, deployment.Namespace),
							fmt.Sprintf("kubectl get pods -l %s -n %s", labelSelector, deployment.Namespace),
						},
						Risk: "No changes made; investigation only",
					},
				})
			}
		}
		if len(failures) > 0 {
			preAnalysis[fmt.Sprintf("%s/%s", deployment.Namespace, deployment.Name)] = common.PreAnalysis{
				FailureDetails: failures,
				Deployment:     deployment,
			}
			AnalyzerErrorsMetric.WithLabelValues(kind, deployment.Name, deployment.Namespace).Set(float64(len(failures)))
		}

	}

	for key, value := range preAnalysis {
		var currentAnalysis = common.Result{
			Kind:  kind,
			Name:  key,
			Error: value.FailureDetails,
		}

		a.Results = append(a.Results, currentAnalysis)
	}

	return a.Results, nil
}
