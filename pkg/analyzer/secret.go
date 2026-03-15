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
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"math"
	"time"

	"github.com/k8sgpt-ai/k8sgpt/pkg/common"
	"github.com/k8sgpt-ai/k8sgpt/pkg/kubernetes"
	"github.com/k8sgpt-ai/k8sgpt/pkg/util"
	corev1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

const (
	certExpiryWarningDays  = 30
	secretSizeWarningBytes = 900 * 1024
)

type SecretAnalyzer struct{}

// secretRef holds the information about a secret reference from a Pod.
type secretRef struct {
	secretName      string
	secretNamespace string
	podName         string
	podNamespace    string
}

func (SecretAnalyzer) Analyze(a common.Analyzer) ([]common.Result, error) {

	kind := "Secret"
	apiDoc := kubernetes.K8sApiReference{
		Kind: kind,
		ApiVersion: schema.GroupVersion{
			Group:   "",
			Version: "v1",
		},
		OpenapiSchema: a.OpenapiSchema,
	}

	AnalyzerErrorsMetric.DeletePartialMatch(map[string]string{
		"analyzer_name": kind,
	})

	var preAnalysis = map[string]common.PreAnalysis{}

	// Phase 1: Pod-centric — find dangling secret references
	pods, err := a.Client.GetClient().CoreV1().Pods(a.Namespace).List(a.Context, metav1.ListOptions{LabelSelector: a.LabelSelector})
	if err != nil {
		return nil, err
	}

	checkedSecrets := map[string]bool{}

	for _, pod := range pods.Items {
		refs := collectSecretRefs(pod)
		for _, ref := range refs {
			key := fmt.Sprintf("%s/%s", ref.secretNamespace, ref.secretName)
			if checkedSecrets[key] {
				continue
			}
			checkedSecrets[key] = true

			_, err := a.Client.GetClient().CoreV1().Secrets(ref.secretNamespace).Get(a.Context, ref.secretName, metav1.GetOptions{})
			if err != nil {
				var failure common.Failure
				doc := apiDoc.GetApiDocV2("metadata.name")

				if k8serrors.IsNotFound(err) {
					failure = common.Failure{
						Text: fmt.Sprintf(
							"Secret %s/%s is referenced by Pod %s/%s but does not exist.",
							ref.secretNamespace, ref.secretName, ref.podNamespace, ref.podName,
						),
						KubernetesDoc: doc,
						Sensitive: []common.Sensitive{
							{
								Unmasked: ref.secretName,
								Masked:   util.MaskString(ref.secretName),
							},
							{
								Unmasked: ref.secretNamespace,
								Masked:   util.MaskString(ref.secretNamespace),
							},
							{
								Unmasked: ref.podName,
								Masked:   util.MaskString(ref.podName),
							},
							{
								Unmasked: ref.podNamespace,
								Masked:   util.MaskString(ref.podNamespace),
							},
						},
						Severity: common.SeverityHigh,
						Remediation: &common.Remediation{
							Type:        common.RemediationTypeCommand,
							Command:     fmt.Sprintf("kubectl create secret generic %s -n %s", ref.secretName, ref.secretNamespace),
							CommandArgs: []string{"kubectl", "create", "secret", "generic", ref.secretName, "-n", ref.secretNamespace},
							Description: "Create the missing secret so the referencing pod can start.",
							Risk:        "Creates an empty secret; you must add the required data keys",
						},
					}
				} else {
					failure = common.Failure{
						Text: fmt.Sprintf(
							"Failed to verify secret %s/%s: %v",
							ref.secretNamespace, ref.secretName, err,
						),
						KubernetesDoc: doc,
						Sensitive: []common.Sensitive{
							{
								Unmasked: ref.secretName,
								Masked:   util.MaskString(ref.secretName),
							},
							{
								Unmasked: ref.secretNamespace,
								Masked:   util.MaskString(ref.secretNamespace),
							},
						},
						Severity: common.SeverityMedium,
						Remediation: &common.Remediation{
							Type:        common.RemediationTypeInvestigation,
							Description: "Investigate the API error when fetching the secret.",
							Steps: []string{
								fmt.Sprintf("kubectl get secret %s -n %s", ref.secretName, ref.secretNamespace),
								"Check RBAC permissions and API server connectivity",
							},
							Risk: "The secret may or may not exist; the analyzer could not verify it",
						},
					}
				}

				preAnalysisKey := fmt.Sprintf("%s/%s", ref.secretNamespace, ref.secretName)
				if existing, ok := preAnalysis[preAnalysisKey]; ok {
					existing.FailureDetails = append(existing.FailureDetails, failure)
					preAnalysis[preAnalysisKey] = existing
				} else {
					preAnalysis[preAnalysisKey] = common.PreAnalysis{
						Secret: corev1.Secret{
							ObjectMeta: metav1.ObjectMeta{
								Name:      ref.secretName,
								Namespace: ref.secretNamespace,
							},
						},
						FailureDetails: []common.Failure{failure},
					}
				}
			}
		}
	}

	// Phase 2: Secret-centric — TLS validation and size checks
	secrets, err := a.Client.GetClient().CoreV1().Secrets(a.Namespace).List(a.Context, metav1.ListOptions{
		LabelSelector: a.LabelSelector,
	})
	if err != nil {
		return nil, err
	}

	for _, secret := range secrets.Items {
		var failures []common.Failure

		// TLS validation
		if secret.Type == corev1.SecretTypeTLS {
			tlsFailures := checkTLSSecret(a, secret, apiDoc)
			failures = append(failures, tlsFailures...)
		}

		// Size check
		totalSize := 0
		for _, v := range secret.Data {
			totalSize += len(v)
		}
		if totalSize > secretSizeWarningBytes {
			doc := apiDoc.GetApiDocV2("data")
			failures = append(failures, common.Failure{
				Text: fmt.Sprintf(
					"Secret %s/%s data size %dKB is approaching the 1MB etcd limit.",
					secret.Namespace, secret.Name, totalSize/1024,
				),
				KubernetesDoc: doc,
				Sensitive: []common.Sensitive{
					{
						Unmasked: secret.Name,
						Masked:   util.MaskString(secret.Name),
					},
					{
						Unmasked: secret.Namespace,
						Masked:   util.MaskString(secret.Namespace),
					},
				},
				Severity: common.SeverityMedium,
				Remediation: &common.Remediation{
					Type:        common.RemediationTypeInvestigation,
					Description: "Review the secret and consider splitting it into multiple smaller secrets.",
					Steps: []string{
						fmt.Sprintf("kubectl get secret %s -n %s -o json | jq '.data | keys'", secret.Name, secret.Namespace),
						"Identify data keys that can be moved to separate secrets or external secret stores",
					},
					Risk: "Oversized secrets may hit etcd size limits and cause API server issues",
				},
			})
		}

		if len(failures) > 0 {
			preAnalysisKey := fmt.Sprintf("%s/%s", secret.Namespace, secret.Name)
			if existing, ok := preAnalysis[preAnalysisKey]; ok {
				existing.FailureDetails = append(existing.FailureDetails, failures...)
				preAnalysis[preAnalysisKey] = existing
			} else {
				preAnalysis[preAnalysisKey] = common.PreAnalysis{
					Secret:         secret,
					FailureDetails: failures,
				}
			}
		}
	}

	// Build results
	for key, value := range preAnalysis {
		var currentAnalysis = common.Result{
			Kind:  kind,
			Name:  key,
			Error: value.FailureDetails,
		}

		if value.Secret.Name != "" {
			parent, found := util.GetParent(a.Client, value.Secret.ObjectMeta)
			if found {
				currentAnalysis.ParentObject = parent
			}
		}
		AnalyzerErrorsMetric.WithLabelValues(kind, value.Secret.Name, value.Secret.Namespace).Set(float64(len(value.FailureDetails)))
		a.Results = append(a.Results, currentAnalysis)
	}

	return a.Results, nil
}

func collectSecretRefs(pod corev1.Pod) []secretRef {
	var refs []secretRef
	ns := pod.Namespace

	// Volume secret references
	for _, volume := range pod.Spec.Volumes {
		if volume.Secret != nil {
			refs = append(refs, secretRef{
				secretName:      volume.Secret.SecretName,
				secretNamespace: ns,
				podName:         pod.Name,
				podNamespace:    ns,
			})
		}
	}

	// ImagePullSecrets
	for _, ips := range pod.Spec.ImagePullSecrets {
		refs = append(refs, secretRef{
			secretName:      ips.Name,
			secretNamespace: ns,
			podName:         pod.Name,
			podNamespace:    ns,
		})
	}

	// Container envFrom and env
	for _, container := range pod.Spec.Containers {
		for _, envFrom := range container.EnvFrom {
			if envFrom.SecretRef != nil {
				refs = append(refs, secretRef{
					secretName:      envFrom.SecretRef.Name,
					secretNamespace: ns,
					podName:         pod.Name,
					podNamespace:    ns,
				})
			}
		}
		for _, env := range container.Env {
			if env.ValueFrom != nil && env.ValueFrom.SecretKeyRef != nil {
				refs = append(refs, secretRef{
					secretName:      env.ValueFrom.SecretKeyRef.Name,
					secretNamespace: ns,
					podName:         pod.Name,
					podNamespace:    ns,
				})
			}
		}
	}

	// InitContainer envFrom and env — iterate separately, do NOT append to Containers
	for _, container := range pod.Spec.InitContainers {
		for _, envFrom := range container.EnvFrom {
			if envFrom.SecretRef != nil {
				refs = append(refs, secretRef{
					secretName:      envFrom.SecretRef.Name,
					secretNamespace: ns,
					podName:         pod.Name,
					podNamespace:    ns,
				})
			}
		}
		for _, env := range container.Env {
			if env.ValueFrom != nil && env.ValueFrom.SecretKeyRef != nil {
				refs = append(refs, secretRef{
					secretName:      env.ValueFrom.SecretKeyRef.Name,
					secretNamespace: ns,
					podName:         pod.Name,
					podNamespace:    ns,
				})
			}
		}
	}

	return refs
}

func checkTLSSecret(a common.Analyzer, secret corev1.Secret, apiDoc kubernetes.K8sApiReference) []common.Failure {
	var failures []common.Failure

	// Check tls.crt exists and is non-empty
	certData, certExists := secret.Data["tls.crt"]
	if !certExists || len(certData) == 0 {
		doc := apiDoc.GetApiDocV2("data")
		failures = append(failures, common.Failure{
			Text: fmt.Sprintf("TLS Secret %s/%s is missing the tls.crt data key.", secret.Namespace, secret.Name),
			KubernetesDoc: doc,
			Sensitive: []common.Sensitive{
				{
					Unmasked: secret.Name,
					Masked:   util.MaskString(secret.Name),
				},
				{
					Unmasked: secret.Namespace,
					Masked:   util.MaskString(secret.Namespace),
				},
			},
			Severity: common.SeverityHigh,
			Remediation: &common.Remediation{
				Type:        common.RemediationTypeInvestigation,
				Description: "Regenerate the TLS secret with a valid certificate.",
				Steps: []string{
					fmt.Sprintf("kubectl describe secret %s -n %s", secret.Name, secret.Namespace),
					"Regenerate the TLS certificate and update the secret with the correct tls.crt data",
				},
				Risk: "Services depending on this TLS secret will not have a valid certificate",
			},
		})
		return failures
	}

	// Check tls.key exists and is non-empty
	keyData, keyExists := secret.Data["tls.key"]
	if !keyExists || len(keyData) == 0 {
		doc := apiDoc.GetApiDocV2("data")
		failures = append(failures, common.Failure{
			Text: fmt.Sprintf("TLS Secret %s/%s is missing the tls.key data key.", secret.Namespace, secret.Name),
			KubernetesDoc: doc,
			Sensitive: []common.Sensitive{
				{
					Unmasked: secret.Name,
					Masked:   util.MaskString(secret.Name),
				},
				{
					Unmasked: secret.Namespace,
					Masked:   util.MaskString(secret.Namespace),
				},
			},
			Severity: common.SeverityHigh,
			Remediation: &common.Remediation{
				Type:        common.RemediationTypeInvestigation,
				Description: "Regenerate the TLS secret with a valid private key.",
				Steps: []string{
					fmt.Sprintf("kubectl describe secret %s -n %s", secret.Name, secret.Namespace),
					"Regenerate the TLS private key and update the secret with the correct tls.key data",
				},
				Risk: "Services depending on this TLS secret will not have a valid private key",
			},
		})
		return failures
	}

	// Parse the certificate
	block, _ := pem.Decode(certData)
	if block == nil {
		doc := apiDoc.GetApiDocV2("data")
		failures = append(failures, common.Failure{
			Text: fmt.Sprintf("TLS Secret %s/%s has invalid PEM data in tls.crt", secret.Namespace, secret.Name),
			KubernetesDoc: doc,
			Sensitive: []common.Sensitive{
				{
					Unmasked: secret.Name,
					Masked:   util.MaskString(secret.Name),
				},
				{
					Unmasked: secret.Namespace,
					Masked:   util.MaskString(secret.Namespace),
				},
			},
			Severity: common.SeverityHigh,
			Remediation: &common.Remediation{
				Type:        common.RemediationTypeInvestigation,
				Description: "The tls.crt field does not contain valid PEM-encoded data. Regenerate the TLS secret with a valid certificate.",
				Steps: []string{
					fmt.Sprintf("kubectl get secret %s -n %s -o jsonpath='{.data.tls\\.crt}' | base64 -d", secret.Name, secret.Namespace),
					"Regenerate the TLS certificate and update the secret",
				},
				Risk: "Services depending on this TLS secret will not have a valid certificate",
			},
		})
		return failures
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		doc := apiDoc.GetApiDocV2("data")
		failures = append(failures, common.Failure{
			Text: fmt.Sprintf("TLS Secret %s/%s has unparseable certificate: %v", secret.Namespace, secret.Name, err),
			KubernetesDoc: doc,
			Sensitive: []common.Sensitive{
				{
					Unmasked: secret.Name,
					Masked:   util.MaskString(secret.Name),
				},
				{
					Unmasked: secret.Namespace,
					Masked:   util.MaskString(secret.Namespace),
				},
			},
			Severity: common.SeverityHigh,
			Remediation: &common.Remediation{
				Type:        common.RemediationTypeInvestigation,
				Description: "The tls.crt field contains PEM data but the certificate cannot be parsed. Regenerate the TLS secret with a valid certificate.",
				Steps: []string{
					fmt.Sprintf("kubectl get secret %s -n %s -o jsonpath='{.data.tls\\.crt}' | base64 -d | openssl x509 -text -noout", secret.Name, secret.Namespace),
					"Regenerate the TLS certificate and update the secret",
				},
				Risk: "Services depending on this TLS secret will not have a valid certificate",
			},
		})
		return failures
	}

	// Check certificate expiry
	daysUntilExpiry := int(math.Floor(time.Until(cert.NotAfter).Hours() / 24))
	if daysUntilExpiry <= certExpiryWarningDays {
		// Determine message text and severity based on whether cert is already expired
		var expiryText string
		var expirySeverity common.Severity
		var remediationDesc string
		if daysUntilExpiry < 0 {
			daysExpiredAgo := -daysUntilExpiry
			expiryText = fmt.Sprintf("TLS Secret %s/%s certificate expired %d days ago", secret.Namespace, secret.Name, daysExpiredAgo)
			expirySeverity = common.SeverityCritical
			remediationDesc = "The TLS certificate has already expired. Renew it immediately."
		} else {
			expiryText = fmt.Sprintf("Secret %s/%s has a TLS certificate expiring in %d days.", secret.Namespace, secret.Name, daysUntilExpiry)
			expirySeverity = common.SeverityHigh
			remediationDesc = "Renew the expiring TLS certificate before it expires."
		}

		// Cross-reference Ingresses using this secret
		ingressNames := findIngressesUsingSecret(a, secret.Namespace, secret.Name)

		for _, ingressName := range ingressNames {
			doc := apiDoc.GetApiDocV2("data")
			var text string
			if daysUntilExpiry < 0 {
				text = fmt.Sprintf("%s, used by Ingress %s.", expiryText, ingressName)
			} else {
				text = fmt.Sprintf(
					"Secret %s/%s has a TLS certificate expiring in %d days, used by Ingress %s.",
					secret.Namespace, secret.Name, daysUntilExpiry, ingressName,
				)
			}
			failures = append(failures, common.Failure{
				Text:          text,
				KubernetesDoc: doc,
				Sensitive: []common.Sensitive{
					{
						Unmasked: secret.Name,
						Masked:   util.MaskString(secret.Name),
					},
					{
						Unmasked: secret.Namespace,
						Masked:   util.MaskString(secret.Namespace),
					},
					{
						Unmasked: ingressName,
						Masked:   util.MaskString(ingressName),
					},
				},
				Severity: expirySeverity,
				Remediation: &common.Remediation{
					Type:        common.RemediationTypeInvestigation,
					Description: remediationDesc,
					Steps: []string{
						fmt.Sprintf("kubectl describe secret %s -n %s", secret.Name, secret.Namespace),
						"Check if cert-manager or another certificate automation tool is configured",
						"Renew the certificate and update the secret",
					},
					Risk: "Expired certificates will cause TLS errors for clients connecting via the Ingress",
				},
			})
		}

		// If no ingresses found, still report the expiry
		if len(ingressNames) == 0 {
			doc := apiDoc.GetApiDocV2("data")
			failures = append(failures, common.Failure{
				Text:          expiryText,
				KubernetesDoc: doc,
				Sensitive: []common.Sensitive{
					{
						Unmasked: secret.Name,
						Masked:   util.MaskString(secret.Name),
					},
					{
						Unmasked: secret.Namespace,
						Masked:   util.MaskString(secret.Namespace),
					},
				},
				Severity: expirySeverity,
				Remediation: &common.Remediation{
					Type:        common.RemediationTypeInvestigation,
					Description: remediationDesc,
					Steps: []string{
						fmt.Sprintf("kubectl describe secret %s -n %s", secret.Name, secret.Namespace),
						"Check if cert-manager or another certificate automation tool is configured",
						"Renew the certificate and update the secret",
					},
					Risk: "Expired certificates will cause TLS errors for services using this secret",
				},
			})
		}
	}

	return failures
}

func findIngressesUsingSecret(a common.Analyzer, namespace, secretName string) []string {
	ingresses, err := a.Client.GetClient().NetworkingV1().Ingresses(namespace).List(a.Context, metav1.ListOptions{})
	if err != nil {
		return nil
	}

	var result []string
	for _, ingress := range ingresses.Items {
		for _, tls := range ingress.Spec.TLS {
			if tls.SecretName == secretName {
				result = append(result, ingress.Name)
				break
			}
		}
	}
	return result
}
