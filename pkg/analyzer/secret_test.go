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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/k8sgpt-ai/k8sgpt/pkg/common"
	"github.com/k8sgpt-ai/k8sgpt/pkg/kubernetes"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

func generateTestCert(t *testing.T, notAfter time.Time) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     notAfter,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
}

func TestSecretAnalyzerHealthy(t *testing.T) {
	clientset := fake.NewSimpleClientset(
		&corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "my-secret",
				Namespace: "default",
			},
			Data: map[string][]byte{
				"key": []byte("value"),
			},
		},
		&corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "my-pod",
				Namespace: "default",
			},
			Spec: corev1.PodSpec{
				Containers: []corev1.Container{
					{
						Name:  "app",
						Image: "nginx",
					},
				},
			},
		},
	)

	analyzer := SecretAnalyzer{}
	config := common.Analyzer{
		Client: &kubernetes.Client{
			Client: clientset,
		},
		Context:   context.Background(),
		Namespace: "default",
	}

	results, err := analyzer.Analyze(config)
	require.NoError(t, err)
	require.Equal(t, 0, len(results))
}

func TestSecretAnalyzerDanglingVolumeRef(t *testing.T) {
	clientset := fake.NewSimpleClientset(
		&corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "my-pod",
				Namespace: "default",
			},
			Spec: corev1.PodSpec{
				Volumes: []corev1.Volume{
					{
						Name: "secret-vol",
						VolumeSource: corev1.VolumeSource{
							Secret: &corev1.SecretVolumeSource{
								SecretName: "missing-secret",
							},
						},
					},
				},
				Containers: []corev1.Container{
					{
						Name:  "app",
						Image: "nginx",
					},
				},
			},
		},
	)

	analyzer := SecretAnalyzer{}
	config := common.Analyzer{
		Client: &kubernetes.Client{
			Client: clientset,
		},
		Context:   context.Background(),
		Namespace: "default",
	}

	results, err := analyzer.Analyze(config)
	require.NoError(t, err)
	require.Equal(t, 1, len(results))

	found := false
	for _, f := range results[0].Error {
		if strings.Contains(f.Text, "missing-secret") && strings.Contains(f.Text, "my-pod") {
			found = true
		}
	}
	require.True(t, found, "expected failure mentioning missing-secret and my-pod")
}

func TestSecretAnalyzerDanglingEnvFromRef(t *testing.T) {
	clientset := fake.NewSimpleClientset(
		&corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "my-pod",
				Namespace: "default",
			},
			Spec: corev1.PodSpec{
				Containers: []corev1.Container{
					{
						Name:  "app",
						Image: "nginx",
						EnvFrom: []corev1.EnvFromSource{
							{
								SecretRef: &corev1.SecretEnvSource{
									LocalObjectReference: corev1.LocalObjectReference{
										Name: "missing-secret",
									},
								},
							},
						},
					},
				},
			},
		},
	)

	analyzer := SecretAnalyzer{}
	config := common.Analyzer{
		Client: &kubernetes.Client{
			Client: clientset,
		},
		Context:   context.Background(),
		Namespace: "default",
	}

	results, err := analyzer.Analyze(config)
	require.NoError(t, err)
	require.Equal(t, 1, len(results))
}

func TestSecretAnalyzerDanglingSecretKeyRef(t *testing.T) {
	clientset := fake.NewSimpleClientset(
		&corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "my-pod",
				Namespace: "default",
			},
			Spec: corev1.PodSpec{
				Containers: []corev1.Container{
					{
						Name:  "app",
						Image: "nginx",
						Env: []corev1.EnvVar{
							{
								Name: "SECRET_VAR",
								ValueFrom: &corev1.EnvVarSource{
									SecretKeyRef: &corev1.SecretKeySelector{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "missing-secret",
										},
										Key: "password",
									},
								},
							},
						},
					},
				},
			},
		},
	)

	analyzer := SecretAnalyzer{}
	config := common.Analyzer{
		Client: &kubernetes.Client{
			Client: clientset,
		},
		Context:   context.Background(),
		Namespace: "default",
	}

	results, err := analyzer.Analyze(config)
	require.NoError(t, err)
	require.Equal(t, 1, len(results))
}

func TestSecretAnalyzerDanglingImagePullSecret(t *testing.T) {
	clientset := fake.NewSimpleClientset(
		&corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "my-pod",
				Namespace: "default",
			},
			Spec: corev1.PodSpec{
				ImagePullSecrets: []corev1.LocalObjectReference{
					{Name: "missing-secret"},
				},
				Containers: []corev1.Container{
					{
						Name:  "app",
						Image: "nginx",
					},
				},
			},
		},
	)

	analyzer := SecretAnalyzer{}
	config := common.Analyzer{
		Client: &kubernetes.Client{
			Client: clientset,
		},
		Context:   context.Background(),
		Namespace: "default",
	}

	results, err := analyzer.Analyze(config)
	require.NoError(t, err)
	require.Equal(t, 1, len(results))
}

func TestSecretAnalyzerDanglingInitContainerRef(t *testing.T) {
	clientset := fake.NewSimpleClientset(
		&corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "my-pod",
				Namespace: "default",
			},
			Spec: corev1.PodSpec{
				InitContainers: []corev1.Container{
					{
						Name:  "init",
						Image: "busybox",
						EnvFrom: []corev1.EnvFromSource{
							{
								SecretRef: &corev1.SecretEnvSource{
									LocalObjectReference: corev1.LocalObjectReference{
										Name: "missing-secret",
									},
								},
							},
						},
					},
				},
				Containers: []corev1.Container{
					{
						Name:  "app",
						Image: "nginx",
					},
				},
			},
		},
	)

	analyzer := SecretAnalyzer{}
	config := common.Analyzer{
		Client: &kubernetes.Client{
			Client: clientset,
		},
		Context:   context.Background(),
		Namespace: "default",
	}

	results, err := analyzer.Analyze(config)
	require.NoError(t, err)
	require.Equal(t, 1, len(results))
}

func TestSecretAnalyzerExistingSecretNoFalsePositive(t *testing.T) {
	clientset := fake.NewSimpleClientset(
		&corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "my-secret",
				Namespace: "default",
			},
			Data: map[string][]byte{
				"key": []byte("value"),
			},
		},
		&corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "my-pod",
				Namespace: "default",
			},
			Spec: corev1.PodSpec{
				Volumes: []corev1.Volume{
					{
						Name: "secret-vol",
						VolumeSource: corev1.VolumeSource{
							Secret: &corev1.SecretVolumeSource{
								SecretName: "my-secret",
							},
						},
					},
				},
				Containers: []corev1.Container{
					{
						Name:  "app",
						Image: "nginx",
						EnvFrom: []corev1.EnvFromSource{
							{
								SecretRef: &corev1.SecretEnvSource{
									LocalObjectReference: corev1.LocalObjectReference{
										Name: "my-secret",
									},
								},
							},
						},
					},
				},
			},
		},
	)

	analyzer := SecretAnalyzer{}
	config := common.Analyzer{
		Client: &kubernetes.Client{
			Client: clientset,
		},
		Context:   context.Background(),
		Namespace: "default",
	}

	results, err := analyzer.Analyze(config)
	require.NoError(t, err)
	require.Equal(t, 0, len(results))
}

func TestSecretAnalyzerTLSMissingKey(t *testing.T) {
	clientset := fake.NewSimpleClientset(
		&corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "tls-secret",
				Namespace: "default",
			},
			Type: corev1.SecretTypeTLS,
			Data: map[string][]byte{
				"tls.key": []byte("fake-key-data"),
			},
		},
	)

	analyzer := SecretAnalyzer{}
	config := common.Analyzer{
		Client: &kubernetes.Client{
			Client: clientset,
		},
		Context:   context.Background(),
		Namespace: "default",
	}

	results, err := analyzer.Analyze(config)
	require.NoError(t, err)
	require.Equal(t, 1, len(results))

	found := false
	for _, f := range results[0].Error {
		if strings.Contains(f.Text, "tls.crt") {
			found = true
		}
	}
	require.True(t, found, "expected failure mentioning tls.crt")
}

func TestSecretAnalyzerTLSEmptyCert(t *testing.T) {
	clientset := fake.NewSimpleClientset(
		&corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "tls-secret",
				Namespace: "default",
			},
			Type: corev1.SecretTypeTLS,
			Data: map[string][]byte{
				"tls.crt": {},
				"tls.key": []byte("fake-key-data"),
			},
		},
	)

	analyzer := SecretAnalyzer{}
	config := common.Analyzer{
		Client: &kubernetes.Client{
			Client: clientset,
		},
		Context:   context.Background(),
		Namespace: "default",
	}

	results, err := analyzer.Analyze(config)
	require.NoError(t, err)
	require.Equal(t, 1, len(results))

	found := false
	for _, f := range results[0].Error {
		if strings.Contains(f.Text, "tls.crt") {
			found = true
		}
	}
	require.True(t, found, "expected failure mentioning tls.crt")
}

func TestSecretAnalyzerTLSMissingKeyOnly(t *testing.T) {
	validCert := generateTestCert(t, time.Now().Add(365*24*time.Hour))
	clientset := fake.NewSimpleClientset(
		&corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "tls-secret",
				Namespace: "default",
			},
			Type: corev1.SecretTypeTLS,
			Data: map[string][]byte{
				"tls.crt": validCert,
			},
		},
	)

	analyzer := SecretAnalyzer{}
	config := common.Analyzer{
		Client: &kubernetes.Client{
			Client: clientset,
		},
		Context:   context.Background(),
		Namespace: "default",
	}

	results, err := analyzer.Analyze(config)
	require.NoError(t, err)
	require.Equal(t, 1, len(results))

	found := false
	for _, f := range results[0].Error {
		if strings.Contains(f.Text, "tls.key") {
			found = true
		}
	}
	require.True(t, found, "expected failure mentioning tls.key")
}

func TestSecretAnalyzerTLSExpiringCert(t *testing.T) {
	expiringCert := generateTestCert(t, time.Now().Add(15*24*time.Hour))
	clientset := fake.NewSimpleClientset(
		&corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "tls-secret",
				Namespace: "default",
			},
			Type: corev1.SecretTypeTLS,
			Data: map[string][]byte{
				"tls.crt": expiringCert,
				"tls.key": []byte("fake-key-data"),
			},
		},
		&networkingv1.Ingress{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "my-ingress",
				Namespace: "default",
			},
			Spec: networkingv1.IngressSpec{
				TLS: []networkingv1.IngressTLS{
					{
						SecretName: "tls-secret",
					},
				},
			},
		},
	)

	analyzer := SecretAnalyzer{}
	config := common.Analyzer{
		Client: &kubernetes.Client{
			Client: clientset,
		},
		Context:   context.Background(),
		Namespace: "default",
	}

	results, err := analyzer.Analyze(config)
	require.NoError(t, err)
	require.Equal(t, 1, len(results))

	foundExpiring := false
	foundIngress := false
	for _, f := range results[0].Error {
		if strings.Contains(f.Text, "expiring") {
			foundExpiring = true
		}
		if strings.Contains(f.Text, "my-ingress") {
			foundIngress = true
		}
	}
	require.True(t, foundExpiring, "expected failure mentioning expiring")
	require.True(t, foundIngress, "expected failure mentioning my-ingress")
}

func TestSecretAnalyzerTLSValidCert(t *testing.T) {
	validCert := generateTestCert(t, time.Now().Add(365*24*time.Hour))
	clientset := fake.NewSimpleClientset(
		&corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "tls-secret",
				Namespace: "default",
			},
			Type: corev1.SecretTypeTLS,
			Data: map[string][]byte{
				"tls.crt": validCert,
				"tls.key": []byte("fake-key-data"),
			},
		},
	)

	analyzer := SecretAnalyzer{}
	config := common.Analyzer{
		Client: &kubernetes.Client{
			Client: clientset,
		},
		Context:   context.Background(),
		Namespace: "default",
	}

	results, err := analyzer.Analyze(config)
	require.NoError(t, err)
	require.Equal(t, 0, len(results))
}

func TestSecretAnalyzerMalformedPEM(t *testing.T) {
	clientset := fake.NewSimpleClientset(
		&corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "tls-secret",
				Namespace: "default",
			},
			Type: corev1.SecretTypeTLS,
			Data: map[string][]byte{
				"tls.crt": []byte("this-is-not-valid-pem-data"),
				"tls.key": []byte("fake-key-data"),
			},
		},
	)

	analyzer := SecretAnalyzer{}
	config := common.Analyzer{
		Client: &kubernetes.Client{
			Client: clientset,
		},
		Context:   context.Background(),
		Namespace: "default",
	}

	results, err := analyzer.Analyze(config)
	require.NoError(t, err)
	require.Equal(t, 0, len(results))
}

func TestSecretAnalyzerOversized(t *testing.T) {
	largeData := make([]byte, 950*1024) // 950KB
	clientset := fake.NewSimpleClientset(
		&corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "large-secret",
				Namespace: "default",
			},
			Data: map[string][]byte{
				"big-file": largeData,
			},
		},
	)

	analyzer := SecretAnalyzer{}
	config := common.Analyzer{
		Client: &kubernetes.Client{
			Client: clientset,
		},
		Context:   context.Background(),
		Namespace: "default",
	}

	results, err := analyzer.Analyze(config)
	require.NoError(t, err)
	require.Equal(t, 1, len(results))

	found := false
	for _, f := range results[0].Error {
		if strings.Contains(f.Text, "approaching the 1MB etcd limit") {
			found = true
		}
	}
	require.True(t, found, "expected failure mentioning approaching the 1MB etcd limit")
}
