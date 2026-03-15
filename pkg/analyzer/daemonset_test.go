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
	"testing"

	"github.com/k8sgpt-ai/k8sgpt/pkg/common"
	"github.com/k8sgpt-ai/k8sgpt/pkg/kubernetes"
	"github.com/stretchr/testify/require"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

func TestDaemonSetAnalyzerHealthy(t *testing.T) {
	clientset := fake.NewSimpleClientset(
		&appsv1.DaemonSet{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "healthy-ds",
				Namespace: "default",
			},
			Status: appsv1.DaemonSetStatus{
				DesiredNumberScheduled: 3,
				CurrentNumberScheduled: 3,
				NumberUnavailable:      0,
				NumberMisscheduled:     0,
			},
		},
	)

	analyzer := DaemonSetAnalyzer{}
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

func TestDaemonSetAnalyzerSchedulingGap(t *testing.T) {
	clientset := fake.NewSimpleClientset(
		&appsv1.DaemonSet{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "scheduling-ds",
				Namespace: "default",
			},
			Status: appsv1.DaemonSetStatus{
				DesiredNumberScheduled: 3,
				CurrentNumberScheduled: 1,
				NumberUnavailable:      0,
				NumberMisscheduled:     0,
			},
		},
	)

	analyzer := DaemonSetAnalyzer{}
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

	var found bool
	for _, f := range results[0].Error {
		if f.Text == "DaemonSet has 3 desired pods but only 1 currently scheduled." {
			found = true
		}
	}
	require.True(t, found, "expected scheduling gap failure message not found")
}

func TestDaemonSetAnalyzerUnavailable(t *testing.T) {
	clientset := fake.NewSimpleClientset(
		&appsv1.DaemonSet{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "unavailable-ds",
				Namespace: "default",
			},
			Status: appsv1.DaemonSetStatus{
				DesiredNumberScheduled: 3,
				CurrentNumberScheduled: 3,
				NumberUnavailable:      2,
				NumberMisscheduled:     0,
			},
		},
	)

	analyzer := DaemonSetAnalyzer{}
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

	var found bool
	for _, f := range results[0].Error {
		if f.Text == "DaemonSet has 2 unavailable pods." {
			found = true
		}
	}
	require.True(t, found, "expected unavailable pods failure message not found")
}

func TestDaemonSetAnalyzerMisscheduled(t *testing.T) {
	clientset := fake.NewSimpleClientset(
		&appsv1.DaemonSet{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "misscheduled-ds",
				Namespace: "default",
			},
			Status: appsv1.DaemonSetStatus{
				DesiredNumberScheduled: 3,
				CurrentNumberScheduled: 3,
				NumberUnavailable:      0,
				NumberMisscheduled:     1,
			},
		},
	)

	analyzer := DaemonSetAnalyzer{}
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

	var found bool
	for _, f := range results[0].Error {
		if f.Text == "DaemonSet has 1 pods running on unexpected nodes." {
			found = true
		}
	}
	require.True(t, found, "expected misscheduled pods failure message not found")
}

func TestDaemonSetAnalyzerMultipleIssues(t *testing.T) {
	clientset := fake.NewSimpleClientset(
		&appsv1.DaemonSet{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "multi-ds",
				Namespace: "default",
			},
			Status: appsv1.DaemonSetStatus{
				DesiredNumberScheduled: 5,
				CurrentNumberScheduled: 3,
				NumberUnavailable:      2,
				NumberMisscheduled:     1,
			},
		},
	)

	analyzer := DaemonSetAnalyzer{}
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
	require.GreaterOrEqual(t, len(results[0].Error), 3)
}

func TestDaemonSetAnalyzerWarningEvent(t *testing.T) {
	clientset := fake.NewSimpleClientset(
		&appsv1.DaemonSet{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "event-ds",
				Namespace: "default",
			},
			Status: appsv1.DaemonSetStatus{
				DesiredNumberScheduled: 3,
				CurrentNumberScheduled: 3,
				NumberUnavailable:      0,
				NumberMisscheduled:     0,
			},
		},
		&corev1.Event{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "event-ds-event",
				Namespace: "default",
			},
			InvolvedObject: corev1.ObjectReference{
				Name:      "event-ds",
				Namespace: "default",
				Kind:      "DaemonSet",
			},
			Type:    "Warning",
			Message: "Error creating: pods is forbidden",
		},
	)

	analyzer := DaemonSetAnalyzer{}
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

	var found bool
	for _, f := range results[0].Error {
		if f.Text == "DaemonSet default/event-ds has event: Error creating: pods is forbidden" {
			found = true
		}
	}
	require.True(t, found, "expected warning event failure message not found")
}

func TestDaemonSetAnalyzerNamespaceFiltering(t *testing.T) {
	clientset := fake.NewSimpleClientset(
		&appsv1.DaemonSet{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "ds-default",
				Namespace: "default",
			},
			Status: appsv1.DaemonSetStatus{
				DesiredNumberScheduled: 3,
				CurrentNumberScheduled: 1,
			},
		},
		&appsv1.DaemonSet{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "ds-other",
				Namespace: "other-namespace",
			},
			Status: appsv1.DaemonSetStatus{
				DesiredNumberScheduled: 3,
				CurrentNumberScheduled: 1,
			},
		},
	)

	analyzer := DaemonSetAnalyzer{}
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

func TestDaemonSetAnalyzerLabelSelectorFiltering(t *testing.T) {
	clientset := fake.NewSimpleClientset(
		&appsv1.DaemonSet{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "labeled-ds",
				Namespace: "default",
				Labels: map[string]string{
					"app": "daemonset",
				},
			},
			Status: appsv1.DaemonSetStatus{
				DesiredNumberScheduled: 3,
				CurrentNumberScheduled: 1,
			},
		},
		&appsv1.DaemonSet{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "unlabeled-ds",
				Namespace: "default",
			},
			Status: appsv1.DaemonSetStatus{
				DesiredNumberScheduled: 3,
				CurrentNumberScheduled: 1,
			},
		},
	)

	analyzer := DaemonSetAnalyzer{}
	config := common.Analyzer{
		Client: &kubernetes.Client{
			Client: clientset,
		},
		Context:       context.Background(),
		Namespace:     "default",
		LabelSelector: "app=daemonset",
	}

	results, err := analyzer.Analyze(config)
	require.NoError(t, err)
	require.Equal(t, 1, len(results))
}
