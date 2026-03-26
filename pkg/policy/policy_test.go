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

package policy

import (
	"testing"

	"github.com/k8sgpt-ai/k8sgpt/pkg/common"
	"github.com/stretchr/testify/assert"
)

func TestMatchKind(t *testing.T) {
	p := Policy{Name: "test", Match: Match{Kind: "Pod"}}
	assert.True(t, p.Matches("Pod", "", common.SeverityHigh, "error text", true))
	assert.False(t, p.Matches("Service", "", common.SeverityHigh, "error text", true))
}

func TestMatchKinds(t *testing.T) {
	p := Policy{Name: "test", Match: Match{Kinds: []string{"Pod", "Service"}}}
	assert.True(t, p.Matches("Pod", "", common.SeverityHigh, "error text", true))
	assert.True(t, p.Matches("Service", "", common.SeverityHigh, "error text", true))
	assert.False(t, p.Matches("Deployment", "", common.SeverityHigh, "error text", true))
}

func TestMatchSeverity(t *testing.T) {
	p := Policy{Name: "test", Match: Match{Severity: []string{"critical", "high"}}}
	assert.True(t, p.Matches("Pod", "", common.SeverityCritical, "error", true))
	assert.True(t, p.Matches("Pod", "", common.SeverityHigh, "error", true))
	assert.False(t, p.Matches("Pod", "", common.SeverityMedium, "error", true))
}

func TestMatchTextPattern(t *testing.T) {
	p := Policy{Name: "test", Match: Match{TextPattern: "CrashLoopBackOff"}}
	assert.True(t, p.Matches("Pod", "", common.SeverityHigh, "pod is in CrashLoopBackOff", true))
	assert.False(t, p.Matches("Pod", "", common.SeverityHigh, "image pull error", true))
}

func TestMatchNamespace(t *testing.T) {
	p := Policy{Name: "test", Match: Match{Namespace: "production"}}
	assert.True(t, p.Matches("Pod", "production", common.SeverityHigh, "error", true))
	assert.False(t, p.Matches("Pod", "staging", common.SeverityHigh, "error", true))
}

func TestMatchHasRemediation(t *testing.T) {
	p := Policy{Name: "test", Match: Match{HasRemediation: boolPtr(true)}}
	assert.True(t, p.Matches("Pod", "", common.SeverityHigh, "error", true))
	assert.False(t, p.Matches("Pod", "", common.SeverityHigh, "error", false))
}

func TestMatchANDLogic(t *testing.T) {
	p := Policy{
		Name:  "test",
		Match: Match{Kind: "Pod", Severity: []string{"critical"}, TextPattern: "CrashLoop"},
	}
	assert.True(t, p.Matches("Pod", "", common.SeverityCritical, "CrashLoopBackOff", true))
	assert.False(t, p.Matches("Service", "", common.SeverityCritical, "CrashLoopBackOff", true))
	assert.False(t, p.Matches("Pod", "", common.SeverityLow, "CrashLoopBackOff", true))
	assert.False(t, p.Matches("Pod", "", common.SeverityCritical, "ImagePullBackOff", true))
}

func TestFirstMatchWins(t *testing.T) {
	policies := []Policy{
		{Name: "first", Match: Match{Kind: "Pod"}, Action: ActionAuto},
		{Name: "second", Match: Match{Kind: "Pod"}, Action: ActionLogOnly},
	}
	match := FindFirstMatch(policies, "Pod", "", common.SeverityHigh, "error", true)
	assert.NotNil(t, match)
	assert.Equal(t, "first", match.Name)
}

func TestNoMatch(t *testing.T) {
	policies := []Policy{{Name: "only-nodes", Match: Match{Kind: "Node"}}}
	match := FindFirstMatch(policies, "Pod", "", common.SeverityHigh, "error", true)
	assert.Nil(t, match)
}

func TestAutoRequiresRemediation(t *testing.T) {
	p := Policy{Name: "test", Match: Match{Kind: "Pod"}, Action: ActionAuto}
	assert.True(t, p.IsEligibleForExecution(true))
	assert.False(t, p.IsEligibleForExecution(false))
}

func TestLogOnlyNoRemediationRequired(t *testing.T) {
	p := Policy{Name: "test", Match: Match{Kind: "Pod"}, Action: ActionLogOnly}
	assert.True(t, p.IsEligibleForExecution(false))
	assert.True(t, p.IsEligibleForExecution(true))
}

func boolPtr(b bool) *bool { return &b }
