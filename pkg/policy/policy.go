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
	"regexp"
	"time"

	"github.com/k8sgpt-ai/k8sgpt/pkg/common"
	"github.com/spf13/viper"
)

type Policy struct {
	Name       string        `json:"name" mapstructure:"name"`
	Match      Match         `json:"match" mapstructure:"match"`
	Action     string        `json:"action" mapstructure:"action"`
	Cooldown   time.Duration `json:"cooldown" mapstructure:"cooldown"`
	MaxRetries int           `json:"maxRetries" mapstructure:"maxRetries"`
}

type Match struct {
	Kind           string   `json:"kind,omitempty" mapstructure:"kind"`
	Kinds          []string `json:"kinds,omitempty" mapstructure:"kinds"`
	Severity       []string `json:"severity,omitempty" mapstructure:"severity"`
	TextPattern    string   `json:"textPattern,omitempty" mapstructure:"textPattern"`
	Namespace      string   `json:"namespace,omitempty" mapstructure:"namespace"`
	HasRemediation *bool    `json:"hasRemediation,omitempty" mapstructure:"hasRemediation"`
}

func LoadPolicies() []Policy {
	var policies []Policy
	_ = viper.UnmarshalKey("remediationPolicies", &policies)
	for i := range policies {
		if policies[i].Action == "" {
			policies[i].Action = "dry-run"
		}
		if policies[i].MaxRetries == 0 {
			policies[i].MaxRetries = 3
		}
	}
	return policies
}

func (p *Policy) Matches(kind, namespace string, severity common.Severity, text string, hasRemediation bool) bool {
	if p.Match.Kind != "" && p.Match.Kind != kind {
		return false
	}
	if len(p.Match.Kinds) > 0 {
		found := false
		for _, k := range p.Match.Kinds {
			if k == kind {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	if len(p.Match.Severity) > 0 {
		found := false
		for _, s := range p.Match.Severity {
			if common.Severity(s) == severity {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	if p.Match.TextPattern != "" {
		matched, err := regexp.MatchString(p.Match.TextPattern, text)
		if err != nil || !matched {
			return false
		}
	}
	if p.Match.Namespace != "" && p.Match.Namespace != namespace {
		return false
	}
	if p.Match.HasRemediation != nil && *p.Match.HasRemediation != hasRemediation {
		return false
	}
	return true
}

func (p *Policy) IsEligibleForExecution(hasRemediation bool) bool {
	if p.Action == "log-only" {
		return true
	}
	return hasRemediation
}

func FindFirstMatch(policies []Policy, kind, namespace string, severity common.Severity, text string, hasRemediation bool) *Policy {
	for i := range policies {
		if policies[i].Matches(kind, namespace, severity, text, hasRemediation) {
			return &policies[i]
		}
	}
	return nil
}
