// SPDX-License-Identifier: Apache-2.0
package policy_test

import (
	"testing"
	"time"

	"github.com/boanlab/agentknox/internal/policy"
	"github.com/boanlab/agentknox/pkg/policyspec"
	"github.com/boanlab/agentknox/pkg/types"
)

// TestTemporalAfterWithin exercises the After/Within condition: "connect AFTER a
// read intent, WITHIN 5s -> Block". It must not fire on a bare connect, must fire
// on a connect shortly after a read intent, must stop firing once the window
// elapses, and must reset after the session is forgotten.
func TestTemporalAfterWithin(t *testing.T) {
	e := policy.New(nil)
	pol := &policyspec.Policy{
		Kind:     "AgentKnoxPolicy",
		Metadata: policyspec.Metadata{Name: "exfil-window-test"},
		Spec: policyspec.Spec{
			Selector: []string{"*"},
			Rules: []policyspec.Rule{{
				Name: "exfil-window",
				When: policyspec.When{
					System:    &policyspec.SystemPred{Op: "connect"},
					Condition: &policyspec.ConditionPred{After: "read", Within: "5s"},
				},
				Effect: "Block",
			}},
		},
	}
	if err := e.Load([]*policyspec.Policy{pol}); err != nil {
		t.Fatal(err)
	}
	sess := &types.AgentSession{ID: "s1", Agent: types.AgentClaudeCode}
	base := time.Now()
	connectAt := func(ts time.Time) types.PolicyEffect {
		return e.EvaluateSyscall(&types.SyscallEvent{
			Category: types.CategoryNetwork, Operation: "connect", Resource: "1.2.3.4:443", Time: ts,
		}, sess).Effect
	}

	if got := connectAt(base); got != types.EffectAllow {
		t.Errorf("bare connect (no prior read): got %s want Allow", got)
	}
	e.EvaluateSemantic(&types.SemanticEvent{
		Kind: types.SemToolUse, Time: base,
		ToolUse: &types.ToolUse{Name: "Read", IntentClass: "read"},
	}, sess)
	if got := connectAt(base.Add(2 * time.Second)); got != types.EffectBlock {
		t.Errorf("connect 2s after read: got %s want Block", got)
	}
	if got := connectAt(base.Add(10 * time.Second)); got != types.EffectAllow {
		t.Errorf("connect 10s after read (> 5s window): got %s want Allow", got)
	}
	e.ForgetSession("s1")
	if got := connectAt(base.Add(3 * time.Second)); got != types.EffectAllow {
		t.Errorf("connect after ForgetSession: got %s want Allow", got)
	}
}
