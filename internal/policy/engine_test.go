// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"testing"
	"time"

	"github.com/boanlab/agentknox/pkg/policyspec"
	"github.com/boanlab/agentknox/pkg/types"
)

// sshPolicy is a purely system-level rule: block open under ~/.ssh/ for
// claude-code sessions.
func sshPolicy() *policyspec.Policy {
	return &policyspec.Policy{
		Kind:     "AgentKnoxPolicy",
		Metadata: policyspec.Metadata{Name: "protect-ssh"},
		Spec: policyspec.Spec{
			Selector: []string{"claude-code"},
			Rules: []policyspec.Rule{{
				Name: "block-ssh-read",
				When: policyspec.When{
					System: &policyspec.SystemPred{
						Op:  "open",
						Dir: "~/.ssh/",
					},
				},
				Effect: "Block",
			}},
		},
	}
}

// exfilPolicy is a dual-layer rule: a read-intent action that reaches a network
// connect is a mismatch worth killing.
func exfilPolicy() *policyspec.Policy {
	return &policyspec.Policy{
		Kind:     "AgentKnoxPolicy",
		Metadata: policyspec.Metadata{Name: "no-read-then-exfil"},
		Spec: policyspec.Spec{
			Selector: []string{"*"},
			Rules: []policyspec.Rule{{
				Name: "read-intent-network-effect",
				When: policyspec.When{
					Semantic: &policyspec.SemanticPred{IntentClass: "read"},
					System:   &policyspec.SystemPred{Op: "connect"},
				},
				Effect: "Kill",
			}},
		},
	}
}

// provenancePolicy forbids executing code the agent itself wrote.
func provenancePolicy() *policyspec.Policy {
	return &policyspec.Policy{
		Kind:     "AgentKnoxPolicy",
		Metadata: policyspec.Metadata{Name: "no-agent-written-code"},
		Spec: policyspec.Spec{
			Selector: []string{"*"},
			Rules: []policyspec.Rule{{
				Name: "deny-agent-written-exec",
				When: policyspec.When{
					Semantic: &policyspec.SemanticPred{Provenance: "agent-written"},
					System:   &policyspec.SystemPred{Op: "exec"},
				},
				Effect: "Block",
			}},
		},
	}
}

func TestProvenance_ArmsKernelPostureAndNamesRule(t *testing.T) {
	e := New(nil)
	if err := e.Load([]*policyspec.Policy{provenancePolicy()}); err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !e.WantsTaintedCodeBlock(types.AgentClaudeCode) {
		t.Fatal("WantsTaintedCodeBlock = false, want true for a provenance+exec Block rule")
	}
	d := e.EvaluateProvenance("agent-written", "exec", "/tmp/run.sh", claudeSession(), time.Now())
	if d.PolicyName != "no-agent-written-code" {
		t.Fatalf("policy = %q, want no-agent-written-code", d.PolicyName)
	}
}

// A correlation label must not satisfy a provenance predicate, and an ordinary
// effect carrying no provenance label must not match the rule at all.
func TestProvenance_DoesNotMatchCorrelationLabelOrBareEffect(t *testing.T) {
	e := New(nil)
	if err := e.Load([]*policyspec.Policy{provenancePolicy()}); err != nil {
		t.Fatalf("Load: %v", err)
	}
	d := e.EvaluateProvenance("sensitive", "exec", "/usr/bin/curl", claudeSession(), time.Now())
	if d.PolicyName == "no-agent-written-code" {
		t.Fatal("correlation label matched a provenance predicate")
	}
	a := &types.CorrelatedAction{
		Effects: []types.Effect{{Category: types.CategoryProcess, Operation: "exec", Resource: "/usr/bin/curl"}},
	}
	if got := e.EvaluateAction(a, claudeSession()); got.PolicyName == "no-agent-written-code" {
		t.Fatal("an exec carrying no provenance label matched the provenance rule")
	}
}

// The two label families may not be spelled through each other's key.
func TestValidate_RejectsProvenanceLabelUnderTaint(t *testing.T) {
	p := provenancePolicy()
	p.Spec.Rules[0].When.Semantic = &policyspec.SemanticPred{Taint: "agent-written"}
	if err := p.Validate(); err == nil {
		t.Fatal("Validate accepted a provenance label under when.semantic.taint")
	}
	p.Spec.Rules[0].When.Semantic = &policyspec.SemanticPred{Provenance: "sensitive"}
	if err := p.Validate(); err == nil {
		t.Fatal("Validate accepted a correlation label under when.semantic.provenance")
	}
}

// tamperPolicy tightens egress when the agent binary's identity is not vouched for.
func tamperPolicy() *policyspec.Policy {
	yes := true
	return &policyspec.Policy{
		Kind:     "AgentKnoxPolicy",
		Metadata: policyspec.Metadata{Name: "untrusted-agent-build"},
		Spec: policyspec.Spec{
			Selector: []string{"*"},
			Rules: []policyspec.Rule{{
				Name: "block-egress-on-tamper",
				When: policyspec.When{
					System:    &policyspec.SystemPred{Op: "connect"},
					Condition: &policyspec.ConditionPred{Tampered: &yes},
				},
				Effect: "Block",
			}},
		},
	}
}

// A Block rule gated on a condition must NOT reach the kernel: the kernel maps
// cannot express the condition, so installing it would enforce unconditionally.
func TestKernelRules_ExcludesConditionGatedRules(t *testing.T) {
	e := New(nil)
	gated := sshPolicy()
	gated.Spec.Rules[0].When.Condition = &policyspec.ConditionPred{Coverage: "degraded"}
	if err := e.Load([]*policyspec.Policy{gated}); err != nil {
		t.Fatalf("Load: %v", err)
	}
	if krs := e.KernelRules(); len(krs) != 0 {
		t.Fatalf("KernelRules len = %d, want 0 (a condition-gated rule stays in userspace)", len(krs))
	}
	// The same rule without the condition still installs.
	e2 := New(nil)
	if err := e2.Load([]*policyspec.Policy{sshPolicy()}); err != nil {
		t.Fatalf("Load: %v", err)
	}
	if krs := e2.KernelRules(); len(krs) != 1 {
		t.Fatalf("KernelRules len = %d, want 1", len(krs))
	}
}

func TestCondition_TamperedGatesTheRule(t *testing.T) {
	e := New(nil)
	if err := e.Load([]*policyspec.Policy{tamperPolicy()}); err != nil {
		t.Fatalf("Load: %v", err)
	}
	ev := &types.SyscallEvent{Category: types.CategoryNetwork, Operation: "connect", Resource: "10.0.0.5:443"}

	if d := e.EvaluateSyscall(ev, claudeSession()); d.Effect != types.EffectAllow {
		t.Fatalf("untampered session: effect = %q, want Allow", d.Effect)
	}
	sess := claudeSession()
	sess.Tampered = true
	if d := e.EvaluateSyscall(ev, sess); d.Effect != types.EffectBlock {
		t.Fatalf("tampered session: effect = %q, want Block", d.Effect)
	}
}

// An absent tampered key must not be read as requiring false.
func TestCondition_TamperedAbsentDoesNotCare(t *testing.T) {
	e := New(nil)
	if err := e.Load([]*policyspec.Policy{sshPolicy()}); err != nil {
		t.Fatalf("Load: %v", err)
	}
	sess := claudeSession()
	sess.Tampered = true
	ev := &types.SyscallEvent{Category: types.CategoryFile, Operation: "open", Resource: "~/.ssh/id_rsa"}
	if d := e.EvaluateSyscall(ev, sess); d.Effect != types.EffectBlock {
		t.Fatalf("effect = %q, want Block (a rule with no tampered key still applies)", d.Effect)
	}
}

func claudeSession() *types.AgentSession {
	return &types.AgentSession{
		ID:       "sess-1",
		Agent:    types.AgentClaudeCode,
		State:    types.SessionActive,
		Coverage: types.CoverageFull,
	}
}

func TestEvaluateSyscall_SSHBlockPre(t *testing.T) {
	e := New(nil)
	if err := e.Load([]*policyspec.Policy{sshPolicy()}); err != nil {
		t.Fatalf("Load: %v", err)
	}

	ev := &types.SyscallEvent{
		Category:  types.CategoryFile,
		Operation: "open",
		Resource:  "~/.ssh/id_rsa",
	}
	d := e.EvaluateSyscall(ev, claudeSession())
	if d.Effect != types.EffectBlock {
		t.Fatalf("effect = %q, want Block", d.Effect)
	}
	if d.Mode != types.EnforcePre {
		t.Fatalf("mode = %q, want EnforcePre", d.Mode)
	}
	if d.PolicyName != "protect-ssh" {
		t.Fatalf("policy = %q, want protect-ssh", d.PolicyName)
	}
}

func TestEvaluateSyscall_WrongAgentNoMatch(t *testing.T) {
	e := New(nil)
	if err := e.Load([]*policyspec.Policy{sshPolicy()}); err != nil {
		t.Fatalf("Load: %v", err)
	}
	ev := &types.SyscallEvent{Operation: "open", Resource: "~/.ssh/id_rsa"}
	sess := &types.AgentSession{Agent: types.AgentCodex, State: types.SessionActive}
	d := e.EvaluateSyscall(ev, sess)
	if d.Effect != types.EffectAllow {
		t.Fatalf("effect = %q, want Allow (selector mismatch)", d.Effect)
	}
}

func TestEvaluateAction_DualLayerKill(t *testing.T) {
	e := New(nil)
	if err := e.Load([]*policyspec.Policy{exfilPolicy()}); err != nil {
		t.Fatalf("Load: %v", err)
	}

	a := &types.CorrelatedAction{
		ToolName:    "Read",
		IntentClass: "read",
		Mismatch:    true,
		Effects: []types.Effect{{
			Category:  types.CategoryNetwork,
			Operation: "connect",
			Resource:  "10.0.0.5:443",
		}},
	}
	d := e.EvaluateAction(a, claudeSession())
	if d.Effect != types.EffectKill {
		t.Fatalf("effect = %q, want Kill", d.Effect)
	}
	if d.PolicyName != "no-read-then-exfil" {
		t.Fatalf("policy = %q, want no-read-then-exfil", d.PolicyName)
	}
}

func TestKernelRules_ContainsSSHBlock(t *testing.T) {
	e := New(nil)
	if err := e.Load([]*policyspec.Policy{sshPolicy(), exfilPolicy()}); err != nil {
		t.Fatalf("Load: %v", err)
	}

	krs := e.KernelRules()
	if len(krs) != 1 {
		t.Fatalf("KernelRules len = %d, want 1 (only the pure-system ssh Block)", len(krs))
	}
	kr := krs[0]
	if kr.PolicyName != "protect-ssh" {
		t.Fatalf("kernel rule policy = %q, want protect-ssh", kr.PolicyName)
	}
	if kr.Operation != "open" {
		t.Fatalf("kernel rule op = %q, want open", kr.Operation)
	}
	if kr.PathPrefix != "~/.ssh/" {
		t.Fatalf("kernel rule prefix = %q, want ~/.ssh/", kr.PathPrefix)
	}
	if kr.Category != types.CategoryFile {
		t.Fatalf("kernel rule category = %q, want file", kr.Category)
	}
	if kr.Effect != types.EffectBlock {
		t.Fatalf("kernel rule effect = %q, want Block", kr.Effect)
	}
}

// fqdnPolicy blocks connects to *.evil.com for all agents.
func fqdnPolicy() *policyspec.Policy {
	return &policyspec.Policy{
		Kind:     "AgentKnoxPolicy",
		Metadata: policyspec.Metadata{Name: "block-evil"},
		Spec: policyspec.Spec{
			Selector: []string{"*"},
			Rules: []policyspec.Rule{{
				Name: "no-evil",
				When: policyspec.When{
					System: &policyspec.SystemPred{Op: "connect", FQDN: "evil.com"},
				},
				Effect: "Block",
			}},
		},
	}
}

func TestMatchFQDNBlock(t *testing.T) {
	e := New(nil)
	if err := e.Load([]*policyspec.Policy{fqdnPolicy()}); err != nil {
		t.Fatalf("Load: %v", err)
	}
	cases := []struct {
		fqdn string
		want bool
	}{
		{"evil.com", true},
		{"api.evil.com", true},
		{"cdn.api.evil.com", true},
		{"notevil.com", false}, // suffix must be label-aligned
		{"evil.com.good.org", false},
		{"example.com", false},
		{"", false},
	}
	for _, c := range cases {
		got, _ := e.MatchFQDNBlock(c.fqdn)
		if got != c.want {
			t.Errorf("MatchFQDNBlock(%q) = %v, want %v", c.fqdn, got, c.want)
		}
	}
}
