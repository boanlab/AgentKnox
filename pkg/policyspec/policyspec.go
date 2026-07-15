// SPDX-License-Identifier: Apache-2.0
// Package policyspec defines the declarative AgentKnox policy schema (local YAML,
// hot-reloaded), shared by the daemon (internal/policy) and akctl. It is the
// dual-layer policy DSL from docs/architecture.md §6.
package policyspec

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// Policy is one policy document.
type Policy struct {
	APIVersion string   `yaml:"apiVersion" json:"apiVersion"`
	Kind       string   `yaml:"kind" json:"kind"`
	Metadata   Metadata `yaml:"metadata" json:"metadata"`
	Spec       Spec     `yaml:"spec" json:"spec"`
	Status     Status   `yaml:"status,omitempty" json:"status,omitempty"`
}

type Metadata struct {
	Name string `yaml:"name" json:"name"`
}

// Spec selects sessions and lists rules.
type Spec struct {
	// Selector matches agent kinds ("claude-code","codex","crush","gemini",
	// "copilot","*").
	Selector []string `yaml:"selector" json:"selector"`
	Rules    []Rule   `yaml:"rules" json:"rules"`
	// DefaultEffect applies when no rule matches (default: Allow).
	DefaultEffect string `yaml:"defaultEffect,omitempty" json:"defaultEffect,omitempty"`
}

// Rule is a dual-layer predicate → effect.
type Rule struct {
	Name   string `yaml:"name" json:"name"`
	When   When   `yaml:"when" json:"when"`
	Effect string `yaml:"effect" json:"effect"` // Allow|Audit|Alert|Block|Kill
}

// When holds the semantic × system × condition predicate triple.
type When struct {
	Semantic  *SemanticPred  `yaml:"semantic,omitempty" json:"semantic,omitempty"`
	System    *SystemPred    `yaml:"system,omitempty" json:"system,omitempty"`
	Condition *ConditionPred `yaml:"condition,omitempty" json:"condition,omitempty"`
}

// SemanticPred matches the semantic layer.
type SemanticPred struct {
	Tool      string `yaml:"tool,omitempty" json:"tool,omitempty"`
	MCPMethod string `yaml:"mcpMethod,omitempty" json:"mcpMethod,omitempty"`
	Provider  string `yaml:"provider,omitempty" json:"provider,omitempty"`
	// Taint requires the effect to carry this CORRELATION label, a userspace
	// property attached when the correlator joins the effect to the session's
	// history: "user-unseen", "sensitive", or "data-flow".
	Taint string `yaml:"taint,omitempty" json:"taint,omitempty"`
	// Provenance requires the operand to carry this PROVENANCE label, a kernel-side
	// property of a file recorded on its inode when a session member writes it:
	// "agent-written" (any file the session wrote) or "agent-code" (an executable
	// one). Distinct from Taint: provenance answers which principal produced an
	// artifact, and is enforced in the kernel at exec and at an interpreter's read
	// rather than evaluated against a joined effect.
	Provenance string `yaml:"provenance,omitempty" json:"provenance,omitempty"`
	// IntentClass matches read|write|network|exec.
	IntentClass string `yaml:"intentClass,omitempty" json:"intentClass,omitempty"`
	// Database predicate: the model's data-access intent, parsed from the plaintext
	// wire (a query's engine, table, and operation). It is semantic content the
	// syscall stream cannot express, and is enforced in the kernel by push-down.
	DBEngine string `yaml:"dbEngine,omitempty" json:"dbEngine,omitempty"`
	DBTable  string `yaml:"dbTable,omitempty" json:"dbTable,omitempty"`
	DBOp     string `yaml:"dbOp,omitempty" json:"dbOp,omitempty"`
}

// SystemPred matches the system layer.
type SystemPred struct {
	Op   string `yaml:"op,omitempty" json:"op,omitempty"` // exec|open|read|write|connect
	Path string `yaml:"path,omitempty" json:"path,omitempty"`
	Dir  string `yaml:"dir,omitempty" json:"dir,omitempty"`
	CIDR string `yaml:"cidr,omitempty" json:"cidr,omitempty"`
	FQDN string `yaml:"fqdn,omitempty" json:"fqdn,omitempty"`
}

// ConditionPred adds temporal / state gates.
type ConditionPred struct {
	After        string `yaml:"after,omitempty" json:"after,omitempty"`
	Within       string `yaml:"within,omitempty" json:"within,omitempty"`
	SessionState string `yaml:"sessionState,omitempty" json:"sessionState,omitempty"`
	// Coverage matches semantic coverage (full|degraded|none) — lets a policy
	// tighten posture when semantic observability is degraded.
	Coverage string `yaml:"coverage,omitempty" json:"coverage,omitempty"`
	// Tampered matches the session's binary-identity flag, set when the agent's
	// build-id is not one the offset database vouches for while its code section
	// matches a plan already resolved. A pointer so that an absent key means "do
	// not care" rather than "require false".
	Tampered *bool `yaml:"tampered,omitempty" json:"tampered,omitempty"`
}

// Status is the reconcile/validation state (Active | Invalid: <reason>).
type Status struct {
	Status string `yaml:"status,omitempty" json:"status,omitempty"`
}

var validEffects = map[string]bool{
	"Allow": true, "Audit": true, "Alert": true, "Block": true, "Kill": true,
}

// Validate checks the policy's structural correctness.
func (p *Policy) Validate() error {
	if p.Kind != "AgentKnoxPolicy" {
		return fmt.Errorf("kind must be AgentKnoxPolicy, got %q", p.Kind)
	}
	if p.Metadata.Name == "" {
		return fmt.Errorf("metadata.name required")
	}
	if len(p.Spec.Selector) == 0 {
		return fmt.Errorf("spec.selector required (use [\"*\"] for all agents)")
	}
	if p.Spec.DefaultEffect != "" && !validEffects[p.Spec.DefaultEffect] {
		return fmt.Errorf("invalid defaultEffect %q", p.Spec.DefaultEffect)
	}
	for i, r := range p.Spec.Rules {
		if r.Name == "" {
			return fmt.Errorf("rule[%d].name required", i)
		}
		if !validEffects[r.Effect] {
			return fmt.Errorf("rule %q: invalid effect %q", r.Name, r.Effect)
		}
		if r.When.Semantic == nil && r.When.System == nil {
			return fmt.Errorf("rule %q: at least one of when.semantic/when.system required", r.Name)
		}
		if s := r.When.Semantic; s != nil {
			// The two label families are distinct and must not be spelled through
			// each other's key: a provenance label under taint would silently never
			// match a joined effect, and a correlation label under provenance would
			// silently never reach the kernel.
			if provenanceLabels[s.Taint] {
				return fmt.Errorf("rule %q: %q is a provenance label; use when.semantic.provenance, not taint", r.Name, s.Taint)
			}
			if s.Provenance != "" && !provenanceLabels[s.Provenance] {
				return fmt.Errorf("rule %q: invalid provenance %q (want agent-written or agent-code)", r.Name, s.Provenance)
			}
		}
	}
	return nil
}

// provenanceLabels are the kernel-side file-provenance labels accepted by
// when.semantic.provenance.
var provenanceLabels = map[string]bool{
	"agent-written": true,
	"agent-code":    true,
}

// LoadFile parses and validates a policy YAML file.
func LoadFile(path string) (*Policy, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var p Policy
	if err := yaml.Unmarshal(b, &p); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	if err := p.Validate(); err != nil {
		return nil, fmt.Errorf("validate %s: %w", path, err)
	}
	return &p, nil
}
