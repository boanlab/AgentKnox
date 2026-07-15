// SPDX-License-Identifier: Apache-2.0
package resolver

import (
	"testing"

	"github.com/boanlab/agentknox/pkg/types"
)

// TestCoverageForAsm: one AEAD family (an inbound + outbound path) is full; a lone
// direction is degraded; nothing is none.
func TestCoverageForAsm(t *testing.T) {
	cases := []struct {
		name string
		offs map[string]uint64
		want types.SemanticCoverage
	}{
		{"chacha both", map[string]uint64{keyChachaOpen: 1, keyChachaSeal: 2}, types.CoverageFull},
		{"gcm both", map[string]uint64{keyAESGCMDec: 1, keyAESGCMEnc: 2}, types.CoverageFull},
		{"avx512 both", map[string]uint64{keyAESGCMDec512: 1, keyAESGCMEnc512: 2}, types.CoverageFull},
		{"cross family", map[string]uint64{keyChachaOpen: 1, keyAESGCMEnc: 2}, types.CoverageFull},
		{"avx512 inbound only", map[string]uint64{keyAESGCMDec512: 1}, types.CoverageDegraded},
		{"inbound only", map[string]uint64{keyChachaOpen: 1}, types.CoverageDegraded},
		{"outbound only", map[string]uint64{keyAESGCMEnc: 1}, types.CoverageDegraded},
		{"empty", map[string]uint64{}, types.CoverageNone},
	}
	for _, c := range cases {
		if got := coverageForAsm(c.offs); got != c.want {
			t.Errorf("%s: got %s want %s", c.name, got, c.want)
		}
	}
}

// TestApplyASM sets the assembly boundary and its keys on the plan.
func TestApplyASM(t *testing.T) {
	r := &Resolver{}
	plan := &types.AttachPlan{Offsets: map[string]uint64{}}
	r.applyASM(plan, map[string]uint64{keyChachaOpen: 0x10, keyChachaSeal: 0x20})
	if plan.Boundary != types.BoundaryAEADAsm {
		t.Errorf("boundary = %s want %s", plan.Boundary, types.BoundaryAEADAsm)
	}
	if plan.Coverage != types.CoverageFull {
		t.Errorf("coverage = %s want full", plan.Coverage)
	}
	if plan.Offsets[keyChachaOpen] != 0x10 {
		t.Errorf("chacha_open offset not set")
	}
}
