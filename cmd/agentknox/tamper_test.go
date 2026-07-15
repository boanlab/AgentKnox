// SPDX-License-Identifier: Apache-2.0
package main

import (
	"testing"

	"github.com/boanlab/agentknox/pkg/types"
)

// TestIdentityUnvouched pins the tamper signal the shipped `tampered: true` rule
// reads: it must fire on an unvouched build identity at any resolver tier, and
// stay silent when nothing could vouch for the binary in the first place.
func TestIdentityUnvouched(t *testing.T) {
	cases := []struct {
		name string
		plan *types.AttachPlan
		want bool
	}{
		{
			name: "unknown build-id against a loaded reference set",
			plan: &types.AttachPlan{BuildID: "aabb", ReferenceSet: true},
			want: true,
		},
		{
			name: "known-good build-id",
			plan: &types.AttachPlan{BuildID: "aabb", ReferenceSet: true, KnownGood: true},
			want: false,
		},
		{
			name: "unstripped build resolved at T1 is still checked",
			plan: &types.AttachPlan{BuildID: "aabb", ReferenceSet: true, Tier: types.TierDynsym},
			want: true,
		},
		{
			name: "no reference set loaded is not evidence of tampering",
			plan: &types.AttachPlan{BuildID: "aabb"},
			want: false,
		},
		{
			name: "same code section under a different build-id",
			plan: &types.AttachPlan{BuildID: "aabb", IdentityChanged: true},
			want: true,
		},
		{
			name: "a binary carrying no identity cannot be judged",
			plan: &types.AttachPlan{ReferenceSet: true},
			want: false,
		},
		{
			name: "no plan",
			plan: nil,
			want: false,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := identityUnvouched(c.plan); got != c.want {
				t.Errorf("identityUnvouched = %v, want %v", got, c.want)
			}
		})
	}
}
