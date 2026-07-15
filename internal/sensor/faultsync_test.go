// SPDX-License-Identifier: Apache-2.0

package sensor

import (
	"bytes"
	"testing"

	"github.com/cilium/ebpf"
)

// The names are the only record of what each ak_errors slot means, so a slot
// added to AK_ERR_SLOTS without a name here would be counted by the kernel and
// never reported. This holds the header and the name list together.
func TestKernelFaultNamesMatchObject(t *testing.T) {
	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(bpfObject))
	if err != nil {
		t.Fatalf("load collection spec: %v", err)
	}
	m := spec.Maps["ak_errors"]
	if m == nil {
		t.Fatal("ak_errors map missing from the object")
	}
	if int(m.MaxEntries) != len(KernelFaultNames) {
		t.Fatalf("ak_errors has %d slots, KernelFaultNames has %d: AK_ERR_SLOTS and the name list are out of sync",
			m.MaxEntries, len(KernelFaultNames))
	}
}
