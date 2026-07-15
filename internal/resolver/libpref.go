// SPDX-License-Identifier: Apache-2.0
package resolver

import "strings"

// pickTLSLib applies findTLSLibrary's preference (libssl > boringssl > libcrypto)
// to a list of candidate paths. Factored out so the ranking is unit-testable
// without a live /proc/<pid>/maps.
func pickTLSLib(paths []string) string {
	var boring, libcrypto string
	for _, p := range paths {
		b := strings.ToLower(baseName(p))
		switch {
		case strings.Contains(b, "libssl"):
			return p
		case strings.Contains(b, "boringssl") && boring == "":
			boring = p
		case strings.Contains(b, "libcrypto") && libcrypto == "":
			libcrypto = p
		}
	}
	if boring != "" {
		return boring
	}
	return libcrypto
}
