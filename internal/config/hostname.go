// SPDX-License-Identifier: Apache-2.0
package config

import "os"

func osHostname() (string, error) { return os.Hostname() }
