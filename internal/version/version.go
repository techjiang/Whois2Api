// Package version carries build metadata injected at link time.
package version

import (
	"fmt"
	"runtime"
)

// Overridden via -ldflags "-X .../internal/version.Version=v1.0.0".
var (
	Version = "dev"
	Commit  = "none"
	Date    = "unknown"
)

// String returns a single-line human readable version stamp.
func String() string {
	return fmt.Sprintf("whois2api %s (commit %s, built %s, %s)", Version, Commit, Date, runtime.Version())
}
