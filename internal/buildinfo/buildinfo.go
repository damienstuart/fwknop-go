// Package buildinfo extracts version and VCS metadata from the Go
// runtime build info embedded automatically by the toolchain (Go 1.18+).
package buildinfo

import (
	"runtime/debug"
	"strings"
)

// Info holds version and VCS metadata for a binary.
type Info struct {
	Version string // semantic version (e.g. "0.1.0" or "v0.1.0")
	Commit  string // short VCS commit hash
	Time    string // VCS commit timestamp
	Dirty   bool   // true if the working tree had uncommitted changes
}

// GetInfo returns build information for the running binary. VCS metadata
// (commit, time, dirty) is populated when the binary was built from a
// local source tree. When the binary was installed from a module proxy
// via "go install module@version", the module version is used instead
// of defaultVersion.
func GetInfo(defaultVersion string) Info {
	info := Info{Version: defaultVersion}

	bi, ok := debug.ReadBuildInfo()
	if !ok {
		return info
	}

	// Extract VCS metadata embedded by the Go toolchain.
	for _, s := range bi.Settings {
		switch s.Key {
		case "vcs.revision":
			info.Commit = s.Value
			if len(info.Commit) > 12 {
				info.Commit = info.Commit[:12]
			}
		case "vcs.time":
			info.Time = s.Value
		case "vcs.modified":
			info.Dirty = s.Value == "true"
		}
	}

	// Use the module version only when installed from a module proxy
	// (go install module@version). In that case VCS info is absent
	// and Main.Version holds the clean tag (e.g. "v1.0.0").
	if info.Commit == "" {
		if v := bi.Main.Version; v != "" && v != "(devel)" {
			info.Version = v
		}
	}

	return info
}

// String formats the version info as a human-readable string.
// Examples:
//
//	"0.1.0"
//	"0.1.0 (commit: a1b2c3d4e5f6, built: 2026-04-10T18:30:00Z)"
//	"0.1.0 (commit: a1b2c3d4e5f6, built: 2026-04-10T18:30:00Z, dirty)"
func (i Info) String() string {
	if i.Commit == "" {
		return i.Version
	}

	var b strings.Builder
	b.WriteString(i.Version)
	b.WriteString(" (commit: ")
	b.WriteString(i.Commit)
	if i.Time != "" {
		b.WriteString(", built: ")
		b.WriteString(i.Time)
	}
	if i.Dirty {
		b.WriteString(", dirty")
	}
	b.WriteByte(')')

	return b.String()
}
