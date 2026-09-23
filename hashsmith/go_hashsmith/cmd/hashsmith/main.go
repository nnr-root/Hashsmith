// Command hashsmith is the command-line interface to the toolkit.
//
// Everything it does lives in internal/smith; this file exists so that the
// implementation is a package rather than a package main, which is what makes
// the toolkit importable. The public library API is the hashsmith package at
// the module root.
package main

import "hashsmith-go/internal/smith"

// Build metadata, overridden at release time with
//
//	-ldflags "-X main.version=1.3.0 -X main.commit=abc1234 -X main.buildDate=2026-09-20"
//
// These live here, in package main, because that is the package name those
// linker flags spell. A -X naming a symbol that does not exist is not an
// error: the build succeeds and the value is simply never set, so moving them
// into the implementation package would have left every release binary quietly
// reporting "dev". The Dockerfile, the release workflow and the pip build all
// name main.version, and none of them had to change.
var (
	version   = ""
	commit    = ""
	buildDate = ""
)

func main() {
	smith.SetBuildInfo(version, commit, buildDate)
	smith.Main()
}
