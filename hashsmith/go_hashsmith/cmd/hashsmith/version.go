package main

import (
	"fmt"
	"os"
	"runtime"
	"runtime/debug"
)

// Build metadata. version is overridden at release time with
//
//	-ldflags "-X main.version=1.3.0 -X main.commit=abc1234 -X main.buildDate=2026-09-20"
//
// and otherwise falls back to whatever the Go toolchain stamped into the
// binary, so even a plain `go build` can say what it is.
var (
	version   = ""
	commit    = ""
	buildDate = ""
)

// versionString renders the one-line version banner.
//
// A binary that cannot identify itself is not deployable: every install path
// for this project builds from source, so "which build is this?" previously had
// no answer at all, and a user reporting a bug had nothing to report against.
func versionString() string {
	v := version
	rev, dirty := "", ""
	if info, ok := debug.ReadBuildInfo(); ok {
		if v == "" && info.Main.Version != "" && info.Main.Version != "(devel)" {
			v = info.Main.Version
		}
		for _, s := range info.Settings {
			switch s.Key {
			case "vcs.revision":
				rev = s.Value
			case "vcs.modified":
				if s.Value == "true" {
					dirty = "-dirty"
				}
			}
		}
	}
	if v == "" {
		v = "dev"
	}
	c := commit
	if c == "" {
		c = rev
	}
	if len(c) > 12 {
		c = c[:12]
	}
	out := "hashsmith " + v + dirty
	if c != "" {
		out += " (" + c + ")"
	}
	if buildDate != "" {
		out += " built " + buildDate
	}
	return out + fmt.Sprintf("  %s/%s %s", runtime.GOOS, runtime.GOARCH, runtime.Version())
}

// printVersion writes the version banner to stdout and exits successfully.
func printVersion() {
	fmt.Println(versionString())
	os.Exit(0)
}
