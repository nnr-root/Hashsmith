package smith

import (
	"fmt"
	"os"
	"runtime"
	"runtime/debug"
)

// Build metadata, set by SetBuildInfo from cmd/hashsmith, which is where the
// release linker flags land. Empty values fall back to whatever the Go
// toolchain stamped into the binary, so even a plain `go build` can say what
// it is.
var (
	version   = ""
	commit    = ""
	buildDate = ""
)

// SetBuildInfo records the release metadata the linker stamped into the
// command.
//
// It exists because those values arrive as -ldflags "-X main.version=...", and
// main is cmd/hashsmith — not this package. When the implementation moved out
// of package main, a linker flag naming a symbol that no longer exists became
// a silent no-op: the build still succeeds and every release binary reports
// "dev". Keeping the three variables in main and handing them over here means
// the Dockerfile, the release workflow and the pip build need no change and
// cannot drift.
func SetBuildInfo(v, c, date string) {
	version, commit, buildDate = v, c, date
}

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
