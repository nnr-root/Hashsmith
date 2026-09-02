//go:build darwin

package main

import "golang.org/x/sys/unix"

// runningTranslated reports whether this process is executing under binary
// translation — Rosetta 2, when a GOARCH=amd64 build runs on an arm64 Mac.
// Timing measurements are meaningless there: both sides of a rate comparison
// are slowed by the translator, and not by the same factor, so a test that
// asserts one path outruns another can fail for reasons that have nothing to
// do with the code under test.
func runningTranslated() bool {
	v, err := unix.SysctlUint32("sysctl.proc_translated")
	return err == nil && v == 1
}
