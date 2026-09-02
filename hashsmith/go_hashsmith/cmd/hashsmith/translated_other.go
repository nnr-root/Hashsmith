//go:build !darwin

package main

// runningTranslated is darwin-only; no other platform this builds for runs
// these tests under binary translation.
func runningTranslated() bool { return false }
