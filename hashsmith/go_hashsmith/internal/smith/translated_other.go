//go:build !darwin

package smith

// runningTranslated is darwin-only; no other platform this builds for runs
// these tests under binary translation.
func runningTranslated() bool { return false }
