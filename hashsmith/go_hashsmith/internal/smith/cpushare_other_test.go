//go:build !unix

package smith

// processCPUSeconds has no portable implementation off Unix. Reporting "not
// available" rather than guessing means the feasibility tests behave exactly
// as they did before this measurement existed: they run, and they trust the
// wall clock.
func processCPUSeconds() (float64, bool) { return 0, false }
