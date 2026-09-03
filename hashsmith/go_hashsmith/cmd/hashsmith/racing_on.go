//go:build race

package main

// racing reports whether this binary was built with the race detector
// (`go test -race`, `go build -race`, …). Go's toolchain sets the `race`
// build tag automatically whenever -race is passed, which is what this file
// (and its !race twin, racing_off.go) key off — the same mechanism
// translated_darwin.go/translated_other.go use for runningTranslated.
//
// Race instrumentation adds substantial per-memory-access overhead, and NOT
// evenly across every code path: a vector-fast core doing many tight,
// alignment-friendly accesses per candidate can be slowed by a different
// factor than a scalar path doing fewer, more scattered ones (observed
// directly developing this task's batch feasibility tests: a real dispatch
// vs. scalar-verify rate comparison that reliably favors the dispatch path
// natively flipped under -race). A rate comparison between two different
// code paths is therefore exactly as unreliable under -race as it is under
// binary translation — see runningTranslated's doc comment — for the same
// underlying reason: both sides are slowed, but not by the same factor.
func racing() bool { return true }
