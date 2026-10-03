//go:build amd64

package smith

import (
	"math/rand"
	"testing"
)

// TestSHA1Group16OldMatchesScalar is a quick correctness check on the
// extracted-from-git pre-fix core before trusting any benchmark against it —
// if the extraction were somehow wrong, a benchmark number would be
// meaningless. Same shape as TestSHA1Group16MatchesScalarFromArbitraryState.
func TestSHA1Group16OldMatchesScalar(t *testing.T) {
	rng := rand.New(rand.NewSource(10))
	for trial := 0; trial < 50; trial++ {
		var states [5][16]uint32
		var schedules [80][16]uint32
		var want [5][16]uint32
		for lane := 0; lane < 16; lane++ {
			laneState := randomState5(rng)
			for w := 0; w < 5; w++ {
				states[w][lane] = laneState[w]
			}
			block := randomBlock(rng)
			var w [80]uint32
			sha1ExpandSchedule(&block, &w)
			for step := 0; step < 80; step++ {
				schedules[step][lane] = w[step]
			}
			state := laneState
			sha1ScalarCompress(&state, &w)
			for word := 0; word < 5; word++ {
				want[word][lane] = state[word]
			}
		}
		got := sha1Group16AVX2Old(&states, &schedules)
		for lane := 0; lane < 16; lane++ {
			for word := 0; word < 5; word++ {
				if got[word][lane] != want[word][lane] {
					t.Fatalf("trial %d lane %d word %d: got %#x, want %#x",
						trial, lane, word, got[word][lane], want[word][lane])
				}
			}
		}
	}
}

// BenchmarkSHA1CompressAVX2GroupOnlyOld is the pre-fix core (2 VMOVDQU/round,
// commit 1b84a33), benchmarked with the EXACT same setup and random seed as
// BenchmarkSHA1CompressAVX2GroupOnly (the current, post-fix core) so the two
// numbers come from the same CI job, same machine, same input data — the
// controlled A/B this comparison needs. Delete alongside
// sha1avx2_oldcompare_amd64.{s,go} and this file once the comparison is done.
func BenchmarkSHA1CompressAVX2GroupOnlyOld(b *testing.B) {
	rng := rand.New(rand.NewSource(23))
	var s [5][16]uint32
	var schedules [80][16]uint32
	for lane := 0; lane < 16; lane++ {
		for w := 0; w < 5; w++ {
			s[w][lane] = sha1IV[w]
		}
		block := randomBlock(rng)
		var w [80]uint32
		sha1ExpandSchedule(&block, &w)
		for step := 0; step < 80; step++ {
			schedules[step][lane] = w[step]
		}
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = sha1Group16AVX2Old(&s, &schedules)
	}
}
