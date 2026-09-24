package smith

import (
	"math/rand"
	"testing"
)

func randomState5(rng *rand.Rand) [5]uint32 {
	var s [5]uint32
	for i := range s {
		s[i] = rng.Uint32()
	}
	return s
}

// TestSHA1Group16MatchesScalarFromIV checks sha1Group16AVX2 (the real N=2
// AVX2 core on amd64, the generic scalar loop everywhere else) against
// sha1ScalarCompress directly, for every lane starting from sha1IV — the
// same shape as TestSHA256Group8MatchesScalarFromIV, widened to 16 lanes.
func TestSHA1Group16MatchesScalarFromIV(t *testing.T) {
	rng := rand.New(rand.NewSource(9))
	for trial := 0; trial < 50; trial++ {
		var states [5][16]uint32
		var schedules [80][16]uint32
		var want [5][16]uint32
		for lane := 0; lane < 16; lane++ {
			for w := 0; w < 5; w++ {
				states[w][lane] = sha1IV[w]
			}
			block := randomBlock(rng)
			var w [80]uint32
			sha1ExpandSchedule(&block, &w)
			for step := 0; step < 80; step++ {
				schedules[step][lane] = w[step]
			}
			state := sha1IV
			sha1ScalarCompress(&state, &w)
			for word := 0; word < 5; word++ {
				want[word][lane] = state[word]
			}
		}
		got := sha1Group16AVX2(&states, &schedules)
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

// TestSHA1Group16MatchesScalarFromArbitraryState is the case that actually
// matters for the PBKDF2 lane hasher: every lane starts from its own
// random state, exactly as HMAC continuation needs.
func TestSHA1Group16MatchesScalarFromArbitraryState(t *testing.T) {
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
		got := sha1Group16AVX2(&states, &schedules)
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

// TestSHA1Group16LanesAreIndependent matches
// TestSHA256Group8LanesAreIndependent: perturbing one lane's input must not
// change any other lane's output.
func TestSHA1Group16LanesAreIndependent(t *testing.T) {
	rng := rand.New(rand.NewSource(11))
	var states [5][16]uint32
	var schedules [80][16]uint32
	for lane := 0; lane < 16; lane++ {
		laneState := randomState5(rng)
		block := randomBlock(rng)
		var w [80]uint32
		sha1ExpandSchedule(&block, &w)
		for word := 0; word < 5; word++ {
			states[word][lane] = laneState[word]
		}
		for step := 0; step < 80; step++ {
			schedules[step][lane] = w[step]
		}
	}
	ref := sha1Group16AVX2(&states, &schedules)

	for changed := 0; changed < 16; changed++ {
		perturbed := states
		perturbed[0][changed] ^= 0x01
		got := sha1Group16AVX2(&perturbed, &schedules)
		for lane := 0; lane < 16; lane++ {
			if lane == changed {
				continue
			}
			for word := 0; word < 5; word++ {
				if got[word][lane] != ref[word][lane] {
					t.Fatalf("perturbing lane %d altered lane %d word %d", changed, lane, word)
				}
			}
		}
	}
}
