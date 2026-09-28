package smith

import (
	"math/rand"
	"testing"
)

func randomState8_64(rng *rand.Rand) [8]uint64 {
	var s [8]uint64
	for i := range s {
		s[i] = rng.Uint64()
	}
	return s
}

func randomBlock128(rng *rand.Rand) [128]byte {
	var b [128]byte
	rng.Read(b[:])
	return b
}

// TestSHA512Group4MatchesScalarFromIV mirrors
// TestSHA256Group8MatchesScalarFromIV at SHA-512's own lane width.
func TestSHA512Group4MatchesScalarFromIV(t *testing.T) {
	rng := rand.New(rand.NewSource(14))
	for trial := 0; trial < 50; trial++ {
		var states [8][4]uint64
		var schedules [80][4]uint64
		var want [8][4]uint64
		for lane := 0; lane < 4; lane++ {
			for w := 0; w < 8; w++ {
				states[w][lane] = sha512IV[w]
			}
			block := randomBlock128(rng)
			var w [80]uint64
			sha512ExpandSchedule(&block, &w)
			for step := 0; step < 80; step++ {
				schedules[step][lane] = w[step]
			}
			state := sha512IV
			sha512ScalarCompress(&state, &w)
			for word := 0; word < 8; word++ {
				want[word][lane] = state[word]
			}
		}
		got := sha512Group4AVX2(&states, &schedules)
		for lane := 0; lane < 4; lane++ {
			for word := 0; word < 8; word++ {
				if got[word][lane] != want[word][lane] {
					t.Fatalf("trial %d lane %d word %d: got %#x, want %#x",
						trial, lane, word, got[word][lane], want[word][lane])
				}
			}
		}
	}
}

// TestSHA512Group4MatchesScalarFromArbitraryState is the case that matters
// for the PBKDF2 lane hasher.
func TestSHA512Group4MatchesScalarFromArbitraryState(t *testing.T) {
	rng := rand.New(rand.NewSource(15))
	for trial := 0; trial < 50; trial++ {
		var states [8][4]uint64
		var schedules [80][4]uint64
		var want [8][4]uint64
		for lane := 0; lane < 4; lane++ {
			laneState := randomState8_64(rng)
			for w := 0; w < 8; w++ {
				states[w][lane] = laneState[w]
			}
			block := randomBlock128(rng)
			var w [80]uint64
			sha512ExpandSchedule(&block, &w)
			for step := 0; step < 80; step++ {
				schedules[step][lane] = w[step]
			}
			state := laneState
			sha512ScalarCompress(&state, &w)
			for word := 0; word < 8; word++ {
				want[word][lane] = state[word]
			}
		}
		got := sha512Group4AVX2(&states, &schedules)
		for lane := 0; lane < 4; lane++ {
			for word := 0; word < 8; word++ {
				if got[word][lane] != want[word][lane] {
					t.Fatalf("trial %d lane %d word %d: got %#x, want %#x",
						trial, lane, word, got[word][lane], want[word][lane])
				}
			}
		}
	}
}

// TestSHA512Group4LanesAreIndependent mirrors
// TestSHA256Group8LanesAreIndependent.
func TestSHA512Group4LanesAreIndependent(t *testing.T) {
	rng := rand.New(rand.NewSource(16))
	var states [8][4]uint64
	var schedules [80][4]uint64
	for lane := 0; lane < 4; lane++ {
		laneState := randomState8_64(rng)
		block := randomBlock128(rng)
		var w [80]uint64
		sha512ExpandSchedule(&block, &w)
		for word := 0; word < 8; word++ {
			states[word][lane] = laneState[word]
		}
		for step := 0; step < 80; step++ {
			schedules[step][lane] = w[step]
		}
	}
	ref := sha512Group4AVX2(&states, &schedules)

	for changed := 0; changed < 4; changed++ {
		perturbed := states
		perturbed[0][changed] ^= 0x01
		got := sha512Group4AVX2(&perturbed, &schedules)
		for lane := 0; lane < 4; lane++ {
			if lane == changed {
				continue
			}
			for word := 0; word < 8; word++ {
				if got[word][lane] != ref[word][lane] {
					t.Fatalf("perturbing lane %d altered lane %d word %d", changed, lane, word)
				}
			}
		}
	}
}
