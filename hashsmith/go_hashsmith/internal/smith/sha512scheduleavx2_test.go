package smith

import (
	"crypto/rand"
	"testing"
)

// TestSHA512ScheduleExpand4AVX2MatchesScalar checks the vectorized
// schedule expansion — sha512ScheduleExpand4AVX2, the real AVX2 assembly
// on amd64 and the portable per-lane fallback elsewhere — directly against
// sha512ExpandRemainingWords, the already-proven scalar recurrence, for
// 200 random first-16-word sets across all 4 lanes independently (so a
// bug tied to one lane's data happening to collide with another's would
// still be caught).
func TestSHA512ScheduleExpand4AVX2MatchesScalar(t *testing.T) {
	for trial := 0; trial < 200; trial++ {
		var w [80][pbkdf2Sha512Lanes]uint64
		var wantPerLane [pbkdf2Sha512Lanes][80]uint64
		for lane := 0; lane < pbkdf2Sha512Lanes; lane++ {
			var raw [16 * 8]byte
			if _, err := rand.Read(raw[:]); err != nil {
				t.Fatal(err)
			}
			for word := 0; word < 16; word++ {
				var v uint64
				for b := 0; b < 8; b++ {
					v = v<<8 | uint64(raw[word*8+b])
				}
				w[word][lane] = v
				wantPerLane[lane][word] = v
			}
			sha512ExpandRemainingWords(&wantPerLane[lane])
		}

		sha512ScheduleExpand4AVX2(&w)

		for lane := 0; lane < pbkdf2Sha512Lanes; lane++ {
			for step := 16; step < 80; step++ {
				if w[step][lane] != wantPerLane[lane][step] {
					t.Fatalf("trial %d, lane %d, step %d: got %#x, want %#x",
						trial, lane, step, w[step][lane], wantPerLane[lane][step])
				}
			}
		}
	}
}

// TestSHA512ScheduleFirst16FromWordsMatchesScalar checks the vectorized
// twin of sha512ScheduleFromWords's own w[0..15] setup against it directly,
// for random digest words across all 4 lanes.
func TestSHA512ScheduleFirst16FromWordsMatchesScalar(t *testing.T) {
	var data [pbkdf2Sha512Lanes][8]uint64
	for lane := 0; lane < pbkdf2Sha512Lanes; lane++ {
		var raw [64]byte
		if _, err := rand.Read(raw[:]); err != nil {
			t.Fatal(err)
		}
		for word := 0; word < 8; word++ {
			var v uint64
			for b := 0; b < 8; b++ {
				v = v<<8 | uint64(raw[word*8+b])
			}
			data[lane][word] = v
		}
	}

	var w [80][pbkdf2Sha512Lanes]uint64
	sha512ScheduleFirst16FromWords(&data, &w)

	for lane := 0; lane < pbkdf2Sha512Lanes; lane++ {
		var want [80]uint64
		sha512ScheduleFromWords(&data[lane], &want)
		for step := 0; step < 16; step++ {
			if w[step][lane] != want[step] {
				t.Fatalf("lane %d, step %d: got %#x, want %#x", lane, step, w[step][lane], want[step])
			}
		}
	}
}
