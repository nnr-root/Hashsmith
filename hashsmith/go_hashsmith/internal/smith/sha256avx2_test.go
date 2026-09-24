package smith

import (
	"crypto/sha256"
	"math/rand"
	"testing"
)

// padOneBlock pads msg per FIPS 180-4 Sec 5.1.1, panicking if it does not
// fit in a single 64-byte block (len(msg) <= 55) — every case in this file
// deliberately stays under that so sha256ScalarCompress from sha256IV can
// be checked directly against crypto/sha256.Sum256, which is the whole
// point of these cases: an independent oracle for the from-IV case, before
// trusting sha256ScalarCompress to also be right when the caller hands it
// a non-IV starting state (§ tested separately below, since crypto/sha256
// exposes no way to start from an arbitrary state to check that path
// against).
func padOneBlock(msg []byte) [64]byte {
	if len(msg) > 55 {
		panic("padOneBlock: message too long for one block")
	}
	var block [64]byte
	copy(block[:], msg)
	block[len(msg)] = 0x80
	bitLen := uint64(len(msg)) * 8
	for i := 0; i < 8; i++ {
		block[63-i] = byte(bitLen >> (8 * i))
	}
	return block
}

// TestSHA256ScalarCompressMatchesCryptoSHA256 is the foundational oracle
// check: sha256ScalarCompress from sha256IV, over a correctly padded
// single-block message, must equal crypto/sha256.Sum256 exactly. Every
// other test in this file (and the AVX2 core's own correctness) is only as
// trustworthy as this one, since sha256ScalarCompress is what they are all
// ultimately checked against.
func TestSHA256ScalarCompressMatchesCryptoSHA256(t *testing.T) {
	cases := []string{
		"", "a", "abc", "message digest",
		"abcdefghijklmnopqrstuvwxyz",
		"12345678901234567890123456789012345678901234567890123456789012345678901234567890"[:55],
	}
	for _, msg := range cases {
		block := padOneBlock([]byte(msg))
		state := sha256IV
		var w [64]uint32
		sha256ExpandSchedule(&block, &w)
		sha256ScalarCompress(&state, &w)
		var got [32]byte
		for i := 0; i < 8; i++ {
			got[i*4] = byte(state[i] >> 24)
			got[i*4+1] = byte(state[i] >> 16)
			got[i*4+2] = byte(state[i] >> 8)
			got[i*4+3] = byte(state[i])
		}
		want := sha256.Sum256([]byte(msg))
		if got != want {
			t.Fatalf("msg %q: sha256ScalarCompress = %x, want %x", msg, got, want)
		}
	}
}

// TestSHA256ScalarCompressRandomMatchesCryptoSHA256 extends the table above
// with randomized short messages, still all from sha256IV (crypto/sha256
// remains a valid oracle only for that case).
func TestSHA256ScalarCompressRandomMatchesCryptoSHA256(t *testing.T) {
	rng := rand.New(rand.NewSource(2))
	for i := 0; i < 500; i++ {
		n := rng.Intn(56) // 0..55, the one-block ceiling
		msg := make([]byte, n)
		rng.Read(msg)
		block := padOneBlock(msg)
		state := sha256IV
		var w [64]uint32
		sha256ExpandSchedule(&block, &w)
		sha256ScalarCompress(&state, &w)
		var got [32]byte
		for j := 0; j < 8; j++ {
			got[j*4] = byte(state[j] >> 24)
			got[j*4+1] = byte(state[j] >> 16)
			got[j*4+2] = byte(state[j] >> 8)
			got[j*4+3] = byte(state[j])
		}
		want := sha256.Sum256(msg)
		if got != want {
			t.Fatalf("random msg %x: sha256ScalarCompress = %x, want %x", msg, got, want)
		}
	}
}

// randomState returns a pseudo-random [8]uint32, standing in for an
// arbitrary HMAC-continuation state — the case crypto/sha256 cannot serve
// as an oracle for, since compression from a non-IV state is exactly what
// HMAC's inner/outer continuation needs and Sum256 never exposes.
func randomState(rng *rand.Rand) [8]uint32 {
	var s [8]uint32
	for i := range s {
		s[i] = rng.Uint32()
	}
	return s
}

func randomBlock(rng *rand.Rand) [64]byte {
	var b [64]byte
	rng.Read(b[:])
	return b
}

// TestSHA256Group8MatchesScalarFromIV checks sha256Group8AVX2 (the real
// AVX2 core on amd64, the generic scalar loop everywhere else — see
// sha256avx2_amd64.go / sha256avx2_generic.go) against sha256ScalarCompress
// directly, for every lane starting from sha256IV. This is the same shape
// as TestMD5AVX2GroupMatchesCryptoMD5, adapted for a core whose natural
// input is a pre-expanded schedule rather than a raw candidate.
func TestSHA256Group8MatchesScalarFromIV(t *testing.T) {
	rng := rand.New(rand.NewSource(3))
	for trial := 0; trial < 50; trial++ {
		var states [8][8]uint32
		var schedules [64][8]uint32
		var wantStates [8][8]uint32
		for lane := 0; lane < 8; lane++ {
			for w := 0; w < 8; w++ {
				states[w][lane] = sha256IV[w]
			}
			block := randomBlock(rng)
			var w [64]uint32
			sha256ExpandSchedule(&block, &w)
			for step := 0; step < 64; step++ {
				schedules[step][lane] = w[step]
			}
			state := sha256IV
			sha256ScalarCompress(&state, &w)
			for word := 0; word < 8; word++ {
				wantStates[word][lane] = state[word]
			}
		}
		got := sha256Group8AVX2(&states, &schedules)
		for lane := 0; lane < 8; lane++ {
			for word := 0; word < 8; word++ {
				if got[word][lane] != wantStates[word][lane] {
					t.Fatalf("trial %d lane %d word %d: got %#x, want %#x",
						trial, lane, word, got[word][lane], wantStates[word][lane])
				}
			}
		}
	}
}

// TestSHA256Group8MatchesScalarFromArbitraryState is the test that actually
// exercises this core's reason for existing over a plain "hash a message"
// primitive: every lane starts from its OWN random state, exactly as the
// PBKDF2 lane hasher's HMAC continuation will (each candidate's own
// precomputed inner/outer state, which differs by password).
func TestSHA256Group8MatchesScalarFromArbitraryState(t *testing.T) {
	rng := rand.New(rand.NewSource(4))
	for trial := 0; trial < 50; trial++ {
		var states [8][8]uint32
		var schedules [64][8]uint32
		var wantStates [8][8]uint32
		for lane := 0; lane < 8; lane++ {
			laneState := randomState(rng)
			for w := 0; w < 8; w++ {
				states[w][lane] = laneState[w]
			}
			block := randomBlock(rng)
			var w [64]uint32
			sha256ExpandSchedule(&block, &w)
			for step := 0; step < 64; step++ {
				schedules[step][lane] = w[step]
			}
			state := laneState
			sha256ScalarCompress(&state, &w)
			for word := 0; word < 8; word++ {
				wantStates[word][lane] = state[word]
			}
		}
		got := sha256Group8AVX2(&states, &schedules)
		for lane := 0; lane < 8; lane++ {
			for word := 0; word < 8; word++ {
				if got[word][lane] != wantStates[word][lane] {
					t.Fatalf("trial %d lane %d word %d: got %#x, want %#x",
						trial, lane, word, got[word][lane], wantStates[word][lane])
				}
			}
		}
	}
}

// TestSHA256Group8LanesAreIndependent is the classic interleaved-SIMD
// check, matching TestMD5AVX2GroupLanesAreIndependent: perturbing one
// lane's input must not change any other lane's output.
func TestSHA256Group8LanesAreIndependent(t *testing.T) {
	rng := rand.New(rand.NewSource(5))
	var states [8][8]uint32
	var schedules [64][8]uint32
	for lane := 0; lane < 8; lane++ {
		laneState := randomState(rng)
		block := randomBlock(rng)
		var w [64]uint32
		sha256ExpandSchedule(&block, &w)
		for word := 0; word < 8; word++ {
			states[word][lane] = laneState[word]
		}
		for step := 0; step < 64; step++ {
			schedules[step][lane] = w[step]
		}
	}
	ref := sha256Group8AVX2(&states, &schedules)

	for changed := 0; changed < 8; changed++ {
		perturbed := states
		perturbed[0][changed] ^= 0x01
		got := sha256Group8AVX2(&perturbed, &schedules)
		for lane := 0; lane < 8; lane++ {
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

func BenchmarkSHA256Group8AVX2(b *testing.B) {
	rng := rand.New(rand.NewSource(6))
	var states [8][8]uint32
	var schedules [64][8]uint32
	for lane := 0; lane < 8; lane++ {
		for w := 0; w < 8; w++ {
			states[w][lane] = sha256IV[w]
		}
		block := randomBlock(rng)
		var w [64]uint32
		sha256ExpandSchedule(&block, &w)
		for step := 0; step < 64; step++ {
			schedules[step][lane] = w[step]
		}
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = sha256Group8AVX2(&states, &schedules)
	}
	b.ReportMetric(float64(b.N*8)/b.Elapsed().Seconds()/1e6, "MH/s")
}
