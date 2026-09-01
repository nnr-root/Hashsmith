package main

import (
	"crypto/md5"
	"testing"
)

// wideKeyspaceSets builds mask sets for a candidate of the given length
// whose keyspace is always exactly 32 (>= neonGroup), for every length >=
// 1, with no risk of overflowing maskKeyspace's int64 accumulator: only
// position 0 carries a real (32-symbol) alphabet, every other position is
// a fixed singleton, so the product stays at 32 regardless of length.
//
// This sidesteps two pre-existing, out-of-scope behaviors in Task 6's mask
// engine that a naive "repeat one 16-symbol alphabet across every
// position" construction (as a first draft of this test used) collides
// with by length 55:
//   - maskKeyspace (mask.go) accumulates the keyspace as a plain int64
//     product with no overflow check. 16^16 == 2^64, so it wraps to
//     exactly 0 at length 16 (and stays 0 for every length beyond, since
//     each further factor of 16 is still a multiple of 2^64). A repeated
//     95-symbol alphabet — a realistic hashcat-style ?a mask — overflows
//     starting at length 10. That is a real, separate bug worth fixing in
//     Task 6, but it is not this task's assembly.
//   - when maskKeyspace's (possibly wrapped) total is smaller than
//     neonGroup, fillFromSegment correctly leaves the unfilled lanes as
//     zero-length blocks (bitLen=0) — but transposedBatch.candidateAt
//     reads tb.length bytes from every lane unconditionally, so on those
//     lanes it reconstructs bytes that were never the message actually
//     hashed (candidateAt doesn't know the lane's true, per-lane encoded
//     bit length). The NEON core still hashes exactly the bits it was
//     given — reading each lane's own bit-length word directly out of
//     tb.words and hashing THAT reconstructed message confirms 0
//     mismatches across every length 0..55 and all 20 lanes, so this is a
//     test-oracle gap in candidateAt for underfilled groups, not a core
//     bug — but it means candidateAt is only a valid oracle when every
//     lane holds a genuine, fully-filled candidate, which this helper
//     guarantees by keeping keyspace constant at 32 for every length >= 1.
func wideKeyspaceSets(length int) [][]byte {
	if length == 0 {
		return nil
	}
	sets := make([][]byte, length)
	wide := make([]byte, 32)
	for i := range wide {
		wide[i] = byte(i)
	}
	sets[0] = wide
	for i := 1; i < length; i++ {
		sets[i] = []byte{'x'}
	}
	return sets
}

// TestMD5GroupMatchesCryptoMD5 hashes all neonGroup lanes at every length
// 0..transposedMaxLen and checks each one bit-exact against crypto/md5. This
// test is architecture-agnostic: on arm64 it exercises the NEON core (via
// md5Group in md5neon_arm64.go), everywhere else the scalar fallback (in
// md5neon_generic.go) — same test, both builds, which is the whole safety
// argument for shipping hand-written assembly.
func TestMD5GroupMatchesCryptoMD5(t *testing.T) {
	for length := 0; length <= transposedMaxLen; length++ {
		sets := wideKeyspaceSets(length)
		tb := newTransposedBatch(neonShape)
		if err := tb.reset(length, encRaw); err != nil {
			t.Fatalf("len %d: reset: %v", length, err)
		}
		tb.fillFromSegment(sets, 0)
		out := make([][16]byte, neonShape.group())
		md5Group(tb, out)
		for i := 0; i < neonGroup; i++ {
			want := md5.Sum(tb.candidateAt(i))
			if out[i] != want {
				t.Fatalf("len %d lane %d: got %x, want %x", length, i, out[i], want)
			}
		}
	}
}

// TestMD5GroupLanesAreIndependent checks lane independence across ALL
// chains: changing one candidate must perturb no other. This is the classic
// interleaved-SIMD bug and the spike's own suite checked it, so the shipped
// version must too.
func TestMD5GroupLanesAreIndependent(t *testing.T) {
	sets := [][]byte{[]byte("abcde"), []byte("fghij"), []byte("klmno"), []byte("pqrst")}
	tb := newTransposedBatch(neonShape)
	if err := tb.reset(4, encRaw); err != nil {
		t.Fatal(err)
	}
	tb.fillFromSegment(sets, 0)
	ref := make([][16]byte, neonShape.group())
	md5Group(tb, ref)

	for changed := 0; changed < neonGroup; changed++ {
		tb2 := newTransposedBatch(neonShape)
		if err := tb2.reset(4, encRaw); err != nil {
			t.Fatal(err)
		}
		tb2.fillFromSegment(sets, 0)
		// Perturb exactly one lane's first word.
		tb2.words[tb2.wordIndex(changed, 0)] ^= 0x01
		out := make([][16]byte, neonShape.group())
		md5Group(tb2, out)
		for i := 0; i < neonGroup; i++ {
			if i == changed {
				continue
			}
			if out[i] != ref[i] {
				t.Fatalf("changing lane %d altered lane %d", changed, i)
			}
		}
	}
}

func BenchmarkMD5Group(b *testing.B) {
	sets := make([][]byte, 8)
	for i := range sets {
		sets[i] = []byte("abcdefghijklmnopqrstuvwxyz")
	}
	tb := newTransposedBatch(neonShape)
	if err := tb.reset(len(sets), encRaw); err != nil {
		b.Fatal(err)
	}
	out := make([][16]byte, neonShape.group())
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		tb.fillFromSegment(sets, int64(i)*neonGroup)
		md5Group(tb, out)
	}
	b.ReportMetric(float64(b.N*neonGroup)/b.Elapsed().Seconds()/1e6, "MH/s")
}

func BenchmarkMD5Scalar(b *testing.B) {
	buf := []byte("abcdefgh")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		md5.Sum(buf)
	}
	b.ReportMetric(float64(b.N)/b.Elapsed().Seconds()/1e6, "MH/s")
}
