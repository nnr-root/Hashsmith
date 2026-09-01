package main

import (
	"crypto/md5"
	"testing"
)

// avx2WideKeyspaceSets builds mask sets for a candidate of the given length
// whose keyspace is always exactly 32 (>= avx2Shape.group(), 24), for every
// length >= 1, with no risk of overflowing maskKeyspace's int64
// accumulator: only position 0 carries a real (32-symbol) alphabet, every
// other position is a fixed singleton, so the product stays at 32
// regardless of length. Mirrors md5neon_test.go's wideKeyspaceSets — see
// that function's doc comment for why this shape (rather than a repeated
// wide alphabet at every position) is needed to keep tb.candidateAt a valid
// oracle for every length.
func avx2WideKeyspaceSets(length int) [][]byte {
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

// TestMD5AVX2GroupMatchesCryptoMD5 hashes all avx2Shape.group() (24) lanes
// at every length 0..transposedMaxLen (encRaw) and 0..transposedMaxLenUTF16LE
// (encUTF16LE), checking each one bit-exact against crypto/md5. This test is
// architecture-agnostic: on amd64 it exercises the AVX2 core (via
// md5GroupAVX2 in md5avx2_amd64.go), everywhere else the scalar fallback (in
// md5avx2_generic.go) — same test, both builds, which is the whole safety
// argument for shipping hand-written assembly.
func TestMD5AVX2GroupMatchesCryptoMD5(t *testing.T) {
	for _, enc := range []encodeMode{encRaw, encUTF16LE} {
		maxLen := transposedMaxLen
		if enc == encUTF16LE {
			maxLen = transposedMaxLenUTF16LE
		}
		for length := 0; length <= maxLen; length++ {
			sets := avx2WideKeyspaceSets(length)
			tb := newTransposedBatch(avx2Shape)
			if err := tb.reset(length, enc); err != nil {
				t.Fatalf("enc %v len %d: reset: %v", enc, length, err)
			}
			tb.fillFromSegment(sets, 0)
			out := make([][16]byte, avx2Shape.group())
			md5GroupAVX2(tb, out)
			for i := 0; i < avx2Shape.group(); i++ {
				msg := tb.candidateAt(i)
				if enc == encUTF16LE {
					msg = utf16le(string(msg))
				}
				want := md5.Sum(msg)
				if out[i] != want {
					t.Fatalf("enc %v len %d lane %d: got %x, want %x", enc, length, i, out[i], want)
				}
			}
		}
	}
}

// TestMD5AVX2GroupLanesAreIndependent checks lane independence across ALL
// three chains: changing one candidate must perturb no other. This is the
// classic interleaved-SIMD bug and the NEON core's own suite checks it, so
// the AVX2 core must too.
func TestMD5AVX2GroupLanesAreIndependent(t *testing.T) {
	sets := [][]byte{[]byte("abcde"), []byte("fghij"), []byte("klmno"), []byte("pqrst")}
	tb := newTransposedBatch(avx2Shape)
	if err := tb.reset(4, encRaw); err != nil {
		t.Fatal(err)
	}
	tb.fillFromSegment(sets, 0)
	ref := make([][16]byte, avx2Shape.group())
	md5GroupAVX2(tb, ref)

	for changed := 0; changed < avx2Shape.group(); changed++ {
		tb2 := newTransposedBatch(avx2Shape)
		if err := tb2.reset(4, encRaw); err != nil {
			t.Fatal(err)
		}
		tb2.fillFromSegment(sets, 0)
		// Perturb exactly one lane's first word.
		tb2.words[tb2.wordIndex(changed, 0)] ^= 0x01
		out := make([][16]byte, avx2Shape.group())
		md5GroupAVX2(tb2, out)
		for i := 0; i < avx2Shape.group(); i++ {
			if i == changed {
				continue
			}
			if out[i] != ref[i] {
				t.Fatalf("changing lane %d altered lane %d", changed, i)
			}
		}
	}
}

func BenchmarkMD5AVX2Group(b *testing.B) {
	sets := make([][]byte, 8)
	for i := range sets {
		sets[i] = []byte("abcdefghijklmnopqrstuvwxyz")
	}
	tb := newTransposedBatch(avx2Shape)
	if err := tb.reset(len(sets), encRaw); err != nil {
		b.Fatal(err)
	}
	out := make([][16]byte, avx2Shape.group())
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		tb.fillFromSegment(sets, int64(i)*int64(avx2Shape.group()))
		md5GroupAVX2(tb, out)
	}
	b.ReportMetric(float64(b.N*avx2Shape.group())/b.Elapsed().Seconds()/1e6, "MH/s")
}
