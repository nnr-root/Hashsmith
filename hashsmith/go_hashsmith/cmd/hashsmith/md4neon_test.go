package main

import (
	"testing"

	"golang.org/x/crypto/md4"
)

// TestMD4GroupMatchesScalar hashes all neonGroup lanes at every length in
// both encoding modes and checks each one bit-exact against
// golang.org/x/crypto/md4. This test is architecture-agnostic: on arm64 it
// exercises the NEON core (via md4Group in md4neon_arm64.go), everywhere
// else the scalar fallback (in md4neon_generic.go) — same test, both
// builds, which is the whole safety argument for shipping hand-written
// assembly.
func TestMD4GroupMatchesScalar(t *testing.T) {
	for _, enc := range []encodeMode{encRaw, encUTF16LE} {
		maxLen := 55
		if enc == encUTF16LE {
			maxLen = 27
		}
		for length := 0; length <= maxLen; length++ {
			sets := make([][]byte, length)
			for i := range sets {
				sets[i] = []byte("abcdefghijklmnop")
			}
			tb := newTransposedBatch(neonShape)
			if err := tb.reset(length, enc); err != nil {
				t.Fatalf("enc %v len %d: %v", enc, length, err)
			}
			// n is how many of the neonGroup lanes fillFromSegment actually
			// wrote real candidates into. At length 0 (keyspace 1: only the
			// empty candidate exists) and length 1 with this 16-symbol,
			// single-position alphabet (keyspace 16 < neonGroup), n < 20:
			// lanes n..19 are cleaned to the empty-message block rather
			// than holding a length-byte candidate (see fillFromSegment's
			// doc comment and the matching gotcha documented in
			// md5neon_test.go's wideKeyspaceSets). tb.candidateAt
			// unconditionally reconstructs tb.length bytes regardless of
			// what a lane truly holds, so it is only a valid oracle for
			// lanes < n; for the cleaned lanes >= n the true message is
			// empty, independent of tb.length.
			n := tb.fillFromSegment(sets, 0, maskKeyspace(sets))
			out := make([][16]byte, neonShape.group())
			md4Group(tb, out)
			for i := 0; i < neonGroup; i++ {
				var msg []byte
				if i < n {
					msg = tb.candidateAt(i)
					if enc == encUTF16LE {
						msg = utf16le(string(msg))
					}
				}
				h := md4.New()
				h.Write(msg)
				var want [16]byte
				copy(want[:], h.Sum(nil))
				if out[i] != want {
					t.Fatalf("enc %v len %d lane %d: got %x want %x", enc, length, i, out[i], want)
				}
			}
		}
	}
}

// TestMD4GroupLanesAreIndependent checks lane independence across ALL
// chains: changing one candidate must perturb no other. This is the classic
// interleaved-SIMD bug and the MD5 core's own suite checks it, so the
// shipped MD4 core must too.
func TestMD4GroupLanesAreIndependent(t *testing.T) {
	sets := [][]byte{[]byte("abcde"), []byte("fghij"), []byte("klmno"), []byte("pqrst")}
	total := maskKeyspace(sets)
	tb := newTransposedBatch(neonShape)
	if err := tb.reset(4, encRaw); err != nil {
		t.Fatal(err)
	}
	tb.fillFromSegment(sets, 0, total)
	ref := make([][16]byte, neonShape.group())
	md4Group(tb, ref)
	for changed := 0; changed < neonGroup; changed++ {
		tb2 := newTransposedBatch(neonShape)
		if err := tb2.reset(4, encRaw); err != nil {
			t.Fatal(err)
		}
		tb2.fillFromSegment(sets, 0, total)
		tb2.words[tb2.wordIndex(changed, 0)] ^= 0x01
		out := make([][16]byte, neonShape.group())
		md4Group(tb2, out)
		for i := 0; i < neonGroup; i++ {
			if i != changed && out[i] != ref[i] {
				t.Fatalf("changing lane %d altered lane %d", changed, i)
			}
		}
	}
}

func BenchmarkMD4Group(b *testing.B) {
	sets := make([][]byte, 8)
	for i := range sets {
		sets[i] = []byte("abcdefghijklmnopqrstuvwxyz")
	}
	total := maskKeyspace(sets)
	tb := newTransposedBatch(neonShape)
	if err := tb.reset(len(sets), encRaw); err != nil {
		b.Fatal(err)
	}
	out := make([][16]byte, neonShape.group())
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		tb.fillFromSegment(sets, int64(i)*neonGroup, total)
		md4Group(tb, out)
	}
	b.ReportMetric(float64(b.N*neonGroup)/b.Elapsed().Seconds()/1e6, "MH/s")
}

func BenchmarkMD4Scalar(b *testing.B) {
	buf := []byte("abcdefgh")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		h := md4.New()
		h.Write(buf)
		h.Sum(nil)
	}
	b.ReportMetric(float64(b.N)/b.Elapsed().Seconds()/1e6, "MH/s")
}
