package main

import (
	"os"
	"runtime"
	"testing"

	"golang.org/x/crypto/md4"
)

// md4Ref is the known-good MD4 oracle every differential check below
// compares against: golang.org/x/crypto/md4, the same reference the scalar
// crack path and the NEON core's suite use.
func md4Ref(msg []byte) [16]byte {
	h := md4.New()
	h.Write(msg)
	var d [16]byte
	copy(d[:], h.Sum(nil))
	return d
}

// TestMD4AVX2GroupMatchesScalar hashes all avx2Shape.group() (24) lanes at
// every length 0..transposedMaxLen (encRaw) and 0..transposedMaxLenUTF16LE
// (encUTF16LE, i.e. NTLM), checking each one bit-exact against
// golang.org/x/crypto/md4.
//
// This is the real correctness gate for md4avx2_amd64.s, and it is
// deliberately NOT gated on hasAVX2() or on GOARCH. Which implementation of
// md4GroupAVX2 it drives is decided by BUILD TAG, not by a runtime feature
// check: on amd64 it always calls the assembly in md4avx2_amd64.s, and
// everywhere else it always calls md4avx2_generic.go's scalar fallback. So
// there is no code path on which this test can quietly decline to exercise
// the assembly on an amd64 build — see TestMD4AVX2CoreWasActuallyExercised
// for the guard that keeps it that way.
//
// avx2WideKeyspaceSets (md5avx2_test.go) keeps the keyspace at exactly 32
// (>= 24) for every length, so fillFromSegment fills all 24 lanes with real
// candidates and tb.candidateAt is a valid oracle for every one of them.
// TestMD4AVX2GroupPartialGroupLanes below covers the complementary case
// where it is not.
func TestMD4AVX2GroupMatchesScalar(t *testing.T) {
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
			tb.fillFromSegment(sets, 0, maskKeyspace(sets))
			out := make([][16]byte, avx2Shape.group())
			md4GroupAVX2(tb, out)
			for i := 0; i < avx2Shape.group(); i++ {
				msg := tb.candidateAt(i)
				if enc == encUTF16LE {
					msg = utf16le(string(msg))
				}
				if want := md4Ref(msg); out[i] != want {
					t.Fatalf("enc %v len %d lane %d: got %x, want %x", enc, length, i, out[i], want)
				}
			}
		}
	}
}

// TestMD4AVX2GroupPartialGroupLanes covers the lanes the test above cannot:
// those fillFromSegment CLEANED. When a segment's keyspace is smaller than
// the 24-lane group (or the final group of a larger keyspace is partial),
// fillFromSegment writes n < 24 real candidates and cleans lanes n..23 to
// the empty-message block (word 0 = 0x80, bit length 0) so no stale
// candidate from a previous fill is re-hashed and falsely reported. The
// core must produce MD4("") for exactly those lanes, whatever tb.length is.
//
// tb.candidateAt is NOT a valid oracle for a cleaned lane — it
// unconditionally reconstructs tb.length bytes regardless of what the lane
// truly holds — so the expectation for lanes >= n is the empty message,
// mirroring md4neon_test.go's handling of the same hazard.
func TestMD4AVX2GroupPartialGroupLanes(t *testing.T) {
	for _, enc := range []encodeMode{encRaw, encUTF16LE} {
		maxLen := transposedMaxLen
		if enc == encUTF16LE {
			maxLen = transposedMaxLenUTF16LE
		}
		for length := 0; length <= maxLen; length++ {
			// A 5-symbol alphabet at position 0 only: keyspace 5 (and 1 at
			// length 0), both far below the 24-lane group, so every run here
			// leaves 19+ cleaned lanes.
			var sets [][]byte
			if length > 0 {
				sets = make([][]byte, length)
				sets[0] = []byte("abcde")
				for i := 1; i < length; i++ {
					sets[i] = []byte{'q'}
				}
			}
			tb := newTransposedBatch(avx2Shape)
			if err := tb.reset(length, enc); err != nil {
				t.Fatalf("enc %v len %d: reset: %v", enc, length, err)
			}
			n := tb.fillFromSegment(sets, 0, maskKeyspace(sets))
			if n >= avx2Shape.group() {
				t.Fatalf("enc %v len %d: fill covered all %d lanes; this test needs cleaned lanes", enc, length, n)
			}
			out := make([][16]byte, avx2Shape.group())
			md4GroupAVX2(tb, out)
			for i := 0; i < avx2Shape.group(); i++ {
				var msg []byte
				if i < n {
					msg = tb.candidateAt(i)
					if enc == encUTF16LE {
						msg = utf16le(string(msg))
					}
				}
				if want := md4Ref(msg); out[i] != want {
					t.Fatalf("enc %v len %d lane %d (n=%d): got %x, want %x", enc, length, i, n, out[i], want)
				}
			}
		}
	}
}

// TestMD4AVX2GroupLanesAreIndependent checks lane independence across ALL
// three chains: changing one candidate must perturb no other. This is the
// classic interleaved-SIMD bug — a misindexed register or a shared
// temporary that is live across chains — and both sibling cores' suites
// check it, so this one must too.
func TestMD4AVX2GroupLanesAreIndependent(t *testing.T) {
	sets := [][]byte{[]byte("abcde"), []byte("fghij"), []byte("klmno"), []byte("pqrst")}
	total := maskKeyspace(sets)
	tb := newTransposedBatch(avx2Shape)
	if err := tb.reset(4, encRaw); err != nil {
		t.Fatal(err)
	}
	tb.fillFromSegment(sets, 0, total)
	ref := make([][16]byte, avx2Shape.group())
	md4GroupAVX2(tb, ref)

	for changed := 0; changed < avx2Shape.group(); changed++ {
		tb2 := newTransposedBatch(avx2Shape)
		if err := tb2.reset(4, encRaw); err != nil {
			t.Fatal(err)
		}
		tb2.fillFromSegment(sets, 0, total)
		tb2.words[tb2.wordIndex(changed, 0)] ^= 0x01
		out := make([][16]byte, avx2Shape.group())
		md4GroupAVX2(tb2, out)
		for i := 0; i < avx2Shape.group(); i++ {
			if i != changed && out[i] != ref[i] {
				t.Fatalf("changing lane %d altered lane %d", changed, i)
			}
		}
	}
}

// TestMD4AVX2IsNotMD5 is a paranoia check with one job: prove the AVX2 MD4
// core is not secretly computing MD5. Both digests are 16 bytes and both
// cores share a generator lineage, an IV, a message layout and an output
// layout, so a mis-wired dispatch (or a generator ported round-for-round
// from md5avx2_gen.py without retargeting the round structure) produces
// output that is the right SIZE and the right SHAPE and simply wrong. The
// two known-good references disagree on every input, so asserting
// agreement with MD4 *and* disagreement with MD5 catches that class
// directly rather than by inference.
func TestMD4AVX2IsNotMD5(t *testing.T) {
	sets := avx2WideKeyspaceSets(6)
	tb := newTransposedBatch(avx2Shape)
	if err := tb.reset(6, encRaw); err != nil {
		t.Fatal(err)
	}
	tb.fillFromSegment(sets, 0, maskKeyspace(sets))
	got := make([][16]byte, avx2Shape.group())
	md4GroupAVX2(tb, got)
	md5out := make([][16]byte, avx2Shape.group())
	md5GroupAVX2(tb, md5out)
	for i := 0; i < avx2Shape.group(); i++ {
		if got[i] != md4Ref(tb.candidateAt(i)) {
			t.Fatalf("lane %d: MD4 core disagrees with the MD4 reference", i)
		}
		if got[i] == md5out[i] {
			t.Fatalf("lane %d: MD4 core produced the MD5 digest %x — wrong algorithm", i, got[i])
		}
	}
}

// TestMD4AVX2CoreWasActuallyExercised is the anti-false-green guard.
//
// THE HAZARD: this repo is developed on an arm64 Mac. Nothing here can run
// AVX2 natively, and hasAVX2() reports false under Rosetta. A test that
// skipped on !hasAVX2() would therefore pass on every machine the author
// can reach while proving nothing, and a wrong MD4 core would land green —
// then report "not found" for passwords that are present, on every x86
// user's machine, with no other signal.
//
// THE DESIGN THAT AVOIDS IT: none of the tests above skip. Which
// md4GroupAVX2 they call is chosen by build tag, so on any amd64 build they
// necessarily execute md4avx2_amd64.s; on a CPU without AVX2 the assembly
// would fault outright rather than silently degrade. This test pins that
// property so a future change cannot quietly reintroduce a runtime fallback
// inside md4GroupAVX2 (which would make the amd64 lane test the scalar
// oracle against itself — always green, always meaningless).
//
// WHICH CI JOB IS THE GATE: the `test` job in .github/workflows/ci.yml runs
// on ubuntu-latest (amd64) and sets HASHSMITH_REQUIRE_AVX2=1. With that set,
// this test demands that the build linked the assembly AND that the CPU
// really reports AVX2 AND that the live backend resolves md4/ntlm to it —
// so if any of those silently stops being true, that job fails loudly
// instead of passing on the fallback. The `race` and `bench` jobs run on
// the same amd64 runners and exercise the same assembly.
func TestMD4AVX2CoreWasActuallyExercised(t *testing.T) {
	if runtime.GOARCH == "amd64" && !md4AVX2IsAssembly {
		t.Fatal("amd64 build linked md4avx2_generic.go instead of md4avx2_amd64.s: " +
			"the AVX2 MD4 assembly is not being exercised by any test on this build")
	}
	if os.Getenv("HASHSMITH_REQUIRE_AVX2") != "1" {
		t.Logf("HASHSMITH_REQUIRE_AVX2 unset; on GOARCH=%s the AVX2 MD4 tests drove %s",
			runtime.GOARCH, map[bool]string{true: "md4avx2_amd64.s (real assembly)",
				false: "md4avx2_generic.go (scalar fallback)"}[md4AVX2IsAssembly])
		t.Skip("not the AVX2-required CI lane")
	}
	if !md4AVX2IsAssembly {
		t.Fatalf("HASHSMITH_REQUIRE_AVX2=1 but GOARCH=%s linked the scalar fallback: "+
			"this lane did NOT exercise the AVX2 MD4 core", runtime.GOARCH)
	}
	if !hasAVX2() {
		t.Fatal("HASHSMITH_REQUIRE_AVX2=1 but hasAVX2() is false: this runner cannot " +
			"be the lane that validates the AVX2 cores")
	}
	if b := vectorBackendName(); b != "avx2" {
		t.Fatalf("HASHSMITH_REQUIRE_AVX2=1 but vectorBackendName() = %q, want \"avx2\"", b)
	}
	for _, typ := range []string{"md4", "ntlm"} {
		algo, ok := fastAlgoFor(typ)
		if !ok {
			t.Fatalf("%s does not resolve to a fast-path descriptor on the live avx2 backend: "+
				"the AVX2 MD4 core exists but nothing dispatches to it", typ)
		}
		if algo.shape != avx2Shape {
			t.Errorf("%s resolved to shape %+v, want %+v", typ, algo.shape, avx2Shape)
		}
	}
}

func BenchmarkMD4AVX2Group(b *testing.B) {
	sets := make([][]byte, 8)
	for i := range sets {
		sets[i] = []byte("abcdefghijklmnopqrstuvwxyz")
	}
	total := maskKeyspace(sets)
	tb := newTransposedBatch(avx2Shape)
	if err := tb.reset(len(sets), encRaw); err != nil {
		b.Fatal(err)
	}
	out := make([][16]byte, avx2Shape.group())
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		tb.fillFromSegment(sets, int64(i)*int64(avx2Shape.group()), total)
		md4GroupAVX2(tb, out)
	}
	b.ReportMetric(float64(b.N*avx2Shape.group())/b.Elapsed().Seconds()/1e6, "MH/s")
}
