package main

import (
	"bytes"
	"context"
	"crypto/md5"
	"testing"

	"golang.org/x/crypto/md4"
)

// The fast path must find exactly what the scalar path finds — same candidate,
// same keyspace, including when the keyspace is not a multiple of the 20-wide
// group and when the answer sits in the final partial group.
func TestFastPathAgreesWithScalar(t *testing.T) {
	algo, ok := fastAlgoFor("md5")
	if !ok {
		// No vector backend on this build (e.g. amd64 without AVX2, or
		// under Rosetta, which reports no AVX at all). fastAlgoFor is
		// backend-dependent since the runtime-selection change, so there is
		// no descriptor to exercise and the scalar path is correct here.
		t.Skipf("md5 has no fast-path descriptor on backend %q", vectorBackendName())
	}
	for _, plain := range []string{"aaa", "abc", "zzz", "mnq"} {
		l := bruteLayout("abcdefghijklmnopqrstuvwxyz", 3, 3)
		sum := md5.Sum([]byte(plain))

		var a1, a2 int64
		fast, err := runLayoutFast(context.Background(), l, 0, 4, &a1, nil, algo, sum)
		if err != nil {
			t.Fatalf("%s: fast: %v", plain, err)
		}
		scalar, err := runLayout(context.Background(), l, 0, 4, &a2, nil,
			func(c string) bool { return md5.Sum([]byte(c)) == sum })
		if err != nil {
			t.Fatalf("%s: scalar: %v", plain, err)
		}
		if fast != plain || scalar != plain {
			t.Errorf("%s: fast=%q scalar=%q", plain, fast, scalar)
		}
	}
}

// A miss must exhaust the keyspace and report nothing — and must not report a
// spurious hit from an unused lane in the final partial group. Unused lanes
// hash to md5(""), so this test targets md5("") itself — the ONE hash that
// can structurally trigger the spurious-hit bug class — over a keyspace that
// (a) does NOT contain the empty candidate (min length 1, so no real
// candidate can legitimately match) and (b) has a total (14) that is not a
// multiple of neonGroup (20), so the final group is partial and genuinely has
// unused, empty-string-hashing lanes to potentially misfire on. A target like
// md5("not-in-keyspace") cannot exercise this bug at all: only the padding
// lanes ever hash to md5(""), so such a target can never produce a spurious
// hit no matter how broken the lane-count handling is.
func TestFastPathExhaustsWithoutSpuriousHit(t *testing.T) {
	algo, ok := fastAlgoFor("md5")
	if !ok {
		// No vector backend on this build (e.g. amd64 without AVX2, or
		// under Rosetta, which reports no AVX at all). fastAlgoFor is
		// backend-dependent since the runtime-selection change, so there is
		// no descriptor to exercise and the scalar path is correct here.
		t.Skipf("md5 has no fast-path descriptor on backend %q", vectorBackendName())
	}
	l := bruteLayout("ab", 1, 3) // 2 + 4 + 8 = 14, deliberately not a multiple of 20; excludes ""
	sum := md5.Sum([]byte(""))
	var attempts int64
	got, err := runLayoutFast(context.Background(), l, 0, 2, &attempts, nil, algo, sum)
	if err != nil {
		t.Fatalf("runLayoutFast: %v", err)
	}
	if got != "" {
		t.Errorf("got %q, want no match", got)
	}
	// The exhaustion count is what distinguishes "correctly found nothing"
	// from "bailed out early on a spurious padding-lane hit": a spurious hit
	// stops the run before the keyspace is exhausted, so attempts < l.total
	// would reveal it even if (by bad luck) got were also "".
	if attempts != l.total {
		t.Errorf("attempts = %d, want the full keyspace %d", attempts, l.total)
	}
}

// The empty-string candidate must be reachable and must be detected as a
// genuine hit, not confused with the padding in unused lanes (which also
// hashes to md5("")). The returned candidate string is "" either way a real
// hit on "" or no hit at all — so it cannot disambiguate the two outcomes.
// Instead, disambiguate via the attempt counter: a genuine hit stops the run
// before the keyspace is exhausted (attempts < l.total), whereas finding
// nothing exhausts it (attempts == l.total).
func TestFastPathHandlesEmptyCandidate(t *testing.T) {
	algo, ok := fastAlgoFor("md5")
	if !ok {
		// No vector backend on this build (e.g. amd64 without AVX2, or
		// under Rosetta, which reports no AVX at all). fastAlgoFor is
		// backend-dependent since the runtime-selection change, so there is
		// no descriptor to exercise and the scalar path is correct here.
		t.Skipf("md5 has no fast-path descriptor on backend %q", vectorBackendName())
	}
	l := bruteLayout("ab", 0, 1)
	if l.total == 0 {
		t.Skip("layout does not include the empty candidate")
	}
	sum := md5.Sum([]byte(""))
	var attempts int64
	if _, err := runLayoutFast(context.Background(), l, 0, 1, &attempts, nil, algo, sum); err != nil {
		t.Fatalf("runLayoutFast: %v", err)
	}
	if attempts >= l.total {
		t.Errorf("attempts = %d, want < %d (a genuine early hit on the empty candidate, not keyspace exhaustion)", attempts, l.total)
	}
}

func TestFastPathEligibility(t *testing.T) {
	l := bruteLayout("abc", 3, 3)
	if _, ok := fastPathEligible("md5", "", l); !ok && vectorBackendName() != "" {
		t.Error("plain md5 fixed-length brute should be eligible on an accelerated build")
	}
	if _, ok := fastPathEligible("md5", "somesalt", l); ok {
		t.Error("salted md5 must not be eligible")
	}
	if _, ok := fastPathEligible("sha256", "", l); ok {
		t.Error("sha256 must not be eligible — there is no sha256 vector core")
	}
}

// The fast path must find exactly what the scalar path finds, for every
// accelerated type.
func TestFastPathAgreesWithScalarPerAlgo(t *testing.T) {
	if vectorBackendName() == "" {
		t.Skip("no vector core on this build; fastPathEligible declines everything by design")
	}
	cases := []struct {
		typ    string
		digest func(string) [16]byte
	}{
		{"md5", func(s string) [16]byte { return md5.Sum([]byte(s)) }},
		{"md4", func(s string) [16]byte {
			h := md4.New()
			h.Write([]byte(s))
			var d [16]byte
			copy(d[:], h.Sum(nil))
			return d
		}},
		{"ntlm", func(s string) [16]byte {
			h := md4.New()
			h.Write(utf16le(s))
			var d [16]byte
			copy(d[:], h.Sum(nil))
			return d
		}},
	}
	for _, c := range cases {
		t.Run(c.typ, func(t *testing.T) {
			// md4/ntlm have no descriptor on the AVX2 backend (no AVX2 MD4
			// core exists yet) and correctly stay off the fast path there;
			// only assert agreement for algorithms the active backend
			// actually supports.
			if _, ok := fastAlgoFor(c.typ); !ok {
				t.Skipf("%s has no fast-path descriptor on backend %q", c.typ, vectorBackendName())
			}
			for _, plain := range []string{"a", "zz", "cat", "wxyz"} {
				l := bruteLayout("abcdefghijklmnopqrstuvwxyz", 1, 4)
				algo, ok := fastPathEligible(c.typ, "", l)
				if !ok {
					t.Fatalf("%s should be eligible on this build", c.typ)
				}
				var attempts int64
				got, err := runLayoutFast(context.Background(), l, 0, 4, &attempts, nil, algo, c.digest(plain))
				if err != nil {
					t.Fatalf("%s/%s: %v", c.typ, plain, err)
				}
				if got != plain {
					t.Errorf("%s: got %q, want %q", c.typ, got, plain)
				}
			}
		})
	}
}

// THE ASCII GUARD. utf16le is a UTF-8 decode, so a non-ASCII charset byte
// does NOT encode as b,0x00 — the scalar path would emit U+FFFD's bytes.
// NTLM must decline such a layout rather than compute a different digest
// than the rest of Hashsmith.
func TestNTLMFastPathRejectsNonASCIICharsets(t *testing.T) {
	if _, ok := fastAlgoFor("ntlm"); !ok {
		t.Skipf("ntlm has no fast-path descriptor on backend %q", vectorBackendName())
	}
	ascii := bruteLayout("abc", 2, 2)
	if _, ok := fastPathEligible("ntlm", "", ascii); !ok {
		t.Error("ntlm over an ASCII charset should be eligible")
	}
	high := bruteLayout(string([]byte{'a', 0xC3, 0xFF}), 2, 2)
	if _, ok := fastPathEligible("ntlm", "", high); ok {
		t.Error("ntlm over a charset with bytes >= 0x80 must NOT be eligible")
	}
	// md4 takes raw bytes, so the same charset is fine for it.
	if _, ok := fastPathEligible("md4", "", high); !ok {
		t.Error("md4 over a high-byte charset should still be eligible")
	}
}

// Proves the guard is not merely cosmetic: for a high-byte candidate the two
// encodings genuinely differ, which is why eligibility has to exclude them.
func TestUTF16LEDiffersFromNaiveExpansionOnHighBytes(t *testing.T) {
	s := string([]byte{0xC3})
	naive := []byte{0xC3, 0x00}
	if bytes.Equal(utf16le(s), naive) {
		t.Skip("utf16le matches naive expansion here; the ASCII guard may be unnecessary")
	}
	t.Logf("utf16le(%q) = %x, naive = %x — guard is load-bearing", s, utf16le(s), naive)
}

// NTLM's candidate ceiling is 27, not 55, because UTF-16LE doubles the message.
func TestNTLMFastPathLengthCeiling(t *testing.T) {
	if _, ok := fastAlgoFor("ntlm"); !ok {
		t.Skipf("ntlm has no fast-path descriptor on backend %q", vectorBackendName())
	}
	if _, ok := fastPathEligible("ntlm", "", bruteLayout("ab", 27, 27)); !ok {
		t.Error("ntlm at length 27 should be eligible")
	}
	if _, ok := fastPathEligible("ntlm", "", bruteLayout("ab", 28, 28)); ok {
		t.Error("ntlm at length 28 must not be eligible (2*28 > 55)")
	}
}

// Exactly one backend may be active, and eligibility must agree with it.
func TestVectorBackendSelection(t *testing.T) {
	b := vectorBackendName()
	switch b {
	case "neon", "avx2", "":
	default:
		t.Fatalf("unexpected backend %q", b)
	}
	l := bruteLayout("abc", 3, 3)
	algo, ok := fastPathEligible("md5", "", l)
	if b == "" && ok {
		t.Error("no backend, yet md5 was eligible")
	}
	if b != "" {
		if !ok {
			t.Fatal("a backend is active, yet md5 was not eligible")
		}
		if algo.shape.group() != algo.shape.chains*algo.shape.lanes {
			t.Errorf("shape %+v inconsistent", algo.shape)
		}
		switch b {
		case "neon":
			if algo.shape.lanes != 4 {
				t.Errorf("neon backend with %d lanes", algo.shape.lanes)
			}
		case "avx2":
			if algo.shape.lanes != 8 {
				t.Errorf("avx2 backend with %d lanes", algo.shape.lanes)
			}
		}
	}
}

// THE THING MOST LIKELY TO GO WRONG: MD4 and NTLM have no AVX2 core. If
// fastAlgoForBackend ever routed either to md5GroupAVX2 (e.g. a careless
// fallthrough, or "reuse the MD5 case for everything"), every candidate
// would hash to the wrong digest — MD4 is a different algorithm from MD5,
// and NTLM is MD4-over-UTF-16LE, not MD5-over-anything — and a real crack
// would silently come back "not found" with nothing else to signal the
// bug. This test is deliberately parameterised on the literal backend name
// rather than gated on vectorBackendName()/hasAVX2(), so it catches the
// mistake on every machine (including this arm64 dev box), not only one
// whose live CPU — or an emulated Docker container's CPU — happens to
// report AVX2 support.
func TestAVX2BackendExcludesMD4AndNTLM(t *testing.T) {
	for _, typ := range []string{"md4", "ntlm", "900", "1000"} {
		if algo, ok := fastAlgoForBackend("avx2", typ); ok {
			t.Errorf("%s must have no AVX2 fast-path descriptor (no AVX2 MD4 core exists); got %+v", typ, algo)
		}
	}
	// Confirm the switch itself works and isn't just an empty case list:
	// md5 must still resolve to the AVX2 descriptor.
	algo, ok := fastAlgoForBackend("avx2", "md5")
	if !ok {
		t.Fatal("md5 should have an AVX2 descriptor")
	}
	if algo.shape != avx2Shape {
		t.Errorf("md5 AVX2 descriptor shape = %+v, want %+v", algo.shape, avx2Shape)
	}
}

// TestAVX2BackendExcludesMD4AndNTLM drives fastAlgoForBackend with the literal
// string "avx2", which is deliberate — it makes the MD4/NTLM hazard testable on
// any machine. But it leaves a seam: if vectorBackendName() ever returned a
// label fastAlgoForBackend does not match (a typo like "AVX2", or a rename
// applied to one and not the other), the fast path would silently switch off on
// real hardware. That is not a wrong answer, so no correctness test would catch
// it — it would just quietly cost users the whole speedup.
//
// This ties the two together: whatever the live backend is, it must resolve.
func TestLiveBackendLabelResolves(t *testing.T) {
	backend := vectorBackendName()
	if backend == "" {
		t.Skip("no vector backend on this build; nothing to resolve")
	}
	algo, ok := fastAlgoForBackend(backend, "md5")
	if !ok {
		t.Fatalf("vectorBackendName() = %q, but fastAlgoForBackend(%q, \"md5\") "+
			"does not resolve — the label and the switch have diverged, and the "+
			"fast path is silently disabled", backend, backend)
	}
	if algo.shape.group() <= 0 {
		t.Errorf("backend %q resolved to an empty shape %+v", backend, algo.shape)
	}
	// And the shape must be the one that backend's core actually expects.
	switch backend {
	case "neon":
		if algo.shape != neonShape {
			t.Errorf("backend neon resolved to shape %+v, want %+v", algo.shape, neonShape)
		}
	case "avx2":
		if algo.shape != avx2Shape {
			t.Errorf("backend avx2 resolved to shape %+v, want %+v", algo.shape, avx2Shape)
		}
	}
}
