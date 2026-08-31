package main

import (
	"context"
	"crypto/md5"
	"testing"
)

// The fast path must find exactly what the scalar path finds — same candidate,
// same keyspace, including when the keyspace is not a multiple of the 20-wide
// group and when the answer sits in the final partial group.
func TestFastPathAgreesWithScalar(t *testing.T) {
	algo, ok := fastAlgoFor("md5")
	if !ok {
		t.Fatal("md5 fast algo not registered")
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
		t.Fatal("md5 fast algo not registered")
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
		t.Fatal("md5 fast algo not registered")
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
	if _, ok := fastPathEligible("md5", "", l); !ok && md5GroupAccelerated() {
		t.Error("plain md5 fixed-length brute should be eligible on an accelerated build")
	}
	if _, ok := fastPathEligible("md5", "somesalt", l); ok {
		t.Error("salted md5 must not be eligible")
	}
	if _, ok := fastPathEligible("sha256", "", l); ok {
		t.Error("sha256 must not be eligible — there is no sha256 vector core")
	}
}
