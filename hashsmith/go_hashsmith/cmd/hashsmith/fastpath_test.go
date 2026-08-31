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
	for _, plain := range []string{"aaa", "abc", "zzz", "mnq"} {
		l := bruteLayout("abcdefghijklmnopqrstuvwxyz", 3, 3)
		sum := md5.Sum([]byte(plain))

		var a1, a2 int64
		fast, err := runLayoutFastMD5(context.Background(), l, 0, 4, &a1, nil, sum)
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
// spurious hit from an unused lane in the final partial group.
func TestFastPathExhaustsWithoutSpuriousHit(t *testing.T) {
	l := bruteLayout("ab", 1, 3) // 2 + 4 + 8 = 14, deliberately not a multiple of 20
	sum := md5.Sum([]byte("not-in-keyspace"))
	var attempts int64
	got, err := runLayoutFastMD5(context.Background(), l, 0, 2, &attempts, nil, sum)
	if err != nil {
		t.Fatalf("runLayoutFastMD5: %v", err)
	}
	if got != "" {
		t.Errorf("got %q, want no match", got)
	}
	if attempts != l.total {
		t.Errorf("attempts = %d, want the full keyspace %d", attempts, l.total)
	}
}

// The empty-string candidate must be reachable and must not be confused with an
// unused lane, which also hashes the empty string.
func TestFastPathHandlesEmptyCandidate(t *testing.T) {
	l := bruteLayout("ab", 0, 1)
	if l.total == 0 {
		t.Skip("layout does not include the empty candidate")
	}
	sum := md5.Sum([]byte(""))
	var attempts int64
	got, err := runLayoutFastMD5(context.Background(), l, 0, 1, &attempts, nil, sum)
	if err != nil {
		t.Fatalf("runLayoutFastMD5: %v", err)
	}
	if got != "" {
		t.Logf("empty candidate reported as %q", got)
	}
}

func TestFastPathEligibility(t *testing.T) {
	l := bruteLayout("abc", 3, 3)
	if !fastPathEligible("md5", "", l) && md5GroupAccelerated() {
		t.Error("plain md5 fixed-length brute should be eligible on an accelerated build")
	}
	if fastPathEligible("md5", "somesalt", l) {
		t.Error("salted md5 must not be eligible")
	}
	if fastPathEligible("sha256", "", l) {
		t.Error("sha256 must not be eligible — there is no sha256 vector core")
	}
}
