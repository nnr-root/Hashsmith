package smith

import (
	"bytes"
	"crypto/sha1"
	"encoding/base64"
	"testing"

	"golang.org/x/crypto/pbkdf2"
)

func pbkdf2Sha1Reference(password, salt []byte, iter, dkLen int) []byte {
	return pbkdf2.Key(password, salt, iter, dkLen, sha1.New)
}

func pbkdf2Sha1Target(salt []byte, iter int, want []byte) string {
	return "sha1:" + itoa(iter) + ":" + base64.StdEncoding.EncodeToString(salt) + ":" + base64.StdEncoding.EncodeToString(want)
}

// TestPBKDF2Sha1LaneHasherMatchesReference mirrors
// TestPBKDF2Sha256LaneHasherMatchesReference exactly, for SHA-1 (dkLen
// capped at 20, SHA-1's output size, instead of 32).
func TestPBKDF2Sha1LaneHasherMatchesReference(t *testing.T) {
	salts := [][]byte{
		[]byte(""),
		[]byte("s"),
		[]byte("normal-salt-16b."),
		bytes.Repeat([]byte{0x5a}, 27),
		bytes.Repeat([]byte{0x5a}, 55),
		bytes.Repeat([]byte{0x5a}, 100),
	}
	iters := []int{1, 2, 3, 1000}
	dkLens := []int{10, 16, 20}
	password := []byte("correct horse battery staple")

	for _, salt := range salts {
		for _, iter := range iters {
			for _, dkLen := range dkLens {
				want := pbkdf2Sha1Reference(password, salt, iter, dkLen)
				target := pbkdf2Sha1Target(salt, iter, want)
				h := newPBKDF2Sha1LaneHasher(target)
				if h == nil {
					t.Fatalf("salt=%dB iter=%d dkLen=%d: newPBKDF2Sha1LaneHasher refused a valid target", len(salt), iter, dkLen)
				}
				out := make([]bool, 1)
				h.Run([][]byte{password}, out)
				if !out[0] {
					t.Fatalf("salt=%dB iter=%d dkLen=%d: lane hasher did not match its own correct target", len(salt), iter, dkLen)
				}
				h.Run([][]byte{[]byte("wrong password")}, out)
				if out[0] {
					t.Fatalf("salt=%dB iter=%d dkLen=%d: lane hasher false-matched a wrong password", len(salt), iter, dkLen)
				}
			}
		}
	}
}

// TestPBKDF2Sha1LaneHasherBatchSizesStraddleLaneWidth mirrors the SHA-256
// version, widened to straddle 16 lanes rather than 8.
func TestPBKDF2Sha1LaneHasherBatchSizesStraddleLaneWidth(t *testing.T) {
	salt := []byte("batch-test-salt")
	iter := 5
	candidates := []string{
		"password", "wrong", "", "a", "12345678", "123456789",
		"passwore", "passwor", "correct", "PASSWORD", "password1",
		"p1", "p2", "p3", "p4", "p5", "p6",
	}
	right := "the-right-password"
	candidates = append(candidates, right)
	want := pbkdf2Sha1Reference([]byte(right), salt, iter, 20)
	target := pbkdf2Sha1Target(salt, iter, want)

	for n := 1; n <= len(candidates); n++ {
		n := n
		t.Run(itoa(n), func(t *testing.T) {
			h := newPBKDF2Sha1LaneHasher(target)
			if h == nil {
				t.Fatal("newPBKDF2Sha1LaneHasher refused a valid target")
			}
			pw := make([][]byte, n)
			for i := 0; i < n; i++ {
				pw[i] = []byte(candidates[i])
			}
			out := make([]bool, n)
			h.Run(pw, out)
			for i := 0; i < n; i++ {
				want := candidates[i] == right
				if out[i] != want {
					t.Errorf("batch of %d, candidate %q (position %d): got %v, want %v",
						n, candidates[i], i, out[i], want)
				}
			}
		})
	}
}

// TestPBKDF2Sha1LaneHasherIsStateless mirrors
// TestPBKDF2Sha256LaneHasherIsStateless.
func TestPBKDF2Sha1LaneHasherIsStateless(t *testing.T) {
	salt := []byte("stateless-test-salt")
	iter := 3
	right := "the-actual-password"
	want := pbkdf2Sha1Reference([]byte(right), salt, iter, 20)
	target := pbkdf2Sha1Target(salt, iter, want)
	h := newPBKDF2Sha1LaneHasher(target)
	if h == nil {
		t.Fatal("newPBKDF2Sha1LaneHasher refused a valid target")
	}

	full := make([][]byte, pbkdf2Sha1Lanes)
	for i := range full {
		full[i] = []byte(right)
	}
	fullOut := make([]bool, pbkdf2Sha1Lanes)
	h.Run(full, fullOut)
	for i, ok := range fullOut {
		if !ok {
			t.Fatalf("full group lane %d: expected a match, got none", i)
		}
	}

	shortWrong := [][]byte{[]byte("nope"), []byte("still nope")}
	shortOut := make([]bool, len(shortWrong))
	h.Run(shortWrong, shortOut)
	for i, ok := range shortOut {
		if ok {
			t.Fatalf("short batch lane %d: false match after a prior full-group hit — stale state leaked", i)
		}
	}
}

func TestNewPBKDF2Sha1LaneHasherRefusesNonSHA1(t *testing.T) {
	salt := base64.StdEncoding.EncodeToString([]byte("salt"))
	cases := []string{
		"md5:1000:" + salt + ":" + base64.StdEncoding.EncodeToString(make([]byte, 16)),
		"sha256:1000:" + salt + ":" + base64.StdEncoding.EncodeToString(make([]byte, 32)),
		"sha1:1000:" + salt + ":" + base64.StdEncoding.EncodeToString(make([]byte, 21)), // over 20 bytes
		"not:a:valid",
		"sha1:0:" + salt + ":" + base64.StdEncoding.EncodeToString(make([]byte, 20)),
	}
	for _, c := range cases {
		if h := newPBKDF2Sha1LaneHasher(c); h != nil {
			t.Errorf("newPBKDF2Sha1LaneHasher(%q) should have been refused", c)
		}
	}
}

// TestNewLaneHasherPBKDF2GateHandlesBothAlgorithms checks that
// newLaneHasher("pbkdf2", ...) tries sha256 and sha1 records correctly and
// exclusively — a sha1 record must never be handled by the sha256 hasher
// or vice versa, since a hasher that appeared to "succeed" on the wrong
// algorithm's record would compute silently wrong digests.
func TestNewLaneHasherPBKDF2GateHandlesBothAlgorithms(t *testing.T) {
	salt := []byte("both-algos-salt")
	sha256Want := pbkdf2Sha256Reference([]byte("pw"), salt, 4, 32)
	sha1Want := pbkdf2Sha1Reference([]byte("pw"), salt, 4, 20)
	sha256Target := pbkdf2Sha256Target(salt, 4, sha256Want)
	sha1Target := pbkdf2Sha1Target(salt, 4, sha1Want)

	if newPBKDF2Sha1LaneHasher(sha256Target) != nil {
		t.Error("newPBKDF2Sha1LaneHasher must refuse a sha256 record")
	}
	if newPBKDF2Sha256LaneHasher(sha1Target) != nil {
		t.Error("newPBKDF2Sha256LaneHasher must refuse a sha1 record")
	}
}

// TestNewLaneHasherPBKDF2GateIsInternallyConsistentForSha1 mirrors
// TestNewLaneHasherPBKDF2GateIsInternallyConsistent (pbkdf2_lane_sha256_test.go)
// for a sha1 record: newLaneHasher must report eligible if and only if
// pbkdf2Sha1AVX2Eligible() says so, since a sha1-named target never reaches
// the sha256 branch in lanes.go's dispatch.
func TestNewLaneHasherPBKDF2GateIsInternallyConsistentForSha1(t *testing.T) {
	salt := []byte("sha1-gate-test-salt")
	want := pbkdf2Sha1Reference([]byte("gate-test-pw"), salt, 4, 20)
	target := pbkdf2Sha1Target(salt, 4, want)

	factory, lanes, ok := newLaneHasher("pbkdf2", target, "", "")
	wantOK := pbkdf2Sha1AVX2Eligible()
	if ok != wantOK {
		t.Fatalf("newLaneHasher(\"pbkdf2\", <sha1 target>) eligible=%v, want %v (pbkdf2Sha1AVX2Eligible)", ok, wantOK)
	}
	if !ok {
		t.Skip("not eligible on this hardware/build — nothing further to check")
	}
	if lanes != pbkdf2Sha1Lanes {
		t.Fatalf("newLaneHasher(\"pbkdf2\", <sha1 target>) lanes = %d, want %d", lanes, pbkdf2Sha1Lanes)
	}
	h := factory()
	if h == nil {
		t.Fatal("newLaneHasher(\"pbkdf2\", <sha1 target>) factory returned nil despite reporting eligible")
	}
	out := make([]bool, 1)
	h.Run([][]byte{[]byte("gate-test-pw")}, out)
	if !out[0] {
		t.Fatal("the wired-up sha1 hasher did not match its own correct target")
	}
}
