package smith

import (
	"bytes"
	"crypto/sha512"
	"encoding/base64"
	"testing"

	"golang.org/x/crypto/pbkdf2"
)

func pbkdf2Sha512Reference(password, salt []byte, iter, dkLen int) []byte {
	return pbkdf2.Key(password, salt, iter, dkLen, sha512.New)
}

func pbkdf2Sha512Target(salt []byte, iter int, want []byte) string {
	return "sha512:" + itoa(iter) + ":" + base64.StdEncoding.EncodeToString(salt) + ":" + base64.StdEncoding.EncodeToString(want)
}

// TestPBKDF2Sha512LaneHasherMatchesReference mirrors
// TestPBKDF2Sha256LaneHasherMatchesReference, with salts spanning
// SHA-512's own (128-byte block) U1 one-block/multi-block boundary and
// dkLen capped at 64.
func TestPBKDF2Sha512LaneHasherMatchesReference(t *testing.T) {
	salts := [][]byte{
		[]byte(""),
		[]byte("s"),
		[]byte("normal-salt-16b."),
		bytes.Repeat([]byte{0x5a}, 55),
		bytes.Repeat([]byte{0x5a}, 107), // salt||INT(1) = 111 bytes, the largest that still fits one U1 block
		bytes.Repeat([]byte{0x5a}, 200), // forces U1 across two blocks
	}
	iters := []int{1, 2, 3, 1000}
	dkLens := []int{20, 32, 64}
	password := []byte("correct horse battery staple")

	for _, salt := range salts {
		for _, iter := range iters {
			for _, dkLen := range dkLens {
				want := pbkdf2Sha512Reference(password, salt, iter, dkLen)
				target := pbkdf2Sha512Target(salt, iter, want)
				h := newPBKDF2Sha512LaneHasher(target)
				if h == nil {
					t.Fatalf("salt=%dB iter=%d dkLen=%d: newPBKDF2Sha512LaneHasher refused a valid target", len(salt), iter, dkLen)
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

// TestPBKDF2Sha512LaneHasherBatchSizesStraddleLaneWidth mirrors the
// SHA-256/SHA-1 versions, straddling the 4-lane width.
func TestPBKDF2Sha512LaneHasherBatchSizesStraddleLaneWidth(t *testing.T) {
	salt := []byte("batch-test-salt")
	iter := 5
	candidates := []string{"password", "wrong", "", "a"}
	right := "the-right-password"
	candidates = append(candidates, right)
	want := pbkdf2Sha512Reference([]byte(right), salt, iter, 64)
	target := pbkdf2Sha512Target(salt, iter, want)

	for n := 1; n <= len(candidates); n++ {
		n := n
		t.Run(itoa(n), func(t *testing.T) {
			h := newPBKDF2Sha512LaneHasher(target)
			if h == nil {
				t.Fatal("newPBKDF2Sha512LaneHasher refused a valid target")
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

// TestPBKDF2Sha512LaneHasherIsStateless mirrors the SHA-256/SHA-1 versions.
func TestPBKDF2Sha512LaneHasherIsStateless(t *testing.T) {
	salt := []byte("stateless-test-salt")
	iter := 3
	right := "the-actual-password"
	want := pbkdf2Sha512Reference([]byte(right), salt, iter, 64)
	target := pbkdf2Sha512Target(salt, iter, want)
	h := newPBKDF2Sha512LaneHasher(target)
	if h == nil {
		t.Fatal("newPBKDF2Sha512LaneHasher refused a valid target")
	}

	full := make([][]byte, pbkdf2Sha512Lanes)
	for i := range full {
		full[i] = []byte(right)
	}
	fullOut := make([]bool, pbkdf2Sha512Lanes)
	h.Run(full, fullOut)
	for i, ok := range fullOut {
		if !ok {
			t.Fatalf("full group lane %d: expected a match, got none", i)
		}
	}

	shortWrong := [][]byte{[]byte("nope")}
	shortOut := make([]bool, len(shortWrong))
	h.Run(shortWrong, shortOut)
	for i, ok := range shortOut {
		if ok {
			t.Fatalf("short batch lane %d: false match after a prior full-group hit — stale state leaked", i)
		}
	}
}

func TestNewPBKDF2Sha512LaneHasherRefusesNonSHA512(t *testing.T) {
	salt := base64.StdEncoding.EncodeToString([]byte("salt"))
	cases := []string{
		"md5:1000:" + salt + ":" + base64.StdEncoding.EncodeToString(make([]byte, 16)),
		"sha256:1000:" + salt + ":" + base64.StdEncoding.EncodeToString(make([]byte, 32)),
		"sha1:1000:" + salt + ":" + base64.StdEncoding.EncodeToString(make([]byte, 20)),
		"sha512:1000:" + salt + ":" + base64.StdEncoding.EncodeToString(make([]byte, 65)), // over 64 bytes
		"not:a:valid",
		"sha512:0:" + salt + ":" + base64.StdEncoding.EncodeToString(make([]byte, 64)),
	}
	for _, c := range cases {
		if h := newPBKDF2Sha512LaneHasher(c); h != nil {
			t.Errorf("newPBKDF2Sha512LaneHasher(%q) should have been refused", c)
		}
	}
}

// TestNewLaneHasherPBKDF2GateHandlesAllThreeAlgorithms extends
// TestNewLaneHasherPBKDF2GateHandlesBothAlgorithms to all three: a record
// naming any one of sha256/sha1/sha512 must be handled by exactly its own
// hasher and refused by both of the others.
func TestNewLaneHasherPBKDF2GateHandlesAllThreeAlgorithms(t *testing.T) {
	salt := []byte("three-algos-salt")
	sha256Target := pbkdf2Sha256Target(salt, 4, pbkdf2Sha256Reference([]byte("pw"), salt, 4, 32))
	sha1Target := pbkdf2Sha1Target(salt, 4, pbkdf2Sha1Reference([]byte("pw"), salt, 4, 20))
	sha512Target := pbkdf2Sha512Target(salt, 4, pbkdf2Sha512Reference([]byte("pw"), salt, 4, 64))

	if newPBKDF2Sha512LaneHasher(sha256Target) != nil {
		t.Error("newPBKDF2Sha512LaneHasher must refuse a sha256 record")
	}
	if newPBKDF2Sha512LaneHasher(sha1Target) != nil {
		t.Error("newPBKDF2Sha512LaneHasher must refuse a sha1 record")
	}
	if newPBKDF2Sha256LaneHasher(sha512Target) != nil {
		t.Error("newPBKDF2Sha256LaneHasher must refuse a sha512 record")
	}
	if newPBKDF2Sha1LaneHasher(sha512Target) != nil {
		t.Error("newPBKDF2Sha1LaneHasher must refuse a sha512 record")
	}
}

// TestNewLaneHasherPBKDF2GateIsInternallyConsistentForSha512 mirrors the
// sha256/sha1 versions.
func TestNewLaneHasherPBKDF2GateIsInternallyConsistentForSha512(t *testing.T) {
	salt := []byte("sha512-gate-test-salt")
	want := pbkdf2Sha512Reference([]byte("gate-test-pw"), salt, 4, 64)
	target := pbkdf2Sha512Target(salt, 4, want)

	factory, lanes, ok := newLaneHasher("pbkdf2", target, "", "")
	wantOK := pbkdf2Sha512AVX2Eligible()
	if ok != wantOK {
		t.Fatalf("newLaneHasher(\"pbkdf2\", <sha512 target>) eligible=%v, want %v (pbkdf2Sha512AVX2Eligible)", ok, wantOK)
	}
	if !ok {
		t.Skip("not eligible on this hardware/build — nothing further to check")
	}
	if lanes != pbkdf2Sha512Lanes {
		t.Fatalf("newLaneHasher(\"pbkdf2\", <sha512 target>) lanes = %d, want %d", lanes, pbkdf2Sha512Lanes)
	}
	h := factory()
	if h == nil {
		t.Fatal("newLaneHasher(\"pbkdf2\", <sha512 target>) factory returned nil despite reporting eligible")
	}
	out := make([]bool, 1)
	h.Run([][]byte{[]byte("gate-test-pw")}, out)
	if !out[0] {
		t.Fatal("the wired-up sha512 hasher did not match its own correct target")
	}
}
