package smith

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"strconv"
	"testing"

	"golang.org/x/crypto/pbkdf2"
)

// pbkdf2Sha256Reference computes PBKDF2-HMAC-SHA256 via this project's own
// existing dependency (the same one verifyPBKDF2 calls in production) — the
// independent oracle every case here is checked against.
func pbkdf2Sha256Reference(password, salt []byte, iter, dkLen int) []byte {
	return pbkdf2.Key(password, salt, iter, dkLen, sha256.New)
}

func pbkdf2Sha256Target(salt []byte, iter int, want []byte) string {
	return "sha256:" + strconv.Itoa(iter) + ":" + base64.StdEncoding.EncodeToString(salt) + ":" + base64.StdEncoding.EncodeToString(want)
}

// TestPBKDF2Sha256LaneHasherMatchesReference is the backbone differential
// test: varied salt lengths spanning U1's one-block/multi-block boundary
// (a salt of 27 bytes makes salt||INT(1) exactly 31 bytes — still one
// block; 28+ pushes toward it, and this project's own maxKDFFieldSize
// allows salts far longer, so a 100-byte salt exercises the genuinely
// multi-block U1 path), varied iteration counts (1, 2, 3 — the smallest
// counts that exercise "no hot loop at all," "exactly one hot-loop
// iteration," and "two" — plus a realistic four-digit count), and dkLen
// both at and under the 32-byte ceiling.
func TestPBKDF2Sha256LaneHasherMatchesReference(t *testing.T) {
	salts := [][]byte{
		[]byte(""),
		[]byte("s"),
		[]byte("normal-salt-16b."),
		bytes.Repeat([]byte{0x5a}, 27),
		bytes.Repeat([]byte{0x5a}, 55),  // the largest salt for which salt||INT(1) (59 bytes) still needs only one U1 block... actually 55+4=59, still <64, one block
		bytes.Repeat([]byte{0x5a}, 100), // forces U1 across two blocks
	}
	iters := []int{1, 2, 3, 1000}
	dkLens := []int{16, 20, 32}
	password := []byte("correct horse battery staple")

	for _, salt := range salts {
		for _, iter := range iters {
			for _, dkLen := range dkLens {
				want := pbkdf2Sha256Reference(password, salt, iter, dkLen)
				target := pbkdf2Sha256Target(salt, iter, want)
				h := newPBKDF2Sha256LaneHasher(target)
				if h == nil {
					t.Fatalf("salt=%dB iter=%d dkLen=%d: newPBKDF2Sha256LaneHasher refused a valid target", len(salt), iter, dkLen)
				}
				out := make([]bool, 1)
				h.Run([][]byte{password}, out)
				if !out[0] {
					t.Fatalf("salt=%dB iter=%d dkLen=%d: lane hasher did not match its own correct target", len(salt), iter, dkLen)
				}
				// A wrong password must not match.
				h.Run([][]byte{[]byte("wrong password")}, out)
				if out[0] {
					t.Fatalf("salt=%dB iter=%d dkLen=%d: lane hasher false-matched a wrong password", len(salt), iter, dkLen)
				}
			}
		}
	}
}

// TestPBKDF2Sha256LaneHasherBatchSizesStraddleLaneWidth is
// TestDescryptLaneHasherMatchesVerify's pattern applied here: candidates at
// every batch size from 1 through one more than the lane width, since a
// partial group is where a laned implementation goes wrong, and this one
// batches 8 passwords per AVX2 call.
func TestPBKDF2Sha256LaneHasherBatchSizesStraddleLaneWidth(t *testing.T) {
	salt := []byte("batch-test-salt")
	iter := 5
	candidates := []string{
		"password", "wrong", "", "a", "12345678", "123456789",
		"passwore", "passwor", "correct", "PASSWORD", "password1",
	}
	// The right password is planted at the LAST position so every batch
	// size from 1 to len(candidates) includes at least one run where it
	// falls in a different lane position, including the final partial
	// group's own last slot.
	right := "the-right-password"
	candidates = append(candidates, right)
	want := pbkdf2Sha256Reference([]byte(right), salt, iter, 32)
	target := pbkdf2Sha256Target(salt, iter, want)

	for n := 1; n <= len(candidates); n++ {
		n := n
		t.Run(itoa(n), func(t *testing.T) {
			h := newPBKDF2Sha256LaneHasher(target)
			if h == nil {
				t.Fatal("newPBKDF2Sha256LaneHasher refused a valid target")
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

// TestPBKDF2Sha256LaneHasherIsStateless matches
// TestDescryptLaneHasherIsStateless: a full group containing the right
// password, then a shorter batch, must not let a lane's leftover key
// schedule or running T from the previous call leak into the new one and
// report a false hit — the specific failure mode this project's own
// laneHasher contract (lanes.go) exists to prevent.
func TestPBKDF2Sha256LaneHasherIsStateless(t *testing.T) {
	salt := []byte("stateless-test-salt")
	iter := 3
	right := "the-actual-password"
	want := pbkdf2Sha256Reference([]byte(right), salt, iter, 32)
	target := pbkdf2Sha256Target(salt, iter, want)
	h := newPBKDF2Sha256LaneHasher(target)
	if h == nil {
		t.Fatal("newPBKDF2Sha256LaneHasher refused a valid target")
	}

	full := make([][]byte, pbkdf2Sha256Lanes)
	for i := range full {
		full[i] = []byte(right)
	}
	fullOut := make([]bool, pbkdf2Sha256Lanes)
	h.Run(full, fullOut)
	for i, ok := range fullOut {
		if !ok {
			t.Fatalf("full group lane %d: expected a match, got none", i)
		}
	}

	// A short batch of wrong candidates run on the SAME hasher afterward
	// must report no matches, even in lane positions the full group above
	// just reported true for.
	shortWrong := [][]byte{[]byte("nope"), []byte("still nope")}
	shortOut := make([]bool, len(shortWrong))
	h.Run(shortWrong, shortOut)
	for i, ok := range shortOut {
		if ok {
			t.Fatalf("short batch lane %d: false match after a prior full-group hit — stale state leaked", i)
		}
	}
}

// TestNewPBKDF2Sha256LaneHasherRefusesNonSHA256 checks the algo gate: any
// spelling of a non-sha256 algorithm, or a dkLen over 32 bytes (v1's
// explicit multi-block-T non-goal), must be refused so the caller falls
// back to the scalar path rather than silently computing the wrong thing.
func TestNewPBKDF2Sha256LaneHasherRefusesNonSHA256(t *testing.T) {
	salt := base64.StdEncoding.EncodeToString([]byte("salt"))
	cases := []string{
		"md5:1000:" + salt + ":" + base64.StdEncoding.EncodeToString(make([]byte, 16)),
		"sha1:1000:" + salt + ":" + base64.StdEncoding.EncodeToString(make([]byte, 20)),
		"sha512:1000:" + salt + ":" + base64.StdEncoding.EncodeToString(make([]byte, 32)),
		"sha256:1000:" + salt + ":" + base64.StdEncoding.EncodeToString(make([]byte, 33)), // over 32 bytes
		"not:a:valid",
		"sha256:0:" + salt + ":" + base64.StdEncoding.EncodeToString(make([]byte, 32)), // iter must be >= 1
	}
	for _, c := range cases {
		if h := newPBKDF2Sha256LaneHasher(c); h != nil {
			t.Errorf("newPBKDF2Sha256LaneHasher(%q) should have been refused", c)
		}
	}
}

// TestNewLaneHasherPBKDF2GateIsInternallyConsistent checks the wiring in
// lanes.go's newLaneHasher, not the underlying hasher: it must report
// eligible if and only if pbkdf2Sha256AVX2Eligible() says the hardware
// qualifies AND the target itself is a valid plain-sha256 record. This is
// written to hold on any machine (Apple Silicon, non-SHA-NI amd64 under
// Docker, or SHA-NI-equipped amd64 alike) rather than asserting a fixed
// true/false, since the real eligibility genuinely varies by hardware —
// see the design doc's §4.4 for why that variance is the whole point.
func TestNewLaneHasherPBKDF2GateIsInternallyConsistent(t *testing.T) {
	salt := []byte("gate-test-salt")
	want := pbkdf2Sha256Reference([]byte("gate-test-pw"), salt, 4, 32)
	target := pbkdf2Sha256Target(salt, 4, want)

	factory, lanes, ok := newLaneHasher("pbkdf2", target, "", "")
	wantOK := pbkdf2Sha256AVX2Eligible()
	if ok != wantOK {
		t.Fatalf("newLaneHasher(\"pbkdf2\", ...) eligible=%v, want %v (pbkdf2Sha256AVX2Eligible)", ok, wantOK)
	}
	if !ok {
		t.Skip("not eligible on this hardware/build — nothing further to check")
	}
	if lanes != pbkdf2Sha256Lanes {
		t.Fatalf("newLaneHasher(\"pbkdf2\", ...) lanes = %d, want %d", lanes, pbkdf2Sha256Lanes)
	}
	h := factory()
	if h == nil {
		t.Fatal("newLaneHasher(\"pbkdf2\", ...) factory returned nil despite reporting eligible")
	}
	out := make([]bool, 1)
	h.Run([][]byte{[]byte("gate-test-pw")}, out)
	if !out[0] {
		t.Fatal("the wired-up hasher did not match its own correct target")
	}

	// A non-empty salt argument (the generic -s/-S flag, distinct from the
	// record's own embedded salt) must always be refused, on any hardware.
	if _, _, ok := newLaneHasher("pbkdf2", target, "extra-salt", "suffix"); ok {
		t.Fatal("newLaneHasher(\"pbkdf2\", ...) must refuse a non-empty generic salt")
	}

	// An MD5 record must never engage this core, regardless of hardware.
	md5Target := "md5:1000:" + base64.StdEncoding.EncodeToString(salt) + ":" + base64.StdEncoding.EncodeToString(want[:16])
	if _, _, ok := newLaneHasher("pbkdf2", md5Target, "", ""); ok {
		t.Fatal("newLaneHasher(\"pbkdf2\", ...) must refuse a non-sha256 record even when hardware is eligible")
	}
}

// TestNewPBKDF2Sha256LaneHasherAcceptsHyphenatedSpelling matches
// pbkdf2HashFactory's own normalization ("SHA-256" and "sha256" are the
// same algorithm), so this core engages for every spelling verifyPBKDF2
// itself accepts.
func TestNewPBKDF2Sha256LaneHasherAcceptsHyphenatedSpelling(t *testing.T) {
	salt := []byte("s")
	want := pbkdf2Sha256Reference([]byte("pw"), salt, 2, 32)
	target := "SHA-256:2:" + base64.StdEncoding.EncodeToString(salt) + ":" + base64.StdEncoding.EncodeToString(want)
	if h := newPBKDF2Sha256LaneHasher(target); h == nil {
		t.Error("newPBKDF2Sha256LaneHasher should accept the hyphenated/uppercase SHA-256 spelling")
	}
}
