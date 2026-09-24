package smith

import (
	"bytes"
	"crypto/sha256"
	"testing"

	"golang.org/x/crypto/pbkdf2"
)

// ansibleHashcatVector mirrors selftest_vectors.go's own published vector,
// passphrase "hashcat".
const ansibleHashcatVector = "$ansible$0*0*6b761adc6faeb0cc0bf197d3d4a4a7d3f1682e4b169cae8fa6b459b3214ed41e*426d313c5809d4a80a4b9bc7d4823070*d8bad190c7fbc7c3cb1c60a27abfb0ff59d6fb73178681c7454d94a0f56a4360"

func TestPBKDF2AnsibleLaneHasherMatchesHashcatVector(t *testing.T) {
	h := newPBKDF2AnsibleLaneHasher(ansibleHashcatVector)
	if h == nil {
		t.Fatal("newPBKDF2AnsibleLaneHasher refused hashcat's own published record")
	}
	out := make([]bool, 1)
	h.Run([][]byte{[]byte("hashcat")}, out)
	if !out[0] {
		t.Fatal("lane hasher did not match hashcat's own published record with the correct password")
	}
	h.Run([][]byte{[]byte("wrong")}, out)
	if out[0] {
		t.Fatal("lane hasher false-matched a wrong password against hashcat's own record")
	}
}

func TestPBKDF2AnsibleLaneHasherMatchesScalarAcrossBatchSizes(t *testing.T) {
	right := "the-right-password"
	candidates := []string{
		"wrong1", "wrong2", "", "a", "12345678", "wrong3",
		"wrong4", "wrong5", right,
	}
	h := newPBKDF2AnsibleLaneHasher(ansibleHashcatVector)
	if h == nil {
		t.Fatal("newPBKDF2AnsibleLaneHasher refused hashcat's own published record")
	}

	for n := 1; n <= len(candidates); n++ {
		n := n
		t.Run(itoa(n), func(t *testing.T) {
			pw := make([][]byte, n)
			for i := 0; i < n; i++ {
				pw[i] = []byte(candidates[i])
			}
			out := make([]bool, n)
			h.Run(pw, out)
			for i := 0; i < n; i++ {
				want, err := verifyAnsible(ansibleHashcatVector, candidates[i])
				if err != nil {
					t.Fatalf("verifyAnsible(%q): %v", candidates[i], err)
				}
				if out[i] != want {
					t.Errorf("batch of %d, candidate %q (position %d): lane hasher = %v, scalar = %v",
						n, candidates[i], i, out[i], want)
				}
			}
		})
	}
}

func TestPBKDF2AnsibleLaneHasherIsStateless(t *testing.T) {
	right := "hashcat"
	h := newPBKDF2AnsibleLaneHasher(ansibleHashcatVector)
	if h == nil {
		t.Fatal("newPBKDF2AnsibleLaneHasher refused hashcat's own published record")
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

	shortWrong := [][]byte{[]byte("nope"), []byte("still nope")}
	shortOut := make([]bool, len(shortWrong))
	h.Run(shortWrong, shortOut)
	for i, ok := range shortOut {
		if ok {
			t.Fatalf("short batch lane %d: false match after a prior full-group hit — stale state leaked", i)
		}
	}
}

func TestNewPBKDF2AnsibleLaneHasherRefusesMalformedRecords(t *testing.T) {
	cases := []string{
		"",
		"not a record",
		"$ansible$0*0*00112233",
	}
	for _, c := range cases {
		if h := newPBKDF2AnsibleLaneHasher(c); h != nil {
			t.Errorf("newPBKDF2AnsibleLaneHasher(%q) should have been refused", c)
		}
	}
}

func TestNewLaneHasherAnsibleGateIsInternallyConsistent(t *testing.T) {
	factory, lanes, ok := newLaneHasher("ansible", ansibleHashcatVector, "", "")
	wantOK := pbkdf2Sha256AVX2Eligible()
	if ok != wantOK {
		t.Fatalf("newLaneHasher(\"ansible\", ...) eligible=%v, want %v (pbkdf2Sha256AVX2Eligible)", ok, wantOK)
	}
	if !ok {
		t.Skip("not eligible on this hardware/build — nothing further to check")
	}
	if lanes != pbkdf2Sha256Lanes {
		t.Fatalf("newLaneHasher(\"ansible\", ...) lanes = %d, want %d", lanes, pbkdf2Sha256Lanes)
	}
	h := factory()
	if h == nil {
		t.Fatal("newLaneHasher(\"ansible\", ...) factory returned nil despite reporting eligible")
	}
	out := make([]bool, 1)
	h.Run([][]byte{[]byte("hashcat")}, out)
	if !out[0] {
		t.Fatal("the wired-up hasher did not match hashcat's own published record")
	}
}

// TestPBKDF2HMACSHA256DeriveBatchNMatchesReferenceAcrossBlockCounts checks
// the new multi-block primitive directly against golang.org/x/crypto/pbkdf2
// for a range of dkLen values straddling one, two and three SHA-256 blocks
// (32, 33, 64, 65, 80, 96 bytes), independent of any format that happens to
// use it.
func TestPBKDF2HMACSHA256DeriveBatchNMatchesReferenceAcrossBlockCounts(t *testing.T) {
	salt := []byte("some-shared-salt")
	iter := 37
	passwords := [pbkdf2Sha256Lanes]string{
		"", "a", "password", "correct horse battery staple",
		"12345678", "hashsmith", "the-right-password", "unicode-éè",
	}
	for _, dkLen := range []int{32, 33, 64, 65, 80, 96} {
		dkLen := dkLen
		t.Run(itoa(dkLen), func(t *testing.T) {
			var lanes [pbkdf2Sha256Lanes][]byte
			for i, pw := range passwords {
				lanes[i] = []byte(pw)
			}
			got := pbkdf2HMACSHA256DeriveBatchN(&lanes, salt, iter, dkLen)
			for i, pw := range passwords {
				want := pbkdf2.Key([]byte(pw), salt, iter, dkLen, sha256.New)
				if !bytes.Equal(got[i], want) {
					t.Errorf("lane %d (password %q): got %x, want %x", i, pw, got[i], want)
				}
				if len(got[i]) != dkLen {
					t.Errorf("lane %d: len(got) = %d, want %d", i, len(got[i]), dkLen)
				}
			}
		})
	}
}
