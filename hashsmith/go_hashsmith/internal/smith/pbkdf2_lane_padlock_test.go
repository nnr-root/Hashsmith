package smith

import "testing"

// padlockHashcatVector mirrors selftest_vectors.go's own cross-checked
// vector, passphrase "openwall".
const padlockHashcatVector = "$padlock$1$10000$64$16$bc5ce69b9b9dadafb4566f570cccd15d$6c0f57ec2a0a98974c567cc25a12fff1$16$226683e36d47dc8a3bf7c49fedfdae88$10$07ccbca4012cfa37997d"

func TestPBKDF2PadlockLaneHasherMatchesCrosscheckedVector(t *testing.T) {
	h := newPBKDF2PadlockLaneHasher(padlockHashcatVector)
	if h == nil {
		t.Fatal("newPBKDF2PadlockLaneHasher refused the cross-checked published record")
	}
	out := make([]bool, 1)
	h.Run([][]byte{[]byte("openwall")}, out)
	if !out[0] {
		t.Fatal("lane hasher did not match the cross-checked record with the correct password")
	}
	h.Run([][]byte{[]byte("wrong")}, out)
	if out[0] {
		t.Fatal("lane hasher false-matched a wrong password against the cross-checked record")
	}
}

func TestPBKDF2PadlockLaneHasherMatchesScalarAcrossBatchSizes(t *testing.T) {
	right := "the-right-password"
	candidates := []string{
		"wrong1", "wrong2", "", "a", "12345678", "wrong3",
		"wrong4", "wrong5", right,
	}
	h := newPBKDF2PadlockLaneHasher(padlockHashcatVector)
	if h == nil {
		t.Fatal("newPBKDF2PadlockLaneHasher refused the cross-checked published record")
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
				want, err := verifyPadlock(padlockHashcatVector, candidates[i])
				if err != nil {
					t.Fatalf("verifyPadlock(%q): %v", candidates[i], err)
				}
				if out[i] != want {
					t.Errorf("batch of %d, candidate %q (position %d): lane hasher = %v, scalar = %v",
						n, candidates[i], i, out[i], want)
				}
			}
		})
	}
}

func TestPBKDF2PadlockLaneHasherIsStateless(t *testing.T) {
	right := "openwall"
	h := newPBKDF2PadlockLaneHasher(padlockHashcatVector)
	if h == nil {
		t.Fatal("newPBKDF2PadlockLaneHasher refused the cross-checked published record")
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

func TestNewPBKDF2PadlockLaneHasherRefusesMalformedRecords(t *testing.T) {
	cases := []string{
		"",
		"not a record",
		"$padlock$1$too$few",
		"$notpadlock$" + padlockHashcatVector[len("$padlock$"):],
	}
	for _, c := range cases {
		if h := newPBKDF2PadlockLaneHasher(c); h != nil {
			t.Errorf("newPBKDF2PadlockLaneHasher(%q) should have been refused", c)
		}
	}
}

func TestNewLaneHasherPadlockGateIsInternallyConsistent(t *testing.T) {
	factory, lanes, ok := newLaneHasher("padlock", padlockHashcatVector, "", "")
	wantOK := pbkdf2Sha256AVX2Eligible()
	if ok != wantOK {
		t.Fatalf("newLaneHasher(\"padlock\", ...) eligible=%v, want %v (pbkdf2Sha256AVX2Eligible)", ok, wantOK)
	}
	if !ok {
		t.Skip("not eligible on this hardware/build — nothing further to check")
	}
	if lanes != pbkdf2Sha256Lanes {
		t.Fatalf("newLaneHasher(\"padlock\", ...) lanes = %d, want %d", lanes, pbkdf2Sha256Lanes)
	}
	h := factory()
	if h == nil {
		t.Fatal("newLaneHasher(\"padlock\", ...) factory returned nil despite reporting eligible")
	}
	out := make([]bool, 1)
	h.Run([][]byte{[]byte("openwall")}, out)
	if !out[0] {
		t.Fatal("the wired-up hasher did not match the cross-checked record")
	}
}
