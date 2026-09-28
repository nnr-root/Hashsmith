package smith

import "testing"

// aixSHA256HashcatVector mirrors selftest_vectors.go's own published vector
// (hashcat mode 6400), passphrase "hashcat".
const aixSHA256HashcatVector = "{ssha256}06$aJckFGJAB30LTe10$ohUsB7LBPlgclE3hJg9x042DLJvQyxVCX.nZZLEz.g2"

func TestPBKDF2AIXLaneHasherMatchesHashcatVector(t *testing.T) {
	h := newPBKDF2AIXLaneHasher(aixSHA256HashcatVector)
	if h == nil {
		t.Fatal("newPBKDF2AIXLaneHasher refused hashcat's own published record")
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

func TestPBKDF2AIXLaneHasherMatchesScalarAcrossBatchSizes(t *testing.T) {
	right := "the-right-password"
	candidates := []string{
		"wrong1", "wrong2", "", "a", "12345678", "wrong3",
		"wrong4", "wrong5", right,
	}
	h := newPBKDF2AIXLaneHasher(aixSHA256HashcatVector)
	if h == nil {
		t.Fatal("newPBKDF2AIXLaneHasher refused hashcat's own published record")
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
				want, err := verifyAIX(aixSHA256HashcatVector, candidates[i])
				if err != nil {
					t.Fatalf("verifyAIX(%q): %v", candidates[i], err)
				}
				if out[i] != want {
					t.Errorf("batch of %d, candidate %q (position %d): lane hasher = %v, scalar = %v",
						n, candidates[i], i, out[i], want)
				}
			}
		})
	}
}

func TestPBKDF2AIXLaneHasherIsStateless(t *testing.T) {
	right := "hashcat"
	h := newPBKDF2AIXLaneHasher(aixSHA256HashcatVector)
	if h == nil {
		t.Fatal("newPBKDF2AIXLaneHasher refused hashcat's own published record")
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

func TestNewPBKDF2AIXLaneHasherRefusesOtherDigestsAndMalformedRecords(t *testing.T) {
	cases := []string{
		"",
		"not a record",
		"{ssha1}06$aJckFGJAB30LTe10$ohUsB7LBPlgclE3hJg9x042DLJvQyxVCX",
		"{ssha512}06$aJckFGJAB30LTe10$ohUsB7LBPlgclE3hJg9x042DLJvQyxVCX",
		"{smd5}aJckFGJAB3$ohUsB7LBPlgclE3hJg9x04",
		"{ssha256}not-a-number$salt$hash",
		"{ssha256}06$salt$",
	}
	for _, c := range cases {
		if h := newPBKDF2AIXLaneHasher(c); h != nil {
			t.Errorf("newPBKDF2AIXLaneHasher(%q) should have been refused", c)
		}
	}
}

func TestNewLaneHasherAIXGateIsInternallyConsistent(t *testing.T) {
	factory, lanes, ok := newLaneHasher("aix", aixSHA256HashcatVector, "", "")
	wantOK := pbkdf2Sha256AVX2Eligible()
	if ok != wantOK {
		t.Fatalf("newLaneHasher(\"aix\", ...) eligible=%v, want %v (pbkdf2Sha256AVX2Eligible)", ok, wantOK)
	}
	if !ok {
		t.Skip("not eligible on this hardware/build — nothing further to check")
	}
	if lanes != pbkdf2Sha256Lanes {
		t.Fatalf("newLaneHasher(\"aix\", ...) lanes = %d, want %d", lanes, pbkdf2Sha256Lanes)
	}
	h := factory()
	if h == nil {
		t.Fatal("newLaneHasher(\"aix\", ...) factory returned nil despite reporting eligible")
	}
	out := make([]bool, 1)
	h.Run([][]byte{[]byte("hashcat")}, out)
	if !out[0] {
		t.Fatal("the wired-up hasher did not match hashcat's own published record")
	}
}
