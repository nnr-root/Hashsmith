package smith

import "testing"

// passlibSHA256Vector mirrors crack_frameworks_test.go's own vector,
// passphrase "password".
const passlibSHA256Vector = "$pbkdf2-sha256$6400$.6UI/S.nXIk8jcbdHx3Fhg$98jZicV16ODfEsEZeYPGHU3kbrUrvUEXOPimVSQDD44"

// passlibSHA1Vector is the sha1-variant sibling from the same test — used
// only to confirm the lane hasher correctly refuses it.
const passlibSHA1Vector = "$pbkdf2-sha1$1000$c2FsdHk$TX4yNQQZVOCfG5gIIedaYDjifAE"

func TestPBKDF2PasslibLaneHasherMatchesVector(t *testing.T) {
	h := newPBKDF2PasslibLaneHasher(passlibSHA256Vector)
	if h == nil {
		t.Fatal("newPBKDF2PasslibLaneHasher refused the published pbkdf2-sha256 vector")
	}
	out := make([]bool, 1)
	h.Run([][]byte{[]byte("password")}, out)
	if !out[0] {
		t.Fatal("lane hasher did not match the vector with the correct passphrase")
	}
	h.Run([][]byte{[]byte("wrong")}, out)
	if out[0] {
		t.Fatal("lane hasher false-matched a wrong passphrase against the vector")
	}
}

func TestPBKDF2PasslibLaneHasherMatchesScalarAcrossBatchSizes(t *testing.T) {
	right := "the-right-password"
	candidates := []string{
		"wrong1", "wrong2", "", "a", "12345678", "wrong3",
		"wrong4", "wrong5", right,
	}
	h := newPBKDF2PasslibLaneHasher(passlibSHA256Vector)
	if h == nil {
		t.Fatal("newPBKDF2PasslibLaneHasher refused the published pbkdf2-sha256 vector")
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
				want, err := verifyPasslibPBKDF2(passlibSHA256Vector, candidates[i])
				if err != nil {
					t.Fatalf("verifyPasslibPBKDF2(%q): %v", candidates[i], err)
				}
				if out[i] != want {
					t.Errorf("batch of %d, candidate %q (position %d): lane hasher = %v, scalar = %v",
						n, candidates[i], i, out[i], want)
				}
			}
		})
	}
}

func TestPBKDF2PasslibLaneHasherIsStateless(t *testing.T) {
	right := "password"
	h := newPBKDF2PasslibLaneHasher(passlibSHA256Vector)
	if h == nil {
		t.Fatal("newPBKDF2PasslibLaneHasher refused the published pbkdf2-sha256 vector")
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

func TestNewPBKDF2PasslibLaneHasherRefusesOtherDigestsAndMalformedRecords(t *testing.T) {
	cases := []string{
		"",
		"not a record",
		passlibSHA1Vector,
		"$pbkdf2-sha256$not-a-number$salt$AAAA",
	}
	for _, c := range cases {
		if h := newPBKDF2PasslibLaneHasher(c); h != nil {
			t.Errorf("newPBKDF2PasslibLaneHasher(%q) should have been refused", c)
		}
	}
}

func TestNewLaneHasherPasslibGateIsInternallyConsistent(t *testing.T) {
	factory, lanes, ok := newLaneHasher("passlib-pbkdf2", passlibSHA256Vector, "", "")
	wantOK := pbkdf2Sha256AVX2Eligible()
	if ok != wantOK {
		t.Fatalf("newLaneHasher(\"passlib-pbkdf2\", ...) eligible=%v, want %v (pbkdf2Sha256AVX2Eligible)", ok, wantOK)
	}
	if !ok {
		t.Skip("not eligible on this hardware/build — nothing further to check")
	}
	if lanes != pbkdf2Sha256Lanes {
		t.Fatalf("newLaneHasher(\"passlib-pbkdf2\", ...) lanes = %d, want %d", lanes, pbkdf2Sha256Lanes)
	}
	h := factory()
	if h == nil {
		t.Fatal("newLaneHasher(\"passlib-pbkdf2\", ...) factory returned nil despite reporting eligible")
	}
	out := make([]bool, 1)
	h.Run([][]byte{[]byte("password")}, out)
	if !out[0] {
		t.Fatal("the wired-up hasher did not match the published vector")
	}
}
