package smith

import "testing"

// dogechainHashcatVector mirrors onePassword8HashcatVector's role: hashcat's
// own published Dogechain example record, password "hashcat".
const dogechainHashcatVector = "$dogechain$0*5000*EEmAkgiMlVrToRhu2suq91R5Frf+VQCvNzv9lj6OwRWIf/3IM31wqhJM7gGQpinXH9kqHkuQ2DMZxspgA7QFAddsUWvZxGdNAkaeKy90EAsTLIuDQnH3plfBQfmL6j5NPaH7Nr7kF1PdvM0pbUw6XHySBYkD/rPHNM6n58NRK4xfO4VVMykeX3+m2LaVyv5s269r/op38svRPT0YFGpRcanY6/U1BeSrvG2IXii1BKXXAcVEN4GFmyEQRWKI0uZE+3M0atf7UEPD4K9tmEKosqdsF4MFLiBtfI4eq0+926ijoezDmUPvHIiyQZ9CH2jZ*6jOgqW/GxL9He1afQiINIg=="

func TestPBKDF2DogechainLaneHasherMatchesHashcatVector(t *testing.T) {
	h := newPBKDF2DogechainLaneHasher(dogechainHashcatVector)
	if h == nil {
		t.Fatal("newPBKDF2DogechainLaneHasher refused hashcat's own published record")
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

func TestPBKDF2DogechainLaneHasherMatchesScalarAcrossBatchSizes(t *testing.T) {
	right := "the-right-password"
	candidates := []string{
		"wrong1", "wrong2", "", "a", "12345678", "wrong3",
		"wrong4", "wrong5", right,
	}
	h := newPBKDF2DogechainLaneHasher(dogechainHashcatVector)
	if h == nil {
		t.Fatal("newPBKDF2DogechainLaneHasher refused hashcat's own published record")
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
				want, err := verifyDogechain(dogechainHashcatVector, candidates[i])
				if err != nil {
					t.Fatalf("verifyDogechain(%q): %v", candidates[i], err)
				}
				if out[i] != want {
					t.Errorf("batch of %d, candidate %q (position %d): lane hasher = %v, scalar = %v",
						n, candidates[i], i, out[i], want)
				}
			}
		})
	}
}

func TestPBKDF2DogechainLaneHasherIsStateless(t *testing.T) {
	right := "hashcat"
	h := newPBKDF2DogechainLaneHasher(dogechainHashcatVector)
	if h == nil {
		t.Fatal("newPBKDF2DogechainLaneHasher refused hashcat's own published record")
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

func TestNewPBKDF2DogechainLaneHasherRefusesMalformedRecords(t *testing.T) {
	cases := []string{
		"",
		"not a record",
		"$dogechain$0*too*few",
		"$othertag$" + dogechainHashcatVector[len("$dogechain$"):],
	}
	for _, c := range cases {
		if h := newPBKDF2DogechainLaneHasher(c); h != nil {
			t.Errorf("newPBKDF2DogechainLaneHasher(%q) should have been refused", c)
		}
	}
}

func TestNewLaneHasherDogechainGateIsInternallyConsistent(t *testing.T) {
	factory, lanes, ok := newLaneHasher("dogechain", dogechainHashcatVector, "", "")
	wantOK := pbkdf2Sha256AVX2Eligible()
	if ok != wantOK {
		t.Fatalf("newLaneHasher(\"dogechain\", ...) eligible=%v, want %v (pbkdf2Sha256AVX2Eligible)", ok, wantOK)
	}
	if !ok {
		t.Skip("not eligible on this hardware/build — nothing further to check")
	}
	if lanes != pbkdf2Sha256Lanes {
		t.Fatalf("newLaneHasher(\"dogechain\", ...) lanes = %d, want %d", lanes, pbkdf2Sha256Lanes)
	}
	h := factory()
	if h == nil {
		t.Fatal("newLaneHasher(\"dogechain\", ...) factory returned nil despite reporting eligible")
	}
	out := make([]bool, 1)
	h.Run([][]byte{[]byte("hashcat")}, out)
	if !out[0] {
		t.Fatal("the wired-up hasher did not match hashcat's own published record")
	}
}
