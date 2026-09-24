package smith

import "testing"

// citrixPBKDF2HashcatVector mirrors selftest_vectors.go's own published
// vector, passphrase "hashcat".
const citrixPBKDF2HashcatVector = "5567243c55099b6b10a714a350db53beea8be6ac9c247fd40fea7e96d206a9f11fd1c45735556ac2004138640de206d0e1522607ab3c3f92816156d2d7845068e"

func TestPBKDF2CitrixPBKDF2LaneHasherMatchesHashcatVector(t *testing.T) {
	h := newPBKDF2CitrixPBKDF2LaneHasher(citrixPBKDF2HashcatVector)
	if h == nil {
		t.Fatal("newPBKDF2CitrixPBKDF2LaneHasher refused hashcat's own published record")
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

func TestPBKDF2CitrixPBKDF2LaneHasherMatchesScalarAcrossBatchSizes(t *testing.T) {
	right := "the-right-password"
	candidates := []string{
		"wrong1", "wrong2", "", "a", "12345678", "wrong3",
		"wrong4", "wrong5", right,
	}
	h := newPBKDF2CitrixPBKDF2LaneHasher(citrixPBKDF2HashcatVector)
	if h == nil {
		t.Fatal("newPBKDF2CitrixPBKDF2LaneHasher refused hashcat's own published record")
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
				want, err := verifyCitrixPBKDF2(citrixPBKDF2HashcatVector, candidates[i])
				if err != nil {
					t.Fatalf("verifyCitrixPBKDF2(%q): %v", candidates[i], err)
				}
				if out[i] != want {
					t.Errorf("batch of %d, candidate %q (position %d): lane hasher = %v, scalar = %v",
						n, candidates[i], i, out[i], want)
				}
			}
		})
	}
}

func TestPBKDF2CitrixPBKDF2LaneHasherIsStateless(t *testing.T) {
	right := "hashcat"
	h := newPBKDF2CitrixPBKDF2LaneHasher(citrixPBKDF2HashcatVector)
	if h == nil {
		t.Fatal("newPBKDF2CitrixPBKDF2LaneHasher refused hashcat's own published record")
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

func TestNewPBKDF2CitrixPBKDF2LaneHasherRefusesMalformedRecords(t *testing.T) {
	cases := []string{
		"",
		"not a record",
		"4567243c55099b6b10a714a350db53beea8be6ac9c247fd40fea7e96d206a9f11fd1c45735556ac2004138640de206d0e1522607ab3c3f92816156d2d7845068e",
	}
	for _, c := range cases {
		if h := newPBKDF2CitrixPBKDF2LaneHasher(c); h != nil {
			t.Errorf("newPBKDF2CitrixPBKDF2LaneHasher(%q) should have been refused", c)
		}
	}
}

func TestNewLaneHasherCitrixPBKDF2GateIsInternallyConsistent(t *testing.T) {
	factory, lanes, ok := newLaneHasher("citrix-pbkdf2", citrixPBKDF2HashcatVector, "", "")
	wantOK := pbkdf2Sha256AVX2Eligible()
	if ok != wantOK {
		t.Fatalf("newLaneHasher(\"citrix-pbkdf2\", ...) eligible=%v, want %v (pbkdf2Sha256AVX2Eligible)", ok, wantOK)
	}
	if !ok {
		t.Skip("not eligible on this hardware/build — nothing further to check")
	}
	if lanes != pbkdf2Sha256Lanes {
		t.Fatalf("newLaneHasher(\"citrix-pbkdf2\", ...) lanes = %d, want %d", lanes, pbkdf2Sha256Lanes)
	}
	h := factory()
	if h == nil {
		t.Fatal("newLaneHasher(\"citrix-pbkdf2\", ...) factory returned nil despite reporting eligible")
	}
	out := make([]bool, 1)
	h.Run([][]byte{[]byte("hashcat")}, out)
	if !out[0] {
		t.Fatal("the wired-up hasher did not match hashcat's own published record")
	}
}
