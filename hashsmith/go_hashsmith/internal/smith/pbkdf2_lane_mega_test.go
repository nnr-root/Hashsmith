package smith

import "testing"

// megaHashcatVector mirrors selftest_vectors.go's own published vector,
// passphrase "hashcat".
const megaHashcatVector = "P!AgD________U2XVjJi1vxkJgMPf5rkQYUn1H_6WI_sKtiic69mqBKP_____________________O_PDG0Om7BSapL1QoRAgUrz9vzaZmrYnU8t-Au6hteg"

func TestPBKDF2MegaLaneHasherMatchesHashcatVector(t *testing.T) {
	h := newPBKDF2MegaLaneHasher(megaHashcatVector)
	if h == nil {
		t.Fatal("newPBKDF2MegaLaneHasher refused hashcat's own published record")
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

func TestPBKDF2MegaLaneHasherMatchesScalarAcrossBatchSizes(t *testing.T) {
	right := "the-right-password"
	candidates := []string{
		"wrong1", "wrong2", "", "a", "12345678",
		"wrong3", right,
	}
	h := newPBKDF2MegaLaneHasher(megaHashcatVector)
	if h == nil {
		t.Fatal("newPBKDF2MegaLaneHasher refused hashcat's own published record")
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
				want, err := verifyMegaLink(megaHashcatVector, candidates[i])
				if err != nil {
					t.Fatalf("verifyMegaLink(%q): %v", candidates[i], err)
				}
				if out[i] != want {
					t.Errorf("batch of %d, candidate %q (position %d): lane hasher = %v, scalar = %v",
						n, candidates[i], i, out[i], want)
				}
			}
		})
	}
}

func TestPBKDF2MegaLaneHasherIsStateless(t *testing.T) {
	right := "hashcat"
	h := newPBKDF2MegaLaneHasher(megaHashcatVector)
	if h == nil {
		t.Fatal("newPBKDF2MegaLaneHasher refused hashcat's own published record")
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

func TestNewPBKDF2MegaLaneHasherRefusesMalformedRecords(t *testing.T) {
	cases := []string{
		"",
		"not a record",
		"P!short",
	}
	for _, c := range cases {
		if h := newPBKDF2MegaLaneHasher(c); h != nil {
			t.Errorf("newPBKDF2MegaLaneHasher(%q) should have been refused", c)
		}
	}
}

func TestNewLaneHasherMegaGateIsInternallyConsistent(t *testing.T) {
	factory, lanes, ok := newLaneHasher("mega", megaHashcatVector, "", "")
	wantOK := pbkdf2Sha512AVX2Eligible()
	if ok != wantOK {
		t.Fatalf("newLaneHasher(\"mega\", ...) eligible=%v, want %v (pbkdf2Sha512AVX2Eligible)", ok, wantOK)
	}
	if !ok {
		t.Skip("not eligible on this hardware/build — nothing further to check")
	}
	if lanes != pbkdf2Sha512Lanes {
		t.Fatalf("newLaneHasher(\"mega\", ...) lanes = %d, want %d", lanes, pbkdf2Sha512Lanes)
	}
	h := factory()
	if h == nil {
		t.Fatal("newLaneHasher(\"mega\", ...) factory returned nil despite reporting eligible")
	}
	out := make([]bool, 1)
	h.Run([][]byte{[]byte("hashcat")}, out)
	if !out[0] {
		t.Fatal("the wired-up hasher did not match hashcat's own published record")
	}
}
