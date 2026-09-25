package smith

import "testing"

// oracle12cHashcatVector mirrors selftest_vectors.go's own published
// vector, passphrase "hashcat".
const oracle12cHashcatVector = "78281A9C0CF626BD05EFC4F41B515B61D6C4D95A250CD4A605CA0EF97168D670EBCB5673B6F5A2FB9CC4E0C0101E659C0C4E3B9B3BEDA846CD15508E88685A2334141655046766111066420254008225"

func TestPBKDF2Oracle12cLaneHasherMatchesHashcatVector(t *testing.T) {
	h := newPBKDF2Oracle12cLaneHasher(oracle12cHashcatVector)
	if h == nil {
		t.Fatal("newPBKDF2Oracle12cLaneHasher refused the published record")
	}
	out := make([]bool, 1)
	h.Run([][]byte{[]byte("hashcat")}, out)
	if !out[0] {
		t.Fatal("lane hasher did not match the published record with the correct password")
	}
	h.Run([][]byte{[]byte("wrong")}, out)
	if out[0] {
		t.Fatal("lane hasher false-matched a wrong password against the published record")
	}
}

func TestPBKDF2Oracle12cLaneHasherMatchesScalarAcrossBatchSizes(t *testing.T) {
	right := "the-right-password"
	candidates := []string{
		"wrong1", "wrong2", "", "a", "12345678",
		"wrong3", right,
	}
	h := newPBKDF2Oracle12cLaneHasher(oracle12cHashcatVector)
	if h == nil {
		t.Fatal("newPBKDF2Oracle12cLaneHasher refused the published record")
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
				want, err := verifyOracle12c(oracle12cHashcatVector, candidates[i])
				if err != nil {
					t.Fatalf("verifyOracle12c(%q): %v", candidates[i], err)
				}
				if out[i] != want {
					t.Errorf("batch of %d, candidate %q (position %d): lane hasher = %v, scalar = %v",
						n, candidates[i], i, out[i], want)
				}
			}
		})
	}
}

func TestPBKDF2Oracle12cLaneHasherIsStateless(t *testing.T) {
	right := "hashcat"
	h := newPBKDF2Oracle12cLaneHasher(oracle12cHashcatVector)
	if h == nil {
		t.Fatal("newPBKDF2Oracle12cLaneHasher refused the published record")
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

func TestNewPBKDF2Oracle12cLaneHasherRefusesMalformedRecords(t *testing.T) {
	cases := []string{
		"",
		"not a record",
		"AA",
	}
	for _, c := range cases {
		if h := newPBKDF2Oracle12cLaneHasher(c); h != nil {
			t.Errorf("newPBKDF2Oracle12cLaneHasher(%q) should have been refused", c)
		}
	}
}

func TestNewLaneHasherOracle12cGateIsInternallyConsistent(t *testing.T) {
	factory, lanes, ok := newLaneHasher("oracle12c", oracle12cHashcatVector, "", "")
	wantOK := pbkdf2Sha512AVX2Eligible()
	if ok != wantOK {
		t.Fatalf("newLaneHasher(\"oracle12c\", ...) eligible=%v, want %v (pbkdf2Sha512AVX2Eligible)", ok, wantOK)
	}
	if !ok {
		t.Skip("not eligible on this hardware/build — nothing further to check")
	}
	if lanes != pbkdf2Sha512Lanes {
		t.Fatalf("newLaneHasher(\"oracle12c\", ...) lanes = %d, want %d", lanes, pbkdf2Sha512Lanes)
	}
	h := factory()
	if h == nil {
		t.Fatal("newLaneHasher(\"oracle12c\", ...) factory returned nil despite reporting eligible")
	}
	out := make([]bool, 1)
	h.Run([][]byte{[]byte("hashcat")}, out)
	if !out[0] {
		t.Fatal("the wired-up hasher did not match the published record")
	}
}
