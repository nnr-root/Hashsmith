package smith

import "testing"

// grub2HashsmithVector mirrors selftest_vectors.go's own cross-checked
// vector, passphrase "hashsmith".
const grub2HashsmithVector = "grub.pbkdf2.sha512.1000.73616C74792D67727562.CD16B324E198DBDC0B8332A77D72A034D68EDE011F6DBF59DDB80F15E1C1C39342F25AC32DB910201112C836D9FAA0D5C141C21C39CB9BD010B848E445385213"

func TestPBKDF2GRUB2LaneHasherMatchesVector(t *testing.T) {
	h := newPBKDF2GRUB2LaneHasher(grub2HashsmithVector)
	if h == nil {
		t.Fatal("newPBKDF2GRUB2LaneHasher refused the published record")
	}
	out := make([]bool, 1)
	h.Run([][]byte{[]byte("hashsmith")}, out)
	if !out[0] {
		t.Fatal("lane hasher did not match the published record with the correct password")
	}
	h.Run([][]byte{[]byte("wrong")}, out)
	if out[0] {
		t.Fatal("lane hasher false-matched a wrong password against the published record")
	}
}

func TestPBKDF2GRUB2LaneHasherMatchesScalarAcrossBatchSizes(t *testing.T) {
	right := "the-right-password"
	candidates := []string{
		"wrong1", "wrong2", "", "a", "12345678",
		"wrong3", right,
	}
	h := newPBKDF2GRUB2LaneHasher(grub2HashsmithVector)
	if h == nil {
		t.Fatal("newPBKDF2GRUB2LaneHasher refused the published record")
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
				want, err := verifyGRUB2(grub2HashsmithVector, candidates[i])
				if err != nil {
					t.Fatalf("verifyGRUB2(%q): %v", candidates[i], err)
				}
				if out[i] != want {
					t.Errorf("batch of %d, candidate %q (position %d): lane hasher = %v, scalar = %v",
						n, candidates[i], i, out[i], want)
				}
			}
		})
	}
}

func TestPBKDF2GRUB2LaneHasherIsStateless(t *testing.T) {
	right := "hashsmith"
	h := newPBKDF2GRUB2LaneHasher(grub2HashsmithVector)
	if h == nil {
		t.Fatal("newPBKDF2GRUB2LaneHasher refused the published record")
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

func TestNewPBKDF2GRUB2LaneHasherRefusesLongDigestAndMalformedRecords(t *testing.T) {
	cases := []string{
		"",
		"not a record",
		"grub.pbkdf2.sha512.1000.AA." + stringsRepeatHexForTest("00", 65), // 65-byte digest, over the single-block limit
	}
	for _, c := range cases {
		if h := newPBKDF2GRUB2LaneHasher(c); h != nil {
			t.Errorf("newPBKDF2GRUB2LaneHasher(%q) should have been refused", c)
		}
	}
}

// stringsRepeatHexForTest builds n bytes of hex from a repeated byte pair.
func stringsRepeatHexForTest(pair string, n int) string {
	out := ""
	for i := 0; i < n; i++ {
		out += pair
	}
	return out
}

func TestNewLaneHasherGRUB2GateIsInternallyConsistent(t *testing.T) {
	factory, lanes, ok := newLaneHasher("grub2", grub2HashsmithVector, "", "")
	wantOK := pbkdf2Sha512AVX2Eligible()
	if ok != wantOK {
		t.Fatalf("newLaneHasher(\"grub2\", ...) eligible=%v, want %v (pbkdf2Sha512AVX2Eligible)", ok, wantOK)
	}
	if !ok {
		t.Skip("not eligible on this hardware/build — nothing further to check")
	}
	if lanes != pbkdf2Sha512Lanes {
		t.Fatalf("newLaneHasher(\"grub2\", ...) lanes = %d, want %d", lanes, pbkdf2Sha512Lanes)
	}
	h := factory()
	if h == nil {
		t.Fatal("newLaneHasher(\"grub2\", ...) factory returned nil despite reporting eligible")
	}
	out := make([]bool, 1)
	h.Run([][]byte{[]byte("hashsmith")}, out)
	if !out[0] {
		t.Fatal("the wired-up hasher did not match the published record")
	}
}
