package smith

import "testing"

// scramHashsmithVector mirrors crack_misc_test.go's own Python-generated
// PostgreSQL SCRAM-SHA-256 vector, passphrase "hashsmith".
const scramHashsmithVector = "SCRAM-SHA-256$4096:ABEiM0RVZnc=$tXvV/5d2dbq937pl1Urt3L2m8LXy7/llbOPTaIXXgsI=:s5u1rzVInmgZSrQkhL722KLzdU3PzDktG2BMsuT009c="

func TestPBKDF2ScramLaneHasherMatchesVector(t *testing.T) {
	h := newPBKDF2ScramLaneHasher(scramHashsmithVector)
	if h == nil {
		t.Fatal("newPBKDF2ScramLaneHasher refused the published SCRAM vector")
	}
	out := make([]bool, 1)
	h.Run([][]byte{[]byte("hashsmith")}, out)
	if !out[0] {
		t.Fatal("lane hasher did not match the SCRAM vector with the correct passphrase")
	}
	h.Run([][]byte{[]byte("wrong")}, out)
	if out[0] {
		t.Fatal("lane hasher false-matched a wrong passphrase against the SCRAM vector")
	}
}

func TestPBKDF2ScramLaneHasherMatchesScalarAcrossBatchSizes(t *testing.T) {
	right := "the-right-password"
	candidates := []string{
		"wrong1", "wrong2", "", "a", "12345678", "wrong3",
		"wrong4", "wrong5", right,
	}
	h := newPBKDF2ScramLaneHasher(scramHashsmithVector)
	if h == nil {
		t.Fatal("newPBKDF2ScramLaneHasher refused the published SCRAM vector")
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
				want, err := verifySCRAM(scramHashsmithVector, candidates[i])
				if err != nil {
					t.Fatalf("verifySCRAM(%q): %v", candidates[i], err)
				}
				if out[i] != want {
					t.Errorf("batch of %d, candidate %q (position %d): lane hasher = %v, scalar = %v",
						n, candidates[i], i, out[i], want)
				}
			}
		})
	}
}

func TestPBKDF2ScramLaneHasherIsStateless(t *testing.T) {
	right := "hashsmith"
	h := newPBKDF2ScramLaneHasher(scramHashsmithVector)
	if h == nil {
		t.Fatal("newPBKDF2ScramLaneHasher refused the published SCRAM vector")
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

func TestNewPBKDF2ScramLaneHasherRefusesMalformedRecords(t *testing.T) {
	cases := []string{
		"",
		"not a record",
		"SCRAM-SHA-256$not-a-number:salt$sk:srv",
		"SCRAM-SHA-1$" + scramHashsmithVector[len("SCRAM-SHA-256$"):],
	}
	for _, c := range cases {
		if h := newPBKDF2ScramLaneHasher(c); h != nil {
			t.Errorf("newPBKDF2ScramLaneHasher(%q) should have been refused", c)
		}
	}
}

func TestNewLaneHasherScramGateIsInternallyConsistent(t *testing.T) {
	factory, lanes, ok := newLaneHasher("scram", scramHashsmithVector, "", "")
	wantOK := pbkdf2Sha256AVX2Eligible()
	if ok != wantOK {
		t.Fatalf("newLaneHasher(\"scram\", ...) eligible=%v, want %v (pbkdf2Sha256AVX2Eligible)", ok, wantOK)
	}
	if !ok {
		t.Skip("not eligible on this hardware/build — nothing further to check")
	}
	if lanes != pbkdf2Sha256Lanes {
		t.Fatalf("newLaneHasher(\"scram\", ...) lanes = %d, want %d", lanes, pbkdf2Sha256Lanes)
	}
	h := factory()
	if h == nil {
		t.Fatal("newLaneHasher(\"scram\", ...) factory returned nil despite reporting eligible")
	}
	out := make([]bool, 1)
	h.Run([][]byte{[]byte("hashsmith")}, out)
	if !out[0] {
		t.Fatal("the wired-up hasher did not match the published SCRAM vector")
	}
}
