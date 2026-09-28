package smith

import "testing"

// werkzeugPBKDF2Vector mirrors selftest_vectors.go's own cross-checked
// vector, passphrase "hashsmith".
const werkzeugPBKDF2Vector = "pbkdf2:sha256:1000$salty$f7d97f4feac0e0ce7a184eb5617dc5091632e8cd8933bdde1a4495a9bc208036"

// werkzeugScryptVector is the scrypt-variant sibling from the same test —
// used only to confirm the lane hasher correctly refuses it.
const werkzeugScryptVector = "scrypt:1024:8:1$salty$3efd3817c49ce62e9d99ac0351928b3dd77f8d05c619836a4e26691dd3990eeaf5de217ddc2d0a9fbab75f0a37b9c7989466484a2796d36b109ea3e644c3da5f"

func TestPBKDF2WerkzeugLaneHasherMatchesVector(t *testing.T) {
	h := newPBKDF2WerkzeugLaneHasher(werkzeugPBKDF2Vector)
	if h == nil {
		t.Fatal("newPBKDF2WerkzeugLaneHasher refused the published pbkdf2:sha256 vector")
	}
	out := make([]bool, 1)
	h.Run([][]byte{[]byte("hashsmith")}, out)
	if !out[0] {
		t.Fatal("lane hasher did not match the vector with the correct passphrase")
	}
	h.Run([][]byte{[]byte("wrong")}, out)
	if out[0] {
		t.Fatal("lane hasher false-matched a wrong passphrase against the vector")
	}
}

func TestPBKDF2WerkzeugLaneHasherMatchesScalarAcrossBatchSizes(t *testing.T) {
	right := "the-right-password"
	candidates := []string{
		"wrong1", "wrong2", "", "a", "12345678", "wrong3",
		"wrong4", "wrong5", right,
	}
	h := newPBKDF2WerkzeugLaneHasher(werkzeugPBKDF2Vector)
	if h == nil {
		t.Fatal("newPBKDF2WerkzeugLaneHasher refused the published pbkdf2:sha256 vector")
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
				want, err := verifyWerkzeug(werkzeugPBKDF2Vector, candidates[i])
				if err != nil {
					t.Fatalf("verifyWerkzeug(%q): %v", candidates[i], err)
				}
				if out[i] != want {
					t.Errorf("batch of %d, candidate %q (position %d): lane hasher = %v, scalar = %v",
						n, candidates[i], i, out[i], want)
				}
			}
		})
	}
}

func TestPBKDF2WerkzeugLaneHasherIsStateless(t *testing.T) {
	right := "hashsmith"
	h := newPBKDF2WerkzeugLaneHasher(werkzeugPBKDF2Vector)
	if h == nil {
		t.Fatal("newPBKDF2WerkzeugLaneHasher refused the published pbkdf2:sha256 vector")
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

func TestNewPBKDF2WerkzeugLaneHasherRefusesScryptAndMalformedRecords(t *testing.T) {
	cases := []string{
		"",
		"not a record",
		werkzeugScryptVector,
		"pbkdf2:sha256:not-a-number$salt$aa",
	}
	for _, c := range cases {
		if h := newPBKDF2WerkzeugLaneHasher(c); h != nil {
			t.Errorf("newPBKDF2WerkzeugLaneHasher(%q) should have been refused", c)
		}
	}
}

func TestNewLaneHasherWerkzeugGateIsInternallyConsistent(t *testing.T) {
	factory, lanes, ok := newLaneHasher("werkzeug", werkzeugPBKDF2Vector, "", "")
	wantOK := pbkdf2Sha256AVX2Eligible()
	if ok != wantOK {
		t.Fatalf("newLaneHasher(\"werkzeug\", ...) eligible=%v, want %v (pbkdf2Sha256AVX2Eligible)", ok, wantOK)
	}
	if !ok {
		t.Skip("not eligible on this hardware/build — nothing further to check")
	}
	if lanes != pbkdf2Sha256Lanes {
		t.Fatalf("newLaneHasher(\"werkzeug\", ...) lanes = %d, want %d", lanes, pbkdf2Sha256Lanes)
	}
	h := factory()
	if h == nil {
		t.Fatal("newLaneHasher(\"werkzeug\", ...) factory returned nil despite reporting eligible")
	}
	out := make([]bool, 1)
	h.Run([][]byte{[]byte("hashsmith")}, out)
	if !out[0] {
		t.Fatal("the wired-up hasher did not match the published vector")
	}

	if _, _, ok := newLaneHasher("werkzeug", werkzeugScryptVector, "", ""); ok {
		t.Fatal("newLaneHasher(\"werkzeug\", ...) accepted a scrypt-variant record")
	}
}
