package smith

import "testing"

// djangoPBKDF2SHA256Vector mirrors crack_django_test.go's own Python-generated
// vector, passphrase "hashsmith".
const djangoPBKDF2SHA256Vector = "pbkdf2_sha256$36000$saltsalt$/7unVWV4lqLJuWJ8M0AkSFZLsgC7+Gh07a9xHYVRA54="

// djangoPBKDF2SHA1Vector is the sha1-variant sibling from the same test —
// used only to confirm the lane hasher correctly refuses it.
const djangoPBKDF2SHA1Vector = "pbkdf2_sha1$36000$saltsalt$+6Qo6HdMPwwHQvlmc9N7EeFaEEI="

func TestPBKDF2DjangoLaneHasherMatchesVector(t *testing.T) {
	h := newPBKDF2DjangoLaneHasher(djangoPBKDF2SHA256Vector)
	if h == nil {
		t.Fatal("newPBKDF2DjangoLaneHasher refused the published pbkdf2_sha256 vector")
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

func TestPBKDF2DjangoLaneHasherMatchesScalarAcrossBatchSizes(t *testing.T) {
	right := "the-right-password"
	candidates := []string{
		"wrong1", "wrong2", "", "a", "12345678", "wrong3",
		"wrong4", "wrong5", right,
	}
	h := newPBKDF2DjangoLaneHasher(djangoPBKDF2SHA256Vector)
	if h == nil {
		t.Fatal("newPBKDF2DjangoLaneHasher refused the published pbkdf2_sha256 vector")
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
				want, err := verifyDjango(djangoPBKDF2SHA256Vector, candidates[i])
				if err != nil {
					t.Fatalf("verifyDjango(%q): %v", candidates[i], err)
				}
				if out[i] != want {
					t.Errorf("batch of %d, candidate %q (position %d): lane hasher = %v, scalar = %v",
						n, candidates[i], i, out[i], want)
				}
			}
		})
	}
}

func TestPBKDF2DjangoLaneHasherIsStateless(t *testing.T) {
	right := "hashsmith"
	h := newPBKDF2DjangoLaneHasher(djangoPBKDF2SHA256Vector)
	if h == nil {
		t.Fatal("newPBKDF2DjangoLaneHasher refused the published pbkdf2_sha256 vector")
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

func TestNewPBKDF2DjangoLaneHasherRefusesSHA1AndMalformedRecords(t *testing.T) {
	cases := []string{
		"",
		"not a record",
		djangoPBKDF2SHA1Vector,
		"pbkdf2_sha256$not-a-number$salt$AAAA",
		"md5$salty$37795b0102ce7e2ec07898d88690a638",
	}
	for _, c := range cases {
		if h := newPBKDF2DjangoLaneHasher(c); h != nil {
			t.Errorf("newPBKDF2DjangoLaneHasher(%q) should have been refused", c)
		}
	}
}

func TestNewLaneHasherDjangoGateIsInternallyConsistent(t *testing.T) {
	factory, lanes, ok := newLaneHasher("django", djangoPBKDF2SHA256Vector, "", "")
	wantOK := pbkdf2Sha256AVX2Eligible()
	if ok != wantOK {
		t.Fatalf("newLaneHasher(\"django\", ...) eligible=%v, want %v (pbkdf2Sha256AVX2Eligible)", ok, wantOK)
	}
	if !ok {
		t.Skip("not eligible on this hardware/build — nothing further to check")
	}
	if lanes != pbkdf2Sha256Lanes {
		t.Fatalf("newLaneHasher(\"django\", ...) lanes = %d, want %d", lanes, pbkdf2Sha256Lanes)
	}
	h := factory()
	if h == nil {
		t.Fatal("newLaneHasher(\"django\", ...) factory returned nil despite reporting eligible")
	}
	out := make([]bool, 1)
	h.Run([][]byte{[]byte("hashsmith")}, out)
	if !out[0] {
		t.Fatal("the wired-up hasher did not match the published vector")
	}

	// A pbkdf2_sha1 record must fall back to the scalar path, not be
	// silently accepted by an eligible SHA-256 hasher.
	if _, _, ok := newLaneHasher("django", djangoPBKDF2SHA1Vector, "", ""); ok {
		t.Fatal("newLaneHasher(\"django\", ...) accepted a pbkdf2_sha1 record")
	}
}
