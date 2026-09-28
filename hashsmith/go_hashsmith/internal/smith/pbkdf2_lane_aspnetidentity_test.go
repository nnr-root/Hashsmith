package smith

import "testing"

// aspNetIdentityV3SHA256Vector mirrors crack_frameworks_test.go's own v3
// vector whose PRF is SHA-256 (raw[1:5] == 1), passphrase "hashsmith".
const aspNetIdentityV3SHA256Vector = "AQAAAAEAAC7gAAAAEBAREhMUFRYXGBkaGxwdHh9USoGEDJIxFUc0beM8B4/IEdus8IdgkrsjqG8Dcfo45w=="

// aspNetIdentityV2Vector is the v2 (fixed SHA-1) sibling — used only to
// confirm the lane hasher correctly refuses it.
const aspNetIdentityV2Vector = "AAABAgMEBQYHCAkKCwwNDg+Ky5554+IoJfqS5hXxjS0w0jPNKExk4LZOmo818o/5sg=="

// aspNetIdentityV3SHA512Vector is the v3/SHA-512 sibling — used only to
// confirm the lane hasher correctly refuses it.
const aspNetIdentityV3SHA512Vector = "AQAAAAIAAYagAAAAECAhIiMkJSYnKCkqKywtLi/ybYxC0Bq/+AGe4PMPgrfdplwVZMI04qy1RcSic3+RGg=="

func TestPBKDF2ASPNetIdentityLaneHasherMatchesVector(t *testing.T) {
	h := newPBKDF2ASPNetIdentityLaneHasher(aspNetIdentityV3SHA256Vector)
	if h == nil {
		t.Fatal("newPBKDF2ASPNetIdentityLaneHasher refused the published v3/SHA-256 vector")
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

func TestPBKDF2ASPNetIdentityLaneHasherMatchesScalarAcrossBatchSizes(t *testing.T) {
	right := "the-right-password"
	candidates := []string{
		"wrong1", "wrong2", "", "a", "12345678", "wrong3",
		"wrong4", "wrong5", right,
	}
	h := newPBKDF2ASPNetIdentityLaneHasher(aspNetIdentityV3SHA256Vector)
	if h == nil {
		t.Fatal("newPBKDF2ASPNetIdentityLaneHasher refused the published v3/SHA-256 vector")
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
				want, err := verifyASPNetIdentity(aspNetIdentityV3SHA256Vector, candidates[i])
				if err != nil {
					t.Fatalf("verifyASPNetIdentity(%q): %v", candidates[i], err)
				}
				if out[i] != want {
					t.Errorf("batch of %d, candidate %q (position %d): lane hasher = %v, scalar = %v",
						n, candidates[i], i, out[i], want)
				}
			}
		})
	}
}

func TestPBKDF2ASPNetIdentityLaneHasherIsStateless(t *testing.T) {
	right := "hashsmith"
	h := newPBKDF2ASPNetIdentityLaneHasher(aspNetIdentityV3SHA256Vector)
	if h == nil {
		t.Fatal("newPBKDF2ASPNetIdentityLaneHasher refused the published v3/SHA-256 vector")
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

func TestNewPBKDF2ASPNetIdentityLaneHasherRefusesOtherVariantsAndMalformedRecords(t *testing.T) {
	cases := []string{
		"",
		"not a record",
		aspNetIdentityV2Vector,
		aspNetIdentityV3SHA512Vector,
	}
	for _, c := range cases {
		if h := newPBKDF2ASPNetIdentityLaneHasher(c); h != nil {
			t.Errorf("newPBKDF2ASPNetIdentityLaneHasher(%q) should have been refused", c)
		}
	}
}

func TestNewLaneHasherASPNetIdentityGateIsInternallyConsistent(t *testing.T) {
	factory, lanes, ok := newLaneHasher("aspnet-identity", aspNetIdentityV3SHA256Vector, "", "")
	wantOK := pbkdf2Sha256AVX2Eligible()
	if ok != wantOK {
		t.Fatalf("newLaneHasher(\"aspnet-identity\", ...) eligible=%v, want %v (pbkdf2Sha256AVX2Eligible)", ok, wantOK)
	}
	if !ok {
		t.Skip("not eligible on this hardware/build — nothing further to check")
	}
	if lanes != pbkdf2Sha256Lanes {
		t.Fatalf("newLaneHasher(\"aspnet-identity\", ...) lanes = %d, want %d", lanes, pbkdf2Sha256Lanes)
	}
	h := factory()
	if h == nil {
		t.Fatal("newLaneHasher(\"aspnet-identity\", ...) factory returned nil despite reporting eligible")
	}
	out := make([]bool, 1)
	h.Run([][]byte{[]byte("hashsmith")}, out)
	if !out[0] {
		t.Fatal("the wired-up hasher did not match the published vector")
	}

	if _, _, ok := newLaneHasher("aspnet-identity", aspNetIdentityV2Vector, "", ""); ok {
		t.Fatal("newLaneHasher(\"aspnet-identity\", ...) accepted a v2 record")
	}
}
