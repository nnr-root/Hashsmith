package smith

import "testing"

// encdvNoKeychainHashcatVector mirrors selftest_vectors.go's own published
// vector without a keychain (nbKeys=1, single-block output), password
// "hashcat".
const encdvNoKeychainHashcatVector = "$encdv-pbkdf2$1$1$121f898edc51ffb2$14e6bf4e9256f9e4$32$1972489853882254644795101599063579097812661888813652597380052274$100000"

// encdvKeychainHashcatVector mirrors selftest_vectors.go's own published
// vector WITH a keychain, password "hashcat" — this one needs the full
// 128-byte (four-block) PBKDF2 output.
const encdvKeychainHashcatVector = "$encdv-pbkdf2$3$1$c232aba45699c80b$473d5dd2e0833ac7$32$4454716926322493581114042616371582782202532493983541577898367049$100000$9a030124cecc2fef5ca44f83ef6e4c7944f8d7c5234b9000c982e209a92bb5535f4c15be6e9914729eb8a9bf870bd0535a231fa1d443d27c1fc4f78b441a7aa765fa0a3d181c485f77f59334ec68f27e66f227eb4be3579464d907ed8cf8bacc817cceb4496587898e43ce41921f66114051c007e1a54b7215b220aed6e33064"

// encdvMD5HashcatVector is the non-PBKDF2 sibling — used only to confirm
// the lane hasher correctly refuses it.
const encdvMD5HashcatVector = "$encdv$1$1$3a427b9ee5851118$4f52176bb9a1b3b6"

func TestPBKDF2EncDataVaultLaneHasherMatchesVectors(t *testing.T) {
	for _, target := range []string{encdvNoKeychainHashcatVector, encdvKeychainHashcatVector} {
		h := newPBKDF2EncDataVaultLaneHasher(target)
		if h == nil {
			t.Fatalf("newPBKDF2EncDataVaultLaneHasher refused the published record %q", target)
		}
		out := make([]bool, 1)
		h.Run([][]byte{[]byte("hashcat")}, out)
		if !out[0] {
			t.Fatalf("lane hasher did not match the published record %q with the correct password", target)
		}
		h.Run([][]byte{[]byte("wrong")}, out)
		if out[0] {
			t.Fatalf("lane hasher false-matched a wrong password against the published record %q", target)
		}
	}
}

func TestPBKDF2EncDataVaultLaneHasherMatchesScalarAcrossBatchSizes(t *testing.T) {
	right := "the-right-password"
	candidates := []string{
		"wrong1", "wrong2", "", "a", "12345678", "wrong3",
		"wrong4", "wrong5", right,
	}
	for _, name := range []struct {
		label  string
		target string
	}{
		{"no-keychain", encdvNoKeychainHashcatVector},
		{"keychain", encdvKeychainHashcatVector},
	} {
		t.Run(name.label, func(t *testing.T) {
			h := newPBKDF2EncDataVaultLaneHasher(name.target)
			if h == nil {
				t.Fatal("newPBKDF2EncDataVaultLaneHasher refused the published record")
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
						want, err := verifyENCDataVault(name.target, candidates[i])
						if err != nil {
							t.Fatalf("verifyENCDataVault(%q): %v", candidates[i], err)
						}
						if out[i] != want {
							t.Errorf("batch of %d, candidate %q (position %d): lane hasher = %v, scalar = %v",
								n, candidates[i], i, out[i], want)
						}
					}
				})
			}
		})
	}
}

func TestPBKDF2EncDataVaultLaneHasherIsStateless(t *testing.T) {
	right := "hashcat"
	h := newPBKDF2EncDataVaultLaneHasher(encdvKeychainHashcatVector)
	if h == nil {
		t.Fatal("newPBKDF2EncDataVaultLaneHasher refused the published record")
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

func TestNewPBKDF2EncDataVaultLaneHasherRefusesMD5AndMalformedRecords(t *testing.T) {
	cases := []string{
		"",
		"not a record",
		encdvMD5HashcatVector,
	}
	for _, c := range cases {
		if h := newPBKDF2EncDataVaultLaneHasher(c); h != nil {
			t.Errorf("newPBKDF2EncDataVaultLaneHasher(%q) should have been refused", c)
		}
	}
}

func TestNewLaneHasherEncDataVaultGateIsInternallyConsistent(t *testing.T) {
	factory, lanes, ok := newLaneHasher("encdatavault", encdvKeychainHashcatVector, "", "")
	wantOK := pbkdf2Sha256AVX2Eligible()
	if ok != wantOK {
		t.Fatalf("newLaneHasher(\"encdatavault\", ...) eligible=%v, want %v (pbkdf2Sha256AVX2Eligible)", ok, wantOK)
	}
	if !ok {
		t.Skip("not eligible on this hardware/build — nothing further to check")
	}
	if lanes != pbkdf2Sha256Lanes {
		t.Fatalf("newLaneHasher(\"encdatavault\", ...) lanes = %d, want %d", lanes, pbkdf2Sha256Lanes)
	}
	h := factory()
	if h == nil {
		t.Fatal("newLaneHasher(\"encdatavault\", ...) factory returned nil despite reporting eligible")
	}
	out := make([]bool, 1)
	h.Run([][]byte{[]byte("hashcat")}, out)
	if !out[0] {
		t.Fatal("the wired-up hasher did not match the published record")
	}

	// The MD5 form must fall back to the scalar path.
	if _, _, ok := newLaneHasher("encdatavault", encdvMD5HashcatVector, "", ""); ok {
		t.Fatal("newLaneHasher(\"encdatavault\", ...) accepted an MD5-form record")
	}
}
