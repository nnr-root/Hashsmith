package smith

import "testing"

// mozillaAESHashcatVector mirrors selftest_vectors.go's own published
// key4.db (AES) vector, passphrase "hashcat".
const mozillaAESHashcatVector = "$mozilla$*AES*5add91733b9b13310ea79a4b38de5c3f797c3bf1*54c17e2a8a066cbdc55f2080c5e9f02ea3954d712cb34b4547f5186548f46512*10000*040e4b5a00f993e63f67a34f6cfc5704*eae9c6c003e6d1b2aa8aa21630838808"

// mozilla3DESHashcatVector is the key3.db (3DES) sibling from the same
// test — used only to confirm the lane hasher correctly refuses it.
const mozilla3DESHashcatVector = "$mozilla$*3DES*b735d19e6cadb5136376a98c2369f22819d08c79*2b36961682200a877f7d5550975b614acc9fefe3*f03f3575fd5bdbc9e32232316eab7623"

func TestPBKDF2MozillaLaneHasherMatchesHashcatVector(t *testing.T) {
	h := newPBKDF2MozillaLaneHasher(mozillaAESHashcatVector)
	if h == nil {
		t.Fatal("newPBKDF2MozillaLaneHasher refused hashcat's own published key4.db record")
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

func TestPBKDF2MozillaLaneHasherMatchesScalarAcrossBatchSizes(t *testing.T) {
	right := "the-right-password"
	candidates := []string{
		"wrong1", "wrong2", "", "a", "12345678", "wrong3",
		"wrong4", "wrong5", right,
	}
	h := newPBKDF2MozillaLaneHasher(mozillaAESHashcatVector)
	if h == nil {
		t.Fatal("newPBKDF2MozillaLaneHasher refused hashcat's own published key4.db record")
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
				want, err := verifyMozilla(mozillaAESHashcatVector, candidates[i])
				if err != nil {
					t.Fatalf("verifyMozilla(%q): %v", candidates[i], err)
				}
				if out[i] != want {
					t.Errorf("batch of %d, candidate %q (position %d): lane hasher = %v, scalar = %v",
						n, candidates[i], i, out[i], want)
				}
			}
		})
	}
}

func TestPBKDF2MozillaLaneHasherIsStateless(t *testing.T) {
	right := "hashcat"
	h := newPBKDF2MozillaLaneHasher(mozillaAESHashcatVector)
	if h == nil {
		t.Fatal("newPBKDF2MozillaLaneHasher refused hashcat's own published key4.db record")
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

func TestNewPBKDF2MozillaLaneHasherRefuses3DESAndMalformedRecords(t *testing.T) {
	cases := []string{
		"",
		"not a record",
		mozilla3DESHashcatVector,
		"$mozilla$*AES*aa*bb*notanumber*cc*dd",
	}
	for _, c := range cases {
		if h := newPBKDF2MozillaLaneHasher(c); h != nil {
			t.Errorf("newPBKDF2MozillaLaneHasher(%q) should have been refused", c)
		}
	}
}

func TestNewLaneHasherMozillaGateIsInternallyConsistent(t *testing.T) {
	factory, lanes, ok := newLaneHasher("mozilla-nss", mozillaAESHashcatVector, "", "")
	wantOK := pbkdf2Sha256AVX2Eligible()
	if ok != wantOK {
		t.Fatalf("newLaneHasher(\"mozilla-nss\", ...) eligible=%v, want %v (pbkdf2Sha256AVX2Eligible)", ok, wantOK)
	}
	if !ok {
		t.Skip("not eligible on this hardware/build — nothing further to check")
	}
	if lanes != pbkdf2Sha256Lanes {
		t.Fatalf("newLaneHasher(\"mozilla-nss\", ...) lanes = %d, want %d", lanes, pbkdf2Sha256Lanes)
	}
	h := factory()
	if h == nil {
		t.Fatal("newLaneHasher(\"mozilla-nss\", ...) factory returned nil despite reporting eligible")
	}
	out := make([]bool, 1)
	h.Run([][]byte{[]byte("hashcat")}, out)
	if !out[0] {
		t.Fatal("the wired-up hasher did not match hashcat's own published record")
	}

	if _, _, ok := newLaneHasher("mozilla-nss", mozilla3DESHashcatVector, "", ""); ok {
		t.Fatal("newLaneHasher(\"mozilla-nss\", ...) accepted a key3.db (3DES) record")
	}
}
