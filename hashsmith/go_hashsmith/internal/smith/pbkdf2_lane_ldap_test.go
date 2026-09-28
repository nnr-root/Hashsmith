package smith

import "testing"

// redHat389HashcatVector mirrors selftest_vectors.go's own regression
// vector, passphrase "secretpw".
const redHat389HashcatVector = "{PBKDF2_SHA256}AAAgAKurq6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6teSuIJLfiaaXQ+9Lg6HFwOqIY4E90fson7SzcEGLcNl7Gz7kcDwEqL/erfHZVKBhT63PSPV16tcCzAq9vBsQ/BH47aEHN5rU+SHtRwmGhTZ2P/5SWTR0ggzO1s6w7w23Anojc3ArXHvPk1THbJQnm2g8gozhRtXrHY9GWYPCd3jZJbZGa51exqeIlO1YDEymmKNyXanvTLcTC2WQxTemMI/bZUgh9Cpi9+3DtyaBKmQNCzZY0burrXZlCMFdzZXHEEZTTt6DBSfv0f/QWecTLcjyI2NfRwUEFP6KrlBDZoHfKcSvGczO7foV2+EsohteoHFW2k6Bq6MNZcmMuU/Yl4"

func TestPBKDF2RedHat389LaneHasherMatchesVector(t *testing.T) {
	h := newPBKDF2RedHat389LaneHasher(redHat389HashcatVector)
	if h == nil {
		t.Fatal("newPBKDF2RedHat389LaneHasher refused the published record")
	}
	out := make([]bool, 1)
	h.Run([][]byte{[]byte("secretpw")}, out)
	if !out[0] {
		t.Fatal("lane hasher did not match the published record with the correct password")
	}
	h.Run([][]byte{[]byte("wrong")}, out)
	if out[0] {
		t.Fatal("lane hasher false-matched a wrong password against the published record")
	}
}

func TestPBKDF2RedHat389LaneHasherMatchesScalarAcrossBatchSizes(t *testing.T) {
	right := "the-right-password"
	candidates := []string{
		"wrong1", "wrong2", "", "a", "12345678", "wrong3",
		"wrong4", "wrong5", right,
	}
	h := newPBKDF2RedHat389LaneHasher(redHat389HashcatVector)
	if h == nil {
		t.Fatal("newPBKDF2RedHat389LaneHasher refused the published record")
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
				want, err := verifyRedHat389PBKDF2(redHat389HashcatVector, candidates[i])
				if err != nil {
					t.Fatalf("verifyRedHat389PBKDF2(%q): %v", candidates[i], err)
				}
				if out[i] != want {
					t.Errorf("batch of %d, candidate %q (position %d): lane hasher = %v, scalar = %v",
						n, candidates[i], i, out[i], want)
				}
			}
		})
	}
}

func TestPBKDF2RedHat389LaneHasherIsStateless(t *testing.T) {
	right := "secretpw"
	h := newPBKDF2RedHat389LaneHasher(redHat389HashcatVector)
	if h == nil {
		t.Fatal("newPBKDF2RedHat389LaneHasher refused the published record")
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

func TestNewPBKDF2RedHat389LaneHasherRefusesMalformedRecords(t *testing.T) {
	cases := []string{
		"",
		"not a record",
		"{PBKDF2_SHA256}AAAA",
		"{PBKDF2_SHA256}not-base64!",
	}
	for _, c := range cases {
		if h := newPBKDF2RedHat389LaneHasher(c); h != nil {
			t.Errorf("newPBKDF2RedHat389LaneHasher(%q) should have been refused", c)
		}
	}
}

func TestNewLaneHasherLDAPPBKDF2GateIsInternallyConsistent(t *testing.T) {
	factory, lanes, ok := newLaneHasher("ldap-pbkdf2", redHat389HashcatVector, "", "")
	wantOK := pbkdf2Sha256AVX2Eligible()
	if ok != wantOK {
		t.Fatalf("newLaneHasher(\"ldap-pbkdf2\", ...) eligible=%v, want %v (pbkdf2Sha256AVX2Eligible)", ok, wantOK)
	}
	if !ok {
		t.Skip("not eligible on this hardware/build — nothing further to check")
	}
	if lanes != pbkdf2Sha256Lanes {
		t.Fatalf("newLaneHasher(\"ldap-pbkdf2\", ...) lanes = %d, want %d", lanes, pbkdf2Sha256Lanes)
	}
	h := factory()
	if h == nil {
		t.Fatal("newLaneHasher(\"ldap-pbkdf2\", ...) factory returned nil despite reporting eligible")
	}
	out := make([]bool, 1)
	h.Run([][]byte{[]byte("secretpw")}, out)
	if !out[0] {
		t.Fatal("the wired-up hasher did not match the published record")
	}
}
