package smith

import "testing"

// metamaskMobileHashcatVector mirrors selftest_vectors.go's own published
// vector, passphrase "hashcat1".
const metamaskMobileHashcatVector = "$metamaskMobile$JV4j2dUDl7n+sujyqW3Wvg==$398f9b04c822d36bfcbdd1e68c82d1e8$auj3J2TwOZ4ev3UIGmNa7VXLh0Nmzr3rDbpXRRrONr4="

func TestPBKDF2MetaMaskMobileLaneHasherMatchesHashcatVector(t *testing.T) {
	h := newPBKDF2MetaMaskMobileLaneHasher(metamaskMobileHashcatVector)
	if h == nil {
		t.Fatal("newPBKDF2MetaMaskMobileLaneHasher refused the published record")
	}
	out := make([]bool, 1)
	h.Run([][]byte{[]byte("hashcat1")}, out)
	if !out[0] {
		t.Fatal("lane hasher did not match the published record with the correct password")
	}
	h.Run([][]byte{[]byte("wrong")}, out)
	if out[0] {
		t.Fatal("lane hasher false-matched a wrong password against the published record")
	}
}

func TestPBKDF2MetaMaskMobileLaneHasherMatchesScalarAcrossBatchSizes(t *testing.T) {
	right := "the-right-password"
	candidates := []string{
		"wrong1", "wrong2", "", "a", "12345678",
		"wrong3", right,
	}
	h := newPBKDF2MetaMaskMobileLaneHasher(metamaskMobileHashcatVector)
	if h == nil {
		t.Fatal("newPBKDF2MetaMaskMobileLaneHasher refused the published record")
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
				want, err := verifyMetaMaskMobile(metamaskMobileHashcatVector, candidates[i])
				if err != nil {
					t.Fatalf("verifyMetaMaskMobile(%q): %v", candidates[i], err)
				}
				if out[i] != want {
					t.Errorf("batch of %d, candidate %q (position %d): lane hasher = %v, scalar = %v",
						n, candidates[i], i, out[i], want)
				}
			}
		})
	}
}

func TestPBKDF2MetaMaskMobileLaneHasherIsStateless(t *testing.T) {
	right := "hashcat1"
	h := newPBKDF2MetaMaskMobileLaneHasher(metamaskMobileHashcatVector)
	if h == nil {
		t.Fatal("newPBKDF2MetaMaskMobileLaneHasher refused the published record")
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

func TestNewPBKDF2MetaMaskMobileLaneHasherRefusesMalformedRecords(t *testing.T) {
	cases := []string{
		"",
		"not a record",
		"$metamaskMobile$AA==$AA==$AA==",
	}
	for _, c := range cases {
		if h := newPBKDF2MetaMaskMobileLaneHasher(c); h != nil {
			t.Errorf("newPBKDF2MetaMaskMobileLaneHasher(%q) should have been refused", c)
		}
	}
}

func TestNewLaneHasherMetaMaskMobileGateIsInternallyConsistent(t *testing.T) {
	factory, lanes, ok := newLaneHasher("metamask-mobile", metamaskMobileHashcatVector, "", "")
	wantOK := pbkdf2Sha512AVX2Eligible()
	if ok != wantOK {
		t.Fatalf("newLaneHasher(\"metamask-mobile\", ...) eligible=%v, want %v (pbkdf2Sha512AVX2Eligible)", ok, wantOK)
	}
	if !ok {
		t.Skip("not eligible on this hardware/build — nothing further to check")
	}
	if lanes != pbkdf2Sha512Lanes {
		t.Fatalf("newLaneHasher(\"metamask-mobile\", ...) lanes = %d, want %d", lanes, pbkdf2Sha512Lanes)
	}
	h := factory()
	if h == nil {
		t.Fatal("newLaneHasher(\"metamask-mobile\", ...) factory returned nil despite reporting eligible")
	}
	out := make([]bool, 1)
	h.Run([][]byte{[]byte("hashcat1")}, out)
	if !out[0] {
		t.Fatal("the wired-up hasher did not match the published record")
	}
}
