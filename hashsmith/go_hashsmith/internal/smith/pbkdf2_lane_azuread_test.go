package smith

import "testing"

// azureADHashcatVector mirrors selftest_vectors.go's own cross-checked
// vector, passphrase "openwall". Note the trailing semicolon John's records
// end with — azureADFields trims it.
const azureADHashcatVector = "v1;PPH1_MD4,724b754c4b6d30526f36,100,367ff0ac2a1cb334bb26609c8bfc8ae5f619d1eaf07568df040f407504a20241;"

func TestPBKDF2AzureADLaneHasherMatchesHashcatVector(t *testing.T) {
	h := newPBKDF2AzureADLaneHasher(azureADHashcatVector)
	if h == nil {
		t.Fatal("newPBKDF2AzureADLaneHasher refused the cross-checked published record")
	}
	out := make([]bool, 1)
	h.Run([][]byte{[]byte("openwall")}, out)
	if !out[0] {
		t.Fatal("lane hasher did not match the cross-checked record with the correct password")
	}
	h.Run([][]byte{[]byte("wrong")}, out)
	if out[0] {
		t.Fatal("lane hasher false-matched a wrong password against the cross-checked record")
	}
}

func TestPBKDF2AzureADLaneHasherMatchesScalarAcrossBatchSizes(t *testing.T) {
	right := "the-right-password"
	candidates := []string{
		"wrong1", "wrong2", "", "a", "12345678", "wrong3",
		"wrong4", "wrong5", right,
	}
	h := newPBKDF2AzureADLaneHasher(azureADHashcatVector)
	if h == nil {
		t.Fatal("newPBKDF2AzureADLaneHasher refused the cross-checked published record")
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
				want, err := verifyAzureAD(azureADHashcatVector, candidates[i])
				if err != nil {
					t.Fatalf("verifyAzureAD(%q): %v", candidates[i], err)
				}
				if out[i] != want {
					t.Errorf("batch of %d, candidate %q (position %d): lane hasher = %v, scalar = %v",
						n, candidates[i], i, out[i], want)
				}
			}
		})
	}
}

func TestPBKDF2AzureADLaneHasherIsStateless(t *testing.T) {
	right := "openwall"
	h := newPBKDF2AzureADLaneHasher(azureADHashcatVector)
	if h == nil {
		t.Fatal("newPBKDF2AzureADLaneHasher refused the cross-checked published record")
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

func TestNewPBKDF2AzureADLaneHasherRefusesMalformedRecords(t *testing.T) {
	cases := []string{
		"",
		"not a record",
		"v1;PPH1_MD4,zz,100,ab",
		"v2;PPH1_MD4,724b754c4b6d30526f36,100,ab",
	}
	for _, c := range cases {
		if h := newPBKDF2AzureADLaneHasher(c); h != nil {
			t.Errorf("newPBKDF2AzureADLaneHasher(%q) should have been refused", c)
		}
	}
}

func TestNewLaneHasherAzureADGateIsInternallyConsistent(t *testing.T) {
	factory, lanes, ok := newLaneHasher("azuread", azureADHashcatVector, "", "")
	wantOK := pbkdf2Sha256AVX2Eligible()
	if ok != wantOK {
		t.Fatalf("newLaneHasher(\"azuread\", ...) eligible=%v, want %v (pbkdf2Sha256AVX2Eligible)", ok, wantOK)
	}
	if !ok {
		t.Skip("not eligible on this hardware/build — nothing further to check")
	}
	if lanes != pbkdf2Sha256Lanes {
		t.Fatalf("newLaneHasher(\"azuread\", ...) lanes = %d, want %d", lanes, pbkdf2Sha256Lanes)
	}
	h := factory()
	if h == nil {
		t.Fatal("newLaneHasher(\"azuread\", ...) factory returned nil despite reporting eligible")
	}
	out := make([]bool, 1)
	h.Run([][]byte{[]byte("openwall")}, out)
	if !out[0] {
		t.Fatal("the wired-up hasher did not match the cross-checked record")
	}
}
