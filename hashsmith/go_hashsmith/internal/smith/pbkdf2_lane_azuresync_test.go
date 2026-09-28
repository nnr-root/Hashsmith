package smith

import "testing"

// azureSyncHashcatVector mirrors crack_vendor_test.go's own hashcat -m 12800
// example record, passphrase "hashcat".
const azureSyncHashcatVector = "v1;PPH1_MD4,54188415275183448824,100,55b530f052a9af79a7ba9c466dddcb8b116f8babf6c3873a51a3898fb008e123"

func TestPBKDF2AzureSyncLaneHasherMatchesHashcatVector(t *testing.T) {
	h := newPBKDF2AzureSyncLaneHasher(azureSyncHashcatVector)
	if h == nil {
		t.Fatal("newPBKDF2AzureSyncLaneHasher refused hashcat's own published record")
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

func TestPBKDF2AzureSyncLaneHasherMatchesScalarAcrossBatchSizes(t *testing.T) {
	right := "the-right-password"
	candidates := []string{
		"wrong1", "wrong2", "", "a", "12345678", "wrong3",
		"wrong4", "wrong5", right,
	}
	h := newPBKDF2AzureSyncLaneHasher(azureSyncHashcatVector)
	if h == nil {
		t.Fatal("newPBKDF2AzureSyncLaneHasher refused hashcat's own published record")
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
				want, err := verifyAzureSync(azureSyncHashcatVector, candidates[i])
				if err != nil {
					t.Fatalf("verifyAzureSync(%q): %v", candidates[i], err)
				}
				if out[i] != want {
					t.Errorf("batch of %d, candidate %q (position %d): lane hasher = %v, scalar = %v",
						n, candidates[i], i, out[i], want)
				}
			}
		})
	}
}

func TestPBKDF2AzureSyncLaneHasherIsStateless(t *testing.T) {
	right := "hashcat"
	h := newPBKDF2AzureSyncLaneHasher(azureSyncHashcatVector)
	if h == nil {
		t.Fatal("newPBKDF2AzureSyncLaneHasher refused hashcat's own published record")
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

func TestNewPBKDF2AzureSyncLaneHasherRefusesMalformedRecords(t *testing.T) {
	cases := []string{
		"",
		"not a record",
		"v1;PPH1_MD4,zz,100,ab",
		"v2;PPH1_MD4,54188415275183448824,100,ab",
	}
	for _, c := range cases {
		if h := newPBKDF2AzureSyncLaneHasher(c); h != nil {
			t.Errorf("newPBKDF2AzureSyncLaneHasher(%q) should have been refused", c)
		}
	}
}

func TestNewLaneHasherAzureSyncGateIsInternallyConsistent(t *testing.T) {
	factory, lanes, ok := newLaneHasher("azuresync", azureSyncHashcatVector, "", "")
	wantOK := pbkdf2Sha256AVX2Eligible()
	if ok != wantOK {
		t.Fatalf("newLaneHasher(\"azuresync\", ...) eligible=%v, want %v (pbkdf2Sha256AVX2Eligible)", ok, wantOK)
	}
	if !ok {
		t.Skip("not eligible on this hardware/build — nothing further to check")
	}
	if lanes != pbkdf2Sha256Lanes {
		t.Fatalf("newLaneHasher(\"azuresync\", ...) lanes = %d, want %d", lanes, pbkdf2Sha256Lanes)
	}
	h := factory()
	if h == nil {
		t.Fatal("newLaneHasher(\"azuresync\", ...) factory returned nil despite reporting eligible")
	}
	out := make([]bool, 1)
	h.Run([][]byte{[]byte("hashcat")}, out)
	if !out[0] {
		t.Fatal("the wired-up hasher did not match hashcat's own published record")
	}
}
