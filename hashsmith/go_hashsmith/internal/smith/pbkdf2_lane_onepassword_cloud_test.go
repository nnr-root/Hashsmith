package smith

import "testing"

// onePasswordCloudHashcatVector mirrors selftest_vectors.go's own
// published vector, passphrase "hashcat".
const onePasswordCloudHashcatVector = "9b6933f4a1f65baf02737545efc8c1caee4c7a5a82ce3ab637bcc19b0b51f5c5:30b952120ca9a190ac673a5e12a358e4:40000:e29b48a8cfd216701a8ced536038d0d49cf58dd25686e02d7ba3aa0463cc369062045db9e95653ac176e2192732b49073d481c26f29e1c611c84aaba93e553a6c51d1a9f7cfce0d01e099fb19f6a412bacd8034a333f7165fda1cc89df845e019c03ac9a09bc77b26c49524ade5c5a812230322f014f058b3bb790319e4a788f917aa164e56e78941f74e9c08921144e14be9b60da1a7321a0d178a1b8c1dcf83ffcadcb1599039049650577780d6913ee924e6529401e7a65b7d71c169a107e502dbd13b6b01c58e0483afb61b926313fa4273e685dd4890218bb797fab038c6a24df90883c7acd2358908edc1f7d95ef498757a3e0659aaaf6981c744ab69254267127fc806cf3cd1ced99ab455ece06479c91c892769af5db0c0f7a70dd83e4341bf86d085bbdc6a7e195ab08fc26"

func TestPBKDF2OnePasswordCloudLaneHasherMatchesHashcatVector(t *testing.T) {
	h := newPBKDF2OnePasswordCloudLaneHasher(onePasswordCloudHashcatVector)
	if h == nil {
		t.Fatal("newPBKDF2OnePasswordCloudLaneHasher refused hashcat's own published record")
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

func TestPBKDF2OnePasswordCloudLaneHasherMatchesScalarAcrossBatchSizes(t *testing.T) {
	right := "the-right-password"
	candidates := []string{
		"wrong1", "wrong2", "", "a", "12345678",
		"wrong3", right,
	}
	h := newPBKDF2OnePasswordCloudLaneHasher(onePasswordCloudHashcatVector)
	if h == nil {
		t.Fatal("newPBKDF2OnePasswordCloudLaneHasher refused hashcat's own published record")
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
				want, err := verifyOnePasswordCloud(onePasswordCloudHashcatVector, candidates[i])
				if err != nil {
					t.Fatalf("verifyOnePasswordCloud(%q): %v", candidates[i], err)
				}
				if out[i] != want {
					t.Errorf("batch of %d, candidate %q (position %d): lane hasher = %v, scalar = %v",
						n, candidates[i], i, out[i], want)
				}
			}
		})
	}
}

func TestPBKDF2OnePasswordCloudLaneHasherIsStateless(t *testing.T) {
	right := "hashcat"
	h := newPBKDF2OnePasswordCloudLaneHasher(onePasswordCloudHashcatVector)
	if h == nil {
		t.Fatal("newPBKDF2OnePasswordCloudLaneHasher refused hashcat's own published record")
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

func TestNewPBKDF2OnePasswordCloudLaneHasherRefusesMalformedRecords(t *testing.T) {
	cases := []string{
		"",
		"not a record",
		"aa:bb:cc",
	}
	for _, c := range cases {
		if h := newPBKDF2OnePasswordCloudLaneHasher(c); h != nil {
			t.Errorf("newPBKDF2OnePasswordCloudLaneHasher(%q) should have been refused", c)
		}
	}
}

func TestNewLaneHasherOnePasswordCloudGateIsInternallyConsistent(t *testing.T) {
	factory, lanes, ok := newLaneHasher("1password-cloud", onePasswordCloudHashcatVector, "", "")
	wantOK := pbkdf2Sha512AVX2Eligible()
	if ok != wantOK {
		t.Fatalf("newLaneHasher(\"1password-cloud\", ...) eligible=%v, want %v (pbkdf2Sha512AVX2Eligible)", ok, wantOK)
	}
	if !ok {
		t.Skip("not eligible on this hardware/build — nothing further to check")
	}
	if lanes != pbkdf2Sha512Lanes {
		t.Fatalf("newLaneHasher(\"1password-cloud\", ...) lanes = %d, want %d", lanes, pbkdf2Sha512Lanes)
	}
	h := factory()
	if h == nil {
		t.Fatal("newLaneHasher(\"1password-cloud\", ...) factory returned nil despite reporting eligible")
	}
	out := make([]bool, 1)
	h.Run([][]byte{[]byte("hashcat")}, out)
	if !out[0] {
		t.Fatal("the wired-up hasher did not match hashcat's own published record")
	}
}
