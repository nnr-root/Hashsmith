package smith

import "testing"

// cisco8HashcatVector mirrors crack_cisco_test.go's own vector, passphrase "hashcat".
const cisco8HashcatVector = "$8$TnGX/fE4KGHOVU$pEhnEvxrvaynpi8j4f.EMHr6M.FzU8xnZnBr/tJdFWk"

func TestPBKDF2Cisco8LaneHasherMatchesHashcatVector(t *testing.T) {
	h := newPBKDF2Cisco8LaneHasher(cisco8HashcatVector)
	if h == nil {
		t.Fatal("newPBKDF2Cisco8LaneHasher refused hashcat's own published record")
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

func TestPBKDF2Cisco8LaneHasherMatchesScalarAcrossBatchSizes(t *testing.T) {
	right := "the-right-password"
	candidates := []string{
		"wrong1", "wrong2", "", "a", "12345678", "wrong3",
		"wrong4", "wrong5", right,
	}
	h := newPBKDF2Cisco8LaneHasher(cisco8HashcatVector)
	if h == nil {
		t.Fatal("newPBKDF2Cisco8LaneHasher refused hashcat's own published record")
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
				want, err := verifyCiscoType8(cisco8HashcatVector, candidates[i])
				if err != nil {
					t.Fatalf("verifyCiscoType8(%q): %v", candidates[i], err)
				}
				if out[i] != want {
					t.Errorf("batch of %d, candidate %q (position %d): lane hasher = %v, scalar = %v",
						n, candidates[i], i, out[i], want)
				}
			}
		})
	}
}

func TestPBKDF2Cisco8LaneHasherIsStateless(t *testing.T) {
	right := "hashcat"
	h := newPBKDF2Cisco8LaneHasher(cisco8HashcatVector)
	if h == nil {
		t.Fatal("newPBKDF2Cisco8LaneHasher refused hashcat's own published record")
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

func TestNewPBKDF2Cisco8LaneHasherRefusesMalformedRecords(t *testing.T) {
	cases := []string{
		"",
		"not a record",
		"$8$too$few$fields",
		"$9$" + cisco8HashcatVector[len("$8$"):],
	}
	for _, c := range cases {
		if h := newPBKDF2Cisco8LaneHasher(c); h != nil {
			t.Errorf("newPBKDF2Cisco8LaneHasher(%q) should have been refused", c)
		}
	}
}

func TestNewLaneHasherCisco8GateIsInternallyConsistent(t *testing.T) {
	factory, lanes, ok := newLaneHasher("cisco8", cisco8HashcatVector, "", "")
	wantOK := pbkdf2Sha256AVX2Eligible()
	if ok != wantOK {
		t.Fatalf("newLaneHasher(\"cisco8\", ...) eligible=%v, want %v (pbkdf2Sha256AVX2Eligible)", ok, wantOK)
	}
	if !ok {
		t.Skip("not eligible on this hardware/build — nothing further to check")
	}
	if lanes != pbkdf2Sha256Lanes {
		t.Fatalf("newLaneHasher(\"cisco8\", ...) lanes = %d, want %d", lanes, pbkdf2Sha256Lanes)
	}
	h := factory()
	if h == nil {
		t.Fatal("newLaneHasher(\"cisco8\", ...) factory returned nil despite reporting eligible")
	}
	out := make([]bool, 1)
	h.Run([][]byte{[]byte("hashcat")}, out)
	if !out[0] {
		t.Fatal("the wired-up hasher did not match hashcat's own published record")
	}
}
