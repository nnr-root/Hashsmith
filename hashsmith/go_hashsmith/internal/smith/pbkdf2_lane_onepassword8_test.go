package smith

import "testing"

// onePassword8HashcatVector is hashcat's own published 1Password 8 mobile
// keychain example record, password "hashcat" — the same vector
// selftest_vectors.go carries for the scalar path's own conformance
// checking, reused here so the lane hasher is checked against a real,
// externally-authored record, not only one this project generated itself.
const onePassword8HashcatVector = "$mobilekeychain$31800@hashcat.net$0226802599846590531367298686059042845608249051353268870564348733$fa53b7d424cdd36667dc12e585810729efc8ea9b2f8e5dd7a3ee72f7576a6788$100000$e1fea241e7b7c84535a0d53388bccbb9$dfd5f9ad6da1a72a47a3c04e03b02142b2fc301b3afff610669058527828a0e0388f5a2b0e6909813a5f9653c54f797adf0869107f4b875d4beb736cfbcec428ca19fc28346642fa32ec00f2ca4ad8dcf119af33cb247273e7b7427fd20eae8fb992779979a5e25aa465b3954794f62f4ea85355032efcd4e43ae3db6b14720d1dda963a384c37b521a92cef3494f77580edab210987ebcf2f0f7ed0220c0a4777be693e075b5f1e1302$995f3703b8ea4519f8cdc1cbded4d595"

// TestPBKDF2Onepassword8LaneHasherMatchesHashcatVector checks the lane
// hasher against hashcat's own published record directly — the strongest
// oracle available for a format like this one, where "correct" means
// "decrypts hashcat's own real ciphertext," not merely "matches a value
// this project also computed."
func TestPBKDF2Onepassword8LaneHasherMatchesHashcatVector(t *testing.T) {
	h := newPBKDF2Onepassword8LaneHasher(onePassword8HashcatVector)
	if h == nil {
		t.Fatal("newPBKDF2Onepassword8LaneHasher refused hashcat's own published record")
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

// TestPBKDF2Onepassword8LaneHasherMatchesScalarAcrossBatchSizes is the
// batch-size-straddling test this project's other lane hashers all carry:
// every size from 1 through one past the 8-lane width, since a partial
// group is where a laned implementation goes wrong. Checked against
// verifyOnePassword8 directly (not a second hand-built oracle), so any
// divergence between the two paths — the exact bug class this whole
// project exists to avoid — fails immediately.
func TestPBKDF2Onepassword8LaneHasherMatchesScalarAcrossBatchSizes(t *testing.T) {
	right := "the-right-password"
	candidates := []string{
		"wrong1", "wrong2", "", "a", "12345678", "wrong3",
		"wrong4", "wrong5", right,
	}
	h := newPBKDF2Onepassword8LaneHasher(onePassword8HashcatVector)
	if h == nil {
		t.Fatal("newPBKDF2Onepassword8LaneHasher refused hashcat's own published record")
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
				want, err := verifyOnePassword8(onePassword8HashcatVector, candidates[i])
				if err != nil {
					t.Fatalf("verifyOnePassword8(%q): %v", candidates[i], err)
				}
				if out[i] != want {
					t.Errorf("batch of %d, candidate %q (position %d): lane hasher = %v, scalar = %v",
						n, candidates[i], i, out[i], want)
				}
			}
		})
	}
}

// TestPBKDF2Onepassword8LaneHasherIsStateless matches this project's other
// lane hashers' staleness guard: a full group containing the right
// password, then a shorter batch of wrong ones, must not let a lane's
// stale schedule or derived key leak a false positive.
func TestPBKDF2Onepassword8LaneHasherIsStateless(t *testing.T) {
	right := "hashcat"
	h := newPBKDF2Onepassword8LaneHasher(onePassword8HashcatVector)
	if h == nil {
		t.Fatal("newPBKDF2Onepassword8LaneHasher refused hashcat's own published record")
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

// TestNewPBKDF2Onepassword8LaneHasherRefusesMalformedRecords checks the
// parser gate: anything parseOnePassword8Record itself rejects must also
// make the lane hasher's constructor return nil, so the dispatch always
// falls back to the scalar path for a record it cannot handle rather than
// panicking or silently misparsing.
func TestNewPBKDF2Onepassword8LaneHasherRefusesMalformedRecords(t *testing.T) {
	cases := []string{
		"",
		"not a record",
		"$mobilekeychain$too$few$fields",
		"$othertag$" + onePassword8HashcatVector[len("$mobilekeychain$"):],
	}
	for _, c := range cases {
		if h := newPBKDF2Onepassword8LaneHasher(c); h != nil {
			t.Errorf("newPBKDF2Onepassword8LaneHasher(%q) should have been refused", c)
		}
	}
}

// TestNewLaneHasherOnepassword8GateIsInternallyConsistent mirrors the
// sha256/sha1/sha512 gate tests: newLaneHasher("1password8", ...) must
// report eligible if and only if pbkdf2Sha256AVX2Eligible() does, since
// this format reuses that exact gate.
func TestNewLaneHasherOnepassword8GateIsInternallyConsistent(t *testing.T) {
	factory, lanes, ok := newLaneHasher("1password8", onePassword8HashcatVector, "", "")
	wantOK := pbkdf2Sha256AVX2Eligible()
	if ok != wantOK {
		t.Fatalf("newLaneHasher(\"1password8\", ...) eligible=%v, want %v (pbkdf2Sha256AVX2Eligible)", ok, wantOK)
	}
	if !ok {
		t.Skip("not eligible on this hardware/build — nothing further to check")
	}
	if lanes != pbkdf2Sha256Lanes {
		t.Fatalf("newLaneHasher(\"1password8\", ...) lanes = %d, want %d", lanes, pbkdf2Sha256Lanes)
	}
	h := factory()
	if h == nil {
		t.Fatal("newLaneHasher(\"1password8\", ...) factory returned nil despite reporting eligible")
	}
	out := make([]bool, 1)
	h.Run([][]byte{[]byte("hashcat")}, out)
	if !out[0] {
		t.Fatal("the wired-up hasher did not match hashcat's own published record")
	}
}
