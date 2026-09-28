package smith

import "testing"

// luksSHA256Vector mirrors selftest_vectors.go's own cross-checked
// luks2smith (12-field) record, passphrase "hashsmith". hashSpec=sha256,
// keyBytes=32 — eligible for the AVX2 lane core. Both slotIter and mkIter
// are 1, so the test runs fast without weakening what it checks: the batch
// primitive's own arithmetic does not know or care how many iterations it
// is asked for.
const luksSHA256Vector = "$luks$1$sha256$aes$xts-plain64$32$dc96fab54243390c27e1ddfd7f9632485d731bbe$6665646362613938373635343332313066656463626139383736353433323130$1$1$3031323334353637383961626364656630313233343536373839616263646566$4$b4a5635f5ae8a9dfe4ef0539a35d6c1d9db8e6389353ff9db11594704e80f6be79fd1609712a5ae0074cfc8be9c9b9179fed889d3d3a78802e887f11ea47dd4d2f4546477c72a40f4dd14c83598d4505935cbbe7efed43810b71c4916284d29ae274b821bf07d4c5ec7be31fae47d4d5431449d2d6dd6763dd61439856441575"

// luksSHA1Vector is a hash-spec sibling built from the same field shape,
// used only to confirm the lane hasher correctly refuses a non-SHA-256
// hash spec.
const luksSHA1AESHashcatVector = "$luks$1$sha1$aes$xts-plain64$32$8d94d5883262e73b6beb9d693d76e02837957fbb$68617368736d6974682d6c756b732d6d6b65792d73616c742d33326279746573$2$2$68617368736d6974682d6c756b732d736c6f742d73616c742d33326279746573$1$b00e9f623a7fc2b8a97f9e79a7d2f0154649f88aab93688d6541b9d0fabd9547"

// luksSHA256AESHashcatVector mirrors selftest_vectors_luks_oldoffice.go's
// own regression vector for the split "luks-sha256-aes" type, password
// "hashcat".
const luksSHA256AESHashcatVector = "$luks$1$sha256$aes$xts-plain64$32$8d94d5883262e73b6beb9d693d76e02837957fbb$68617368736d6974682d6c756b732d6d6b65792d73616c742d33326279746573$2$2$68617368736d6974682d6c756b732d736c6f742d73616c742d33326279746573$1$b00e9f623a7fc2b8a97f9e79a7d2f0154649f88aab93688d6541b9d0fabd9547"

func TestPBKDF2LUKSLaneHasherMatchesVector(t *testing.T) {
	h := newPBKDF2LUKSLaneHasher(luksSHA256Vector)
	if h == nil {
		t.Fatal("newPBKDF2LUKSLaneHasher refused the cross-checked published record")
	}
	out := make([]bool, 1)
	h.Run([][]byte{[]byte("hashsmith")}, out)
	if !out[0] {
		t.Fatal("lane hasher did not match the cross-checked record with the correct password")
	}
	h.Run([][]byte{[]byte("wrong")}, out)
	if out[0] {
		t.Fatal("lane hasher false-matched a wrong password against the cross-checked record")
	}
}

func TestPBKDF2LUKSLaneHasherMatchesScalarAcrossBatchSizes(t *testing.T) {
	right := "the-right-password"
	candidates := []string{
		"wrong1", "wrong2", "", "a", "12345678", "wrong3",
		"wrong4", "wrong5", right,
	}
	h := newPBKDF2LUKSLaneHasher(luksSHA256Vector)
	if h == nil {
		t.Fatal("newPBKDF2LUKSLaneHasher refused the cross-checked published record")
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
				want, err := verifyLUKS(luksSHA256Vector, candidates[i])
				if err != nil {
					t.Fatalf("verifyLUKS(%q): %v", candidates[i], err)
				}
				if out[i] != want {
					t.Errorf("batch of %d, candidate %q (position %d): lane hasher = %v, scalar = %v",
						n, candidates[i], i, out[i], want)
				}
			}
		})
	}
}

func TestPBKDF2LUKSLaneHasherIsStateless(t *testing.T) {
	right := "hashsmith"
	h := newPBKDF2LUKSLaneHasher(luksSHA256Vector)
	if h == nil {
		t.Fatal("newPBKDF2LUKSLaneHasher refused the cross-checked published record")
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

func TestNewPBKDF2LUKSLaneHasherRefusesNonSHA256AndMalformedRecords(t *testing.T) {
	cases := []string{
		"",
		"not a record",
		luksSHA1AESHashcatVector,
		"$luks$1$sha256$aes$xts-plain64$too$few$fields",
	}
	for _, c := range cases {
		if h := newPBKDF2LUKSLaneHasher(c); h != nil {
			t.Errorf("newPBKDF2LUKSLaneHasher(%q) should have been refused", c)
		}
	}
}

func TestPBKDF2LUKSModeLaneHasherMatchesHashcatVector(t *testing.T) {
	mode := luksModeSpecs["luks-sha256-aes"]
	h := newPBKDF2LUKSModeLaneHasher(luksSHA256AESHashcatVector, mode)
	if h == nil {
		t.Fatal("newPBKDF2LUKSModeLaneHasher refused the published regression vector")
	}
	out := make([]bool, 1)
	h.Run([][]byte{[]byte("hashcat")}, out)
	if !out[0] {
		t.Fatal("lane hasher did not match the published regression vector with the correct password")
	}
	h.Run([][]byte{[]byte("wrong")}, out)
	if out[0] {
		t.Fatal("lane hasher false-matched a wrong password against the published regression vector")
	}
}

func TestNewPBKDF2LUKSModeLaneHasherRefusesMismatchedMode(t *testing.T) {
	// luks-sha256-serpent's own mode spec against an AES record: cipher
	// mismatch, must be refused exactly as verifyLUKSMode itself would.
	mode := luksModeSpecs["luks-sha256-serpent"]
	if h := newPBKDF2LUKSModeLaneHasher(luksSHA256AESHashcatVector, mode); h != nil {
		t.Fatal("newPBKDF2LUKSModeLaneHasher accepted a record whose cipher does not match the selected mode")
	}
	// luks-sha1-aes's mode spec against a SHA-256 record: hash spec mismatch.
	sha1Mode := luksModeSpecs["luks-sha1-aes"]
	if h := newPBKDF2LUKSModeLaneHasher(luksSHA256AESHashcatVector, sha1Mode); h != nil {
		t.Fatal("newPBKDF2LUKSModeLaneHasher accepted a record whose hash spec does not match the selected mode")
	}
}

func TestNewLaneHasherLUKSGateIsInternallyConsistent(t *testing.T) {
	factory, lanes, ok := newLaneHasher("luks", luksSHA256Vector, "", "")
	wantOK := pbkdf2Sha256AVX2Eligible()
	if ok != wantOK {
		t.Fatalf("newLaneHasher(\"luks\", ...) eligible=%v, want %v (pbkdf2Sha256AVX2Eligible)", ok, wantOK)
	}
	if !ok {
		t.Skip("not eligible on this hardware/build — nothing further to check")
	}
	if lanes != pbkdf2Sha256Lanes {
		t.Fatalf("newLaneHasher(\"luks\", ...) lanes = %d, want %d", lanes, pbkdf2Sha256Lanes)
	}
	h := factory()
	if h == nil {
		t.Fatal("newLaneHasher(\"luks\", ...) factory returned nil despite reporting eligible")
	}
	out := make([]bool, 1)
	h.Run([][]byte{[]byte("hashsmith")}, out)
	if !out[0] {
		t.Fatal("the wired-up hasher did not match the cross-checked record")
	}

	// A non-SHA-256 record must fall back to the scalar path.
	if _, _, ok := newLaneHasher("luks", luksSHA1AESHashcatVector, "", ""); ok {
		t.Fatal("newLaneHasher(\"luks\", ...) accepted a non-SHA-256 record")
	}
}

func TestNewLaneHasherLUKSModeGateIsInternallyConsistent(t *testing.T) {
	factory, lanes, ok := newLaneHasher("luks-sha256-aes", luksSHA256AESHashcatVector, "", "")
	wantOK := pbkdf2Sha256AVX2Eligible()
	if ok != wantOK {
		t.Fatalf("newLaneHasher(\"luks-sha256-aes\", ...) eligible=%v, want %v (pbkdf2Sha256AVX2Eligible)", ok, wantOK)
	}
	if !ok {
		t.Skip("not eligible on this hardware/build — nothing further to check")
	}
	if lanes != pbkdf2Sha256Lanes {
		t.Fatalf("newLaneHasher(\"luks-sha256-aes\", ...) lanes = %d, want %d", lanes, pbkdf2Sha256Lanes)
	}
	h := factory()
	if h == nil {
		t.Fatal("newLaneHasher(\"luks-sha256-aes\", ...) factory returned nil despite reporting eligible")
	}
	out := make([]bool, 1)
	h.Run([][]byte{[]byte("hashcat")}, out)
	if !out[0] {
		t.Fatal("the wired-up hasher did not match the published regression vector")
	}

	// The split SHA-1 types must never be silently accelerated by the
	// SHA-256 core.
	if _, _, ok := newLaneHasher("luks-sha1-aes", luksSHA1AESHashcatVector, "", ""); ok {
		t.Fatal("newLaneHasher(\"luks-sha1-aes\", ...) was unexpectedly eligible")
	}
}
