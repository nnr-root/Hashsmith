package main

import "testing"

// John's own vectors for each of the four, plus the two things about them
// that a reader would not guess.
func TestJohnOddFormats(t *testing.T) {
	for _, tc := range []struct{ name, record, pass string }{
		{"EPI", "0x5F1D84A6DE97E2BEFB637A3CB5318AFEF0750B856CF1836BD1D4470175BE 0x4D5EFDFA143EDF74193076F174AC47CEBF2F417F", "Abc.!23"},
		{"leet", "salt$f86036a85e3ff84e73bf10769011ecdbccbf5aaed9df0240310776b42f5bb8776e612ab15a78bbfc39e867448a08337d97427e182e72922bbaa903ee75b2bfd4", "password"},
		{"sl3", "$sl3$35831503698405$d8f6b336a4df3336bf7de58a38b1189f6c5ce1e8", "621888462499899"},
		{"adxcrypt", "$adxcrypt$54886955", "99999999"},
		{"adxcrypt short password", "$adxcrypt$43891846", "30"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			types := detectHashTypes(tc.record)
			if len(types) == 0 {
				t.Fatal("no type detected")
			}
			var ok bool
			for _, ty := range types {
				if good, err := verifyCandidate(tc.pass, tc.record, ty, "", ""); err == nil && good {
					ok = true
				}
			}
			if !ok {
				t.Errorf("no detected type of %v answered %q", types, tc.pass)
			}
		})
	}
}

// ADX's own reference vectors include a collision, and the comment beside it
// in John's source says it "works fine on a real system". Pinning it here
// keeps anyone from later reading this format as a password hash: a match
// against eight digits folded out of thirty-two bits is evidence of very
// little, and the tool should not be made to pretend otherwise.
func TestADXCollidesByDesign(t *testing.T) {
	const record = "$adxcrypt$54886955"
	for _, pass := range []string{"99999999", "786r"} {
		ok, err := verifyADX(record, pass)
		if err != nil || !ok {
			t.Errorf("%q: ok=%v err=%v, want both passwords to verify", pass, ok, err)
		}
	}
}

// An SL3 unlock code is fifteen digits and its digits are hashed as the
// numbers zero to nine, not as the characters. A code of the right length
// made of the wrong characters must be refused rather than hashed.
func TestSL3TakesFifteenDigitsOnly(t *testing.T) {
	const record = "$sl3$35831503698405$d8f6b336a4df3336bf7de58a38b1189f6c5ce1e8"
	for _, bad := range []string{"62188846249989", "6218884624998999", "62188846249989a", ""} {
		if ok, err := verifySL3(record, bad); err != nil || ok {
			t.Errorf("%q: ok=%v err=%v, want a refusal", bad, ok, err)
		}
	}
	if ok, err := verifySL3(record, "621888462499899"); err != nil || !ok {
		t.Errorf("the right code: ok=%v err=%v", ok, err)
	}
}
