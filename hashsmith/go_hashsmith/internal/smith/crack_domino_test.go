package smith

import "testing"

// Domino's block padding has an edge Hashcat's own example record cannot
// reach: its example password is seven characters, and the rule only differs
// at lengths that are exact multiples of sixteen. Hashcat's loop runs while
// `curpos + 16 < size`, strictly, so a 16-byte message is ONE block and the
// padding block it prepares is never hashed — where PKCS#7 would add a whole
// extra block.
//
// These records were generated from this implementation and then cracked by
// hashcat -m 8700 to confirm the reading, which is the only way to test a
// boundary the published vector does not cross. The middle one fails against a
// PKCS#7-style padding rule and passes against the real one.
func TestDominoPaddingAtBlockBoundary(t *testing.T) {
	for _, c := range []struct{ record, password string }{
		{"(GDJ0nDZI8l8RJzlRbemg)", "hashcat"},              // 7, the published vector
		{"(GDJ0nDZHHORv/sfQ5UBi)", "hashcat123456789"},     // 16, exactly one block
		{"(GDJ0nDZIVYC0nJNNOw5D)", "hashcathashcathashca"}, // 20, two blocks
	} {
		ok, err := verifyDomino6(c.record, c.password)
		if err != nil {
			t.Errorf("%s: %v", c.record, err)
			continue
		}
		if !ok {
			t.Errorf("%s did not verify against %q (%d bytes)", c.record, c.password, len(c.password))
		}
		if bad, _ := verifyDomino6(c.record, c.password+"x"); bad {
			t.Errorf("%s verified against a wrong password", c.record)
		}
	}
}
