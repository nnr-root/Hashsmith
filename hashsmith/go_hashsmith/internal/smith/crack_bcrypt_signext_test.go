package smith

import "testing"

// John's own $2x$ vector. The password is one Cyrillic letter, two bytes of
// UTF-8 both above the ASCII range — which is the only kind of password the
// variant exists for.
func TestBcryptSignExtension(t *testing.T) {
	const record = "$2x$05$6bNw2HLQYeqHYyBfLMsv/OiwqTymGIGzFsA4hOTWebfehXHNprcAS"
	if ok, err := verifyBcryptSignExt(record, "ё"); err != nil || !ok {
		t.Errorf("the right password: ok=%v err=%v", ok, err)
	}
	if ok, _ := verifyBcryptSignExt(record, "e"); ok {
		t.Error("accepted a wrong password")
	}
}

// An ASCII password is hashed identically by both schedules, because no byte
// reaches 0x80 and nothing is sign-extended. That is what let the bug live for
// fourteen years, and it is a property the implementation must have rather
// than merely be believed to have: the sign-extended key for an ASCII
// password must produce the same digest an ordinary bcrypt does.
func TestBcryptSignExtensionIsIdentityOnASCII(t *testing.T) {
	for _, pw := range []string{"", "a", "password", "0123456789abcdef0123456789abcdef0123456789"} {
		key := bcryptSignExtendedKey(pw)
		for _, b := range key {
			if b == 0xFF {
				t.Errorf("%q: an ASCII password produced a filled byte", pw)
				break
			}
		}
		// And the seventy-two bytes must be the password, its NUL, and then
		// the two cycled around — nothing else.
		withNUL := append([]byte(pw), 0)
		for i := range key {
			if key[i] != withNUL[i%len(withNUL)] {
				t.Fatalf("%q: byte %d is %#x, want %#x", pw, i, key[i], withNUL[i%len(withNUL)])
			}
		}
	}
}

// The fill runs backwards within a group and stops at the group boundary: a
// high byte sets every EARLIER byte of its own four, and touches no other
// group. Anything else would be a different hash.
func TestBcryptSignExtensionFillsWithinItsGroup(t *testing.T) {
	// A five-byte password whose last byte is high; with the trailing NUL the
	// key is six bytes and cycles.
	key := bcryptSignExtendedKey("abcd\xff")
	// Group 0 is "abcd": no high byte, so untouched.
	for i, want := range []byte{'a', 'b', 'c', 'd'} {
		if key[i] != want {
			t.Errorf("group 0 byte %d = %#x, want %#x", i, key[i], want)
		}
	}
	// Group 1 is 0xff, 0x00, 'a', 'b' — the high byte is first, so nothing
	// before it in the group changes and nothing after it does either.
	if got := key[4:8]; got[0] != 0xff || got[1] != 0x00 || got[2] != 'a' || got[3] != 'b' {
		t.Errorf("group 1 = % x, want ff 00 61 62", got)
	}
	// Group 2 is 'c', 'd', 0xff, 0x00 — the high byte is third, so the two
	// before it fill and the one after does not.
	if got := key[8:12]; got[0] != 0xff || got[1] != 0xff || got[2] != 0xff || got[3] != 0x00 {
		t.Errorf("group 2 = % x, want ff ff ff 00", got)
	}
}
