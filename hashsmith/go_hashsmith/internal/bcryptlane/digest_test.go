package bcryptlane

import (
	"testing"

	"golang.org/x/crypto/bcrypt"
)

// Digest must reproduce, character for character, what x/crypto/bcrypt would
// have written for the same password, salt and cost. Anything less and a
// nested-bcrypt format built on it would feed a wrong inner string to the
// outer comparison and never crack.
func TestDigestReproducesXCrypto(t *testing.T) {
	for _, pw := range []string{"hashcat", "", "correct horse battery staple", "\x00leading-nul"} {
		for _, cost := range []int{4, 6} {
			// Let x/crypto pick the salt, then ask this package what it would
			// have produced for the same one.
			ref, err := bcrypt.GenerateFromPassword([]byte(pw), cost)
			if err != nil {
				t.Fatal(err)
			}
			h, err := NewHasher(string(ref))
			if err != nil {
				t.Fatalf("%q cost %d: %v", pw, cost, err)
			}
			got := h.Digest([]byte(pw))
			want := string(ref[len(ref)-31:])
			if got != want {
				t.Errorf("Digest(%q) at cost %d = %q; x/crypto wrote %q", pw, cost, got, want)
			}
			// And a different password must not produce the same digest.
			if other := h.Digest([]byte(pw + "x")); other == want {
				t.Errorf("Digest is insensitive to the password at cost %d", cost)
			}
		}
	}
}
