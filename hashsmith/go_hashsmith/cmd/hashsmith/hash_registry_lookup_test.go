package main

import "testing"

func TestHashcatModeLookup(t *testing.T) {
	cases := []struct {
		typ  string
		want int
	}{
		{"md5", 0}, {"ntlm", 1000}, {"sha1", 100}, {"sha256", 1400},
		{"lm", 3000}, {"md4", 900}, {"sha512crypt", 1800},
	}
	for _, c := range cases {
		got, ok := universalHashRegistry.hashcatMode(c.typ)
		if !ok {
			t.Errorf("hashcatMode(%q): not found, want %d", c.typ, c.want)
			continue
		}
		if got != c.want {
			t.Errorf("hashcatMode(%q) = %d, want %d", c.typ, got, c.want)
		}
	}
}

// A format with several Hashcat modes reports the lowest, deterministically.
func TestHashcatModeIsDeterministicForMultiModeFormats(t *testing.T) {
	first, ok := universalHashRegistry.hashcatMode("gpg")
	if !ok {
		t.Skip("gpg carries no numeric alias on this tree")
	}
	for i := 0; i < 20; i++ {
		again, _ := universalHashRegistry.hashcatMode("gpg")
		if again != first {
			t.Fatalf("hashcatMode(gpg) is unstable: %d then %d", first, again)
		}
	}
}

func TestJohnLabelLookup(t *testing.T) {
	cases := []struct {
		typ  string
		want string
	}{
		{"md5", "raw-md5"}, {"ntlm", "NT"}, {"lm", "LM"},
		{"sha1", "raw-sha1"}, {"sha512crypt", "sha512crypt"},
		{"descrypt", "descrypt"}, {"bcrypt", "bcrypt"},
	}
	for _, c := range cases {
		got, ok := universalHashRegistry.johnLabel(c.typ)
		if !ok {
			t.Errorf("johnLabel(%q): not found, want %q", c.typ, c.want)
			continue
		}
		if got != c.want {
			t.Errorf("johnLabel(%q) = %q, want %q", c.typ, got, c.want)
		}
	}
}

// Every John label declared must name a format that exists, or the column
// will print a label for a type Hashsmith cannot actually crack.
func TestJohnLabelSeedNamesRealFormats(t *testing.T) {
	for typ, label := range johnLabelSeed() {
		if _, ok := universalHashRegistry.formats[typ]; !ok {
			t.Errorf("johnLabelSeed declares label %q for unknown format %q", label, typ)
		}
	}
}

func TestUnknownFormatHasNoMetadata(t *testing.T) {
	if _, ok := universalHashRegistry.hashcatMode("no-such-format"); ok {
		t.Error("hashcatMode invented a mode for an unknown format")
	}
	if _, ok := universalHashRegistry.johnLabel("no-such-format"); ok {
		t.Error("johnLabel invented a label for an unknown format")
	}
}
