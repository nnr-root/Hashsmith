package smith

import (
	"os"
	"path/filepath"
	"testing"
)

func TestPotfileRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "test.pot")
	p, err := loadPotfile(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := p.lookup("deadbeef"); ok {
		t.Fatal("empty potfile should have no entries")
	}
	// A hash containing ':' (NetNTLM-style) and a plaintext containing ':' must
	// round-trip intact thanks to the TAB separator.
	hash := "user::DOMAIN:1122:aabb:ccdd"
	plain := "p:a:s:s"
	p.add(hash, plain)
	p.add(hash, "ignored-duplicate")

	reloaded, err := loadPotfile(path)
	if err != nil {
		t.Fatal(err)
	}
	got, ok := reloaded.lookup(hash)
	if !ok || got != plain {
		t.Fatalf("round-trip failed: got %q ok=%v", got, ok)
	}
}

func TestDecodeHashcatHexPlain(t *testing.T) {
	cases := []struct{ in, want string }{
		{"hello", "hello"},
		{"café", "café"},
		{"$HEX[61623a6364]", "ab:cd"},
		{"$HEX[610962]", "a\tb"},
		{"$HEX[zz]", "$HEX[zz]"}, // invalid hex inside — hashcat's own ambiguity, left raw
	}
	for _, c := range cases {
		if got := decodeHashcatHexPlain(c.in); got != c.want {
			t.Errorf("decodeHashcatHexPlain(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestLoadPotfileHashcatFormat(t *testing.T) {
	path := filepath.Join(t.TempDir(), "hashcat.pot")
	// Written by hand in hashcat's own on-disk shape, exactly as produced by
	// a real `hashcat --potfile-path` run (verified empirically 2026-10-02):
	// plain ascii unescaped, a colon-containing plaintext hex-escaped, and a
	// salted-mode entry whose key has the salt folded in via hashcat's own
	// colon join.
	content := "5d41402abc4b2a76b9719d911017c592:hello\n" +
		"7421742cb38488304149bb5332975204:$HEX[61623a6364]\n" +
		"8e8327204e54d58ce328098b38200580:abc123:secretpw\n"
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	p, err := loadPotfile(path)
	if err != nil {
		t.Fatal(err)
	}
	if got, ok := p.lookup("5d41402abc4b2a76b9719d911017c592"); !ok || got != "hello" {
		t.Errorf("plain ascii: got %q ok=%v", got, ok)
	}
	if got, ok := p.lookup("7421742cb38488304149bb5332975204"); !ok || got != "ab:cd" {
		t.Errorf("hex-escaped: got %q ok=%v", got, ok)
	}
	if got, ok := p.lookup("8e8327204e54d58ce328098b38200580:abc123"); !ok || got != "secretpw" {
		t.Errorf("salt-folded key: got %q ok=%v", got, ok)
	}
}
