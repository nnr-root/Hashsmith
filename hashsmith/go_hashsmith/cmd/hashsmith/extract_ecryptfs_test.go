package main

import (
	"os"
	"path/filepath"
	"testing"
)

// eCryptfs wrapped-passphrase extraction, over both file versions and over the
// salt that lives outside the file.
//
// The record's contents are hashcat's published -m 12200 example taken apart:
// salt 4207883745556753 and signature 567daa975114206c for the password
// "hashcat". Rebuilding the container around them means the extractor is
// checked against a record known to be right, rather than against itself.
func TestECryptfsExtraction(t *testing.T) {
	const (
		sig      = "567daa975114206c"
		saltHex  = "4207883745556753"
		password = "hashcat"
	)
	salt := []byte{0x42, 0x07, 0x88, 0x37, 0x45, 0x55, 0x67, 0x53}

	t.Run("version 2 carries its own salt", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "wrapped-passphrase")
		body := append([]byte{':', 0x02}, salt...)
		if err := os.WriteFile(path, append(body, sig...), 0o600); err != nil {
			t.Fatal(err)
		}
		recs, err := extractECryptfsRecords(path)
		if err != nil {
			t.Fatal(err)
		}
		want := "$ecryptfs$0$1$" + saltHex + "$" + sig
		if recs[0] != want {
			t.Errorf("got %q, want %q", recs[0], want)
		}
		assertECryptfsCracks(t, recs[0], password)
	})

	t.Run("version 1 with a .ecryptfsrc beside it", func(t *testing.T) {
		dir := t.TempDir()
		ecryptfs := filepath.Join(dir, ".ecryptfs")
		if err := os.MkdirAll(ecryptfs, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, ".ecryptfsrc"),
			[]byte("key=passphrase\nsalt="+saltHex+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(ecryptfs, "wrapped-passphrase")
		if err := os.WriteFile(path, []byte(sig), 0o600); err != nil {
			t.Fatal(err)
		}
		recs, err := extractECryptfsRecords(path)
		if err != nil {
			t.Fatal(err)
		}
		want := "$ecryptfs$0$1$" + saltHex + "$" + sig
		if recs[0] != want {
			t.Errorf("got %q, want %q — the salt beside the file was not picked up", recs[0], want)
		}
		assertECryptfsCracks(t, recs[0], password)
	})

	// The parent-directory search must NOT fire for a file that is merely
	// somewhere under a home directory. A wrapped-passphrase copied elsewhere
	// would otherwise take a salt it was never wrapped with, producing a
	// record that looks MORE precise than the short one and cannot crack.
	t.Run("a loose copy does not borrow a salt", func(t *testing.T) {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, ".ecryptfsrc"),
			[]byte("salt="+saltHex+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		sub := filepath.Join(dir, "copies")
		if err := os.MkdirAll(sub, 0o700); err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(sub, "wp")
		if err := os.WriteFile(path, []byte(sig), 0o600); err != nil {
			t.Fatal(err)
		}
		recs, err := extractECryptfsRecords(path)
		if err != nil {
			t.Fatal(err)
		}
		if recs[0] != "$ecryptfs$0$"+sig {
			t.Errorf("got %q; a file outside a .ecryptfs directory must not take the "+
				"parent's salt", recs[0])
		}
	})

	t.Run("a file that is not a wrapped passphrase is refused", func(t *testing.T) {
		dir := t.TempDir()
		for name, body := range map[string]string{
			"short":    "abc",
			"nonhex":   "zzzzzzzzzzzzzzzz",
			"trunc_v2": ":\x02short",
		} {
			path := filepath.Join(dir, name)
			if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := extractECryptfsRecords(path); err == nil {
				t.Errorf("%s was accepted as a wrapped-passphrase", name)
			}
		}
	})
}

func assertECryptfsCracks(t *testing.T, record, password string) {
	t.Helper()
	ok, err := verifyCandidate(password, record, "ecryptfs", "", "")
	if err != nil {
		t.Fatalf("verifying %s: %v", record, err)
	}
	if !ok {
		t.Errorf("%s did not crack with %q", record, password)
	}
	if ok, _ := verifyCandidate("definitely-not-it-9137", record, "ecryptfs", "", ""); ok {
		t.Errorf("%s accepted a wrong password", record)
	}
}
