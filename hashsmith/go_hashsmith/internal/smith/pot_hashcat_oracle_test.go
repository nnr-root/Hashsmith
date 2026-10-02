package smith

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestImportRealHashcatPotfile runs the real hashcat binary to produce a
// genuine potfile (colon format, $HEX[]-escaped where hashcat itself
// decides to), then confirms Hashsmith's --show reads it correctly. Skips
// if hashcat is not installed rather than failing, matching
// scripts/rules-oracle.sh's convention.
func TestImportRealHashcatPotfile(t *testing.T) {
	hashcatBin, err := exec.LookPath("hashcat")
	if err != nil {
		t.Skip("hashcat not installed, skipping real-oracle potfile test")
	}

	dir := t.TempDir()
	hashFile := filepath.Join(dir, "hash.txt")
	wordFile := filepath.Join(dir, "words.txt")
	potFile := filepath.Join(dir, "hashcat.pot")

	// md5("ab:cd") — deliberately chosen to force hashcat's own $HEX[]
	// escaping (see the spec: a plaintext containing ':' always triggers it).
	target := "7421742cb38488304149bb5332975204"
	if err := os.WriteFile(hashFile, []byte(target+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(wordFile, []byte("ab:cd\n"), 0600); err != nil {
		t.Fatal(err)
	}

	cmd := exec.Command(hashcatBin, "-m", "0", "-a", "0",
		"--potfile-path", potFile, "--force", hashFile, wordFile)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("hashcat run failed: %v\n%s", err, out)
	}

	p, err := loadPotfile(potFile)
	if err != nil {
		t.Fatal(err)
	}
	got, ok := p.lookup(target)
	if !ok {
		t.Fatalf("Hashsmith failed to read the real hashcat potfile entry for %s", target)
	}
	if got != "ab:cd" {
		t.Fatalf("got plaintext %q, want %q", got, "ab:cd")
	}
}

// TestVerifiedPlainSaltFoldedFallbackRealHashcat is the live-oracle version
// of TestVerifiedPlainSaltFoldedFallback (pot_test.go / pot_verify_test.go),
// which pins the same shape with a hand-built fixture. Here the real
// hashcat binary runs a genuine -m 10 (md5($pass.$salt)) crack and writes
// its own potfile, which Hashsmith then reads and verifies through
// verifiedPlain's salt-folded fallback — closing the "oracle-untested"
// finding on that fallback's premise (that hashcat folds the salt into the
// potfile key via "hash:salt:plain" for modes whose input line is itself
// "hash:salt"). The test vector (md5("secretpw"+"abc123") =
// 8e8327204e54d58ce328098b38200580) is the same one the spec documents as
// confirmed directly against real hashcat 7.1.2, 2026-10-02.
func TestVerifiedPlainSaltFoldedFallbackRealHashcat(t *testing.T) {
	hashcatBin, err := exec.LookPath("hashcat")
	if err != nil {
		t.Skip("hashcat not installed, skipping real-oracle potfile test")
	}

	dir := t.TempDir()
	hashFile := filepath.Join(dir, "hash.txt")
	wordFile := filepath.Join(dir, "words.txt")
	potFile := filepath.Join(dir, "hashcat.pot")

	const (
		target = "8e8327204e54d58ce328098b38200580" // md5("secretpw" + "abc123")
		salt   = "abc123"
		plain  = "secretpw"
	)
	// -m 10's own input line shape is "hash:salt" — not Hashsmith's separate
	// -s flag, which is exactly the mismatch verifiedPlain's fallback exists
	// to bridge.
	if err := os.WriteFile(hashFile, []byte(target+":"+salt+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(wordFile, []byte(plain+"\n"), 0600); err != nil {
		t.Fatal(err)
	}

	cmd := exec.Command(hashcatBin, "-m", "10", "-a", "0",
		"--potfile-path", potFile, "--force", hashFile, wordFile)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("hashcat run failed: %v\n%s", err, out)
	}

	p, err := loadPotfile(potFile)
	if err != nil {
		t.Fatal(err)
	}
	// verifiedPlain is called with the BARE target hash and salt supplied
	// separately, exactly as Hashsmith's own -s/-S flags would pass them —
	// not the hash:salt combined string hashcat wrote as its key. "suffix"
	// matches -m 10's md5($pass.$salt) construction (salt appended after
	// the password), the same saltMode pot_verify_test.go's hand-built
	// fixture test uses for this identical vector.
	got, status := p.verifiedPlain(target, "md5", salt, "suffix")
	if status != potVerified {
		t.Fatalf("status = %v, want potVerified", status)
	}
	if got != plain {
		t.Fatalf("got plaintext %q, want %q", got, plain)
	}
}

// TestPotfileWriteFormatHashcatReadableByRealHashcat is the reverse
// round-trip the finding names: Hashsmith WRITES a potfile in
// --potfile-format hashcat, and the real hashcat binary — not just a
// string comparison against the raw bytes — reads it back via --show and
// reports the same plaintext. This confirms what Hashsmith emits is
// genuinely parseable by hashcat itself, including the $HEX[] escaping
// hashcat's own --show output re-applies when it echoes a colon-containing
// plaintext (confirmed by hand against the real binary while writing this
// test: hashcat's --show output for this entry is itself
// "<hash>:$HEX[...]", decoded here with the same decodeHashcatHexPlain
// production code loadPotfile uses, rather than a second hand-rolled
// decoder).
func TestPotfileWriteFormatHashcatReadableByRealHashcat(t *testing.T) {
	hashcatBin, err := exec.LookPath("hashcat")
	if err != nil {
		t.Skip("hashcat not installed, skipping real-oracle potfile test")
	}

	dir := t.TempDir()
	potFile := filepath.Join(dir, "hashcat.pot")
	hashFile := filepath.Join(dir, "hash.txt")

	// Same vector as TestImportRealHashcatPotfile: md5("ab:cd"), chosen
	// because a ':' in the plaintext forces Hashsmith's $HEX[] escaping on
	// write (see needsHashcatHexEncode in pot.go) — the trickiest case to
	// round-trip, not the easy unescaped one.
	const target = "7421742cb38488304149bb5332975204"
	const plain = "ab:cd"

	p, err := loadPotfile(potFile) // file does not exist yet: empty potfile at this path
	if err != nil {
		t.Fatal(err)
	}
	p.writeFormat = "hashcat"
	p.add(target, plain) // Hashsmith's own write path under test

	if err := os.WriteFile(hashFile, []byte(target+"\n"), 0600); err != nil {
		t.Fatal(err)
	}

	// Real hashcat reads the file Hashsmith just wrote as its
	// --potfile-path and reports what it finds for this hash via --show —
	// this is hashcat itself parsing Hashsmith's output, not Hashsmith
	// re-reading its own write.
	cmd := exec.Command(hashcatBin, "-m", "0", "--show",
		"--potfile-path", potFile, hashFile)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("hashcat --show failed: %v\n%s", err, out)
	}

	outStr := strings.TrimSpace(string(out))
	i := strings.LastIndexByte(outStr, ':')
	if i <= 0 {
		t.Fatalf("unexpected hashcat --show output: %q", outStr)
	}
	gotHash, gotPlainField := outStr[:i], outStr[i+1:]
	if gotHash != target {
		t.Fatalf("hashcat --show reported hash %q, want %q (full output: %q)", gotHash, target, outStr)
	}
	if got := decodeHashcatHexPlain(gotPlainField); got != plain {
		t.Fatalf("hashcat --show reported plaintext %q, want %q (full output: %q)", got, plain, outStr)
	}
}
