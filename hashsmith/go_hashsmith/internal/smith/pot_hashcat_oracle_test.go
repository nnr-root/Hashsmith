package smith

import (
	"os"
	"os/exec"
	"path/filepath"
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
