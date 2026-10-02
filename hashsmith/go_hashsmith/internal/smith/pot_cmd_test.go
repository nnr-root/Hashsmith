package smith

import (
	"os"
	"path/filepath"
	"testing"
)

// TestRunCrackPotfileFormatHashcat exercises the real CLI flag end-to-end:
// cracking a target with --potfile-format hashcat must append a
// hashcat-shaped (colon, $HEX[]-escaped where needed) line, not Hashsmith's
// native TAB line.
func TestRunCrackPotfileFormatHashcat(t *testing.T) {
	dir := t.TempDir()
	potPath := filepath.Join(dir, "out.pot")
	wordlistPath := filepath.Join(dir, "words.txt")
	mustWrite(t, wordlistPath, "ab:cd\n")
	target := md5hex("ab:cd")

	if err := runCrack([]string{"-t", "md5", "-w", wordlistPath,
		"--pot", potPath, "--potfile-format", "hashcat", target}); err != nil {
		t.Fatalf("runCrack: %v", err)
	}

	raw, err := os.ReadFile(potPath)
	if err != nil {
		t.Fatal(err)
	}
	want := target + ":$HEX[61623a6364]\n"
	if string(raw) != want {
		t.Fatalf("potfile content = %q, want %q", raw, want)
	}
}
