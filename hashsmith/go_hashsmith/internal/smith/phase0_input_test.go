package smith

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// Phase 0 regression tests. Each one pins a defect measured on 2026-09-20 and
// recorded in docs/superpowers/plans/2026-09-20-beating-john-and-hashcat.md §2.1.
// They exist so the input layer can never silently rewrite user input again.

// Defect A: a comma inside one positional argument must not split it into two
// inputs. Hashcat's own records for -m 10300/21600/30601/34000/35000/70000
// contain commas and were unreachable from the command line because of this.
func TestCollectInputsDoesNotSplitOnComma(t *testing.T) {
	got, err := collectInputs("a,b")
	if err != nil {
		t.Fatalf("collectInputs: %v", err)
	}
	if len(got) != 1 || got[0] != "a,b" {
		t.Errorf("collectInputs(%q) = %q; want one input %q", "a,b", got, "a,b")
	}
}

// Opting in with --split restores the documented comma-list convenience.
func TestCollectInputsSplitsWhenAsked(t *testing.T) {
	got, err := collectInputsOpts("a, b ,c", inputOpts{split: true, sep: ","})
	if err != nil {
		t.Fatalf("collectInputsOpts: %v", err)
	}
	want := []string{"a", "b", "c"}
	if len(got) != len(want) {
		t.Fatalf("got %q; want %q", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("element %d = %q; want %q", i, got[i], want[i])
		}
	}
}

// Defect B: surrounding whitespace is data. quoted-printable exists to encode
// it; stripping it makes the codec unable to produce the =20 it is for.
func TestCollectInputsPreservesSurroundingWhitespace(t *testing.T) {
	const in = "  padded  "
	got, err := collectInputs(in)
	if err != nil {
		t.Fatalf("collectInputs: %v", err)
	}
	if len(got) != 1 || got[0] != in {
		t.Errorf("collectInputs(%q) = %q; want the input unchanged", in, got)
	}
}

// Defect D: "-" means stdin, everywhere, like every other Unix tool.
func TestCollectInputsReadsStdinForDash(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.WriteString("alpha\nbeta\n"); err != nil {
		t.Fatal(err)
	}
	w.Close()
	saved := os.Stdin
	os.Stdin = r
	defer func() { os.Stdin = saved; r.Close() }()

	got, err := collectInputsOpts("-", inputOpts{stdin: true})
	if err != nil {
		t.Fatalf("collectInputsOpts(-): %v", err)
	}
	if len(got) != 2 || got[0] != "alpha" || got[1] != "beta" {
		t.Errorf("stdin inputs = %q; want [alpha beta]", got)
	}
}

// Defect E: isGzipFile must never consume bytes from a non-regular file. It is
// called on -w paths purely to label the source line; on /dev/stdin the old
// destructive read ate the first two bytes of the first candidate, so
// "password" was attempted as "ssword".
func TestIsGzipFileDoesNotConsumeFromPipe(t *testing.T) {
	dir := t.TempDir()
	fifo := filepath.Join(dir, "wl.fifo")
	if err := makeFIFO(fifo); err != nil {
		t.Skipf("cannot create FIFO on this platform: %v", err)
	}
	go func() {
		f, err := os.OpenFile(fifo, os.O_WRONLY, 0)
		if err != nil {
			return
		}
		f.WriteString("password\nabcdef\n")
		f.Close()
	}()

	if isGzipFile(fifo) {
		t.Fatal("a plain-text FIFO must not be reported as gzip")
	}
	rc, _, err := openWordlist(fifo)
	if err != nil {
		t.Fatalf("openWordlist: %v", err)
	}
	defer rc.Close()
	buf := make([]byte, 64)
	n, _ := rc.Read(buf)
	if got := string(buf[:n]); !strings.HasPrefix(got, "password") {
		t.Errorf("first bytes of the wordlist = %q; want it to start with \"password\" (bytes were consumed)", got)
	}
}

// Defect F: an explicit -t is the user declaring the format. The normalizer,
// which exists to help auto-detection, must not overrule it. Hashcat's own
// descrypt record 24leDr0hHfb3A was being rewritten as Base32hex and rejected.
func TestExplicitTypeSuppressesNormalization(t *testing.T) {
	const descryptRecord = "24leDr0hHfb3A"
	if got, enc := normalizeHashInput(descryptRecord); enc == "" || got == descryptRecord {
		t.Skipf("normalizeHashInput no longer rewrites %q (enc=%q); defect F cannot recur this way", descryptRecord, enc)
	}
	if shouldNormalizeTarget("descrypt") {
		t.Error("shouldNormalizeTarget(\"descrypt\") = true; an explicit type must suppress normalization")
	}
	if !shouldNormalizeTarget("") {
		t.Error("shouldNormalizeTarget(\"\") = false; auto-detection still needs normalization")
	}
	if !shouldNormalizeTarget("auto") {
		t.Error("shouldNormalizeTarget(\"auto\") = false; auto-detection still needs normalization")
	}
}

// End-to-end proof of defect F against Hashcat's canonical descrypt record.
func TestCrackDescryptAcceptsHashcatCanonicalRecord(t *testing.T) {
	bin := buildTestBinary(t)
	dir := t.TempDir()
	wl := filepath.Join(dir, "wl.txt")
	if err := os.WriteFile(wl, []byte("decoy\nhashcat\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(bin, "-N", "crack", "-t", "descrypt", "24leDr0hHfb3A",
		"-w", wl, "--no-pot")
	out, _ := cmd.CombinedOutput()
	if !strings.Contains(string(out), "hashcat") {
		t.Errorf("descrypt crack of hashcat's own example did not recover the password.\n%s", out)
	}
}

// Defect: crack must write its results to stdout so they can be piped.
func TestCrackWritesResultToStdout(t *testing.T) {
	bin := buildTestBinary(t)
	dir := t.TempDir()
	wl := filepath.Join(dir, "wl.txt")
	if err := os.WriteFile(wl, []byte("decoy\npassword\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(bin, "-N", "crack", "-t", "md5",
		"5f4dcc3b5aa765d61d8327deb882cf99", "-w", wl, "--no-pot")
	var stdout strings.Builder
	cmd.Stdout = &stdout
	cmd.Stderr = nil
	if err := cmd.Run(); err != nil {
		t.Fatalf("crack: %v", err)
	}
	if !strings.Contains(stdout.String(), "password") {
		t.Errorf("crack stdout = %q; want the recovered plaintext on stdout", stdout.String())
	}
}

// The binary must be able to say what it is.
func TestVersionFlag(t *testing.T) {
	bin := buildTestBinary(t)
	for _, args := range [][]string{{"--version"}, {"version"}, {"-V"}} {
		out, err := exec.Command(bin, args...).CombinedOutput()
		if err != nil {
			t.Errorf("%v: %v\n%s", args, err, out)
			continue
		}
		if !strings.Contains(string(out), "hashsmith") {
			t.Errorf("%v printed %q; want a version line naming hashsmith", args, out)
		}
	}
}

// Every subcommand must answer --help instead of erroring.
func TestPerCommandHelp(t *testing.T) {
	bin := buildTestBinary(t)
	for _, cmd := range []string{"crack", "encode", "decode", "hash", "identify", "rules", "benchmark"} {
		out, err := exec.Command(bin, "-N", cmd, "--help").CombinedOutput()
		if err != nil {
			t.Errorf("%s --help exited %v\n%s", cmd, err, out)
			continue
		}
		if strings.Contains(string(out), "flag: help requested") {
			t.Errorf("%s --help leaked the flag-package error:\n%s", cmd, out)
		}
		if !strings.Contains(strings.ToLower(string(out)), cmd) {
			t.Errorf("%s --help did not describe the command:\n%s", cmd, out)
		}
	}
}
