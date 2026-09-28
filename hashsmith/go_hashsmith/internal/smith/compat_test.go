package smith

// Tests for compat.go: the hashcat/John the Ripper argv-rewriter.

import (
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func assertCompat(t *testing.T, in, want []string) {
	t.Helper()
	got, err := translateCompatArgs(in)
	if err != nil {
		t.Fatalf("translateCompatArgs(%v): %v", in, err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("translateCompatArgs(%v)\n  got:  %v\n  want: %v", in, got, want)
	}
}

func assertCompatRefuses(t *testing.T, in []string, wantSubstr string) {
	t.Helper()
	_, err := translateCompatArgs(in)
	if err == nil {
		t.Fatalf("translateCompatArgs(%v) should have refused, got no error", in)
	}
	if !strings.Contains(err.Error(), wantSubstr) {
		t.Errorf("translateCompatArgs(%v) error = %v, want it to mention %q", in, err, wantSubstr)
	}
}

// ── No trigger flag: passthrough unchanged ──────────────────────────────────

func TestCompatNoTriggerLeavesArgsUnchanged(t *testing.T) {
	in := []string{"-M", "dict", "-w", "list.txt", "-t", "md5", "hash.txt"}
	got, err := translateCompatArgs(in)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !reflect.DeepEqual(got, in) {
		t.Errorf("got %v, want args returned byte-identical (no trigger present)", got)
	}
}

// ── -a mode translation, including positional reinterpretation ─────────────

func TestCompatAttackMode0Straight(t *testing.T) {
	assertCompat(t,
		[]string{"-a", "0", "-m", "1000", "hash.txt", "wl.txt"},
		[]string{"-t", "1000", "-M", "dict", "-w", "wl.txt", "hash.txt"})
}

func TestCompatAttackMode1Combination(t *testing.T) {
	assertCompat(t,
		[]string{"-a", "1", "-m", "0", "hash.txt", "left.txt", "right.txt"},
		[]string{"-t", "0", "-M", "combinator", "-w", "left.txt", "--wordlist2", "right.txt", "hash.txt"})
}

func TestCompatAttackMode3Mask(t *testing.T) {
	assertCompat(t,
		[]string{"-a", "3", "-m", "0", "hash.txt", "?d?d?d?d?d?d"},
		[]string{"-t", "0", "-M", "mask", "--mask", "?d?d?d?d?d?d", "hash.txt"})
}

func TestCompatAttackMode6HybridWordlistThenMask(t *testing.T) {
	assertCompat(t,
		[]string{"-a", "6", "-m", "0", "hash.txt", "wl.txt", "?d?d"},
		[]string{"-t", "0", "-M", "hybrid", "-w", "wl.txt", "--mask", "?d?d", "hash.txt"})
}

func TestCompatAttackMode7HybridMaskThenWordlist(t *testing.T) {
	assertCompat(t,
		[]string{"-a", "7", "-m", "0", "hash.txt", "?d?d", "wl.txt"},
		[]string{"-t", "0", "-M", "hybrid", "--mask-first", "--mask", "?d?d", "-w", "wl.txt", "hash.txt"})
}

func TestCompatAttackMode9Association(t *testing.T) {
	assertCompat(t,
		[]string{"-a", "9", "-m", "0", "hash.txt", "wl1.txt", "wl2.txt"},
		[]string{"-t", "0", "-M", "association", "--assoc-wordlist", "wl1.txt", "--assoc-wordlist", "wl2.txt", "hash.txt"})
}

func TestCompatAttackModeUnsupportedNumberRefuses(t *testing.T) {
	assertCompatRefuses(t, []string{"-a", "2", "-m", "0", "hash.txt", "wl.txt"}, "-a 2")
}

func TestCompatAttackModeWrongPositionalCountRefuses(t *testing.T) {
	// mode 0 wants exactly one positional (a wordlist) after the target.
	assertCompatRefuses(t, []string{"-a", "0", "-m", "1000", "hash.txt"}, "-a 0")
	assertCompatRefuses(t, []string{"-a", "0", "-m", "1000", "hash.txt", "wl.txt", "extra.txt"}, "-a 0")
}

func TestCompatMissingTargetRefuses(t *testing.T) {
	assertCompatRefuses(t, []string{"-a", "0", "-m", "1000"}, "target")
}

// ── --format (JtR) and bare -m without -a ───────────────────────────────────

func TestCompatFormatEqualsSyntax(t *testing.T) {
	assertCompat(t,
		[]string{"--format=raw-md5", "hash.txt"},
		[]string{"-t", "raw-md5", "hash.txt"})
}

func TestCompatFormatSpaceSyntax(t *testing.T) {
	assertCompat(t,
		[]string{"--format", "raw-md5", "hash.txt"},
		[]string{"-t", "raw-md5", "hash.txt"})
}

func TestCompatBareHashTypeWithoutAttackMode(t *testing.T) {
	assertCompat(t,
		[]string{"-m", "1000", "hash.txt"},
		[]string{"-t", "1000", "hash.txt"})
}

func TestCompatBareHashTypeExtraPositionalRefuses(t *testing.T) {
	// Without -a there is no attack-mode-specific positional to interpret —
	// an extra positional beyond the target must not be silently dropped.
	assertCompatRefuses(t, []string{"-m", "1000", "hash.txt", "wl.txt"}, "positional")
}

// ── Passthrough of already-identical flags ──────────────────────────────────

func TestCompatPassesThroughIdenticalFlags(t *testing.T) {
	assertCompat(t,
		[]string{"-a", "0", "-m", "1000", "--show", "--left", "-1", "?l?d", "hash.txt", "wl.txt"},
		[]string{"-t", "1000", "--show", "--left", "-1", "?l?d", "-M", "dict", "-w", "wl.txt", "hash.txt"})
}

func TestCompatIncrementMinMax(t *testing.T) {
	assertCompat(t,
		[]string{"-a", "0", "-m", "1000", "--increment-min", "4", "--increment-max", "8", "hash.txt", "wl.txt"},
		[]string{"-t", "1000", "-n", "4", "-x", "8", "-M", "dict", "-w", "wl.txt", "hash.txt"})
}

// ── Refused: hashcat/JtR flags colliding with an existing native flag ──────

func TestCompatRefusesCollidingShortFlags(t *testing.T) {
	for _, flag := range []string{"-M", "-t", "-p", "-n", "-s", "-w", "-r", "-S", "-i", "-l", "-u", "-T", "-j", "-k"} {
		t.Run(flag, func(t *testing.T) {
			assertCompatRefuses(t, []string{"-a", "0", "-m", "1000", flag, "x", "hash.txt", "wl.txt"}, flag)
		})
	}
}

func TestCompatRefusesUnsupportedCustomCharsets(t *testing.T) {
	for _, flag := range []string{"-5", "-6", "-7", "-8"} {
		t.Run(flag, func(t *testing.T) {
			assertCompatRefuses(t, []string{"-a", "0", "-m", "1000", flag, "?l", "hash.txt", "wl.txt"}, "1-4")
		})
	}
}

func TestCompatRefusesFork(t *testing.T) {
	assertCompatRefuses(t, []string{"--format=raw-md5", "--fork", "4", "hash.txt"}, "skip")
}

func TestCompatRefusesIncremental(t *testing.T) {
	assertCompatRefuses(t, []string{"--format=raw-md5", "--incremental", "hash.txt"}, "markov")
	assertCompatRefuses(t, []string{"--format=raw-md5", "--incremental=All", "hash.txt"}, "markov")
}

// ── End-to-end: a real pasted hashcat-style command line actually cracks ──

func TestCompatEndToEndStraightAttackCracks(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	dir := t.TempDir()

	target := md5hex("correcthorse")
	targetsFile := filepath.Join(dir, "targets.txt")
	mustWrite(t, targetsFile, target+"\n")

	wl := filepath.Join(dir, "wl.txt")
	mustWrite(t, wl, "wrongguess\ncorrecthorse\nanotherguess\n")

	stderr := captureStderr(t, func() error {
		// A real hashcat invocation: -a 0 (straight), -m 0 (MD5), positional
		// hashlist then wordlist — no native -M/-w/-t at all.
		return runCrack([]string{"-a", "0", "-m", "0", "--no-pot", targetsFile, wl})
	})
	if !strings.Contains(stderr, "correcthorse") {
		t.Fatalf("hashcat-style invocation should have cracked the target, stderr:\n%s", stderr)
	}
}

func TestCompatEndToEndMaskAttackCracks(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	dir := t.TempDir()

	target := md5hex("1234")
	targetsFile := filepath.Join(dir, "targets.txt")
	mustWrite(t, targetsFile, target+"\n")

	stderr := captureStderr(t, func() error {
		// -a 3 (mask), mask given positionally, exactly as real hashcat.
		return runCrack([]string{"-a", "3", "-m", "0", "--no-pot", targetsFile, "?d?d?d?d"})
	})
	if !strings.Contains(stderr, "1234") {
		t.Fatalf("hashcat-style mask attack should have cracked the target, stderr:\n%s", stderr)
	}
}

func TestCompatEndToEndAssociationAttackCracks(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	dir := t.TempDir()

	target0 := md5hex("wordA")
	target1 := md5hex("wordB")
	targetsFile := filepath.Join(dir, "targets.txt")
	mustWrite(t, targetsFile, target0+"\n"+target1+"\n")

	wl := filepath.Join(dir, "assoc.txt")
	mustWrite(t, wl, "wordA\nwordB\n")

	stderr := captureStderr(t, func() error {
		// -a 9 (association), a real hashcat invocation shape.
		return runCrack([]string{"-a", "9", "-m", "0", "--no-pot", targetsFile, wl})
	})
	if !strings.Contains(stderr, "wordA") || !strings.Contains(stderr, "wordB") {
		t.Fatalf("hashcat-style association attack should have cracked both targets, stderr:\n%s", stderr)
	}
}

func TestCompatEndToEndCollidingFlagRefusesLoudly(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	dir := t.TempDir()
	target := md5hex("x")
	targetsFile := filepath.Join(dir, "targets.txt")
	mustWrite(t, targetsFile, target+"\n")
	wl := filepath.Join(dir, "wl.txt")
	mustWrite(t, wl, "x\n")

	// A real hashcat workload flag (-w 4) must never be silently
	// misinterpreted as this project's own -w (wordlist path "4").
	err := runCrack([]string{"-a", "0", "-m", "0", "-w", "4", "--no-pot", targetsFile, wl})
	if err == nil {
		t.Fatal("a pasted hashcat -w (workload profile) must refuse, not silently misread as a wordlist path")
	}
	if !strings.Contains(err.Error(), "-w") {
		t.Errorf("refusal should name -w specifically, got: %v", err)
	}
}
