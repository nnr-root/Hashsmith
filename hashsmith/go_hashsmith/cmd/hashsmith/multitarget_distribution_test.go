package main

// Multi-target (hash dump) distribution: --skip/--limit slicing and --session
// resume, driven through the real CLI.
//
// The bug these tests exist for: a dump run with --skip/--limit used to be
// diverted away from multi-hash mode entirely and re-cracked one target at a
// time, reporting single-target "Not found" lines instead of the per-hash
// listing. That is precisely backwards for distributed cracking — splitting ONE
// dump's keyspace across machines is what --skip/--limit are for — and it is
// the worst failure shape this tool has: an operator who splits a dump and gets
// nothing back from every slice concludes the passwords are not in the
// keyspace, when in fact they were compared against the wrong thing (or, with
// the per-target sweep's N-fold cost, never reached at all).
//
// So every assertion below is on the recovered (hash, plaintext) PAIRS, never
// on a count: a count cannot tell "found five" from "found five of somebody
// else's targets", and mis-attribution under slicing or resume is the quiet
// half of the same failure.

import (
	"fmt"
	"path/filepath"
	"strings"
	"testing"
)

// ── harness ─────────────────────────────────────────────────────────────────

// dumpCharset/dumpLen fix a small, exactly-enumerable keyspace (1000
// candidates) so a test can place a plaintext at a CHOSEN global index and then
// slice or interrupt around it. Boundary placement is the whole point: an
// off-by-one in a slice bound only shows up when a target sits exactly on it.
const (
	dumpCharset = "abcdefghij"
	dumpLen     = 3
	dumpTotal   = 1000
)

func dumpLayout() *keyspaceLayout { return bruteLayout(dumpCharset, dumpLen, dumpLen) }

// writeDump builds a dump file holding the md5 of the candidate at each of
// `idxs` plus `ghosts` uncrackable targets, and returns the file path together
// with the hash -> plaintext map the run must recover EXACTLY.
func writeDump(t *testing.T, dir string, idxs []int64, ghosts int) (string, map[string]string) {
	t.Helper()
	l := dumpLayout()
	want := map[string]string{}
	var lines []string
	for i, idx := range idxs {
		pw := l.candidate(idx)
		want[md5hex(pw)] = pw
		lines = append(lines, md5hex(pw))
		if i < ghosts {
			// Interleave the ghosts so a run that somehow attacked only a
			// prefix of the file would still be caught by the pair set.
			lines = append(lines, md5hex(fmt.Sprintf("ghost-%d-never-in-keyspace", i)))
		}
	}
	for i := len(idxs); i < ghosts; i++ {
		lines = append(lines, md5hex(fmt.Sprintf("ghost-%d-never-in-keyspace", i)))
	}
	path := filepath.Join(dir, "dump.txt")
	mustWrite(t, path, strings.Join(lines, "\n")+"\n")
	return path, want
}

// crackDump runs the CLI over `dumpPath` with the given extra flags and returns
// the recovered hash -> plaintext pairs (read back from -o) plus stderr. Every
// pair is checked for self-consistency here, so ATTRIBUTION is verified on
// every single run in this file rather than in one dedicated test: a plaintext
// filed against a hash it does not produce is a failure no matter which
// property the caller was actually asserting.
func crackDump(t *testing.T, dir, tag, dumpPath string, extra ...string) (map[string]string, string) {
	t.Helper()
	outFile := filepath.Join(dir, tag+".out")
	args := append([]string{
		"-t", "md5", "-M", "brute", "-C", dumpCharset,
		"-n", fmt.Sprint(dumpLen), "-x", fmt.Sprint(dumpLen),
		"-o", outFile,
	}, extra...)
	args = append(args, dumpPath)

	exitCode = 0
	stderr := captureStderr(t, func() error { return runCrack(args) })

	got := map[string]string{}
	for _, line := range readResultPairs(t, outFile) {
		h, pw, ok := strings.Cut(line, ":")
		if !ok {
			t.Fatalf("%s: malformed result line %q", tag, line)
		}
		if md5hex(pw) != h {
			t.Fatalf("%s: MIS-ATTRIBUTION: %q filed against %s (it hashes to %s)",
				tag, pw, h, md5hex(pw))
		}
		if prev, dup := got[h]; dup {
			t.Fatalf("%s: %s reported twice (%q then %q)", tag, h, prev, pw)
		}
		got[h] = pw
	}
	return got, stderr
}

func assertPairs(t *testing.T, tag string, got, want map[string]string) {
	t.Helper()
	for h, pw := range want {
		if got[h] != pw {
			t.Errorf("%s: %s => %q, want %q", tag, h, got[h], pw)
		}
	}
	for h, pw := range got {
		if _, ok := want[h]; !ok {
			t.Errorf("%s: recovered an unexpected pair %s => %q", tag, h, pw)
		}
	}
}

// ── property 1: the bug itself ──────────────────────────────────────────────

// A slice covering the WHOLE keyspace must recover exactly what the unbounded
// run recovers. This is the reported failure, reduced: `--skip 0 --limit <more
// than the keyspace>` swept everything and matched nothing, because the flags
// diverted the dump off multi-hash mode altogether.
func TestMultiTargetWholeKeyspaceSliceMatchesUnboundedRun(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	dumpPath, want := writeDump(t, dir, []int64{0, 137, 500, 999}, 6)

	unbounded, _ := crackDump(t, dir, "unbounded", dumpPath, "--no-pot")
	assertPairs(t, "unbounded", unbounded, want)

	sliced, stderr := crackDump(t, dir, "sliced", dumpPath,
		"--no-pot", "--skip", "0", "--limit", fmt.Sprint(dumpTotal*12))
	assertPairs(t, "whole-keyspace slice", sliced, want)

	// Same pairs is the property; taking the right PATH is the diagnosis. A
	// sliced dump must be cracked as a dump — one sweep, every target compared
	// against every candidate — not re-run once per hash.
	if !strings.Contains(stderr, batchBannerPrefix) {
		t.Errorf("a sliced dump did not enter multi-hash mode:\n%s", stderr)
	}
	if strings.Contains(stderr, "Not found") {
		t.Errorf("a sliced dump printed single-target output:\n%s", stderr)
	}
}

// ── property 2: tiling ──────────────────────────────────────────────────────

// The union of disjoint slices of a dump must recover every target exactly
// once — nothing missed, nothing reported twice. This is the property
// distribution exists for: four machines, four slices, one dump.
//
// The plaintexts sit ON the slice boundaries (0, 249/250, 499/500, 999) so an
// inclusive/exclusive mix-up in a slice bound loses one or double-counts it.
func TestMultiTargetDisjointSlicesTileTheDump(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	dumpPath, want := writeDump(t, dir, []int64{0, 249, 250, 499, 500, 999}, 8)

	const slices = 4
	const sliceSize = dumpTotal / slices

	union := map[string]string{}
	seen := map[string]int{}
	for s := 0; s < slices; s++ {
		tag := fmt.Sprintf("slice%d", s)
		got, stderr := crackDump(t, dir, tag, dumpPath,
			"--no-pot", // each slice is an independent machine: no shared potfile
			"--skip", fmt.Sprint(s*sliceSize), "--limit", fmt.Sprint(sliceSize))
		if !strings.Contains(stderr, batchBannerPrefix) {
			t.Fatalf("%s did not enter multi-hash mode:\n%s", tag, stderr)
		}
		for h, pw := range got {
			seen[h]++
			union[h] = pw
		}
	}

	assertPairs(t, "union of slices", union, want)
	for h, n := range seen {
		if n != 1 {
			t.Errorf("%s was recovered by %d slices, want exactly 1", h, n)
		}
	}
	if len(seen) != len(want) {
		t.Errorf("slices recovered %d target(s), want %d", len(seen), len(want))
	}
}

// A slice that covers none of the crackable candidates must recover nothing —
// otherwise "each target exactly once" above could be satisfied by a bound
// that is quietly ignored.
func TestMultiTargetSliceRespectsItsBound(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	dumpPath, want := writeDump(t, dir, []int64{900, 950}, 4)

	empty, _ := crackDump(t, dir, "empty", dumpPath,
		"--no-pot", "--skip", "0", "--limit", "500")
	if len(empty) != 0 {
		t.Errorf("a slice holding none of the plaintexts recovered %v", empty)
	}
	rest, _ := crackDump(t, dir, "rest", dumpPath,
		"--no-pot", "--skip", "500", "--limit", "500")
	assertPairs(t, "second half", rest, want)
}

// ── property 3: session resume on a dump ────────────────────────────────────

// A multi-target run must checkpoint and resume, and — the part a checkpoint
// that over-reports progress destroys — a target positioned AFTER the
// interruption point must still be found by the resumed leg.
//
// Leg 1 is stopped by --limit rather than by a signal: both end the run with a
// saved checkpoint through the identical path (runSessionRunner's watermark),
// and only this form is deterministic enough to assert "leg 1 did NOT reach the
// late target, leg 2 did".
func TestMultiTargetSessionResumeFindsTargetsPastTheCheckpoint(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	const early, late = int64(100), int64(700)
	dumpPath, want := writeDump(t, dir, []int64{early, late}, 6)
	l := dumpLayout()
	earlyHash, lateHash := md5hex(l.candidate(early)), md5hex(l.candidate(late))

	leg1, stderr1 := crackDump(t, dir, "leg1", dumpPath, "--session", "dumpsess", "--limit", "400")
	if leg1[earlyHash] != l.candidate(early) {
		t.Fatalf("leg 1 missed the target inside its slice: %v\n%s", leg1, stderr1)
	}
	if _, ok := leg1[lateHash]; ok {
		t.Fatalf("leg 1 recovered a target past its --limit — the bound was ignored")
	}
	if !strings.Contains(stderr1, "Slice exhausted") {
		t.Errorf("leg 1 did not report that it stopped on its slice, not the keyspace:\n%s", stderr1)
	}

	// The checkpoint must record the slice actually swept — never more.
	sess, err := loadSession("dumpsess")
	if err != nil || sess == nil {
		t.Fatalf("no session saved after leg 1: %v", err)
	}
	if sess.Checkpoint > 400 {
		t.Fatalf("checkpoint %d claims more progress than the 400 candidates swept — "+
			"a resumed run would skip the gap in silence", sess.Checkpoint)
	}
	if sess.Total != dumpTotal {
		t.Errorf("session Total = %d, want the full keyspace %d", sess.Total, dumpTotal)
	}

	// Leg 2 resumes with no bound at all. It must pick up at the checkpoint and
	// reach the late target. Note the potfile is live here: leg 1's crack is
	// already recorded, which changes the still-unfound target set — the
	// session must still match itself across that change.
	leg2, stderr2 := crackDump(t, dir, "leg2", dumpPath, "--session", "dumpsess")
	if !strings.Contains(stderr2, "Resuming session") {
		t.Fatalf("leg 2 did not resume the session:\n%s", stderr2)
	}
	if leg2[lateHash] != l.candidate(late) {
		t.Fatalf("the resumed leg lost the target at index %d (past the checkpoint): %v\n%s",
			late, leg2, stderr2)
	}

	union := map[string]string{}
	for _, m := range []map[string]string{leg1, leg2} {
		for h, pw := range m {
			union[h] = pw
		}
	}
	assertPairs(t, "leg1 + leg2", union, want)

	// A completed sweep retires the session.
	if s, _ := loadSession("dumpsess"); s != nil {
		t.Errorf("session survived a run that exhausted the keyspace (checkpoint %d/%d)",
			s.Checkpoint, s.Total)
	}
}

// A session that has already swept the keyspace must resume as a no-op, not
// wrap around and re-sweep — the checkpoint is an index, not a count.
func TestMultiTargetSessionResumePastTheEndIsANoOp(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	dumpPath, want := writeDump(t, dir, []int64{5}, 3)

	first, _ := crackDump(t, dir, "first", dumpPath, "--no-pot", "--session", "s", "--limit", "3")
	if len(first) != 0 {
		t.Fatalf("the first 3 candidates should hold none of the plaintexts, got %v", first)
	}
	second, _ := crackDump(t, dir, "second", dumpPath, "--no-pot", "--session", "s")
	assertPairs(t, "resumed", second, want)
}

// --session on a dump in a mode with no stable global index must say so, not
// pretend to checkpoint. Silence here is the failure being designed out.
func TestMultiTargetSessionRefusesLoudlyWhereItCannotCheckpoint(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	wl := filepath.Join(dir, "wl.txt")
	mustWrite(t, wl, "aaa\nbbb\naab\n")
	dumpPath, _ := writeDump(t, dir, []int64{0}, 2)

	exitCode = 0
	stderr := captureStderr(t, func() error {
		return runCrack([]string{"-t", "md5", "-M", "dict", "-w", wl, "--no-pot",
			"--session", "dictsess", dumpPath})
	})
	if !strings.Contains(stderr, "--session is not checkpointed") {
		t.Errorf("a dict dump run with --session said nothing about not checkpointing:\n%s", stderr)
	}
	if s, _ := loadSession("dictsess"); s != nil {
		t.Errorf("a mode that cannot checkpoint wrote a session file anyway: %+v", s)
	}
}

// ── property 5: nothing else moved ──────────────────────────────────────────

// A single target with --skip/--limit keeps behaving exactly as it did: the
// slice holding the plaintext finds it, the slices that don't, don't.
func TestSingleTargetSkipLimitUnchanged(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	l := dumpLayout()
	pw := l.candidate(600)
	target := md5hex(pw)

	run := func(tag string, extra ...string) map[string]string {
		outFile := filepath.Join(dir, tag+".out")
		args := append([]string{"-t", "md5", "-M", "brute", "-C", dumpCharset,
			"-n", fmt.Sprint(dumpLen), "-x", fmt.Sprint(dumpLen),
			"--no-pot", "--outfile-format", "1,2", "-o", outFile}, extra...)
		args = append(args, target)
		exitCode = 0
		captureStderr(t, func() error { return runCrack(args) })
		got := map[string]string{}
		for _, line := range readResultPairs(t, outFile) {
			h, p, _ := strings.Cut(line, ":")
			got[h] = p
		}
		return got
	}

	if got := run("hit", "--skip", "500", "--limit", "500"); got[target] != pw {
		t.Errorf("single-target slice [500,1000) missed %q: %v", pw, got)
	}
	if got := run("miss", "--skip", "0", "--limit", "500"); len(got) != 0 {
		t.Errorf("single-target slice [0,500) recovered %v, want nothing", got)
	}
}

// --show never attacks — with or without a slice. It reports potfile hits and
// stops, so no attack banner may appear and no candidate may be tried.
func TestShowOnDumpNeverAttacksEvenWhenSliced(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	l := dumpLayout()
	dumpPath, _ := writeDump(t, dir, []int64{0, 999}, 3)

	potPath := filepath.Join(dir, "show.pot")
	p, err := loadPotfile(potPath)
	if err != nil {
		t.Fatal(err)
	}
	p.add(md5hex(l.candidate(0)), l.candidate(0))

	for _, extra := range [][]string{nil, {"--skip", "0", "--limit", fmt.Sprint(dumpTotal)}} {
		args := append([]string{"--pot", potPath, "-t", "md5", "--show"}, extra...)
		args = append(args, dumpPath)
		exitCode = 0
		stderr := captureStderr(t, func() error { return runCrack(args) })
		if strings.Contains(stderr, batchBannerPrefix) || strings.Contains(stderr, "Attempts:") {
			t.Errorf("--show %v launched an attack:\n%s", extra, stderr)
		}
		if !strings.Contains(stderr, l.candidate(0)) {
			t.Errorf("--show %v did not report the potfile hit:\n%s", extra, stderr)
		}
	}
}

// The scalar-only modes must slice a dump exactly as brute does — same pairs
// from a split as from one unbounded run. hybrid stands in for the group
// (hybrid/markov/combinator/prince all reach the same bounded runLayout call),
// and dict for the word-index unit, which is a different bound entirely.
func TestNonVectorModesSliceADumpIdentically(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	wl := filepath.Join(dir, "wl.txt")
	mustWrite(t, wl, "alpha\nbravo\ncharlie\ndelta\necho\nfoxtrot\n")
	words := []string{"alpha", "bravo", "charlie", "delta", "echo", "foxtrot"}

	t.Run("hybrid", func(t *testing.T) {
		// hybrid layout = 6 words x 10 digits = 60 candidates.
		var lines []string
		want := map[string]string{}
		for _, pw := range []string{"alpha1", "delta7", "foxtrot9"} {
			lines = append(lines, md5hex(pw))
			want[md5hex(pw)] = pw
		}
		lines = append(lines, md5hex("never-in-this-keyspace"))
		dumpPath := filepath.Join(dir, "hybrid.txt")
		mustWrite(t, dumpPath, strings.Join(lines, "\n")+"\n")

		run := func(tag string, extra ...string) map[string]string {
			outFile := filepath.Join(dir, tag+".out")
			args := append([]string{"-t", "md5", "-M", "hybrid", "-w", wl,
				"--mask", "?d", "--no-pot", "-o", outFile}, extra...)
			args = append(args, dumpPath)
			exitCode = 0
			captureStderr(t, func() error { return runCrack(args) })
			got := map[string]string{}
			for _, line := range readResultPairs(t, outFile) {
				h, pw, _ := strings.Cut(line, ":")
				if md5hex(pw) != h {
					t.Fatalf("%s: MIS-ATTRIBUTION: %q filed against %s", tag, pw, h)
				}
				got[h] = pw
			}
			return got
		}
		assertPairs(t, "hybrid unbounded", run("hyb-full"), want)
		union := map[string]string{}
		for s := 0; s < 3; s++ {
			for h, pw := range run(fmt.Sprintf("hyb-%d", s),
				"--skip", fmt.Sprint(s*20), "--limit", "20") {
				if _, dup := union[h]; dup {
					t.Errorf("hybrid slice %d re-reported %s", s, h)
				}
				union[h] = pw
			}
		}
		assertPairs(t, "hybrid slices", union, want)
	})

	t.Run("dict", func(t *testing.T) {
		var lines []string
		want := map[string]string{}
		for _, pw := range []string{"alpha", "delta", "foxtrot"} {
			lines = append(lines, md5hex(pw))
			want[md5hex(pw)] = pw
		}
		lines = append(lines, md5hex("never-in-this-list"))
		dumpPath := filepath.Join(dir, "dict.txt")
		mustWrite(t, dumpPath, strings.Join(lines, "\n")+"\n")

		run := func(tag string, extra ...string) map[string]string {
			outFile := filepath.Join(dir, tag+".out")
			args := append([]string{"-t", "md5", "-M", "dict", "-w", wl,
				"--no-pot", "-o", outFile}, extra...)
			args = append(args, dumpPath)
			exitCode = 0
			captureStderr(t, func() error { return runCrack(args) })
			got := map[string]string{}
			for _, line := range readResultPairs(t, outFile) {
				h, pw, _ := strings.Cut(line, ":")
				if md5hex(pw) != h {
					t.Fatalf("%s: MIS-ATTRIBUTION: %q filed against %s", tag, pw, h)
				}
				got[h] = pw
			}
			return got
		}
		assertPairs(t, "dict unbounded", run("dict-full"), want)
		union := map[string]string{}
		seen := map[string]int{}
		for s := 0; s < len(words); s += 2 {
			for h, pw := range run(fmt.Sprintf("dict-%d", s),
				"--skip", fmt.Sprint(s), "--limit", "2") {
				seen[h]++
				union[h] = pw
			}
		}
		assertPairs(t, "dict word slices", union, want)
		for h, n := range seen {
			if n != 1 {
				t.Errorf("dict slices recovered %s %d times, want 1", h, n)
			}
		}
	})
}

// --keyspace prints the slicing unit and must be untouched by any of this: a
// script divides this number to build the very slices above, so a change here
// silently re-partitions everybody's jobs.
func TestKeyspaceValueUnchanged(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	wl := filepath.Join(dir, "wl.txt")
	mustWrite(t, wl, "alpha\nbravo\ncharlie\ndelta\necho\nfoxtrot\n")

	cases := []struct {
		args []string
		want string
	}{
		{[]string{"-M", "brute", "-C", dumpCharset, "-n", "3", "-x", "3"}, "1000"},
		{[]string{"-M", "mask", "--mask", "?l?d?d"}, "2600"},
		{[]string{"-M", "dict", "-w", wl}, "6"},
		{[]string{"-M", "dict", "-w", wl, "-r"}, "6"},
		{[]string{"-M", "hybrid", "-w", wl, "--mask", "?d"}, "60"},
	}
	for _, tc := range cases {
		out := captureStdout(t, func() error {
			return runCrack(append(append([]string{}, tc.args...), "--keyspace"))
		})
		if strings.TrimSpace(out) != tc.want {
			t.Errorf("--keyspace %v = %q, want %q", tc.args, strings.TrimSpace(out), tc.want)
		}
	}
}
