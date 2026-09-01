package main

// Tests for rule stacking: applying several --rules files as a cross product.
//
// The central correctness oracle (see rules.go's expandStacked doc comment)
// is that stacking rule A then rule B must be exactly equivalent to compiling
// the single rule line A.src+B.src and applying it once. That is checked
// against compileRuleLine/ruleProgram.apply — the already-shipping, unstacked
// engine — not against expandStacked's own logic, so it is a genuine external
// oracle rather than a restatement of the implementation.

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// mustCompile compiles a rule line, failing the test on error.
func mustCompile(t *testing.T, line string) ruleProgram {
	t.Helper()
	p, err := compileRuleLine(line)
	if err != nil {
		t.Fatalf("compileRuleLine(%q): %v", line, err)
	}
	return p
}

// stackedEngine builds a ruleEngine whose layers are the compiled programs of
// each rule-line slice given (one slice per stacking layer), bypassing file
// I/O for tests that only care about expand's semantics.
func stackedEngine(t *testing.T, layerLines ...[]string) *ruleEngine {
	t.Helper()
	e := &ruleEngine{}
	product := int64(1)
	for _, lines := range layerLines {
		var progs []ruleProgram
		for _, ln := range lines {
			progs = append(progs, mustCompile(t, ln))
		}
		e.layers = append(e.layers, progs)
		product = satMul(product, int64(len(progs)))
	}
	e.stackedCount = int(product)
	return e
}

// ── The oracle ───────────────────────────────────────────────────────────────

// TestStackedOracleMatchesConcatenatedLine is the main correctness test: for
// many words and many rule-file pairs (and triples), every combination a
// stacked engine can produce must equal what compiling the single line
// (src_0+src_1+...+src_n) and applying it once produces — agreeing on
// rejection too.
func TestStackedOracleMatchesConcatenatedLine(t *testing.T) {
	fileA := []string{"c", "l", "u", "$1", "'3", ">6"}          // caps/case/append/truncate/length-gate
	fileB := []string{"$9", "d", "r", "so0", "@a", "_4"}        // append/dup/reverse/subst/purge/exact-length
	fileC := []string{":", "T0", "{", "D1", "!z", "z2"}         // no-op/toggle/rotate/delete/contains-gate/dup-first

	words := []string{
		"password", "P4ss", "hi", "a", "", "aaaa", "Summer2024",
		"héllo", "日本語", "café", "naïve",
	}

	// 2-deep stacks: every (A,B) pair.
	for _, aSrc := range fileA {
		pa := mustCompile(t, aSrc)
		for _, bSrc := range fileB {
			pb := mustCompile(t, bSrc)
			combined, err := compileRuleLine(aSrc + bSrc)
			if err != nil {
				t.Fatalf("compile concatenated %q: %v", aSrc+bSrc, err)
			}
			for _, w := range words {
				// Stacked application: thread through apply() per layer,
				// exactly as expandStacked does (string round-trip between
				// layers).
				var stackedResult string
				var stackedOK bool
				if mid, ok := pa.apply(w); ok {
					stackedResult, stackedOK = pb.apply(mid)
				}
				wantResult, wantOK := combined.apply(w)
				if stackedOK != wantOK {
					t.Fatalf("stack %q+%q on %q: ok=%v want ok=%v", aSrc, bSrc, w, stackedOK, wantOK)
				}
				if stackedOK && stackedResult != wantResult {
					t.Fatalf("stack %q+%q on %q: got %q want %q", aSrc, bSrc, w, stackedResult, wantResult)
				}
			}
		}
	}

	// 3-deep stacks: sample combinations across all three files.
	for _, aSrc := range fileA {
		pa := mustCompile(t, aSrc)
		for _, bSrc := range fileB {
			pb := mustCompile(t, bSrc)
			for _, cSrc := range fileC {
				pc := mustCompile(t, cSrc)
				combined, err := compileRuleLine(aSrc + bSrc + cSrc)
				if err != nil {
					t.Fatalf("compile concatenated %q: %v", aSrc+bSrc+cSrc, err)
				}
				for _, w := range words {
					var stackedResult string
					var stackedOK bool
					if mid1, ok := pa.apply(w); ok {
						if mid2, ok := pb.apply(mid1); ok {
							stackedResult, stackedOK = pc.apply(mid2)
						}
					}
					wantResult, wantOK := combined.apply(w)
					if stackedOK != wantOK {
						t.Fatalf("stack %q+%q+%q on %q: ok=%v want ok=%v", aSrc, bSrc, cSrc, w, stackedOK, wantOK)
					}
					if stackedOK && stackedResult != wantResult {
						t.Fatalf("stack %q+%q+%q on %q: got %q want %q", aSrc, bSrc, cSrc, w, stackedResult, wantResult)
					}
				}
			}
		}
	}
}

// TestStackedOracleViaEngine re-runs the oracle through the actual
// ruleEngine.expandStacked path (not just the manual two-apply() composition
// above), confirming the engine's own candidate set — after its dedup — is a
// subset of what the concatenated-line oracle would produce, and that every
// candidate the concatenated line for some (i,j) pair produces is present.
func TestStackedOracleViaEngine(t *testing.T) {
	linesA := []string{"c", "l", "$1"}
	linesB := []string{"$9", "r", "so0"}
	e := stackedEngine(t, linesA, linesB)

	for _, w := range []string{"password", "Hi", "café", ""} {
		got := e.expand(w)
		gotSet := make(map[string]string, len(got)) // password -> ruleLabel
		for _, mw := range got {
			gotSet[mw.password] = mw.ruleLabel
		}

		wantSet := make(map[string]struct{})
		for _, aSrc := range linesA {
			for _, bSrc := range linesB {
				combined, err := compileRuleLine(aSrc + bSrc)
				if err != nil {
					t.Fatalf("compile %q: %v", aSrc+bSrc, err)
				}
				cand, ok := combined.apply(w)
				if !ok || cand == w {
					continue
				}
				wantSet[cand] = struct{}{}
			}
		}
		if len(gotSet) != len(wantSet) {
			t.Fatalf("word %q: engine produced %d unique candidates, oracle set has %d\n got=%v\nwant=%v",
				w, len(gotSet), len(wantSet), gotSet, wantSet)
		}
		for cand := range wantSet {
			if _, ok := gotSet[cand]; !ok {
				t.Errorf("word %q: oracle candidate %q missing from engine output", w, cand)
			}
		}
	}
}

// TestStackedRuleLabelReproducesCandidate checks design ruling #7: a stacked
// candidate's ruleLabel is itself a valid rule line that reproduces the exact
// candidate when compiled and applied to the original word.
func TestStackedRuleLabelReproducesCandidate(t *testing.T) {
	e := stackedEngine(t,
		[]string{"c", "l", "u"},
		[]string{"$1", "$2", "r"},
		[]string{"so0", ":"},
	)
	for _, w := range []string{"password", "Test", "abcabc"} {
		for _, mw := range e.expand(w) {
			p, err := compileRuleLine(mw.ruleLabel)
			if err != nil {
				t.Fatalf("word %q candidate %q: ruleLabel %q does not compile: %v", w, mw.password, mw.ruleLabel, err)
			}
			got, ok := p.apply(w)
			if !ok {
				t.Fatalf("word %q candidate %q: ruleLabel %q rejected on replay", w, mw.password, mw.ruleLabel)
			}
			if got != mw.password {
				t.Fatalf("word %q: ruleLabel %q replayed to %q, want %q", w, mw.ruleLabel, got, mw.password)
			}
		}
	}
}

// ── Order, rejection, dedup ──────────────────────────────────────────────────

// TestStackedOrderFirstFileOuterLoop checks design ruling #2: the first file
// is the outer loop, the last file varies fastest.
func TestStackedOrderFirstFileOuterLoop(t *testing.T) {
	// layer0 has 2 distinguishable programs, layer1 has 3. With no rejections
	// or dedup collisions, order must be:
	// (0,0) (0,1) (0,2) (1,0) (1,1) (1,2)
	e := stackedEngine(t,
		[]string{"^A", "^B"},        // prepend A / prepend B — layer0
		[]string{"$1", "$2", "$3"}, // append 1/2/3 — layer1
	)
	got := e.expand("x")
	// ^A prepends A -> "Ax"; then $1 appends -> "Ax1" etc.
	wantOrdered := []string{"Ax1", "Ax2", "Ax3", "Bx1", "Bx2", "Bx3"}
	if len(got) != len(wantOrdered) {
		t.Fatalf("got %d candidates, want %d: %+v", len(got), len(wantOrdered), got)
	}
	for i, mw := range got {
		if mw.password != wantOrdered[i] {
			t.Errorf("position %d: got %q want %q (full: %v)", i, mw.password, wantOrdered[i], got)
		}
	}
}

// TestStackedRejectionShortCircuits checks design ruling #3: when layer0
// rejects a word, no layer1 program ever runs for that branch, and no
// candidate is produced for it.
func TestStackedRejectionShortCircuits(t *testing.T) {
	// "_9" rejects unless length == 9 exactly. "short" has length 5, so it's
	// always rejected by layer0's gate — no layer1 program should ever fire.
	e := stackedEngine(t,
		[]string{"_9", ":"}, // program0 always rejects "short"; program1 (":") always passes
		[]string{"$1", "$2", "$3"},
	)
	got := e.expand("short")
	// Only the passing layer0 program (":") should reach layer1, producing
	// exactly 3 candidates (short1, short2, short3) — none from "_9".
	if len(got) != 3 {
		t.Fatalf("got %d candidates, want 3 (only from the non-rejecting layer0 program): %+v", len(got), got)
	}
	wantPw := map[string]bool{"short1": true, "short2": true, "short3": true}
	for _, mw := range got {
		if !wantPw[mw.password] {
			t.Errorf("unexpected candidate %q — should have been short-circuited by _9's rejection", mw.password)
		}
		if strings.Contains(mw.ruleLabel, "_9") {
			t.Errorf("candidate %q has ruleLabel %q containing the rejecting program — short-circuit failed", mw.password, mw.ruleLabel)
		}
	}
}

// TestStackedDedupWithinWord checks design ruling #4: dedup semantics are
// preserved across stacks — the base word itself and any duplicate candidate
// string collapse to one entry.
func TestStackedDedupWithinWord(t *testing.T) {
	// layer0: ":" (no-op) and "l" (lowercase) both produce "abc" from "abc"
	// (identity). layer1: ":" and "u" — so combos are:
	//  (":", ":") -> "abc" (== base word, excluded)
	//  (":", "u") -> "ABC"
	//  ("l", ":") -> "abc" (== base word, excluded)
	//  ("l", "u") -> "ABC" (duplicate of the second combo, collapsed)
	e := stackedEngine(t, []string{":", "l"}, []string{":", "u"})
	got := e.expand("abc")
	if len(got) != 1 {
		t.Fatalf("want 1 unique candidate (ABC), got %d: %+v", len(got), got)
	}
	if got[0].password != "ABC" {
		t.Errorf("got %q, want %q", got[0].password, "ABC")
	}
}

// ── count() ──────────────────────────────────────────────────────────────────

// TestStackedCountIsProduct checks design ruling #5: count() returns the
// product of per-layer counts (an upper bound on actual output, matching the
// existing single-file semantics — see crack.go's "up to rules.count() extra
// candidates" comment).
func TestStackedCountIsProduct(t *testing.T) {
	e := stackedEngine(t,
		[]string{"c", "l", "u", ":"},          // 4
		[]string{"$1", "$2", "r"},             // 3
		[]string{"so0", "sa@", "T0", "d", "f"}, // 5
	)
	want := 4 * 3 * 5
	if got := e.count(); got != want {
		t.Errorf("count() = %d, want %d", got, want)
	}
}

// ── Cap enforcement (loadRuleFiles) ─────────────────────────────────────────

// writeRuleFileLines writes n valid, distinct rule lines to a temp file and
// returns its path. Lines alternate between a small set of ops so every line
// compiles, without needing n distinct literal characters.
func writeRuleFileLines(t *testing.T, dir, name string, n int) string {
	t.Helper()
	ops := []string{":", "l", "u", "c", "C", "r", "d", "f", "q", "{", "}", "[", "]", "k", "K"}
	var b strings.Builder
	for i := 0; i < n; i++ {
		b.WriteString(ops[i%len(ops)])
		b.WriteByte('\n')
	}
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(b.String()), 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

// TestLoadRuleFilesRefusesOversizedStack checks design ruling #6: a stack
// whose product exceeds maxStackedCandidates is refused at load time with an
// error naming the files, rather than built and later truncated or left to
// exhaust memory.
func TestLoadRuleFilesRefusesOversizedStack(t *testing.T) {
	dir := t.TempDir()
	// 1100 * 1100 = 1,210,000 > 1,000,000 cap.
	a := writeRuleFileLines(t, dir, "a.rule", 1100)
	b := writeRuleFileLines(t, dir, "b.rule", 1100)
	_, _, err := loadRuleFiles([]string{a, b})
	if err == nil {
		t.Fatal("expected an error for a stack exceeding the cap, got nil")
	}
	if !strings.Contains(err.Error(), a) || !strings.Contains(err.Error(), b) {
		t.Errorf("error should name both files, got: %v", err)
	}
	if !strings.Contains(err.Error(), "1210000") {
		t.Errorf("error should name the product (1210000), got: %v", err)
	}
}

// TestLoadRuleFilesAcceptsAtCap checks the boundary: a product exactly at the
// cap is accepted, not refused (the cap bounds "exceeds", not "reaches").
func TestLoadRuleFilesAcceptsAtCap(t *testing.T) {
	dir := t.TempDir()
	a := writeRuleFileLines(t, dir, "a.rule", 1000)
	b := writeRuleFileLines(t, dir, "b.rule", 1000)
	e, _, err := loadRuleFiles([]string{a, b})
	if err != nil {
		t.Fatalf("product exactly at cap (1,000,000) should be accepted: %v", err)
	}
	if e.count() != maxStackedCandidates {
		t.Errorf("count() = %d, want %d", e.count(), maxStackedCandidates)
	}
}

// TestLoadRuleFilesSingleFileByteIdentical checks design ruling #1: passing
// exactly one rule file through loadRuleFiles must behave identically to the
// pre-stacking loadRuleFile path — same programs, same expand output.
func TestLoadRuleFilesSingleFileByteIdentical(t *testing.T) {
	dir := t.TempDir()
	path := writeRuleFileLines(t, dir, "solo.rule", 12)
	direct, badDirect, errDirect := loadRuleFile(path)
	viaStack, badStack, errStack := loadRuleFiles([]string{path})
	if errDirect != nil || errStack != nil {
		t.Fatalf("errors: direct=%v stack=%v", errDirect, errStack)
	}
	if badDirect != badStack {
		t.Fatalf("bad-rule counts differ: direct=%d stack=%d", badDirect, badStack)
	}
	if viaStack.layers != nil {
		t.Fatalf("single-file loadRuleFiles must use the unstacked `programs` shape, got non-nil layers")
	}
	if len(direct.programs) != len(viaStack.programs) {
		t.Fatalf("program counts differ: direct=%d stack=%d", len(direct.programs), len(viaStack.programs))
	}
	for _, w := range []string{"password", "hello", "TEST123"} {
		gd, gs := direct.expand(w), viaStack.expand(w)
		if len(gd) != len(gs) {
			t.Fatalf("word %q: expand length differs: direct=%d stack=%d", w, len(gd), len(gs))
		}
		for i := range gd {
			if gd[i] != gs[i] {
				t.Errorf("word %q candidate %d: direct=%+v stack=%+v", w, i, gd[i], gs[i])
			}
		}
	}
}

// ── --skip/--limit tiling with stacked rules ────────────────────────────────

// TestDictSkipLimitTilesWithStackedRules checks the property called out
// explicitly in the task: --skip/--limit slice a dict attack by WORD index,
// and a stacked rule set must still tile correctly — every (word, stacked
// candidate) pair tried exactly once across disjoint slices, none lost or
// repeated. This property has broken before; it is tested directly here
// rather than assumed from the fact that expand() is a pure function.
func TestDictSkipLimitTilesWithStackedRules(t *testing.T) {
	dir := t.TempDir()
	words := []string{"alpha", "beta", "gamma", "delta", "epsilon", "zeta", "eta", "theta"}
	wordlistPath := filepath.Join(dir, "words.txt")
	if err := os.WriteFile(wordlistPath, []byte(strings.Join(words, "\n")+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	e := stackedEngine(t, []string{"c", "l"}, []string{"$1", "$2"})

	collectAll := func(skip, limit int64) map[string]int {
		seen := map[string]int{}
		var attempts int64
		_, err := dictAttack(context.Background(), wordlistPath, skip, limit, 1, &attempts, e, func(pw string) bool {
			seen[pw]++
			return false // never match — force the full slice to be tried
		})
		if err != nil {
			t.Fatalf("dictAttack(skip=%d,limit=%d): %v", skip, limit, err)
		}
		return seen
	}

	// Unsplit baseline: every word (base word + all stacked candidates).
	baseline := collectAll(0, 0)

	// Split into 3 word-index slices of size 3 (covers all 8 words).
	union := map[string]int{}
	for _, sl := range []struct{ skip, limit int64 }{
		{0, 3}, {3, 3}, {6, 3},
	} {
		part := collectAll(sl.skip, sl.limit)
		for pw, n := range part {
			union[pw] += n
		}
	}

	if len(union) != len(baseline) {
		t.Fatalf("union covers %d distinct candidates, baseline has %d", len(union), len(baseline))
	}
	for pw, n := range baseline {
		if union[pw] != n {
			t.Errorf("candidate %q: union count %d, baseline count %d (want equal — no loss, no repeat)", pw, union[pw], n)
		}
	}
	for pw := range union {
		if _, ok := baseline[pw]; !ok {
			t.Errorf("union produced %q which the unsplit baseline never tried", pw)
		}
	}
}

// ── --stdout with stacked rules ─────────────────────────────────────────────

// TestStreamCandidatesStacked confirms --stdout (streamCandidates, which
// shares expand()) emits stacked candidates in dict mode.
func TestStreamCandidatesStacked(t *testing.T) {
	dir := t.TempDir()
	wordlistPath := filepath.Join(dir, "words.txt")
	if err := os.WriteFile(wordlistPath, []byte("password\n"), 0600); err != nil {
		t.Fatal(err)
	}
	e := stackedEngine(t, []string{"c"}, []string{"$1", "$2"})
	out := captureStdout(t, func() error {
		return streamCandidates("dict", wordlistPath, "", "", 0, 0, princeDefaultElems, nil, e, 0, 0)
	})
	lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
	want := []string{"password", "Password1", "Password2"}
	if len(lines) != len(want) {
		t.Fatalf("got %d lines %v, want %v", len(lines), lines, want)
	}
	for i := range want {
		if lines[i] != want[i] {
			t.Errorf("line %d: got %q want %q", i, lines[i], want[i])
		}
	}
}

// ── UTF-8 round-trip caveat ──────────────────────────────────────────────────

// TestStackedNonASCIIRoundTrip probes the documented caveat: stacked
// application round-trips through []rune -> string -> []rune between layers,
// while a concatenated line stays in []rune throughout. Every op in this
// engine only ever builds rune slices out of runes already present in a valid
// (already-decoded) rune slice or literal single-byte (0-255) rule-source
// characters — both always valid Unicode scalar values — so string(r) from
// any op's output is always valid UTF-8, and no divergence should be
// observable even when the ORIGINAL word contains invalid UTF-8 bytes (which
// only get sanitized once, at the very first []rune conversion, identically
// on both paths). This test exercises that directly instead of assuming it.
func TestStackedNonASCIIRoundTrip(t *testing.T) {
	invalidUTF8 := string([]byte{0x68, 0x65, 0xff, 0xfe, 0x6c, 0x80, 0x6f}) // "he" + invalid bytes + "l" + invalid + "o"
	words := []string{"héllo", "日本語", "café", "naïve", "Ω≈ç√∫", invalidUTF8}

	fileA := []string{"c", "l", "u", "r", "$X", "^Y"}
	fileB := []string{"$1", "d", "so0", "T0", "'3"}

	for _, aSrc := range fileA {
		pa := mustCompile(t, aSrc)
		for _, bSrc := range fileB {
			pb := mustCompile(t, bSrc)
			combined, err := compileRuleLine(aSrc + bSrc)
			if err != nil {
				t.Fatalf("compile %q: %v", aSrc+bSrc, err)
			}
			for _, w := range words {
				var stackedResult string
				var stackedOK bool
				if mid, ok := pa.apply(w); ok {
					stackedResult, stackedOK = pb.apply(mid)
				}
				wantResult, wantOK := combined.apply(w)
				if stackedOK != wantOK {
					t.Errorf("DIVERGENCE (ok): stack %q+%q on %q: stacked ok=%v concatenated ok=%v",
						aSrc, bSrc, w, stackedOK, wantOK)
					continue
				}
				if stackedOK && stackedResult != wantResult {
					t.Errorf("DIVERGENCE (value): stack %q+%q on %q: stacked=%q concatenated=%q",
						aSrc, bSrc, w, stackedResult, wantResult)
				}
			}
		}
	}
}

// ── Live-crack sanity: composition actually finds a password reachable only
//    via the stack (paired with the CLI demo; this is the same scenario at
//    the Go level so it runs in `go test` too). ─────────────────────────────

func TestStackedRulesCrackWordUnreachableByEitherFileAlone(t *testing.T) {
	// caps.rule: capitalize only. digits.rule: append 1..9.
	caps := []string{"c"}
	digits := []string{"$1", "$2", "$3", "$4", "$5", "$6", "$7", "$8", "$9"}

	capsOnly := stackedEngine(t, caps)
	digitsOnly := stackedEngine(t, digits)
	stacked := stackedEngine(t, caps, digits)

	base := "password"
	target := "Password7"

	find := func(e *ruleEngine) bool {
		if base == target {
			return true
		}
		for _, mw := range e.expand(base) {
			if mw.password == target {
				return true
			}
		}
		return false
	}

	if find(capsOnly) {
		t.Fatal("caps.rule alone should not reach Password7")
	}
	if find(digitsOnly) {
		t.Fatal("digits.rule alone should not reach Password7")
	}
	if !find(stacked) {
		t.Fatal("the stack of caps.rule + digits.rule should reach Password7")
	}
}
