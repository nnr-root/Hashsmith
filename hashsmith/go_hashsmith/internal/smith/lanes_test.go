package smith

import (
	"context"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"

	"golang.org/x/crypto/bcrypt"
)

// TestDictAttackLanesFindsAtEveryPosition is the test that matters: the lane
// buffer must be flushed at end-of-batch and end-of-wordlist, or trailing
// candidates go untested and a crackable password is silently reported as not
// found - the worst possible failure for a cracker.
func TestDictAttackLanesFindsAtEveryPosition(t *testing.T) {
	crypt, err := bcrypt.GenerateFromPassword([]byte("needle"), 4)
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range []int{1, 2, 3, 5, 7, 8, 9, 17} {
		for _, pos := range []int{0, n / 2, n - 1} {
			words := make([]string, n)
			for i := range words {
				words[i] = "chaff"
			}
			words[pos] = "needle"

			dir := t.TempDir()
			path := filepath.Join(dir, "wl.txt")
			var buf []byte
			for _, w := range words {
				buf = append(buf, w...)
				buf = append(buf, '\n')
			}
			if err := os.WriteFile(path, buf, 0o600); err != nil {
				t.Fatal(err)
			}

			var attempts int64
			verify := func(c string) bool {
				return bcrypt.CompareHashAndPassword(crypt, []byte(c)) == nil
			}
			res, err := dictAttack(context.Background(), path, 0, 0, 2, &attempts, nil,
				verify, string(crypt), "bcrypt", "", "prefix")
			if err != nil {
				t.Fatalf("n=%d pos=%d: %v", n, pos, err)
			}
			if res.password != "needle" {
				t.Errorf("n=%d pos=%d: got %q, want \"needle\"", n, pos, res.password)
			}
			if atomic.LoadInt64(&attempts) < int64(pos+1) {
				t.Errorf("n=%d pos=%d: only %d attempts counted", n, pos, attempts)
			}
		}
	}
}

// TestDictAttackLanesExhaustiveAttemptCount closes review finding I-1: the
// positive-hit tests above are redundancy-blind to a missing flush, because
// buf persists across batch boundaries so the end-of-batch and !ok flushes
// cover for each other (mutation testing showed either one deleted alone
// still passes them). With the password absent, cancellation never fires, so
// EVERY word must be attempted exactly once — attempts must equal wordcount
// exactly. Any single missed flush point leaves a short count, which a >=
// bound (as used above) would not catch but == does. n sweeps lengths that
// straddle both the lane width (bcryptlane.Lanes=4) and a batch boundary.
//
// What this test does and does not prove: it catches the loss of ALL
// flushing — deleting both flush points at once leaves attempts short for
// every n above except one exactly divisible by Lanes — and it pins attempt
// accounting to exact equality rather than a loose lower bound. It cannot,
// and is not meant to, attribute a failure to either individual flush point:
// with buf auto-flushing at Lanes, each flush point alone is structurally
// sufficient to cover for the other's absence in any exhaustive run, so no
// test of this shape can tell them apart. See the "deliberately redundant"
// comments at both flush call sites in crack.go.
func TestDictAttackLanesExhaustiveAttemptCount(t *testing.T) {
	crypt, err := bcrypt.GenerateFromPassword([]byte("absent-password"), 4)
	if err != nil {
		t.Fatal(err)
	}
	verify := func(c string) bool {
		return bcrypt.CompareHashAndPassword(crypt, []byte(c)) == nil
	}
	for _, n := range []int{1, 2, 3, 5, 511, 512, 513, 1027} {
		words := make([]string, n)
		for i := range words {
			words[i] = "chaff"
		}

		dir := t.TempDir()
		path := filepath.Join(dir, "wl.txt")
		var buf []byte
		for _, w := range words {
			buf = append(buf, w...)
			buf = append(buf, '\n')
		}
		if err := os.WriteFile(path, buf, 0o600); err != nil {
			t.Fatal(err)
		}

		var attempts int64
		res, err := dictAttack(context.Background(), path, 0, 0, 2, &attempts, nil,
			verify, string(crypt), "bcrypt", "", "prefix")
		if err != nil {
			t.Fatalf("n=%d: %v", n, err)
		}
		if res.password != "" {
			t.Errorf("n=%d: unexpectedly found %q in a wordlist with no match", n, res.password)
		}
		if got := atomic.LoadInt64(&attempts); got != int64(n) {
			t.Errorf("n=%d: attempts=%d, want exactly %d — a flush was skipped and candidates went untested silently", n, got, n)
		}
	}
}

// TestDictAttackLanesMultiBatchConcurrent closes review finding I-2: every
// test above uses n <= 17, far below dictBatchSize, so the reader emits
// exactly one batch and only one of the two workers ever receives words —
// lh.Run is never actually exercised concurrently by more than one goroutine,
// so a green -race run on those tests is not evidence that per-worker lane
// hashers are safe under real concurrency. This test forces multiple batches
// and four workers so more than one worker's lh.Run genuinely runs at once,
// with the needle planted at the first word, at two batch boundaries, and at
// the last word.
//
// The size is DERIVED from dictBatchSize rather than written out. It used to
// be "n=1600 spans four: 512, 512, 512, 64", with the boundaries spelled as
// 512 and 1024 — correct until dictBatchSize was raised to 4096, at which
// point 1600 words are a single batch and this test silently stops testing
// concurrency at all while still passing. Deriving it means the test follows
// the constant instead of quietly falling behind it.
func TestDictAttackLanesMultiBatchConcurrent(t *testing.T) {
	crypt, err := bcrypt.GenerateFromPassword([]byte("needle"), 4)
	if err != nil {
		t.Fatal(err)
	}
	// Three full batches and a short fourth, so the final partial-batch flush
	// is exercised too.
	n := dictBatchSize*3 + 64
	for _, pos := range []int{0, dictBatchSize, dictBatchSize * 2, n - 1} {
		words := make([]string, n)
		for i := range words {
			words[i] = "chaff"
		}
		words[pos] = "needle"

		dir := t.TempDir()
		path := filepath.Join(dir, "wl.txt")
		var buf []byte
		for _, w := range words {
			buf = append(buf, w...)
			buf = append(buf, '\n')
		}
		if err := os.WriteFile(path, buf, 0o600); err != nil {
			t.Fatal(err)
		}

		var attempts int64
		verify := func(c string) bool {
			return bcrypt.CompareHashAndPassword(crypt, []byte(c)) == nil
		}
		res, err := dictAttack(context.Background(), path, 0, 0, 4, &attempts, nil,
			verify, string(crypt), "bcrypt", "", "prefix")
		if err != nil {
			t.Fatalf("pos=%d: %v", pos, err)
		}
		if res.password != "needle" {
			t.Errorf("pos=%d: got %q, want \"needle\"", pos, res.password)
		}
		if atomic.LoadInt64(&attempts) == 0 {
			t.Errorf("pos=%d: zero attempts counted", pos)
		}
	}
}

// TestDictAttackLanesRuleLabels pins hit attribution: this fixture's hit
// ("needle1") lands at lane index 1 of the second buffered flush (the first
// flush is ["aaa","aaa1","bbb","bbb1"]; the second is ["needle","needle1",...]),
// and it must report that lane's own rule label, not a neighbour's.
func TestDictAttackLanesRuleLabels(t *testing.T) {
	crypt, err := bcrypt.GenerateFromPassword([]byte("needle1"), 4)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "wl.txt")
	if err := os.WriteFile(path, []byte("aaa\nbbb\nneedle\nccc\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	// Ruling F-8: the brief calls a nonexistent newRuleEngineFromRules
	// constructor. Build the engine directly, matching this repo's own
	// tests (see rules_test.go:106-114 / TestRuleEngineDedup).
	e := &ruleEngine{}
	p, err := compileRuleLine("$1")
	if err != nil {
		t.Fatal(err)
	}
	e.programs = append(e.programs, p)
	rules := e
	var attempts int64
	verify := func(c string) bool {
		return bcrypt.CompareHashAndPassword(crypt, []byte(c)) == nil
	}
	res, err := dictAttack(context.Background(), path, 0, 0, 2, &attempts, rules,
		verify, string(crypt), "bcrypt", "", "prefix")
	if err != nil {
		t.Fatal(err)
	}
	if res.password != "needle1" {
		t.Fatalf("got %q, want \"needle1\"", res.password)
	}
	if res.ruleLabel != "$1" {
		t.Errorf("rule label %q, want \"$1\"", res.ruleLabel)
	}
}

// TestMaskLanesFindsAtEveryPosition mirrors the dict test for the keyspace
// runner. The mask ?l?l covers 676 candidates; planting the answer at the first,
// a middle and the last index exercises the same flush boundaries.
func TestMaskLanesFindsAtEveryPosition(t *testing.T) {
	for _, pw := range []string{"aa", "mn", "zz"} {
		crypt, err := bcrypt.GenerateFromPassword([]byte(pw), 4)
		if err != nil {
			t.Fatal(err)
		}
		cfg := buildMaskConfig("?l?l", "", "", "", "", false, 0, false)
		var attempts int64
		got, err := maskAttack(context.Background(), string(crypt), "bcrypt", cfg, 2, "", "prefix", &attempts)
		if err != nil {
			t.Fatalf("%s: %v", pw, err)
		}
		if got != pw {
			t.Errorf("mask found %q, want %q", got, pw)
		}
	}
}

// TestLanesRespectSessionWatermark pins the contract runLayoutLanes shares with
// its sibling runners: a resumed run must not retest what the first run covered
// and must still find an answer past the resume point.
func TestLanesRespectSessionWatermark(t *testing.T) {
	crypt, err := bcrypt.GenerateFromPassword([]byte("zz"), 4)
	if err != nil {
		t.Fatal(err)
	}
	h, lanes, ok := newLaneHasher("bcrypt", string(crypt), "", "prefix")
	if !ok {
		t.Fatal("newLaneHasher declined a valid bcrypt target")
	}
	layout, err := maskLayout(buildMaskConfig("?l?l", "", "", "", "", false, 0, false))
	if err != nil {
		t.Fatal(err)
	}
	var attempts, watermark int64
	// Start past every candidate except the last few; the answer is index 675.
	got, err := runLayoutLanes(context.Background(), layout, 670, 0, 2, &attempts, &watermark, h, lanes)
	if err != nil {
		t.Fatal(err)
	}
	if got != "zz" {
		t.Errorf("resumed run found %q, want \"zz\"", got)
	}
	// Exact assertions, not a loose bound: indices 0..669 must never be
	// touched (attempts counts only 670..675, six candidates) and the
	// watermark must land exactly on the keyspace total once the run
	// completes. A regression that resets from to start instead of
	// max(start, resumeFrom) — retesting the whole chunk from 0 — would still
	// find "zz" and would still leave watermark >= 670, so this exact form is
	// what actually catches it.
	if attempts != 6 {
		t.Errorf("attempts = %d, want 6 (indices 670..675)", attempts)
	}
	if watermark != 676 {
		t.Errorf("watermark = %d, want 676", watermark)
	}
}

// TestLanesFlushFinalChunkTail closes the gap TestMaskLanesFindsAtEveryPosition
// leaves open: ?l?l is exactly 676 = 169*Lanes candidates in one chunk, so its
// tail is always empty and it cannot detect a missing end-of-chunk flush.
// bruteLayout("abc", 1, 3) has 39 candidates (3 + 9 + 27) — NOT a multiple of
// Lanes(4) — so the final chunk (the only chunk; 39 < keyspaceChunk) ends with
// a real 3-candidate tail (indices 36, 37, 38). Planting the answer at the
// last index (38, "ccc") means an unflushed tail loses it: this test fails if
// the end-of-chunk `if flush() { return }` after the candidate loop is
// removed.
func TestLanesFlushFinalChunkTail(t *testing.T) {
	crypt, err := bcrypt.GenerateFromPassword([]byte("ccc"), 4)
	if err != nil {
		t.Fatal(err)
	}
	h, lanes, ok := newLaneHasher("bcrypt", string(crypt), "", "prefix")
	if !ok {
		t.Fatal("newLaneHasher declined a valid bcrypt target")
	}
	layout := bruteLayout("abc", 1, 3)
	if layout.total != 39 {
		t.Fatalf("test setup: keyspace is %d candidates, want 39", layout.total)
	}
	if got := layout.candidate(38); got != "ccc" {
		t.Fatalf("test setup: index 38 is %q, want \"ccc\"", got)
	}
	var attempts, watermark int64
	got, err := runLayoutLanes(context.Background(), layout, 0, 0, 1, &attempts, &watermark, h, lanes)
	if err != nil {
		t.Fatal(err)
	}
	if got != "ccc" {
		t.Errorf("got %q, want \"ccc\" — the unflushed chunk tail was silently skipped", got)
	}
}

// TestBcryptBruteThroughProductionDispatch drives a bcrypt brute run through
// doCrack -> runBruteOrMaskLayout, the ACTUAL production dispatch `-M brute`
// and `-M mask` use (crack.go:117-125). TestMaskLanesFindsAtEveryPosition and
// TestLanesRespectSessionWatermark exercise maskAttack / runLayoutLanes
// directly, but maskAttack has no non-test caller in this module — it does
// not prove the dispatch branch added to runBruteOrMaskLayout is ever
// actually reached and correct end to end.
func TestBcryptBruteThroughProductionDispatch(t *testing.T) {
	crypt, err := bcrypt.GenerateFromPassword([]byte("cab"), 4)
	if err != nil {
		t.Fatal(err)
	}
	cc, err := newCrackCtx("", true, "", false, "", false, 0, 0, "", 0)
	if err != nil {
		t.Fatalf("newCrackCtx: %v", err)
	}
	found, err := doCrack(string(crypt), "bcrypt", "brute", "", "abc", 1, 3, 2, "", "prefix", "", false, nil, nil, cc)
	if err != nil {
		t.Fatalf("doCrack: %v", err)
	}
	if !found {
		t.Fatal("bcrypt brute through the production runBruteOrMaskLayout dispatch must find its password")
	}
}
