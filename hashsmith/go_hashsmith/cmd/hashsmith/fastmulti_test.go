package main

// Tests for the multi-target vector fast path (fastmulti.go).
//
// The property that matters most here is ATTRIBUTION. With N targets and a
// group of 20-24 candidates hashed at once, a mis-mapped lane index reports
// the right password against the WRONG account — a wrong answer wearing the
// appearance of success, the same failure family as the single-crack
// cross-contamination bug this codebase already guards against. So the
// assertions below are not hit COUNTS: every test that recovers anything
// re-hashes each recovered plaintext and demands it equal the digest of the
// target it was filed under, and every target that must NOT be cracked is
// asserted to stay empty. A mis-mapping therefore shows up as "cracked
// something it should not" or "this plaintext does not hash to this target",
// never as a number being one off.

import (
	"context"
	"crypto/md5"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync/atomic"
	"testing"
)

// ── harness ─────────────────────────────────────────────────────────────────

// requireVectorBackend skips when this build has no vector core (amd64
// without AVX2, anything non-arm64, this suite under Rosetta). There is no
// fast path to exercise there and the scalar path is correct by construction.
func requireVectorBackend(t *testing.T) {
	t.Helper()
	if _, ok := fastAlgoFor("md5"); !ok {
		t.Skipf("no md5 fast-path descriptor on backend %q", vectorBackendName())
	}
}

// newBatchOf builds a batchTarget list from plaintexts (targets that CAN be
// cracked from the keyspace under test) and ghosts (digests of strings that
// are NOT in the keyspace, and must therefore never be reported).
func newBatchOf(plains, ghosts []string) []*batchTarget {
	var b []*batchTarget
	add := func(s string) {
		h := md5hex(s)
		b = append(b, &batchTarget{norm: h, key: h, orig: h})
	}
	// Interleave, so a lookup that files a hit one index off lands on a
	// ghost — visibly cracking something that is not in the keyspace.
	for i := 0; i < len(plains) || i < len(ghosts); i++ {
		if i < len(plains) {
			add(plains[i])
		}
		if i < len(ghosts) {
			add(ghosts[i])
		}
	}
	return b
}

// batchRecorder returns the CAS-guarded recorder batchRunType installs, plus
// the shared remaining counter, so tests drive the same recording path
// production does.
func batchRecorder(batch []*batchTarget, remaining *int64) func(string, []int) bool {
	*remaining = int64(len(batch))
	return func(candidate string, idxs []int) bool {
		for _, idx := range idxs {
			if atomic.CompareAndSwapInt32(&batch[idx].flag, 0, 1) {
				batch[idx].password = candidate
				if atomic.AddInt64(remaining, -1) == 0 {
					return true
				}
			}
		}
		return false
	}
}

func allIdx(n int) []int {
	out := make([]int, n)
	for i := range out {
		out[i] = i
	}
	return out
}

// assertAttribution is the core check: every recovered plaintext must hash to
// the exact target it was filed under, the expected set must be complete, and
// nothing outside it may be reported.
func assertAttribution(t *testing.T, batch []*batchTarget, want map[string]string) {
	t.Helper()
	for _, e := range batch {
		found := atomic.LoadInt32(&e.flag) == 1
		wantPw, shouldFind := want[e.key]
		switch {
		case found && !shouldFind:
			t.Errorf("target %s was cracked as %q but must NOT be crackable from this keyspace "+
				"(a mis-attributed hit files a real plaintext against the wrong account)", e.key, e.password)
		case !found && shouldFind:
			t.Errorf("target %s (%q) was not recovered", e.key, wantPw)
		case found:
			if e.password != wantPw {
				t.Errorf("target %s: recovered %q, want %q", e.key, e.password, wantPw)
			}
			// Independent of the expectation table: the plaintext filed
			// against this hash must actually hash to it.
			if got := md5hex(e.password); got != e.key {
				t.Errorf("MIS-ATTRIBUTION: %q filed against %s, but md5(%q) = %s",
					e.password, e.key, e.password, got)
			}
		}
	}
}

// ── the sorted target set ───────────────────────────────────────────────────

// The binary search in fastTargets.lookup is only correct over a SORTED key
// array, and its prefilter can only ever skip work, never decide a hit. Both
// are asserted directly here so dropping the sort fails a test on its own,
// without depending on a keyspace sweep to notice.
func TestFastTargetsIsSortedAndFindsEveryTarget(t *testing.T) {
	plains := []string{"zzz", "aaa", "mmm", "qrs", "bcd", "hij", "cba", "pqr", "def", "xyz"}
	hexes := make([]string, len(plains))
	for i, p := range plains {
		hexes[i] = md5hex(p)
	}
	ft, ok := newFastTargets(hexes, allIdx(len(hexes)))
	if !ok {
		t.Fatal("newFastTargets declined a valid md5 target list")
	}
	for i := 1; i < len(ft.keys); i++ {
		if !ft.keys[i-1].less(ft.keys[i]) {
			t.Fatalf("keys are not sorted ascending at %d: %v then %v "+
				"(binary search silently misses targets on an unsorted array)",
				i, ft.keys[i-1], ft.keys[i])
		}
	}
	for i, p := range plains {
		d := md5.Sum([]byte(p))
		idxs, ok := ft.lookup(&d)
		if !ok {
			t.Fatalf("lookup missed target %d (%q / %s)", i, p, hexes[i])
		}
		if len(idxs) != 1 || idxs[0] != i {
			t.Fatalf("lookup(%q) = %v, want [%d]", p, idxs, i)
		}
	}
	// A non-target must not resolve.
	d := md5.Sum([]byte("not-a-target-at-all"))
	if idxs, ok := ft.lookup(&d); ok {
		t.Fatalf("lookup reported a non-target as %v", idxs)
	}
}

// Duplicate digests — the same hash listed twice, or two accounts sharing a
// password — collapse to ONE key owning both caller indices, in the caller's
// original order, exactly as the scalar path's map slices do.
func TestFastTargetsCollapsesDuplicateDigests(t *testing.T) {
	h := md5hex("shared")
	other := md5hex("other")
	ft, ok := newFastTargets([]string{h, other, h}, []int{7, 8, 9})
	if !ok {
		t.Fatal("newFastTargets declined")
	}
	if len(ft.keys) != 2 {
		t.Fatalf("got %d distinct keys, want 2", len(ft.keys))
	}
	d := md5.Sum([]byte("shared"))
	idxs, ok := ft.lookup(&d)
	if !ok {
		t.Fatal("duplicate digest not found")
	}
	if len(idxs) != 2 || idxs[0] != 7 || idxs[1] != 9 {
		t.Fatalf("duplicate owners = %v, want [7 9] in input order", idxs)
	}
}

// A target that is not exactly 16 bytes of hex makes the whole set decline,
// so the pass falls back wholesale to the scalar path rather than silently
// attacking a subset of the dump.
func TestFastTargetsDeclinesNonMD5Sized(t *testing.T) {
	if _, ok := newFastTargets([]string{md5hex("a"), "deadbeef"}, []int{0, 1}); ok {
		t.Error("an 8-byte digest must make the target set decline")
	}
	if _, ok := newFastTargets([]string{"zz" + md5hex("a")[2:]}, []int{0}); ok {
		t.Error("non-hex must make the target set decline")
	}
	if _, ok := newFastTargets(nil, nil); ok {
		t.Error("an empty target list must decline")
	}
}

// ── attribution over a real keyspace ────────────────────────────────────────

// A dump of crackable and uncrackable targets, run through the multi-target
// fast path: every crackable one recovered, attributed to ITS OWN hash, and
// not one uncrackable one reported.
func TestFastMultiAttributesEachPlaintextToItsOwnTarget(t *testing.T) {
	requireVectorBackend(t)
	for _, workers := range []int{1, 4} {
		plains := []string{"aaa", "abc", "dei", "gaj", "jjj", "cid", "hhf", "bbe"}
		ghosts := []string{"nope-1", "nope-2", "nope-3", "nope-4", "nope-5", "nope-6"}
		batch := newBatchOf(plains, ghosts)
		want := map[string]string{}
		for _, p := range plains {
			want[md5hex(p)] = p
		}

		var remaining, attempts int64
		rec := batchRecorder(batch, &remaining)
		layout := bruteLayout("abcdefghij", 3, 3)
		if !batchFastLayout(context.Background(), "md5", "", layout, allIdx(len(batch)), batch,
			0, 0, workers, &attempts, nil, rec) {
			t.Fatal("batchFastLayout declined an md5 brute pass on an accelerated build")
		}
		assertAttribution(t, batch, want)
	}
}

// Several targets whose plaintexts sit at ADJACENT keyspace indices land in
// the SAME vector group (20 lanes on NEON, 24 on AVX2). Code that stops at
// the first hit in a group advances past the rest of that group and silently
// loses them, so every one of these must come back.
func TestFastMultiFindsEveryHitInsideOneGroup(t *testing.T) {
	requireVectorBackend(t)
	layout := bruteLayout("abcdefghij", 3, 3)
	// Indices 0..3 are lanes 0..3 of the very first group under every
	// shipped shape, so all four are hashed in a single core call.
	var plains []string
	for i := int64(0); i < 4; i++ {
		plains = append(plains, layout.candidate(i))
	}
	batch := newBatchOf(plains, nil)
	want := map[string]string{}
	for _, p := range plains {
		want[md5hex(p)] = p
	}

	var remaining, attempts int64
	rec := batchRecorder(batch, &remaining)
	if !batchFastLayout(context.Background(), "md5", "", layout, allIdx(len(batch)), batch,
		0, 0, 1, &attempts, nil, rec) {
		t.Fatal("batchFastLayout declined")
	}
	assertAttribution(t, batch, want)
	if atomic.LoadInt64(&remaining) != 0 {
		t.Fatalf("remaining = %d: a hit inside a group was dropped — all %d targets share one group",
			remaining, len(plains))
	}
}

// The same digest listed twice must credit BOTH entries, as the map-based
// scalar path does.
func TestFastMultiCreditsDuplicateTargets(t *testing.T) {
	requireVectorBackend(t)
	dup := md5hex("cab")
	batch := []*batchTarget{
		{norm: dup, key: dup, orig: dup},
		{norm: md5hex("hid"), key: md5hex("hid"), orig: md5hex("hid")},
		{norm: dup, key: dup, orig: dup + "#2"},
	}
	var remaining, attempts int64
	rec := batchRecorder(batch, &remaining)
	if !batchFastLayout(context.Background(), "md5", "", bruteLayout("abcdefghij", 3, 3),
		allIdx(len(batch)), batch, 0, 0, 4, &attempts, nil, rec) {
		t.Fatal("batchFastLayout declined")
	}
	assertAttribution(t, batch, map[string]string{dup: "cab", md5hex("hid"): "hid"})
}

// Unused lanes of a partial final group hash the EMPTY string. A target that
// is md5("") is the one hash that can structurally be reported by a padding
// lane, so a keyspace that excludes "" and whose total is not a multiple of
// any group width must still exhaust and never report it.
func TestFastMultiNeverReportsPaddingLanes(t *testing.T) {
	requireVectorBackend(t)
	layout := bruteLayout("ab", 1, 3) // 2+4+8 = 14: partial final group, excludes ""
	empty := md5hex("")
	real := md5hex("ab")
	batch := []*batchTarget{
		{norm: empty, key: empty, orig: empty},
		{norm: real, key: real, orig: real},
	}
	var remaining, attempts int64
	rec := batchRecorder(batch, &remaining)
	if !batchFastLayout(context.Background(), "md5", "", layout, allIdx(len(batch)), batch,
		0, 0, 1, &attempts, nil, rec) {
		t.Fatal("batchFastLayout declined")
	}
	assertAttribution(t, batch, map[string]string{real: "ab"})
	if attempts != layout.total {
		t.Errorf("attempts = %d, want the full keyspace %d (one target is still unfound, "+
			"so the run must exhaust)", attempts, layout.total)
	}
}

// The run stops as soon as every target is accounted for — it must not sweep
// the rest of the keyspace once nothing is left to find.
func TestFastMultiStopsOnceAllTargetsAreFound(t *testing.T) {
	requireVectorBackend(t)
	layout := bruteLayout("abcdefghij", 3, 5) // 1000 + 10000 + 100000
	plains := []string{layout.candidate(0), layout.candidate(1)}
	batch := newBatchOf(plains, nil)
	var remaining, attempts int64
	rec := batchRecorder(batch, &remaining)
	if !batchFastLayout(context.Background(), "md5", "", layout, allIdx(len(batch)), batch,
		0, 0, 1, &attempts, nil, rec) {
		t.Fatal("batchFastLayout declined")
	}
	if atomic.LoadInt64(&remaining) != 0 {
		t.Fatalf("remaining = %d, want 0", remaining)
	}
	if attempts >= layout.total {
		t.Errorf("attempts = %d, want well under the keyspace %d — the run must stop "+
			"when every target is found", attempts, layout.total)
	}
}

// ── agreement with the scalar path ──────────────────────────────────────────

// scalarBatchPass reproduces batchRunType's scalar path exactly: the same
// digest map, the same recorder, driven by runLayout.
func scalarBatchPass(layout *keyspaceLayout, active []int, batch []*batchTarget,
	workers int, attempts *int64, rec func(string, []int) bool) {

	m := map[string][]int{}
	for _, idx := range active {
		m[batch[idx].key] = append(m[batch[idx].key], idx)
	}
	digestFn := rawDigest("md5")
	_, _ = runLayout(context.Background(), layout, 0, 0, workers, attempts, nil,
		func(c string) bool {
			idxs, ok := m[digestFn(c)]
			if !ok {
				return false
			}
			return rec(c, idxs)
		})
}

// The fast path must recover exactly the (hash, plaintext) pairs the scalar
// path recovers, for the same dump over the same keyspace — brute and mask.
func TestFastMultiAgreesWithScalarPass(t *testing.T) {
	requireVectorBackend(t)
	plains := []string{"aab", "cde", "jig", "bad", "hhh", "fee"}
	ghosts := []string{"ghost-a", "ghost-b", "ghost-c"}

	mc := &maskConfig{mask: "?l?l?l"}
	maskLay, err := maskLayout(mc)
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name   string
		layout *keyspaceLayout
	}{
		{"brute", bruteLayout("abcdefghij", 3, 3)},
		{"mask", maskLay},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fastBatch := newBatchOf(plains, ghosts)
			scalarB := newBatchOf(plains, ghosts)

			var r1, r2, a1, a2 int64
			if !batchFastLayout(context.Background(), "md5", "", tc.layout,
				allIdx(len(fastBatch)), fastBatch, 0, 0, 4, &a1, nil, batchRecorder(fastBatch, &r1)) {
				t.Fatal("batchFastLayout declined")
			}
			scalarBatchPass(tc.layout, allIdx(len(scalarB)), scalarB, 4, &a2,
				batchRecorder(scalarB, &r2))

			for i := range fastBatch {
				f, s := fastBatch[i], scalarB[i]
				if atomic.LoadInt32(&f.flag) != atomic.LoadInt32(&s.flag) || f.password != s.password {
					t.Errorf("entry %d (%s): fast=(%d,%q) scalar=(%d,%q)",
						i, f.key, f.flag, f.password, s.flag, s.password)
				}
				if f.flag == 1 && md5hex(f.password) != f.key {
					t.Errorf("MIS-ATTRIBUTION: %q filed against %s", f.password, f.key)
				}
			}
		})
	}
}

// ── eligibility ─────────────────────────────────────────────────────────────

// Only brute and mask layouts of an accelerated, unsalted digest are
// eligible. Everything else must decline so the caller runs the identical
// layout on the scalar path — nothing recorded, nothing counted.
func TestBatchFastLayoutDeclinesIneligiblePasses(t *testing.T) {
	l := bruteLayout("abcdefghij", 3, 3)
	batch := newBatchOf([]string{"abc"}, nil)
	nop := func(string, []int) bool { return false }
	var attempts int64

	if batchFastLayout(context.Background(), "sha256", "", l, allIdx(len(batch)), batch, 0, 0, 1, &attempts, nil, nop) {
		t.Error("sha256 has no vector core and must decline")
	}
	// A generator layout (markov and friends set l.gen) is not mixed-radix
	// decodable and must stay scalar.
	gen := bruteLayout("abcdefghij", 3, 3)
	gen.gen = func(i int64) string { return "x" }
	if batchFastLayout(context.Background(), "md5", "", gen, allIdx(len(batch)), batch, 0, 0, 1, &attempts, nil, nop) {
		t.Error("a gen-override layout must decline")
	}
	if batchFastLayout(context.Background(), "md5", "", nil, allIdx(len(batch)), batch, 0, 0, 1, &attempts, nil, nop) {
		t.Error("a nil layout must decline")
	}
	if batchFastLayout(context.Background(), "md5", "", l, nil, batch, 0, 0, 1, &attempts, nil, nop) {
		t.Error("an empty active set must decline")
	}
	// A non-md5-sized target in the dump declines the whole pass.
	mixed := append([]*batchTarget{}, batch...)
	mixed = append(mixed, &batchTarget{norm: "deadbeef", key: "deadbeef", orig: "deadbeef"})
	if batchFastLayout(context.Background(), "md5", "", l, allIdx(len(mixed)), mixed, 0, 0, 1, &attempts, nil, nop) {
		t.Error("an undecodable target must decline the whole pass")
	}
	if attempts != 0 {
		t.Errorf("a declined pass counted %d attempt(s); it must record and count nothing", attempts)
	}
	// HASHSMITH_NO_FASTPATH is the clean A/B and must reach here too.
	t.Setenv("HASHSMITH_NO_FASTPATH", "1")
	if batchFastLayout(context.Background(), "md5", "", l, allIdx(len(batch)), batch, 0, 0, 1, &attempts, nil, nop) {
		t.Error("HASHSMITH_NO_FASTPATH must force the scalar path in multi-hash mode")
	}
}

// ── end-to-end: the CLI must produce identical output either way ────────────

// readResultPairs returns the "hash:password" lines of an -o file, in the
// order they were written — which is runBatch's report order.
func readResultPairs(t *testing.T, path string) []string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var out []string
	for _, l := range strings.Split(strings.TrimRight(string(b), "\n"), "\n") {
		if l != "" {
			out = append(out, l)
		}
	}
	return out
}

// A ~30-target dump with several crackable targets, cracked through the real
// CLI twice — once on the vector fast path, once with HASHSMITH_NO_FASTPATH=1
// forcing the scalar path — must produce byte-identical results in the same
// order, including a potfile hit that is never re-attacked.
func TestMultiTargetCLIMatchesScalarPathExactly(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)

	plains := []string{"aaa", "cab", "dig", "hej", "jjj", "bid"}
	potPlain := "gab" // seeded into the potfile: reported, never attacked
	var lines []string
	for i, p := range plains {
		lines = append(lines, md5hex(p))
		lines = append(lines, md5hex("ghost-"+string(rune('a'+i))))
	}
	lines = append(lines, md5hex(potPlain))
	for i := 0; i < 10; i++ {
		lines = append(lines, md5hex("filler-"+string(rune('a'+i))))
	}
	targetsFile := filepath.Join(dir, "dump.txt")
	mustWrite(t, targetsFile, strings.Join(lines, "\n")+"\n")

	run := func(tag string, scalar bool) []string {
		potPath := filepath.Join(dir, tag+".pot")
		p, err := loadPotfile(potPath)
		if err != nil {
			t.Fatal(err)
		}
		p.add(md5hex(potPlain), potPlain)
		outFile := filepath.Join(dir, tag+".out")
		if scalar {
			t.Setenv("HASHSMITH_NO_FASTPATH", "1")
		} else {
			t.Setenv("HASHSMITH_NO_FASTPATH", "")
		}
		exitCode = 0
		stderr := captureStderr(t, func() error {
			return runCrack([]string{"--pot", potPath, "-t", "md5", "-M", "brute",
				"-C", "abcdefghij", "-n", "3", "-x", "3", "-o", outFile, targetsFile})
		})
		if !strings.Contains(stderr, batchBannerPrefix) {
			t.Fatalf("%s: multi-hash mode did not run:\n%s", tag, stderr)
		}
		// A potfile hit is reported but never attacked, under either
		// runner — assert that directly rather than inferring it.
		if !strings.Contains(stderr, md5hex(potPlain)) || !strings.Contains(stderr, "(potfile)") {
			t.Fatalf("%s: the potfile hit was not reported as such:\n%s", tag, stderr)
		}
		return readResultPairs(t, outFile)
	}

	fast := run("fast", false)
	scalarPairs := run("scalar", true)

	if len(fast) == 0 {
		t.Fatal("the fast run recovered nothing")
	}
	if strings.Join(fast, "\n") != strings.Join(scalarPairs, "\n") {
		t.Fatalf("fast and scalar paths disagree.\nfast:\n%s\nscalar:\n%s",
			strings.Join(fast, "\n"), strings.Join(scalarPairs, "\n"))
	}
	// Independent of the A/B: every reported pair must be self-consistent,
	// and exactly the crackable set (plus the potfile hit) must appear.
	// The potfile hit is reported to stderr (asserted above) but, as before
	// this change, never written to -o — so -o holds exactly the freshly
	// cracked set.
	want := map[string]string{}
	for _, p := range plains {
		want[md5hex(p)] = p
	}
	got := map[string]string{}
	for _, line := range fast {
		h, pw, ok := strings.Cut(line, ":")
		if !ok {
			t.Fatalf("malformed result line %q", line)
		}
		if md5hex(pw) != h {
			t.Errorf("MIS-ATTRIBUTION in CLI output: %q filed against %s", pw, h)
		}
		got[h] = pw
	}
	gotKeys := make([]string, 0, len(got))
	for k := range got {
		gotKeys = append(gotKeys, k)
	}
	sort.Strings(gotKeys)
	if len(got) != len(want) {
		t.Fatalf("recovered %d pair(s), want %d: %v", len(got), len(want), gotKeys)
	}
	for h, pw := range want {
		if got[h] != pw {
			t.Errorf("target %s: got %q, want %q", h, got[h], pw)
		}
	}
}
