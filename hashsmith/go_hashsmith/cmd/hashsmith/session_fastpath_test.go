package main

// Tests for the one property that makes a resumable run trustworthy:
//
//	A CHECKPOINT MUST NEVER RECORD PROGRESS THAT DID NOT HAPPEN.
//
// A session checkpoint is a global keyspace index meaning "everything below
// this has been tested". If the runner publishes an index ahead of the
// candidates it actually tried, the resumed run starts past the gap and the
// candidates in it are never tested by anybody — and the user is told "not
// found" for a password that was in the keyspace all along. Nothing prints,
// nothing errors; the run just quietly lies.
//
// That risk is why --session used to pin every brute/mask run to the scalar
// runner even for the vector-eligible digests, at roughly a tenth of the
// throughput. These tests are what replaces that conservatism: they hold the
// vector runner (runLayoutFast) to exactly the watermark contract the scalar
// runner (runLayout) has always met, from both sides — nothing skipped, and a
// checkpoint written by either runner resuming correctly under the other.

import (
	"context"
	"crypto/md5"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// ── harness ─────────────────────────────────────────────────────────────────

// layoutRun is one runner reduced to the arguments these tests vary. Both the
// scalar and the vector runner are driven through this single shape so every
// property below can be asserted of BOTH without the test knowing which is
// which — the point being that the two are interchangeable.
type layoutRun struct {
	name string
	run  func(ctx context.Context, l *keyspaceLayout, resumeFrom, limit int64,
		workers int, attempts, watermark *int64, target [16]byte) (string, error)
}

func scalarRun() layoutRun {
	return layoutRun{"scalar", func(ctx context.Context, l *keyspaceLayout, resumeFrom, limit int64,
		workers int, attempts, watermark *int64, target [16]byte) (string, error) {
		return runLayout(ctx, l, resumeFrom, limit, workers, attempts, watermark,
			func(c string) bool { return md5.Sum([]byte(c)) == target })
	}}
}

// fastRun returns the vector runner bound to MD5, or ok=false on a build with
// no active vector backend (amd64 without AVX2, or anything non-arm64 —
// including this suite under Rosetta), where there is no fast path to test.
func fastRun() (layoutRun, bool) {
	algo, ok := fastAlgoFor("md5")
	if !ok {
		return layoutRun{}, false
	}
	return layoutRun{"fast", func(ctx context.Context, l *keyspaceLayout, resumeFrom, limit int64,
		workers int, attempts, watermark *int64, target [16]byte) (string, error) {
		return runLayoutFast(ctx, l, resumeFrom, limit, workers, attempts, watermark, algo, target)
	}}, true
}

// bothRunners returns the scalar runner always, plus the vector runner when
// this build has one. Tests that must exercise the vector runner specifically
// call requireFast instead of silently passing on scalar alone.
func bothRunners() []layoutRun {
	rs := []layoutRun{scalarRun()}
	if f, ok := fastRun(); ok {
		rs = append(rs, f)
	}
	return rs
}

func requireFast(t *testing.T) layoutRun {
	t.Helper()
	f, ok := fastRun()
	if !ok {
		t.Skipf("no vector backend on this build (%q); there is no fast path to hold to the contract",
			vectorBackendName())
	}
	return f
}

// newTestSession returns a sessionState whose save() writes somewhere
// harmless. The flush goroutine in runSessionRunner calls save() on a ticker,
// and a zero-value path would drop a ".tmp" file in the working directory.
func newTestSession(t *testing.T, name string) *sessionState {
	t.Helper()
	return &sessionState{Name: name, path: filepath.Join(t.TempDir(), name+".json")}
}

// runWithSession drives one runner through the REAL checkpointing core —
// runSessionRunner, the same function crackHash uses — and returns the result
// and the checkpoint that would have been persisted.
func runWithSession(t *testing.T, ctx context.Context, r layoutRun, l *keyspaceLayout,
	resumeFrom, limit int64, workers int, attempts *int64, target [16]byte) (string, int64) {
	t.Helper()
	s := newTestSession(t, "wm")
	pw, _, err := runSessionRunner(ctx, l, s, resumeFrom, func(wm *int64) (string, error) {
		return r.run(ctx, l, resumeFrom, limit, workers, attempts, wm, target)
	})
	if err != nil {
		t.Fatalf("%s: run: %v", r.name, err)
	}
	return pw, s.Checkpoint
}

// probeLayout is deliberately multi-segment (three candidate lengths, so the
// vector runner must reset its fixed-length batch mid-run) with segment
// boundaries at 1000 and 11000 — neither a multiple of keyspaceChunk (4096)
// nor of any vector group width, so chunk, segment and group boundaries all
// fall out of step with each other. Candidates are unique across the whole
// layout (different lengths cannot collide), which is what lets a test map a
// found password back to the exact index it was planted at.
func probeLayout() *keyspaceLayout { return bruteLayout("abcdefghij", 3, 5) } // 1000+10000+100000

func md5At(l *keyspaceLayout, i int64) [16]byte { return md5.Sum([]byte(l.candidate(i))) }

// ── 1. a completed slice checkpoints at its bound, exactly ──────────────────

// A run that exhausts [resumeFrom, resumeFrom+limit) must checkpoint at the
// bound: not short of it (which would re-test work, and on a --limit slice
// would misreport how much of the keyspace is covered) and above all not past
// it. Asserted for both runners, at cut points that are chunk-aligned, one
// candidate off a chunk boundary, inside a segment and straddling one.
func TestSessionCheckpointEqualsExhaustedBound(t *testing.T) {
	l := probeLayout()
	for _, r := range bothRunners() {
		for _, cut := range []int64{1, 999, 1000, 1001, 4096, 4097, 11000, 12345, 40960, l.total} {
			var attempts int64
			// Target absent from the keyspace, so the run always exhausts its
			// slice rather than stopping early on a hit.
			var absent [16]byte
			absent[0] = 0xff
			pw, ckpt := runWithSession(t, context.Background(), r, l, 0, cut, 4, &attempts, absent)
			if pw != "" {
				t.Fatalf("%s cut=%d: spurious hit %q", r.name, cut, pw)
			}
			if ckpt != cut {
				t.Errorf("%s: slice [0,%d) exhausted but checkpointed at %d — a checkpoint "+
					"above the bound skips candidates on resume, below it re-runs them",
					r.name, cut, ckpt)
			}
			if attempts != cut {
				t.Errorf("%s cut=%d: attempted %d candidates, want exactly %d", r.name, cut, attempts, cut)
			}
		}
	}
}

// ── 2. the two halves of an interrupted run tile the keyspace ───────────────

// The union of [0,cut) and [cut,total) must be the whole keyspace: every
// candidate found by exactly one half, none by both, none by neither. This is
// the resume property stated directly on candidates rather than on indices —
// "no candidate missed, none tried twice" — for the vector runner, at cut
// points that are checkpoints a real interrupted run could produce.
func TestFastPathHalvesTileTheKeyspace(t *testing.T) {
	r := requireFast(t)
	l := probeLayout()
	for _, cut := range []int64{1000, 4096, 11000, 12345, 40960} {
		// Probe indices chosen to sit exactly where an off-by-one in the chunk,
		// group or segment arithmetic would hide: on both sides of the cut, on
		// both sides of every segment boundary, and at the ends.
		probes := []int64{0, 1, 999, 1000, 1001, 10999, 11000, 11001,
			cut - 2, cut - 1, cut, cut + 1, cut + 2, l.total - 1}
		for _, j := range probes {
			if j < 0 || j >= l.total {
				continue
			}
			target := md5At(l, j)
			want := l.candidate(j)

			var a1, a2 int64
			lower, _ := runWithSession(t, context.Background(), r, l, 0, cut, 4, &a1, target)
			upper, _ := runWithSession(t, context.Background(), r, l, cut, 0, 4, &a2, target)

			inLower, inUpper := lower == want, upper == want
			switch {
			case inLower && inUpper:
				t.Errorf("cut=%d index=%d (%q): tried by BOTH halves", cut, j, want)
			case !inLower && !inUpper:
				t.Errorf("cut=%d index=%d (%q): tried by NEITHER half — a resume from "+
					"checkpoint %d would report 'not found' for a password that is in the keyspace",
					cut, j, want, cut)
			case inLower != (j < cut):
				t.Errorf("cut=%d index=%d (%q): found by the wrong half (lower=%v)", cut, j, want, inLower)
			}
		}
	}
}

// ── 3. cross-runner resume, both directions ────────────────────────────────

// runLayoutFast's doc comment claims a checkpoint written by one runner
// resumes correctly under the other. This makes that a test, in both
// directions, so it stays true: the claim is the entire basis for letting a
// session switch runners between one release and the next (an existing
// checkpoint file, written by the scalar-only release, must resume under the
// vector runner — and a machine with no vector backend must be able to pick
// up a checkpoint written by one that had).
func TestCrossRunnerCheckpointResume(t *testing.T) {
	fast := requireFast(t)
	scalar := scalarRun()
	l := probeLayout()

	for _, dir := range []struct{ first, second layoutRun }{
		{fast, scalar}, {scalar, fast}, {fast, fast}, {scalar, scalar},
	} {
		for _, cut := range []int64{1000, 4097, 11000, 12345} {
			var absent [16]byte
			absent[0] = 0xff
			var a0 int64
			_, ckpt := runWithSession(t, context.Background(), dir.first, l, 0, cut, 4, &a0, absent)
			if ckpt != cut {
				t.Fatalf("%s->%s cut=%d: first half checkpointed at %d", dir.first.name, dir.second.name, cut, ckpt)
			}

			// The password sits at the FIRST index the resume will touch: the
			// exact candidate a checkpoint one step too eager would skip.
			atCkpt := md5At(l, ckpt)
			var a1 int64
			got, _ := runWithSession(t, context.Background(), dir.second, l, ckpt, 0, 4, &a1, atCkpt)
			if want := l.candidate(ckpt); got != want {
				t.Errorf("%s wrote checkpoint %d, %s resumed there and did not find %q (got %q)",
					dir.first.name, ckpt, dir.second.name, want, got)
			}

			// And the candidate just BELOW the checkpoint must not be retried:
			// the checkpoint is a claim that it was already covered.
			if ckpt > 0 {
				var a2 int64
				got, _ := runWithSession(t, context.Background(), dir.second, l, ckpt, 0, 4, &a2, md5At(l, ckpt-1))
				if got != "" {
					t.Errorf("%s->%s: resume from %d retried index %d (%q), which the checkpoint "+
						"says was already covered", dir.first.name, dir.second.name, ckpt, ckpt-1, got)
				}
			}
		}
	}
}

// ── 4. a genuinely interrupted run never over-reports ──────────────────────

// interruptLayout is large enough that a timed cancel lands mid-run rather
// than after it: 10^8 candidates is seconds of work even at the vector
// runner's rate, so a ~150ms cancel is comfortably in the middle.
func interruptLayout() *keyspaceLayout { return bruteLayout("abcdefghij", 8, 8) }

// The invariant that catches an optimistic watermark WITHOUT depending on
// where the cancel happens to land: with a single worker every candidate
// tried is credited to attempts, and the checkpoint claims every index below
// it was tried. So checkpoint-resumeFrom can never exceed attempts. A runner
// that advanced its watermark before doing the work (rather than after) fails
// this on any interrupt at all, not just a lucky one.
func TestInterruptedCheckpointNeverExceedsWorkDone(t *testing.T) {
	l := interruptLayout()
	var absent [16]byte
	absent[0] = 0xff

	for _, r := range bothRunners() {
		for _, workers := range []int{1, 4} {
			for _, resumeFrom := range []int64{0, 12345} {
				ctx, cancel := context.WithCancel(context.Background())
				go func() { time.Sleep(150 * time.Millisecond); cancel() }()
				var attempts int64
				_, ckpt := runWithSession(t, ctx, r, l, resumeFrom, 0, workers, &attempts, absent)
				cancel()

				done := atomic.LoadInt64(&attempts)
				if ckpt-resumeFrom > done {
					t.Errorf("%s workers=%d resumeFrom=%d: checkpoint %d claims %d candidates "+
						"tested but only %d were attempted — the gap is silently skipped on resume",
						r.name, workers, resumeFrom, ckpt, ckpt-resumeFrom, done)
				}
				if ckpt < resumeFrom {
					t.Errorf("%s workers=%d: checkpoint %d below resumeFrom %d", r.name, workers, ckpt, resumeFrom)
				}
				if ckpt >= l.total {
					t.Fatalf("%s workers=%d: run finished instead of being interrupted (checkpoint %d of %d); "+
						"the keyspace is no longer big enough for this test", r.name, workers, ckpt, l.total)
				}
			}
		}
	}
}

// The failure this whole file exists to prevent, staged end to end on the
// runner: interrupt a real vector run, take the checkpoint it wrote, plant the
// password at exactly that index, resume — and require it to be found. A
// watermark that ran even one candidate ahead of the work makes this fail.
func TestFastPathResumeFindsPasswordAtTheCheckpoint(t *testing.T) {
	r := requireFast(t)
	l := interruptLayout()
	var absent [16]byte
	absent[0] = 0xff

	ctx, cancel := context.WithCancel(context.Background())
	go func() { time.Sleep(150 * time.Millisecond); cancel() }()
	var a0 int64
	_, ckpt := runWithSession(t, ctx, r, l, 0, 0, 4, &a0, absent)
	cancel()
	if ckpt <= 0 || ckpt >= l.total {
		t.Fatalf("interrupt produced checkpoint %d of %d; expected a mid-run value", ckpt, l.total)
	}

	// Two plants: the first index the resume touches, and the one below it,
	// which the interrupted half is responsible for.
	for _, j := range []int64{ckpt, ckpt + 1} {
		var a1 int64
		got, _ := runWithSession(t, context.Background(), r, l, ckpt, 0, 4, &a1, md5At(l, j))
		if want := l.candidate(j); got != want {
			t.Errorf("resume from checkpoint %d did not find %q at index %d (got %q)", ckpt, want, j, got)
		}
	}
	var a2 int64
	below := ckpt - 1
	got, _ := runWithSession(t, context.Background(), r, l, 0, ckpt, 4, &a2, md5At(l, below))
	if want := l.candidate(below); got != want {
		t.Errorf("the interrupted half [0,%d) does not cover index %d (%q) that its own "+
			"checkpoint claims — got %q", ckpt, below, want, got)
	}
}

// ── 5. end to end through doCrack: --session now takes the fast path ───────

// The whole point of the change: a --session brute run of a vector-eligible
// digest must actually reach runLayoutFast, and still resume correctly. The
// dispatch is asserted through fastPathEligible (the single gate
// runBruteOrMaskLayout consults) so this test states the routing, not just
// that the answer came out right.
func TestSessionBruteRunIsFastPathEligible(t *testing.T) {
	requireFast(t)
	if _, ok := fastPathEligible("md5", "", "", bruteLayout("abc", 1, 4)); !ok {
		t.Fatal("an unsalted md5 brute layout must be fast-path eligible; a session no longer changes that")
	}
}

// A --limit slice is an interruption with a deterministic stopping point, so
// this exercises the real CLI path — doCrack, a session file on disk, a fresh
// crackCtx reloading it — with the password planted at exactly the index the
// resume starts from. It also pins requirement 5: --skip/--limit still compose
// with --session, unchanged.
func TestDoCrackSessionResumeFindsPasswordAtCheckpoint(t *testing.T) {
	requireFast(t)
	t.Setenv("HOME", t.TempDir())

	l := bruteLayout("abcdefghij", 4, 4) // 10,000
	const cut = 6000
	pw := l.candidate(cut) // planted exactly at the resume point
	target := md5hex(pw)
	const sessName = "fastpath-resume-test"

	// Phase 1: bounded to [0,6000), which excludes the password. The slice
	// exhausts, so the session is saved at checkpoint 6000.
	cc, err := newCrackCtx("", true, sessName, false, "", false, 0, cut)
	if err != nil {
		t.Fatalf("newCrackCtx: %v", err)
	}
	found, err := doCrack(target, "md5", "brute", "", "abcdefghij", 4, 4, 4, "", "prefix", "", false, nil, nil, cc)
	if err != nil {
		t.Fatalf("phase 1: %v", err)
	}
	if found {
		t.Fatalf("phase 1: password sits at index %d, outside the [0,%d) slice", cut, cut)
	}
	s, err := loadSession(sessName)
	if err != nil || s == nil {
		t.Fatalf("phase 1 saved no session: %v", err)
	}
	if s.Checkpoint != cut {
		t.Fatalf("phase 1 checkpoint = %d, want %d", s.Checkpoint, cut)
	}

	// Phase 2: same target, no bound, resuming from the saved checkpoint. The
	// password is the very first candidate the resume touches.
	cc2, err := newCrackCtx("", true, sessName, false, "", false, 0, 0)
	if err != nil {
		t.Fatalf("newCrackCtx (resume): %v", err)
	}
	if cc2.session == nil || cc2.session.Checkpoint != cut {
		t.Fatalf("resume did not load the checkpoint: %+v", cc2.session)
	}
	found, err = doCrack(target, "md5", "brute", "", "abcdefghij", 4, 4, 4, "", "prefix", "", false, nil, nil, cc2)
	if err != nil {
		t.Fatalf("phase 2: %v", err)
	}
	if !found {
		t.Fatalf("resume from checkpoint %d did not find %q, which is the candidate AT that index — "+
			"this is the silent-skip failure a session checkpoint must never produce", cut, pw)
	}
	if s2, _ := loadSession(sessName); s2 != nil {
		s2.remove()
		t.Error("session file survived a successful crack; it must be removed on success")
	}
}

// --skip must keep overriding a saved checkpoint, and --limit must keep
// bounding the run, exactly as before — now over the fast path.
func TestSessionSkipLimitComposeOverFastPath(t *testing.T) {
	requireFast(t)
	t.Setenv("HOME", t.TempDir())

	l := bruteLayout("abcdefghij", 4, 4)
	const skip, limit = 2000, 1000
	inside := l.candidate(skip + 500)
	outside := l.candidate(skip + limit + 10)
	const sessName = "fastpath-slice-test"

	for _, tc := range []struct {
		name  string
		plain string
		want  bool
	}{{"inside the slice", inside, true}, {"outside the slice", outside, false}} {
		t.Run(tc.name, func(t *testing.T) {
			cc, err := newCrackCtx("", true, sessName, false, "", false, skip, limit)
			if err != nil {
				t.Fatalf("newCrackCtx: %v", err)
			}
			found, err := doCrack(md5hex(tc.plain), "md5", "brute", "", "abcdefghij", 4, 4, 4,
				"", "prefix", "", false, nil, nil, cc)
			if err != nil {
				t.Fatalf("doCrack: %v", err)
			}
			if found != tc.want {
				t.Fatalf("found = %v, want %v for %q in slice [%d,%d)", found, tc.want, tc.plain, skip, skip+limit)
			}
			s, _ := loadSession(sessName)
			if tc.want {
				if s != nil {
					s.remove()
					t.Error("session survived a successful crack")
				}
				return
			}
			if s == nil {
				t.Fatal("exhausted slice saved no session")
			}
			defer s.remove()
			if s.Checkpoint != skip+limit {
				t.Errorf("checkpoint = %d, want %d (where --limit stopped it)", s.Checkpoint, skip+limit)
			}
			if s.Total != l.total {
				t.Errorf("session Total = %d, want the unbounded keyspace %d", s.Total, l.total)
			}
		})
	}
}

// ── 6. everything not fast-path eligible is untouched ──────────────────────

// The change must be a routing change for MD5/MD4/NTLM brute and mask ONLY —
// salted or not, since the cores hash one block whatever is in it. Every other
// mode keeps the scalar, session-aware runner it has always had, and the gate
// that decides is fastPathEligible — so assert on the gate directly, per mode,
// rather than inferring it from a result.
func TestNonEligibleModesStayOnTheScalarPath(t *testing.T) {
	if vectorBackendName() == "" {
		t.Skip("no vector backend; fastPathEligible declines everything here by construction")
	}
	brute := bruteLayout("abcdefghij", 4, 4)
	cases := []struct {
		name     string
		typ      string
		salt     string
		saltMode string
		layout   *keyspaceLayout
	}{
		// A salt itself is eligible now; a salt that does not leave the
		// candidate inside one 64-byte block still is not (52 + 4 = 56 > 55).
		{"over-long salted md5", "md5", strings.Repeat("s", 52), "prefix", brute},
		{"over-long suffix-salted md5", "md5", strings.Repeat("s", 52), "suffix", brute},
		// NTLM doubles the candidate AND the salt: 2*(4+20) = 48 fits, but
		// 2*(4+24) = 56 does not.
		{"over-long salted ntlm", "ntlm", strings.Repeat("s", 24), "prefix", brute},
		// A UTF-16LE password against a raw-byte salt is a mixed encoding one
		// encodeMode cannot express.
		{"md5-utf16le-pass-salt", "md5-utf16le-pass-salt", "abc", "", brute},
		// A generic salted type with no salt at all cannot be hashed.
		{"md5-salt-pass without a salt", "md5-salt-pass", "", "", brute},
		{"sha256", "sha256", "", "", brute},
		{"salted sha256", "sha256", "abc", "prefix", brute},
		{"bcrypt", "bcrypt", "", "", brute},
		{"markov", "md5", "", "", markovLayout(&markovModel{charset: []byte("abc")}, 2, 3)},
		{"hybrid", "md5", "", "", hybridLayout([]string{"aa", "bb"}, [][]byte{[]byte("ab")}, false)},
		{"combinator", "md5", "", "", combinatorLayout([]string{"aa"}, []string{"bb"})},
	}
	for _, c := range cases {
		if _, ok := fastPathEligible(c.typ, c.salt, c.saltMode, c.layout); ok {
			t.Errorf("%s must NOT be routed to the vector runner", c.name)
		}
	}

	// PRINCE builds its layout through its own constructor; keep it in the
	// same list rather than trusting that it happens to set gen.
	pl, _, err := princeLayout([]string{"ab", "cd"}, 2, 6, 2)
	if err != nil {
		t.Fatalf("princeLayout: %v", err)
	}
	if _, ok := fastPathEligible("md5", "", "", pl); ok {
		t.Error("prince must NOT be routed to the vector runner")
	}
}

// A salted brute run with a session must still work end to end — same runner,
// same checkpointing, same result as before the change.
func TestSaltedSessionRunUnchanged(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	const sessName = "salted-session-test"
	cc, err := newCrackCtx("", true, sessName, false, "", false, 0, 0)
	if err != nil {
		t.Fatalf("newCrackCtx: %v", err)
	}
	target := md5hex("s4lt" + "cab")
	found, err := doCrack(target, "md5", "brute", "", "abc", 1, 3, 4, "s4lt", "prefix", "", false, nil, nil, cc)
	if err != nil {
		t.Fatalf("doCrack: %v", err)
	}
	if !found {
		t.Fatal("salted brute with a session must still find its password")
	}
}

// ── 7. the benchmarking escape hatch is a routing switch and nothing more ──

// HASHSMITH_NO_FASTPATH exists so CI can time the scalar path in the same
// binary (--session no longer forces it). It must change WHICH runner runs and
// nothing else: same eligibility question answered "no", same answers out.
func TestNoFastPathEnvForcesScalarWithoutChangingResults(t *testing.T) {
	requireFast(t)
	l := bruteLayout("abcdefghij", 4, 4)
	if _, ok := fastPathEligible("md5", "", "", l); !ok {
		t.Fatal("precondition: md5 brute should be eligible here")
	}
	t.Setenv("HASHSMITH_NO_FASTPATH", "1")
	if _, ok := fastPathEligible("md5", "", "", l); ok {
		t.Fatal("HASHSMITH_NO_FASTPATH must force the scalar path")
	}

	t.Setenv("HOME", t.TempDir())
	cc, err := newCrackCtx("", true, "envsess", false, "", false, 0, 0)
	if err != nil {
		t.Fatalf("newCrackCtx: %v", err)
	}
	found, err := doCrack(md5hex("dcba"), "md5", "brute", "", "abcd", 4, 4, 4, "", "prefix", "", false, nil, nil, cc)
	if err != nil {
		t.Fatalf("doCrack: %v", err)
	}
	if !found {
		t.Fatal("forced-scalar session run must still find its password")
	}
}
