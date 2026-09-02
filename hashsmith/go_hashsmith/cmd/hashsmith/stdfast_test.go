package main

// Tests for the contiguous-batch stdlib-digest fast path (stdfast.go).
//
// Three failure families drive everything here, because each one produces a
// wrong answer that LOOKS like a right one:
//
//  1. GENERATION. The odometer replaces a mixed-radix decode with an
//     increment-and-carry. Drop the carry and the run still enumerates
//     something, still reports a rate, and silently never tries most of the
//     keyspace. So the generator is compared against maskIdxToStr candidate by
//     candidate over whole segments, not sampled.
//
//  2. COMPARISON WIDTH. SHA-256 is 32 bytes. A comparison that stopped at 16
//     would agree with a full compare on essentially every input ever tried
//     and be catastrophically wrong. So the target set is asserted to reject a
//     digest that matches a target on a long shared prefix and differs after.
//
//  3. ATTRIBUTION. With N targets and 64 candidates hashed per round, a
//     mis-mapped index files a real plaintext against the wrong account. Every
//     multi-target assertion below re-hashes each recovered plaintext and
//     demands it equal the digest it was filed under — never a hit count.
//
// Plus the property session resume rests on, held here to exactly the contract
// session_fastpath_test.go holds the vector runner to: a checkpoint never
// records progress that did not happen.

import (
	"bytes"
	"context"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"sort"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// ── helpers ─────────────────────────────────────────────────────────────────

func sha1hex(s string) string   { d := sha1.Sum([]byte(s)); return hex.EncodeToString(d[:]) }
func sha256hex(s string) string { d := sha256.Sum256([]byte(s)); return hex.EncodeToString(d[:]) }

func hexOf(typ, s string) string {
	if typ == "sha1" {
		return sha1hex(s)
	}
	return sha256hex(s)
}

// stdAlgoOrFail returns the descriptor for typ, failing loudly if it is
// missing: unlike the vector path there is no backend to skip on — this path
// is pure Go and must exist on every build and every architecture.
func stdAlgoOrFail(t *testing.T, typ string) *stdAlgo {
	t.Helper()
	a, ok := stdAlgoFor(typ)
	if !ok {
		t.Fatalf("no stdlib fast-path descriptor for %q; this path has no backend requirement", typ)
	}
	return a
}

func stdTargetsOf(t *testing.T, algo *stdAlgo, hexes ...string) *stdTargets {
	t.Helper()
	st, ok := newStdTargets(hexes, allIdx(len(hexes)), algo.digLen)
	if !ok {
		t.Fatalf("newStdTargets(%v) rejected a valid target set", hexes)
	}
	return st
}

// ── 1. generation: the odometer must equal a full mixed-radix decode ────────

// Every candidate contigBatch generates must be byte-identical to
// maskIdxToStr's, for every index of a segment, from every possible batch
// alignment. Enumerating whole segments (rather than sampling) is what makes a
// dropped odometer carry impossible to miss: the carry only fires when a
// position wraps, so a spot check of the first few indices passes with the
// carry deleted.
func TestContigFillMatchesMaskIdxToStr(t *testing.T) {
	segs := [][][]byte{
		{[]byte("ab")},                                              // 2
		{[]byte("abc"), []byte("de")},                               // 6
		{[]byte("abcde"), []byte("xy"), []byte("012")},              // 30
		{[]byte("abc"), []byte("abc"), []byte("abc"), []byte("ab")}, // 54, several carries deep
		{[]byte("ab"), []byte("cd"), []byte("ef"), []byte("gh"),
			[]byte("ij"), []byte("kl"), []byte("mn")}, // 128 > one batch
	}
	cb := newContigBatch(stdBatchGroup, sha256.Size, stdSalt{})
	for si, sets := range segs {
		total := maskKeyspace(sets)
		// Start from every offset, so the batch boundary lands at every
		// possible phase relative to the segment's own carries.
		for from := int64(0); from < total; from++ {
			for _, want := range []int{1, 3, stdBatchGroup} {
				n := cb.fillFromSegment(sets, from, total, want)
				expect := want
				if int64(expect) > total-from {
					expect = int(total - from)
				}
				if n != expect {
					t.Fatalf("seg %d from=%d want=%d: filled %d, expected %d", si, from, want, n, expect)
				}
				for i := 0; i < n; i++ {
					got := string(cb.candidate(i))
					exp := maskIdxToStr(from+int64(i), sets)
					if got != exp {
						t.Fatalf("seg %d from=%d want=%d lane %d: generated %q, maskIdxToStr says %q",
							si, from, want, i, got, exp)
					}
				}
			}
		}
	}
}

// The batch must never hand back a candidate past the end of its segment: a
// batch that straddled a segment boundary would hash candidates of the wrong
// length against the wrong offsets.
func TestContigFillStopsAtSegmentEnd(t *testing.T) {
	sets := [][]byte{[]byte("abc"), []byte("de")} // total 6
	cb := newContigBatch(stdBatchGroup, sha1.Size, stdSalt{})
	if n := cb.fillFromSegment(sets, 4, 6, stdBatchGroup); n != 2 {
		t.Errorf("from=4 of 6: filled %d, want 2", n)
	}
	if n := cb.fillFromSegment(sets, 6, 6, stdBatchGroup); n != 0 {
		t.Errorf("from=total: filled %d, want 0", n)
	}
	if n := cb.fillFromSegment(sets, 0, 6, 0); n != 0 {
		t.Errorf("want=0: filled %d, want 0", n)
	}
}

// ── 2. hashing: the batch core must equal the stdlib one-shot ───────────────

func TestStdHashBatchMatchesStdlib(t *testing.T) {
	for _, typ := range []string{"sha1", "sha256"} {
		algo := stdAlgoOrFail(t, typ)
		for _, msgLen := range []int{1, 3, 5, 55, 56, 64, 65, 120} {
			for _, n := range []int{1, 2, 17, stdBatchGroup} {
				msgs := make([]byte, n*msgLen)
				for i := range msgs {
					msgs[i] = byte('a' + (i*7+msgLen)%26)
				}
				out := make([]byte, n*algo.digLen)
				algo.hashBatch(msgs, msgLen, n, out)
				for i := 0; i < n; i++ {
					want, _ := hex.DecodeString(hexOf(typ, string(msgs[i*msgLen:(i+1)*msgLen])))
					if got := out[i*algo.digLen : (i+1)*algo.digLen]; !bytes.Equal(got, want) {
						t.Fatalf("%s msgLen=%d n=%d i=%d: %x != %x", typ, msgLen, n, i, got, want)
					}
				}
			}
		}
	}
}

// ── 3. the target set ───────────────────────────────────────────────────────

// lookup's binary search is only correct over a sorted key slab, and its
// prefilter may only ever skip work, never decide a hit.
func TestStdTargetsSortedAndComplete(t *testing.T) {
	algo := stdAlgoOrFail(t, "sha256")
	var hexes []string
	for i := 0; i < 200; i++ {
		hexes = append(hexes, sha256hex(fmt.Sprintf("pw-%d", i)))
	}
	st := stdTargetsOf(t, algo, hexes...)
	dl := st.digLen
	for i := 1; i < st.count; i++ {
		if bytes.Compare(st.keys[(i-1)*dl:i*dl], st.keys[i*dl:(i+1)*dl]) >= 0 {
			t.Fatalf("keys not strictly ascending at %d", i)
		}
	}
	for i, h := range hexes {
		d, _ := hex.DecodeString(h)
		idxs, ok := st.lookup(d)
		if !ok {
			t.Fatalf("target %d (%s) not found by its own lookup", i, h)
		}
		if len(idxs) != 1 || idxs[0] != i {
			t.Fatalf("target %d: lookup returned %v", i, idxs)
		}
	}
	// A digest that is not a target must not be reported, whatever the
	// prefilter says.
	for i := 0; i < 500; i++ {
		d, _ := hex.DecodeString(sha256hex(fmt.Sprintf("absent-%d", i)))
		if _, ok := st.lookup(d); ok {
			t.Fatalf("absent-%d reported as a target", i)
		}
	}
}

// THE truncation guard. A digest that agrees with a real target on its first
// 16 bytes — and on 31 of its 32 — must NOT be reported as that target. A
// comparison that stopped short would pass every other test in this file: no
// two real SHA-256 digests ever collide on 16 bytes by accident, so only a
// deliberately constructed near-miss can distinguish a full compare from a
// truncated one.
func TestStdTargetsRejectsTruncatedMatch(t *testing.T) {
	algo := stdAlgoOrFail(t, "sha256")
	real, _ := hex.DecodeString(sha256hex("the-real-password"))

	for _, sharedPrefix := range []int{8, 16, 24, 31} {
		near := make([]byte, len(real))
		copy(near, real[:sharedPrefix])
		// Everything after the shared prefix differs.
		for i := sharedPrefix; i < len(near); i++ {
			near[i] = real[i] ^ 0xff
		}
		st := stdTargetsOf(t, algo, hex.EncodeToString(real))
		if _, ok := st.lookup(near); ok {
			t.Errorf("a digest sharing only the first %d of %d bytes was reported as the target: "+
				"the comparison is truncated, and SHA-256 hits would be attributed to the wrong hash",
				sharedPrefix, len(real))
		}
		// Sanity: the genuine digest is still found, so the test above is not
		// passing merely because lookup rejects everything.
		if _, ok := st.lookup(real); !ok {
			t.Fatalf("the genuine target was not found (prefix=%d)", sharedPrefix)
		}
	}
}

// Duplicated digests collapse to one key owning every caller index, in the
// caller's original order — the order the scalar path's map slices carry and
// the order results are reported in.
func TestStdTargetsCollapsesDuplicates(t *testing.T) {
	algo := stdAlgoOrFail(t, "sha1")
	shared := sha1hex("shared")
	other := sha1hex("other")
	st, ok := newStdTargets([]string{shared, other, shared, shared}, []int{7, 3, 1, 9}, algo.digLen)
	if !ok {
		t.Fatal("newStdTargets rejected a valid set")
	}
	if st.count != 2 {
		t.Fatalf("count = %d, want 2 distinct digests", st.count)
	}
	d, _ := hex.DecodeString(shared)
	idxs, found := st.lookup(d)
	if !found {
		t.Fatal("shared digest not found")
	}
	if len(idxs) != 3 || idxs[0] != 7 || idxs[1] != 1 || idxs[2] != 9 {
		t.Errorf("owners = %v, want [7 1 9] in caller order", idxs)
	}
}

// A target set with any wrong-width digest is refused WHOLESALE, so the run
// falls back to the scalar path rather than silently attacking a subset.
func TestStdTargetsRejectsWrongWidth(t *testing.T) {
	cases := [][]string{
		{md5hex("x")},                    // 16 bytes offered to a 32-byte algo
		{sha1hex("x")},                   // 20 bytes
		{sha256hex("a"), sha1hex("b")},   // one good, one short
		{sha256hex("a") + "00"},          // too long
		{"not-hex-at-all-not-hex-at-al"}, // not hex
	}
	for _, c := range cases {
		if _, ok := newStdTargets(c, allIdx(len(c)), sha256.Size); ok {
			t.Errorf("newStdTargets accepted %v for a 32-byte digest", c)
		}
	}
	if _, ok := newStdTargets(nil, nil, sha256.Size); ok {
		t.Error("newStdTargets accepted an empty set")
	}
}

// ── 4. eligibility ──────────────────────────────────────────────────────────

func TestStdPathEligibility(t *testing.T) {
	l := bruteLayout("abc", 3, 3)

	for _, typ := range []string{"sha1", "sha256", "SHA256", "100", "1400", "raw-sha1", "raw-sha256"} {
		if _, _, ok := stdPathEligible(typ, "", "prefix", l); !ok {
			t.Errorf("%q should be eligible for the stdlib fast path", typ)
		}
	}
	// The vector-cored digests must NOT be diverted here: they have a faster
	// path, and routing them through this one would be a silent regression.
	for _, typ := range []string{"md5", "md4", "ntlm", "0", "900", "1000"} {
		if _, _, ok := stdPathEligible(typ, "", "prefix", l); ok {
			t.Errorf("%q must not take the stdlib path (it has a vector core)", typ)
		}
	}
	// Types whose message is not the raw candidate bytes must be refused
	// outright rather than hashed as if it were.
	for _, typ := range []string{"sha1-utf16le", "sha256-utf16le", "sha512", "sha224",
		"md5crypt", "bcrypt", "ripemd160", "whirlpool"} {
		if _, _, ok := stdPathEligible(typ, "", "prefix", l); ok {
			t.Errorf("%q must not be eligible in this pass", typ)
		}
	}
	// Salted md5/sha1/sha256 IS eligible now — that is the point of the salted
	// pass — in both salt modes and in both spellings.
	for _, c := range []struct{ typ, salt, saltMode string }{
		{"md5", "somesalt", "prefix"},
		{"md5", "somesalt", "suffix"},
		{"sha1", "somesalt", "prefix"},
		{"sha256", "somesalt", "prefix"},
		{"sha256", "somesalt", "suffix"},
		{"md5-salt-pass", "somesalt", "prefix"},
		{"md5-pass-salt", "somesalt", "prefix"},
		{"sha1-salt-pass", "somesalt", "prefix"},
		{"sha256-pass-salt", "somesalt", "prefix"},
	} {
		if _, _, ok := stdPathEligible(c.typ, c.salt, c.saltMode, l); !ok {
			t.Errorf("salted %s/%s should be eligible", c.typ, c.saltMode)
		}
	}
	// …but only for constructions this path actually computes. A UTF-16LE
	// variant hashes a re-encoded password; sha512 has no core here; a compat
	// type with no salt at all has nothing to hash with; and an over-long salt
	// would not fit the generation buffer.
	for _, c := range []struct{ typ, salt, saltMode string }{
		{"md5-utf16le-pass-salt", "somesalt", "prefix"},
		{"sha1-salt-utf16le-pass", "somesalt", "prefix"},
		{"sha512", "somesalt", "prefix"},
		{"sha512-pass-salt", "somesalt", "prefix"},
		{"blake2b-pass-salt", "somesalt", "prefix"},
		{"md5-salt-pass", "", "prefix"},
		{"bcrypt", "somesalt", "prefix"},
		{"md5crypt", "somesalt", "prefix"},
		{"sha256", strings.Repeat("s", stdMaxSaltLen+1), "prefix"},
	} {
		if _, _, ok := stdPathEligible(c.typ, c.salt, c.saltMode, l); ok {
			t.Errorf("%s with salt %q must not be eligible", c.typ, c.salt)
		}
	}
	// Unsalted md5 still belongs to the vector core, salted or not is the
	// whole distinction: adding md5HashBatch must not have diverted it.
	if _, _, ok := stdPathEligible("md5", "", "prefix", l); ok {
		t.Error("unsalted md5 must stay on the vector path")
	}
	if _, _, ok := stdPathEligible("sha256", "", "prefix", nil); ok {
		t.Error("a nil layout must not be eligible")
	}
	gen := bruteLayout("abc", 3, 3)
	gen.gen = func(i int64) string { return "x" }
	if _, _, ok := stdPathEligible("sha256", "", "prefix", gen); ok {
		t.Error("a generator layout must not be eligible (its candidates are not mixed-radix decodable)")
	}
	long := newLayout([][][]byte{make([][]byte, stdMaxCandidateLen+1)})
	if _, _, ok := stdPathEligible("sha256", "", "prefix", long); ok {
		t.Error("an over-long segment must not be eligible")
	}
	empty := newLayout([][][]byte{{[]byte("ab"), {}}})
	if _, _, ok := stdPathEligible("sha256", "", "prefix", empty); ok {
		t.Error("a segment with an empty character set must not be eligible")
	}
}

// HASHSMITH_NO_FASTPATH is the A/B switch this whole change is measured with:
// it must disable BOTH fast paths, or the two sides of the comparison are not
// the same keyspace runner.
func TestStdPathHonoursNoFastPathEnv(t *testing.T) {
	t.Setenv("HASHSMITH_NO_FASTPATH", "1")
	l := bruteLayout("abc", 3, 3)
	if _, _, ok := stdPathEligible("sha256", "", "prefix", l); ok {
		t.Error("HASHSMITH_NO_FASTPATH must disable the stdlib fast path")
	}
	if _, ok := fastPathEligible("md5", "", "", l); ok {
		t.Error("HASHSMITH_NO_FASTPATH must still disable the vector fast path")
	}
}

// ── 5. single-target agreement with the scalar runner ───────────────────────

// stdSingle drives runLayoutStdSingle for one hex target.
func stdSingle(t *testing.T, ctx context.Context, typ string, l *keyspaceLayout,
	resumeFrom, limit int64, workers int, attempts *int64, watermark *int64, targetHex string) string {
	t.Helper()
	algo := stdAlgoOrFail(t, typ)
	st := stdTargetsOf(t, algo, targetHex)
	pw, err := runLayoutStdSingle(ctx, l, resumeFrom, limit, workers, attempts, watermark, algo, stdSalt{}, st)
	if err != nil {
		t.Fatalf("runLayoutStdSingle: %v", err)
	}
	return pw
}

func TestStdPathAgreesWithScalar(t *testing.T) {
	for _, typ := range []string{"sha1", "sha256"} {
		// Multi-segment on purpose (lengths 2..4), so the batch has to change
		// candidate length mid-run, and the total (26+676+17576) is not a
		// multiple of the 64-wide batch.
		l := bruteLayout("abcdefghijklmnopqrstuvwxyz", 1, 3)
		for _, plain := range []string{"a", "z", "aa", "zz", "aaa", "mnq", "zzz"} {
			target := hexOf(typ, plain)
			var a1, a2 int64
			fast := stdSingle(t, context.Background(), typ, l, 0, 0, 4, &a1, nil, target)
			scalar, err := runLayout(context.Background(), l, 0, 0, 4, &a2, nil,
				func(c string) bool { return hexOf(typ, c) == target })
			if err != nil {
				t.Fatalf("%s/%s scalar: %v", typ, plain, err)
			}
			if fast != plain || scalar != plain {
				t.Errorf("%s/%s: fast=%q scalar=%q", typ, plain, fast, scalar)
			}
			// Independent attribution check: the plaintext returned must
			// actually hash to the target it was returned for.
			if hexOf(typ, fast) != target {
				t.Errorf("%s: %q was returned for %s but hashes to %s", typ, fast, target, hexOf(typ, fast))
			}
		}
	}
}

// A miss must exhaust the slice and report nothing. The target here is the
// digest of the EMPTY string over a keyspace that excludes it (min length 1),
// with a total that is not a multiple of the batch width — the one shape that
// can expose a runner treating unfilled batch slots as candidates.
func TestStdPathExhaustsWithoutSpuriousHit(t *testing.T) {
	for _, typ := range []string{"sha1", "sha256"} {
		l := bruteLayout("ab", 1, 3) // 2+4+8 = 14, not a multiple of 64; excludes ""
		var attempts int64
		got := stdSingle(t, context.Background(), typ, l, 0, 0, 2, &attempts, nil, hexOf(typ, ""))
		if got != "" {
			t.Errorf("%s: got %q, want no match", typ, got)
		}
		if attempts != l.total {
			t.Errorf("%s: attempts = %d, want the full keyspace %d (a spurious hit stops the run early)",
				typ, attempts, l.total)
		}
	}
}

// The empty candidate must still be reachable when the keyspace contains it.
// The returned string is "" whether it was a genuine hit or no hit at all, so
// the attempt counter disambiguates: a genuine hit stops before exhaustion.
func TestStdPathHandlesEmptyCandidate(t *testing.T) {
	l := bruteLayout("ab", 0, 1)
	if l.total == 0 {
		t.Skip("layout does not include the empty candidate")
	}
	var attempts int64
	stdSingle(t, context.Background(), "sha256", l, 0, 0, 1, &attempts, nil, sha256hex(""))
	if attempts >= l.total {
		t.Errorf("attempts = %d, want < %d (a genuine early hit on the empty candidate)", attempts, l.total)
	}
}

// ── 6. --skip / --limit ─────────────────────────────────────────────────────

// stdProbeLayout mirrors session_fastpath_test.go's probeLayout: three
// candidate lengths so the batch changes width mid-run, with boundaries at
// 1000 and 11000 — neither a multiple of keyspaceChunk (4096) nor of the batch
// width (64), so chunk, segment and batch boundaries all fall out of step.
func stdProbeLayout() *keyspaceLayout { return bruteLayout("abcdefghij", 3, 5) }

// A slice must be attempted exactly, and the two halves of a cut must tile the
// keyspace: every candidate tried by exactly one half. This is --skip/--limit
// stated on candidates rather than indices.
func TestStdPathSkipLimitTilesExactlyOnce(t *testing.T) {
	l := stdProbeLayout()
	typ := "sha256"
	for _, cut := range []int64{1000, 4096, 11000, 12345, 40960} {
		// Exhaustion count first: the slice [0,cut) must cost exactly cut.
		var a0 int64
		if got := stdSingle(t, context.Background(), typ, l, 0, cut, 4, &a0, nil,
			hexOf(typ, "definitely-not-in-this-keyspace")); got != "" {
			t.Fatalf("cut=%d: spurious hit %q", cut, got)
		}
		if a0 != cut {
			t.Errorf("cut=%d: attempted %d, want exactly %d", cut, a0, cut)
		}

		probes := []int64{0, 1, 999, 1000, 1001, 10999, 11000, 11001,
			cut - 2, cut - 1, cut, cut + 1, cut + 2, l.total - 1}
		for _, j := range probes {
			if j < 0 || j >= l.total {
				continue
			}
			want := l.candidate(j)
			target := hexOf(typ, want)
			var a1, a2 int64
			lower := stdSingle(t, context.Background(), typ, l, 0, cut, 4, &a1, nil, target)
			upper := stdSingle(t, context.Background(), typ, l, cut, 0, 4, &a2, nil, target)
			inLower, inUpper := lower == want, upper == want
			switch {
			case inLower && inUpper:
				t.Errorf("cut=%d index=%d (%q): tried by BOTH halves", cut, j, want)
			case !inLower && !inUpper:
				t.Errorf("cut=%d index=%d (%q): tried by NEITHER half — a resume from %d "+
					"would report 'not found' for a password that is in the keyspace", cut, j, want, cut)
			case inLower != (j < cut):
				t.Errorf("cut=%d index=%d (%q): found by the wrong half (lower=%v)", cut, j, want, inLower)
			}
		}
	}
}

// ── 7. sessions: a checkpoint must never claim work that did not happen ─────

func stdRunWithSession(t *testing.T, ctx context.Context, typ string, l *keyspaceLayout,
	resumeFrom, limit int64, workers int, attempts *int64, targetHex string) (string, int64) {
	t.Helper()
	algo := stdAlgoOrFail(t, typ)
	st := stdTargetsOf(t, algo, targetHex)
	s := newTestSession(t, "stdwm")
	pw, _, err := runSessionRunner(ctx, l, s, resumeFrom, func(wm *int64) (string, error) {
		return runLayoutStdSingle(ctx, l, resumeFrom, limit, workers, attempts, wm, algo, stdSalt{}, st)
	})
	if err != nil {
		t.Fatalf("runSessionRunner: %v", err)
	}
	return pw, s.Checkpoint
}

func TestStdPathCheckpointEqualsExhaustedBound(t *testing.T) {
	l := stdProbeLayout()
	absent := sha256hex("definitely-not-in-this-keyspace")
	for _, cut := range []int64{1, 999, 1000, 1001, 4096, 4097, 11000, 12345, 40960, l.total} {
		var attempts int64
		pw, ckpt := stdRunWithSession(t, context.Background(), "sha256", l, 0, cut, 4, &attempts, absent)
		if pw != "" {
			t.Fatalf("cut=%d: spurious hit %q", cut, pw)
		}
		if ckpt != cut {
			t.Errorf("slice [0,%d) exhausted but checkpointed at %d — above the bound skips "+
				"candidates on resume, below it re-runs them", cut, ckpt)
		}
		if attempts != cut {
			t.Errorf("cut=%d: attempted %d candidates, want exactly %d", cut, attempts, cut)
		}
	}
}

// A checkpoint written by either runner must resume correctly under the other,
// in both directions — the same claim session_fastpath_test.go pins for the
// vector runner, and the basis for a saved session surviving a release that
// changes which runner a type takes.
func TestStdPathCrossRunnerCheckpointResume(t *testing.T) {
	l := stdProbeLayout()
	typ := "sha256"
	absent := sha256hex("definitely-not-in-this-keyspace")

	scalarWithSession := func(resumeFrom, limit int64, target string) (string, int64) {
		s := newTestSession(t, "scalarwm")
		var a int64
		pw, _, err := runSessionRunner(context.Background(), l, s, resumeFrom, func(wm *int64) (string, error) {
			return runLayout(context.Background(), l, resumeFrom, limit, 4, &a, wm,
				func(c string) bool { return hexOf(typ, c) == target })
		})
		if err != nil {
			t.Fatalf("scalar: %v", err)
		}
		return pw, s.Checkpoint
	}
	stdWithSession := func(resumeFrom, limit int64, target string) (string, int64) {
		var a int64
		return stdRunWithSession(t, context.Background(), typ, l, resumeFrom, limit, 4, &a, target)
	}

	type runner struct {
		name string
		fn   func(resumeFrom, limit int64, target string) (string, int64)
	}
	std := runner{"std", stdWithSession}
	scalar := runner{"scalar", scalarWithSession}

	for _, dir := range []struct{ first, second runner }{
		{std, scalar}, {scalar, std}, {std, std},
	} {
		for _, cut := range []int64{1000, 4097, 11000, 12345} {
			_, ckpt := dir.first.fn(0, cut, absent)
			if ckpt != cut {
				t.Fatalf("%s->%s cut=%d: first half checkpointed at %d", dir.first.name, dir.second.name, cut, ckpt)
			}
			// The password sits at the FIRST index the resume will touch —
			// exactly what a checkpoint one step too eager would skip.
			want := l.candidate(ckpt)
			got, _ := dir.second.fn(ckpt, 0, hexOf(typ, want))
			if got != want {
				t.Errorf("%s wrote checkpoint %d, %s resumed there and did not find %q (got %q)",
					dir.first.name, ckpt, dir.second.name, want, got)
			}
			// And the candidate just below it must not be retried.
			if ckpt > 0 {
				got, _ := dir.second.fn(ckpt, 0, hexOf(typ, l.candidate(ckpt-1)))
				if got != "" {
					t.Errorf("%s->%s: resume from %d retried index %d, which the checkpoint "+
						"says was already covered", dir.first.name, dir.second.name, ckpt, ckpt-1)
				}
			}
		}
	}
}

// With one worker every candidate tried is credited to attempts, and the
// checkpoint claims every index below it was tested — so checkpoint-resumeFrom
// can never exceed attempts. A runner that advanced its watermark before doing
// the work fails this on any interrupt at all.
func TestStdPathInterruptedCheckpointNeverExceedsWorkDone(t *testing.T) {
	l := bruteLayout("abcdefghij", 8, 8) // 10^8: seconds of work, so a 150ms cancel lands mid-run
	absent := sha256hex("definitely-not-in-this-keyspace")
	for _, workers := range []int{1, 4} {
		for _, resumeFrom := range []int64{0, 12345} {
			ctx, cancel := context.WithCancel(context.Background())
			go func() { time.Sleep(150 * time.Millisecond); cancel() }()
			var attempts int64
			_, ckpt := stdRunWithSession(t, ctx, "sha256", l, resumeFrom, 0, workers, &attempts, absent)
			cancel()

			done := atomic.LoadInt64(&attempts)
			if ckpt-resumeFrom > done {
				t.Errorf("workers=%d resumeFrom=%d: checkpoint %d claims %d candidates tested "+
					"but only %d were attempted — the gap is silently skipped on resume",
					workers, resumeFrom, ckpt, ckpt-resumeFrom, done)
			}
			if ckpt < resumeFrom {
				t.Errorf("workers=%d: checkpoint %d below resumeFrom %d", workers, ckpt, resumeFrom)
			}
			if ckpt >= l.total {
				t.Fatalf("workers=%d: the run finished instead of being interrupted (checkpoint %d of %d)",
					workers, ckpt, l.total)
			}
		}
	}
}

// ── 8. multi-target: attribution, completeness, and no ghosts ───────────────

// newStdBatchOf builds a batchTarget list from plaintexts that ARE in the
// keyspace and ghosts that are NOT, interleaved so a lookup that files a hit
// one index off lands on a ghost — visibly cracking something unreachable.
func newStdBatchOf(typ string, plains, ghosts []string) []*batchTarget {
	var b []*batchTarget
	add := func(s string) {
		h := hexOf(typ, s)
		b = append(b, &batchTarget{norm: h, key: h, orig: h})
	}
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

// assertStdAttribution re-hashes every recovered plaintext and demands it
// equal the digest it was filed under — the check that a hit count cannot
// make. Nothing outside `want` may be reported, and everything in it must be.
func assertStdAttribution(t *testing.T, typ string, batch []*batchTarget, want map[string]string) {
	t.Helper()
	for _, e := range batch {
		found := atomic.LoadInt32(&e.flag) == 1
		wantPw, shouldFind := want[e.key]
		switch {
		case found && !shouldFind:
			t.Errorf("target %s was cracked as %q but is not reachable from this keyspace "+
				"(a mis-attributed hit files a real plaintext against the wrong account)", e.key, e.password)
		case !found && shouldFind:
			t.Errorf("target %s (%q) was not recovered", e.key, wantPw)
		case found:
			if e.password != wantPw {
				t.Errorf("target %s: recovered %q, want %q", e.key, e.password, wantPw)
			}
			if got := hexOf(typ, e.password); got != e.key {
				t.Errorf("MIS-ATTRIBUTION: %q filed against %s, but %s(%q) = %s",
					e.password, e.key, typ, e.password, got)
			}
		}
	}
}

func TestStdBatchAttribution(t *testing.T) {
	for _, typ := range []string{"sha1", "sha256"} {
		plains := []string{"aaa", "abc", "mnq", "zzz", "aab", "zza"}
		ghosts := []string{"not-here", "nor-here", "absent1", "absent2"}
		batch := newStdBatchOf(typ, plains, ghosts)
		var remaining int64
		record := batchRecorder(batch, &remaining)

		l := bruteLayout("abcdefghijklmnopqrstuvwxyz", 3, 3)
		var attempts int64
		if !batchStdLayout(context.Background(), typ, l, allIdx(len(batch)), batch, "", "prefix",
			0, 0, 4, &attempts, nil, record) {
			t.Fatalf("%s: batchStdLayout declined an eligible pass", typ)
		}
		want := map[string]string{}
		for _, p := range plains {
			want[hexOf(typ, p)] = p
		}
		assertStdAttribution(t, typ, batch, want)
		if attempts != l.total {
			t.Errorf("%s: attempted %d of %d — the pass stopped early with ghosts outstanding",
				typ, attempts, l.total)
		}
	}
}

// Two targets whose plaintexts are ADJACENT in the keyspace land in the same
// 64-wide batch. Reporting only the first hit in a batch would silently lose
// the second — and would still look like a successful run.
func TestStdBatchFindsAdjacentHitsInOneBatch(t *testing.T) {
	typ := "sha256"
	l := bruteLayout("abcdefghijklmnopqrstuvwxyz", 3, 3)
	// Deliberately consecutive indices, so they cannot be in different batches.
	var plains []string
	for i := int64(0); i < 5; i++ {
		plains = append(plains, l.candidate(700+i))
	}
	batch := newStdBatchOf(typ, plains, nil)
	var remaining int64
	record := batchRecorder(batch, &remaining)
	var attempts int64
	if !batchStdLayout(context.Background(), typ, l, allIdx(len(batch)), batch, "", "prefix",
		0, 0, 4, &attempts, nil, record) {
		t.Fatal("batchStdLayout declined an eligible pass")
	}
	want := map[string]string{}
	for _, p := range plains {
		want[hexOf(typ, p)] = p
	}
	assertStdAttribution(t, typ, batch, want)
}

// Two accounts sharing a password: one digest, both credited.
func TestStdBatchSharedDigestCreditsEveryOwner(t *testing.T) {
	typ := "sha1"
	shared := hexOf(typ, "abc")
	batch := []*batchTarget{
		{norm: shared, key: shared, orig: shared},
		{norm: hexOf(typ, "not-here"), key: hexOf(typ, "not-here"), orig: hexOf(typ, "not-here")},
		{norm: shared, key: shared, orig: shared},
	}
	var remaining int64
	record := batchRecorder(batch, &remaining)
	var attempts int64
	l := bruteLayout("abcdefghijklmnopqrstuvwxyz", 3, 3)
	if !batchStdLayout(context.Background(), typ, l, allIdx(len(batch)), batch, "", "prefix", 0, 0, 4, &attempts, nil, record) {
		t.Fatal("batchStdLayout declined an eligible pass")
	}
	for _, i := range []int{0, 2} {
		if atomic.LoadInt32(&batch[i].flag) != 1 || batch[i].password != "abc" {
			t.Errorf("owner %d of the shared digest was not credited (flag=%d pw=%q)",
				i, batch[i].flag, batch[i].password)
		}
	}
	if atomic.LoadInt32(&batch[1].flag) != 0 {
		t.Errorf("the unreachable target was cracked as %q", batch[1].password)
	}
}

// The end-to-end A/B the whole change is justified by: for the same run, the
// fast path must recover exactly the (target, plaintext) pairs the scalar path
// recovers — same set, same plaintext per target — across a --skip/--limit
// slice as well as a whole keyspace.
func TestStdBatchMatchesScalarPathExactly(t *testing.T) {
	typ := "sha256"
	l := bruteLayout("abcdefghij", 3, 4) // 1000 + 10000
	plains := []string{"aaa", "jjj", "abcd", "jjji", "efg", "hij"}
	ghosts := []string{"zzz", "zzzz"}

	// scalarPairs runs the SAME layout slice through runLayout with the
	// generic per-candidate verify — the HASHSMITH_NO_FASTPATH path.
	pairsFor := func(fast bool, resumeFrom, limit int64) map[string]string {
		batch := newStdBatchOf(typ, plains, ghosts)
		var remaining int64
		record := batchRecorder(batch, &remaining)
		var attempts int64
		if fast {
			if !batchStdLayout(context.Background(), typ, l, allIdx(len(batch)), batch, "", "prefix",
				resumeFrom, limit, 4, &attempts, nil, record) {
				t.Fatal("batchStdLayout declined an eligible pass")
			}
		} else {
			byHash := map[string][]int{}
			for i, e := range batch {
				byHash[e.key] = append(byHash[e.key], i)
			}
			verify := func(c string) bool {
				if idxs, ok := byHash[hexOf(typ, c)]; ok {
					return record(c, idxs)
				}
				return false
			}
			if _, err := runLayout(context.Background(), l, resumeFrom, limit, 4, &attempts, nil, verify); err != nil {
				t.Fatalf("scalar: %v", err)
			}
		}
		out := map[string]string{}
		for _, e := range batch {
			if atomic.LoadInt32(&e.flag) == 1 {
				out[e.key] = e.password
			}
		}
		return out
	}

	for _, slice := range []struct{ resumeFrom, limit int64 }{
		{0, 0}, {0, 4096}, {1000, 0}, {512, 3000}, {1000, 10000},
	} {
		fast := pairsFor(true, slice.resumeFrom, slice.limit)
		scalar := pairsFor(false, slice.resumeFrom, slice.limit)
		if len(fast) != len(scalar) {
			t.Errorf("skip=%d limit=%d: fast recovered %d pairs, scalar %d",
				slice.resumeFrom, slice.limit, len(fast), len(scalar))
		}
		for k, v := range scalar {
			if fast[k] != v {
				t.Errorf("skip=%d limit=%d: target %s — scalar says %q, fast says %q",
					slice.resumeFrom, slice.limit, k, v, fast[k])
			}
		}
		for k, v := range fast {
			if _, ok := scalar[k]; !ok {
				t.Errorf("skip=%d limit=%d: fast reported %s=%q which the scalar path did not find",
					slice.resumeFrom, slice.limit, k, v)
			}
			// Independent of either path's bookkeeping.
			if hexOf(typ, v) != k {
				t.Errorf("MIS-ATTRIBUTION: %q filed against %s", v, k)
			}
		}
	}
}

// batchStdLayout must decline — recording nothing, counting nothing — for
// every pass it cannot enumerate, so the caller's scalar fallback is always
// safe.
func TestBatchStdLayoutDeclinesSafely(t *testing.T) {
	l := bruteLayout("abc", 3, 3)
	mk := func(hexes ...string) []*batchTarget {
		var b []*batchTarget
		for _, h := range hexes {
			b = append(b, &batchTarget{norm: h, key: h, orig: h})
		}
		return b
	}
	cases := []struct {
		name  string
		typ   string
		batch []*batchTarget
	}{
		{"vector-cored type", "md5", mk(md5hex("abc"))},
		{"unsupported type", "sha512", mk(strings.Repeat("ab", 64))},
		{"wrong-width target", "sha256", mk(md5hex("abc"))},
		{"one bad target in the set", "sha256", mk(sha256hex("abc"), "zzzz")},
	}
	for _, c := range cases {
		var attempts int64
		record := func(string, []int) bool { t.Fatalf("%s: recorded a hit from a declined pass", c.name); return true }
		if batchStdLayout(context.Background(), c.typ, l, allIdx(len(c.batch)), c.batch, "", "prefix",
			0, 0, 2, &attempts, nil, record) {
			t.Errorf("%s: batchStdLayout accepted a pass it cannot run correctly", c.name)
		}
		if attempts != 0 {
			t.Errorf("%s: a declined pass counted %d attempts", c.name, attempts)
		}
	}
}

// ── 9. the dispatcher ───────────────────────────────────────────────────────

// runBruteOrMaskLayout is the single seam between the runners. sha1/sha256
// must reach the stdlib path and produce the same answer the scalar path
// does — with and without the A/B env var set.
func TestRunBruteOrMaskLayoutRoutesSha(t *testing.T) {
	for _, typ := range []string{"sha1", "sha256"} {
		for _, noFast := range []bool{false, true} {
			name := fmt.Sprintf("%s/nofast=%v", typ, noFast)
			t.Run(name, func(t *testing.T) {
				if noFast {
					t.Setenv("HASHSMITH_NO_FASTPATH", "1")
				} else {
					t.Setenv("HASHSMITH_NO_FASTPATH", "")
				}
				l := bruteLayout("abcdefghijklmnopqrstuvwxyz", 3, 3)
				target := hexOf(typ, "mnq")
				var attempts int64
				pw, _, err := runBruteOrMaskLayout(context.Background(), l, nil, 0, 0, 4, &attempts,
					typ, "", "prefix", target, func(c string) bool { return hexOf(typ, c) == target })
				if err != nil {
					t.Fatalf("%v", err)
				}
				if pw != "mnq" {
					t.Errorf("got %q, want %q", pw, "mnq")
				}
			})
		}
	}
}

// A construction this path does NOT compute — a salted sha512, whose digest
// core is not wired up here — must keep today's scalar path exactly: the
// verify closure decides, not the fast path. This is the assertion that
// catches a widened eligibility test quietly claiming a format it cannot hash.
func TestRunBruteOrMaskLayoutLeavesUnsupportedSaltedAlone(t *testing.T) {
	l := bruteLayout("abcdefghijklmnopqrstuvwxyz", 3, 3)
	// A "target" the fast path could never match; only the closure can.
	// atomic: the verify closure runs on every worker goroutine at once, so a
	// plain bool here is a data race the -race build catches.
	var called atomic.Bool
	var attempts int64
	pw, _, err := runBruteOrMaskLayout(context.Background(), l, nil, 0, 0, 2, &attempts,
		"sha512", "somesalt", "prefix", strings.Repeat("ab", 64), func(c string) bool {
			called.Store(true)
			return c == "mnq"
		})
	if err != nil {
		t.Fatal(err)
	}
	if !called.Load() {
		t.Error("the verify closure was never called for an unsupported salted target — the fast path took over")
	}
	if pw != "mnq" {
		t.Errorf("got %q, want %q", pw, "mnq")
	}
}

// The salted constructions this path DOES compute must route to it and return
// the same plaintext the scalar path does, in both salt modes, for both the
// -s/-S spelling and the hash:salt compat spelling. Asserted against
// HASHSMITH_NO_FASTPATH=1 on the identical inputs, so the two runners are
// compared rather than the fast path being compared to a restatement of
// itself.
func TestRunBruteOrMaskLayoutRoutesSalted(t *testing.T) {
	const want = "mnq"
	cases := []struct{ name, typ, salt, saltMode string }{
		{"md5 prefix", "md5", "deadbeef", "prefix"},
		{"md5 suffix", "md5", "deadbeef", "suffix"},
		{"sha1 prefix", "sha1", "s@lt", "prefix"},
		{"sha1 suffix", "sha1", "s@lt", "suffix"},
		{"sha256 prefix", "sha256", "0123456789abcdef", "prefix"},
		{"sha256 suffix", "sha256", "0123456789abcdef", "suffix"},
		{"hashcat 20 (md5-salt-pass)", "md5-salt-pass", "abc123", "prefix"},
		{"hashcat 10 (md5-pass-salt)", "md5-pass-salt", "abc123", "suffix"},
		{"hashcat 120 (sha1-salt-pass)", "sha1-salt-pass", "abc123", "prefix"},
		{"hashcat 1410 (sha256-pass-salt)", "sha256-pass-salt", "abc123", "prefix"},
	}
	for _, c := range cases {
		for _, noFast := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/nofast=%v", c.name, noFast), func(t *testing.T) {
				if noFast {
					t.Setenv("HASHSMITH_NO_FASTPATH", "1")
				} else {
					t.Setenv("HASHSMITH_NO_FASTPATH", "")
				}
				target, err := hashText(want, c.typ, c.salt, c.saltMode)
				if err != nil {
					t.Fatalf("hashText: %v", err)
				}
				l := bruteLayout("abcdefghijklmnopqrstuvwxyz", 3, 3)
				var attempts int64
				pw, _, err := runBruteOrMaskLayout(context.Background(), l, nil, 0, 0, 4, &attempts,
					c.typ, c.salt, c.saltMode, target, func(cand string) bool {
						ok, _ := verifyCandidate(cand, target, c.typ, c.salt, c.saltMode)
						return ok
					})
				if err != nil {
					t.Fatalf("%v", err)
				}
				if pw != want {
					t.Errorf("got %q, want %q", pw, want)
				}
			})
		}
	}
}

// The same, for a compat target that carries its salt in the target string
// rather than in -s — the hash:salt spelling a dump actually arrives in.
func TestRunBruteOrMaskLayoutRoutesHashColonSalt(t *testing.T) {
	const want = "mnq"
	for _, typ := range []string{"md5-salt-pass", "md5-pass-salt", "sha1-salt-pass", "sha256-pass-salt"} {
		t.Run(typ, func(t *testing.T) {
			digest, err := hashCompatSaltedDigest(want, typ, "pepper")
			if err != nil {
				t.Fatalf("hashCompatSaltedDigest: %v", err)
			}
			target := digest + ":pepper"
			l := bruteLayout("abcdefghijklmnopqrstuvwxyz", 3, 3)
			var attempts int64
			pw, _, err := runBruteOrMaskLayout(context.Background(), l, nil, 0, 0, 4, &attempts,
				typ, "", "prefix", target, func(cand string) bool {
					ok, _ := verifyCandidate(cand, target, typ, "", "prefix")
					return ok
				})
			if err != nil {
				t.Fatalf("%v", err)
			}
			if pw != want {
				t.Errorf("got %q, want %q", pw, want)
			}
		})
	}
}

// ── 10. the digest a candidate is hashed with is the one Hashsmith computes ─

// The fast path must compute exactly what hashText computes for the same
// type, or a crack silently comes back "not found" for a password that is in
// the keyspace. This is the check that would catch a descriptor wired to the
// wrong algorithm — the failure fastAlgoForBackend's comment warns about, in
// its stdlib form.
func TestStdAlgoMatchesHashPassword(t *testing.T) {
	for _, typ := range []string{"sha1", "sha256"} {
		algo := stdAlgoOrFail(t, typ)
		for _, s := range []string{"", "a", "abc", "password123", strings.Repeat("x", 55),
			strings.Repeat("y", 56), strings.Repeat("z", 120)} {
			if len(s) == 0 {
				continue // hashBatch's stride arithmetic needs a non-zero length
			}
			out := make([]byte, algo.digLen)
			algo.hashBatch([]byte(s), len(s), 1, out)
			want, err := hashText(s, typ, "", "")
			if err != nil {
				t.Fatalf("hashText(%s): %v", typ, err)
			}
			if got := hex.EncodeToString(out); got != want {
				t.Errorf("%s(%q): fast path %s, hashPassword %s", typ, s, got, want)
			}
		}
	}
}

// The whole point of a sorted target slab is that a lookup is a search, not a
// scan; assert the sort order the search relies on is what sort.SliceStable
// produced, independent of newStdTargets' own loop.
func TestStdTargetsKeysAreSortedIndependently(t *testing.T) {
	algo := stdAlgoOrFail(t, "sha256")
	var hexes []string
	for i := 0; i < 64; i++ {
		hexes = append(hexes, sha256hex(fmt.Sprintf("k%d", i)))
	}
	st := stdTargetsOf(t, algo, hexes...)
	raw := make([][]byte, 0, len(hexes))
	for _, h := range hexes {
		d, _ := hex.DecodeString(h)
		raw = append(raw, d)
	}
	sort.Slice(raw, func(i, j int) bool { return bytes.Compare(raw[i], raw[j]) < 0 })
	for i, want := range raw {
		if got := st.keys[i*st.digLen : (i+1)*st.digLen]; !bytes.Equal(got, want) {
			t.Fatalf("key %d: %x, want %x", i, got, want)
		}
	}
}

// Guard against the env var leaking between tests in this file: the A/B switch
// is process-wide, and a test that forgot to restore it would make every later
// eligibility assertion vacuous.
func TestStdFastEnvIsClean(t *testing.T) {
	if v := os.Getenv("HASHSMITH_NO_FASTPATH"); v != "" {
		t.Fatalf("HASHSMITH_NO_FASTPATH leaked into the suite as %q", v)
	}
}
