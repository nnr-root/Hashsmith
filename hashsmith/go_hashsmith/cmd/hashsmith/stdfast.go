package main

// Allocation-free batch fast path for the STDLIB raw digests — today SHA-1 and
// SHA-256.
//
// Why this exists, and why it is not a second vector core:
//
// MD5/MD4/NTLM reach ~90-100 MH/s here because runLayoutFast (keyspace.go)
// hands 20 candidates at a time to a hand-written NEON/AVX2 core. SHA-1 and
// SHA-256 had no fast path at all, so every candidate took the generic scalar
// route through runLayout: locate the segment, mixed-radix decode with a
// division and modulo per position, allocate a string (maskIdxToStr), call an
// indirect verify closure, hash, compare. Measured on an M2 that left them at
// ~15 MH/s while one core calling crypto/sha256.Sum256 in a bare loop reaches
// ~10 MH/s and eight reach ~74 MH/s. The hashing was never the problem: Go's
// arm64 crypto/sha1 and crypto/sha256 already use the ARMv8 SHA instructions,
// which is why raw SHA-256 outruns raw MD5 on this machine. The loss was
// entirely per-candidate harness overhead.
//
// So this path deliberately does NOT vectorise anything. It keeps calling the
// stdlib digest — a hand-rolled SIMD SHA-256 would be competing against a
// hardware instruction and would lose — and removes everything around it:
//
//   - candidates are generated with the same decode-once-then-odometer trick
//     fillFromSegment uses, so there is no division per character position;
//   - they land CONTIGUOUSLY in a reused buffer (stride = candidate length),
//     which is the layout a stdlib hash wants, so no transposition and no
//     per-candidate string allocation;
//   - digests land in a reused slab, and only a hit ever allocates.
//
// Two structural notes:
//
//   - The layout is contiguous, NOT transposed. transposedBatch exists to feed
//     32-bit lanes to a vector core; with no vector core the interleave is pure
//     cost, and reading candidates back out of it would mean candidateAt, which
//     is documented as the slow reporting path. A contiguous batch is both
//     faster and simpler here, and candidateAt becomes a subslice.
//
//   - Digests are handled as variable-width byte slices, not as a fixed-size
//     array type. The 16-byte vector path (runLayoutFast's `target [16]byte`,
//     fastmulti.go's digestKey) is left completely untouched — widening it
//     would have put md5/md4/ntlm, including the adversarially reviewed
//     `i < used` hit-detection bound, back in play for a change they gain
//     nothing from. Everything here is parameterised by algo.digLen instead, so
//     sha224/384/512, blake2 and ripemd160 join by adding one stdAlgo case and
//     one hashBatch function — no second redesign.

import (
	"bytes"
	"context"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"math"
	"os"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	// stdBatchGroup is how many candidates are generated, hashed and searched
	// per round. It exists to amortise the indirect call into algo.hashBatch
	// (and the per-round segment/bounds bookkeeping) over many candidates, so
	// the inner hashing loop stays monomorphic and branch-free. It divides
	// keyspaceChunk (4096), so a chunk is a whole number of rounds.
	stdBatchGroup = 64

	// stdMaxCandidateLen caps the candidate length this path accepts. Unlike
	// transposedBatch there is no one-block constraint — a stdlib hash takes
	// any length — this only bounds the reusable buffers and the odometer's
	// stack arrays. Longer masks simply fall back to the scalar path.
	stdMaxCandidateLen = 128

	// stdMaxDigestLen bounds the digest slab. 64 covers SHA-512/BLAKE2b, the
	// widest digests Hashsmith computes, so future algorithms need no change.
	stdMaxDigestLen = 64
)

// stdAlgo describes one stdlib digest this path can run.
//
// hashBatch is the whole extension seam: it hashes n messages of msgLen bytes
// each, packed contiguously in msgs (stride msgLen), writing n digests of
// digLen bytes into out (stride digLen). Batching the call is what keeps the
// per-candidate cost free of an indirect dispatch — one call covers
// stdBatchGroup candidates and the loop inside it is specialised to one
// concrete digest function.
type stdAlgo struct {
	name      string
	digLen    int
	hashBatch func(msgs []byte, msgLen, n int, out []byte)
}

// sha1HashBatch and sha256HashBatch are the two concrete cores wired up in
// this pass. Each writes straight into the caller's slab through a slice-to-
// array-pointer store, so nothing escapes and nothing is allocated.
func sha1HashBatch(msgs []byte, msgLen, n int, out []byte) {
	for i := 0; i < n; i++ {
		*(*[sha1.Size]byte)(out[i*sha1.Size : i*sha1.Size+sha1.Size]) =
			sha1.Sum(msgs[i*msgLen : i*msgLen+msgLen])
	}
}

func sha256HashBatch(msgs []byte, msgLen, n int, out []byte) {
	for i := 0; i < n; i++ {
		*(*[sha256.Size]byte)(out[i*sha256.Size : i*sha256.Size+sha256.Size]) =
			sha256.Sum256(msgs[i*msgLen : i*msgLen+msgLen])
	}
}

// stdAlgoFor returns the contiguous-batch descriptor for a hash type, resolved
// through canonicalHashType so Hashcat mode numbers ("100", "1400") and John
// names ("raw-sha1", "raw-sha256") route here too.
//
// Only entries whose digest is exactly "the stdlib hash of the candidate
// bytes" belong here. The UTF-16LE variants (sha1-utf16le, sha256-utf16le) are
// deliberately absent: they hash a different message, and adding them means
// adding the encoding step and the ASCII guard fastPathEligible carries for
// NTLM — a later pass, not a silent fallthrough. Nothing falls through here.
func stdAlgoFor(typ string) (*stdAlgo, bool) {
	switch canonicalHashType(typ) {
	case "sha1":
		return &stdAlgo{name: "sha1", digLen: sha1.Size, hashBatch: sha1HashBatch}, true
	case "sha256":
		return &stdAlgo{name: "sha256", digLen: sha256.Size, hashBatch: sha256HashBatch}, true
	}
	return nil, false
}

// stdPathEligible reports whether l can be enumerated by runLayoutStd, and if
// so returns the algorithm to run it with. It mirrors fastPathEligible's
// conditions minus the ones that are specific to a vector core:
//
//   - HASHSMITH_NO_FASTPATH disables it, exactly as it disables the vector
//     path, so the same binary can be timed on the scalar path and the A/B
//     stays a single switch;
//   - the type must be a registered stdlib raw digest with no salt;
//   - l must have no gen override — a Markov (or other) generator's candidates
//     are not mixed-radix decodable, which the odometer requires;
//   - every segment must have between 1 and stdMaxCandidateLen positions, each
//     with a non-empty character set.
//
// There is no vector-backend requirement: this path is pure Go and runs
// identically on every architecture.
func stdPathEligible(typ, salt string, l *keyspaceLayout) (*stdAlgo, bool) {
	if os.Getenv("HASHSMITH_NO_FASTPATH") != "" {
		return nil, false
	}
	if salt != "" {
		return nil, false
	}
	if l == nil || l.gen != nil || len(l.segments) == 0 {
		return nil, false
	}
	algo, ok := stdAlgoFor(typ)
	if !ok {
		return nil, false
	}
	if algo.digLen < 8 || algo.digLen > stdMaxDigestLen {
		return nil, false
	}
	for _, seg := range l.segments {
		if len(seg) < 1 || len(seg) > stdMaxCandidateLen {
			return nil, false
		}
		for _, charset := range seg {
			if len(charset) == 0 {
				return nil, false
			}
		}
	}
	return algo, true
}

// ── candidate generation ────────────────────────────────────────────────────

// contigBatch generates up to `group` candidates of one fixed length into a
// single contiguous buffer, and holds the digest slab they hash into.
//
// Unlike transposedBatch it has no stale-lane hazard to manage: only lanes
// 0..n-1 are ever hashed (hashBatch is passed n) and only 0..n-1 are ever
// searched, so bytes left behind by a longer previous fill are never read.
// That is a property of the contiguous layout, not an accident — the
// transposed batch has to scrub leftovers precisely because its core hashes
// the whole fixed-width group unconditionally.
type contigBatch struct {
	msgs   []byte // group*stdMaxCandidateLen; candidate i at [i*length, (i+1)*length)
	out    []byte // group*stdMaxDigestLen; digest i at [i*digLen, (i+1)*digLen)
	group  int
	digLen int
	length int // candidate length of the current fill (0 before the first)
}

func newContigBatch(group, digLen int) *contigBatch {
	return &contigBatch{
		msgs:   make([]byte, group*stdMaxCandidateLen),
		out:    make([]byte, group*stdMaxDigestLen),
		group:  group,
		digLen: digLen,
	}
}

// fillFromSegment writes up to `want` candidates starting at index `from` of
// the mixed-radix segment `sets`, whose total keyspace is `total`
// (== maskKeyspace(sets), hoisted by the caller since it is invariant for a
// segment). It returns how many it wrote and allocates nothing.
//
// The arithmetic is fillFromSegment's (transposed.go), for the same reason:
// maskIdxInto is a division and a modulo per character position and profiling
// found it dominating generation. `from` is decoded once, in full, exactly as
// maskIdxInto would; every later candidate is the previous one with the last
// position's digit incremented and carried left on overflow. That must stay
// byte-identical to maskIdxInto/maskIdxToStr for every index — see
// TestContigFillMatchesMaskIdxToStr, which enumerates whole segments through
// both paths and compares.
//
// `want` is clamped both to the batch's group size and to the segment's own
// remaining candidates, so the returned count never runs past the segment
// boundary. The caller additionally passes a `want` already clamped to its
// chunk's end, which is what keeps a round from being credited past a chunk
// another worker owns.
func (cb *contigBatch) fillFromSegment(sets [][]byte, from, total int64, want int) int {
	if want > cb.group {
		want = cb.group
	}
	if rem := total - from; rem < int64(want) {
		if rem <= 0 {
			return 0
		}
		want = int(rem)
	}
	if want <= 0 {
		return 0
	}
	L := len(sets)
	if L < 1 || L > stdMaxCandidateLen {
		return 0
	}
	cb.length = L

	// dig[i] is the current digit at position i (an index into sets[i]);
	// together with msgs[...] it encodes the candidate being emitted.
	var dig [stdMaxCandidateLen]int

	// Full decode, once, at `from` — identical arithmetic to maskIdxInto.
	idx := from
	for i := L - 1; i >= 0; i-- {
		base := int64(len(sets[i]))
		d := int(idx % base)
		dig[i] = d
		cb.msgs[i] = sets[i][d]
		idx /= base
	}

	for n := 1; n < want; n++ {
		prev := (n - 1) * L
		cur := n * L
		copy(cb.msgs[cur:cur+L], cb.msgs[prev:prev+L])
		// Advance the odometer by one: increment the last position, carrying
		// left on overflow. Mathematically identical to decoding from+n
		// independently, with no division at all.
		for i := L - 1; i >= 0; i-- {
			dig[i]++
			if dig[i] < len(sets[i]) {
				cb.msgs[cur+i] = sets[i][dig[i]]
				break
			}
			dig[i] = 0
			cb.msgs[cur+i] = sets[i][0]
		}
	}
	return want
}

// candidate returns candidate i's bytes as a subslice of the generation
// buffer — no copy, valid only until the next fill.
func (cb *contigBatch) candidate(i int) []byte {
	return cb.msgs[i*cb.length : (i+1)*cb.length]
}

// digest returns digest i's bytes as a subslice of the digest slab.
func (cb *contigBatch) digest(i int) []byte {
	return cb.out[i*cb.digLen : (i+1)*cb.digLen]
}

// ── target lookup ───────────────────────────────────────────────────────────

// stdTargets is the sorted target set runLayoutStd searches. It is
// fastmulti.go's fastTargets generalised off the 16-byte digestKey: digests of
// any width live packed in one slab (`keys`, count*digLen bytes, sorted
// ascending lexicographically), with idxs parallel to it carrying every caller
// index that named that digest, in the caller's original order. Collapsing
// duplicates into one key with a list of owners is what makes "the same hash
// listed twice" and "two accounts sharing a password" behave exactly as the
// map-based scalar path does: one lookup, every owner credited.
//
// bitmap is a prefilter, not a second source of truth: bit (first 8 bytes as a
// big-endian uint64, >> shift) is set for every target, so a clear bit proves
// the digest is not a target and the search is skipped, while a set bit only
// means "maybe" and is always confirmed by a FULL digLen-byte comparison.
// Correctness rests solely on keys/idxs; a false positive costs one search.
//
// Every comparison in here is over the whole digLen bytes. A prefix compare
// would appear to work on essentially every input and be catastrophically
// wrong — see TestStdTargetsRejectsTruncatedMatch.
type stdTargets struct {
	digLen int
	count  int
	keys   []byte
	idxs   [][]int
	bitmap []uint64
	shift  uint
}

// newStdTargets builds the lookup structure for hexDigests[i] owned by
// idxs[i], for an algorithm whose digest is digLen bytes. It reports false —
// rather than dropping the offending entry — if any digest is not exactly
// digLen bytes of hex, so an unusable target set falls back wholesale to the
// scalar path instead of silently attacking a subset.
func newStdTargets(hexDigests []string, idxs []int, digLen int) (*stdTargets, bool) {
	if len(hexDigests) == 0 || len(hexDigests) != len(idxs) {
		return nil, false
	}
	// The prefilter reads 8 bytes of every digest, and the packed slab assumes
	// a fixed stride; both need a sane width.
	if digLen < 8 || digLen > stdMaxDigestLen {
		return nil, false
	}
	type entry struct {
		key []byte
		idx int
	}
	es := make([]entry, 0, len(hexDigests))
	for i, h := range hexDigests {
		b, err := hex.DecodeString(strings.TrimSpace(h))
		if err != nil || len(b) != digLen {
			return nil, false
		}
		es = append(es, entry{b, idxs[i]})
	}
	// Stable, so entries sharing a digest keep the caller's original order —
	// the order the scalar path's map slices are built in, and the order
	// runBatch reports results in.
	sort.SliceStable(es, func(i, j int) bool { return bytes.Compare(es[i].key, es[j].key) < 0 })

	st := &stdTargets{digLen: digLen}
	for _, e := range es {
		if st.count > 0 && bytes.Equal(st.keys[(st.count-1)*digLen:st.count*digLen], e.key) {
			st.idxs[st.count-1] = append(st.idxs[st.count-1], e.idx)
			continue
		}
		st.keys = append(st.keys, e.key...)
		st.idxs = append(st.idxs, []int{e.idx})
		st.count++
	}

	// Size the prefilter to roughly 256 bits per distinct target (a ~0.4%
	// false-positive rate), clamped to a table that stays cache-resident:
	// 4 KiB at the small end, 256 KiB at the large. Same sizing as
	// fastTargets', for the same reason.
	bits := uint(15)
	for (uint64(1)<<bits) < uint64(st.count)*256 && bits < 21 {
		bits++
	}
	st.shift = 64 - bits
	st.bitmap = make([]uint64, (uint64(1)<<bits)/64)
	for i := 0; i < st.count; i++ {
		b := binary.BigEndian.Uint64(st.keys[i*digLen:i*digLen+8]) >> st.shift
		st.bitmap[b>>6] |= 1 << (b & 63)
	}
	return st, true
}

// lookup returns the caller indices owning digest d, if it is a target. d must
// be exactly digLen bytes; the equality check that decides a hit compares all
// of them.
func (st *stdTargets) lookup(d []byte) ([]int, bool) {
	b := binary.BigEndian.Uint64(d[0:8]) >> st.shift
	if st.bitmap[b>>6]&(1<<(b&63)) == 0 {
		return nil, false
	}
	dl := st.digLen
	i, j := 0, st.count
	for i < j {
		m := int(uint(i+j) >> 1)
		if bytes.Compare(st.keys[m*dl:(m+1)*dl], d) < 0 {
			i = m + 1
		} else {
			j = m
		}
	}
	if i < st.count && bytes.Equal(st.keys[i*dl:(i+1)*dl], d) {
		return st.idxs[i], true
	}
	return nil, false
}

// ── the runner ──────────────────────────────────────────────────────────────

// runLayoutStd enumerates the same slice of a keyspace runLayout would, with
// the same chunk allocator, the same watermark contract, the same attempt
// accounting and the same cancellation behaviour — but generates candidates in
// contiguous batches and hashes them through algo.hashBatch instead of calling
// a verify closure once per candidate.
//
// It serves both the single-target and multi-target cases: a single target is
// simply a stdTargets holding one digest, whose lookup is one bitmap probe.
// Keeping one runner rather than two is deliberate — the chunk/watermark logic
// is the delicate part, and the vector path already demonstrates what a second
// hand-maintained copy costs in drift risk. The bitmap prefilter makes the
// one-target lookup indistinguishable in cost from a direct compare.
//
// onHit is called with the winning candidate and the indices owning the digest
// it matched, serialised across workers; it returns true when nothing is left
// to find, which stops the run. EVERY hit in a batch is reported: a batch is
// stdBatchGroup candidates wide, so two targets whose plaintexts are adjacent
// in the keyspace land in the same batch and stopping at the first would
// silently lose the second.
//
// Callers must have confirmed stdPathEligible(typ, salt, l) and pass the
// resulting algo; this function does not re-check eligibility.
//
// Two correctness requirements, the same two the vector path documents:
//
//   - a batch never straddles a segment boundary — fillFromSegment clamps to
//     its segment's own total;
//   - a batch is never credited, or searched, past the chunk's `end` — `want`
//     is clamped to end-pos before the fill, so n is already within both
//     bounds and there are no lanes beyond n to mistake for candidates.
func runLayoutStd(ctx context.Context, l *keyspaceLayout, resumeFrom, limit int64,
	workers int, atomicAttempts *int64, watermark *int64,
	algo *stdAlgo, targets *stdTargets, onHit func(string, []int) bool) error {

	if resumeFrom < 0 {
		resumeFrom = 0
	}
	// bound mirrors runLayout's: the whole keyspace, or resumeFrom+limit when a
	// positive limit narrows it, whichever is smaller (satAdd guards overflow).
	bound := l.total
	if limit > 0 {
		if b := satAdd(resumeFrom, limit); b < bound {
			bound = b
		}
	}
	if bound == 0 || resumeFrom >= bound {
		return nil
	}
	if workers < 1 {
		workers = 1
	}

	innerCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	firstChunk := resumeFrom / keyspaceChunk
	nextChunk := firstChunk

	// cur[w] is the chunk worker w is currently processing (MaxInt64 once
	// done), so min(cur)*chunk is the safe restore watermark — identical
	// meaning to runLayout's cur.
	cur := make([]int64, workers)
	for w := range cur {
		cur[w] = firstChunk
	}

	// onHit is called from every worker, so it is serialised here rather than
	// leaving each caller to remember that its recorder must be thread-safe.
	var hitMu sync.Mutex

	// Batches are stdBatchGroup candidates wide, so poll the context every
	// ctxCheckEvery/stdBatchGroup batches to match runLayout's per-candidate
	// cadence.
	ctxEvery := ctxCheckEvery / stdBatchGroup
	if ctxEvery < 1 {
		ctxEvery = 1
	}

	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(wID int) {
			defer wg.Done()
			cb := newContigBatch(stdBatchGroup, algo.digLen)
			lastSeg := -1
			var segTotal int64
			for {
				c := atomic.AddInt64(&nextChunk, 1) - 1
				start := c * keyspaceChunk
				if start >= bound {
					atomic.StoreInt64(&cur[wID], math.MaxInt64)
					return
				}
				atomic.StoreInt64(&cur[wID], c)
				end := start + keyspaceChunk
				if end > bound {
					end = bound
				}
				from := start
				if from < resumeFrom {
					from = resumeFrom
				}

				var local int64
				rounds := 0
				pos := from
				// Locate pos's segment once per chunk; advanced monotonically
				// below as pos crosses segment boundaries.
				seg := 0
				for seg+1 < len(l.offsets) && l.offsets[seg+1] <= pos {
					seg++
				}
				for pos < end {
					if rounds++; rounds >= ctxEvery {
						rounds = 0
						select {
						case <-innerCtx.Done():
							// Cancelled mid-chunk: leave cur[wID] at the
							// current chunk so the watermark reflects the true
							// resume point (re-tested on resume — safe).
							atomic.AddInt64(atomicAttempts, local)
							return
						default:
						}
					}
					for seg+1 < len(l.offsets) && l.offsets[seg+1] <= pos {
						seg++
					}
					sets := l.segments[seg]
					if seg != lastSeg {
						// maskKeyspace(sets) is invariant for this segment but
						// costs a multiply per position; the segment is walked
						// batch by batch, so cache it here.
						segTotal = maskKeyspace(sets)
						lastSeg = seg
					}
					want := stdBatchGroup
					if remaining := end - pos; int64(want) > remaining {
						want = int(remaining)
					}
					n := cb.fillFromSegment(sets, pos-l.offsets[seg], segTotal, want)
					if n == 0 {
						// Segment exhausted; cannot happen while pos < end <=
						// l.total, but guard rather than spin.
						break
					}
					msgLen := len(sets)
					algo.hashBatch(cb.msgs[:n*msgLen], msgLen, n, cb.out)

					done := false
					for i := 0; i < n; i++ {
						idxs, ok := targets.lookup(cb.digest(i))
						if !ok {
							continue
						}
						cand := string(cb.candidate(i))
						hitMu.Lock()
						stop := onHit(cand, idxs)
						hitMu.Unlock()
						if stop {
							done = true
						}
					}
					local += int64(n)
					pos += int64(n)
					if done {
						atomic.AddInt64(atomicAttempts, local)
						cancel()
						atomic.StoreInt64(&cur[wID], math.MaxInt64)
						return
					}
				}
				atomic.AddInt64(atomicAttempts, local)
			}
		}(w)
	}

	if watermark != nil {
		atomic.StoreInt64(watermark, resumeFrom)
		go func() {
			t := time.NewTicker(200 * time.Millisecond)
			defer t.Stop()
			for {
				select {
				case <-innerCtx.Done():
					return
				case <-t.C:
					updateWatermark(cur, watermark, bound)
				}
			}
		}()
	}

	wg.Wait()
	if watermark != nil {
		updateWatermark(cur, watermark, bound)
	}
	return nil
}

// ── dispatch helpers ────────────────────────────────────────────────────────

// runLayoutStdSingle adapts runLayoutStd to the single-target crack contract:
// return the first matching plaintext, or "" when the slice is exhausted.
// The recorder runs under runLayoutStd's own mutex and the read happens after
// every worker has returned, so no extra synchronisation is needed.
func runLayoutStdSingle(ctx context.Context, l *keyspaceLayout, resumeFrom, limit int64,
	workers int, atomicAttempts *int64, watermark *int64,
	algo *stdAlgo, targets *stdTargets) (string, error) {

	var found string
	err := runLayoutStd(ctx, l, resumeFrom, limit, workers, atomicAttempts, watermark,
		algo, targets, func(cand string, _ []int) bool {
			if found == "" {
				found = cand
			}
			return true
		})
	if err != nil {
		return "", err
	}
	return found, nil
}

// batchStdLayout is batchFastLayout's stdlib-digest sibling: one multi-hash
// brute/mask pass over `layout`, reporting hits through `record` (batchRunType's
// CAS-guarded recorder, which returns true once every target is found).
//
// resumeFrom/limit are --skip/--limit's slice of the layout, with exactly the
// meaning they carry everywhere else; watermark (nil when nothing is
// checkpointing) is the session restore point the runner publishes into.
//
// It returns false when the pass is not eligible — a non-stdlib type, a salt, a
// generator layout, an over-long segment, or a target that is not the right
// number of hex bytes — in which case the caller must run the SAME layout on
// the scalar path exactly as before. Returning false is always safe: nothing
// has been recorded and no candidate has been counted.
func batchStdLayout(ctx context.Context, typ string, layout *keyspaceLayout,
	active []int, batch []*batchTarget, resumeFrom, limit int64, workers int,
	atomicAttempts *int64, watermark *int64, record func(string, []int) bool) bool {

	if layout == nil || len(active) == 0 {
		return false
	}
	algo, ok := stdPathEligible(typ, "", layout)
	if !ok {
		return false
	}
	hexes := make([]string, len(active))
	for i, idx := range active {
		hexes[i] = batch[idx].norm
	}
	st, ok := newStdTargets(hexes, active, algo.digLen)
	if !ok {
		return false
	}
	if err := runLayoutStd(ctx, layout, resumeFrom, limit, workers, atomicAttempts, watermark,
		algo, st, record); err != nil {
		return false
	}
	return true
}
