package main

// A keyspace layout maps a single linear index onto a concrete candidate string,
// unifying brute-force and mask enumeration behind one resumable runner.
//
// The keyspace is a sequence of "segments", each a mixed-radix set list:
//
//   - brute-force: one segment per length L (L positions, all sharing the charset)
//   - mask (fixed): a single segment (the parsed per-position sets)
//   - mask (increment): one segment per prefix length lo..len(sets)
//
// Global index i is located in its segment via cumulative offsets, then decoded
// with maskIdxToStr. Because the mapping is deterministic, a run can resume from
// any saved index and re-derive the exact same candidate stream.

import (
	"context"
	"math"
	"os"
	"runtime"
	"sync"
	"sync/atomic"
	"time"
)

const keyspaceChunk = 4096 // indices claimed per worker grab (restore granularity)

type keyspaceLayout struct {
	segments [][][]byte
	offsets  []int64
	total    int64
	gen      func(int64) string // optional override (e.g. Markov); nil = use segments
}

func newLayout(segments [][][]byte) *keyspaceLayout {
	l := &keyspaceLayout{segments: segments}
	var off int64
	for _, seg := range segments {
		l.offsets = append(l.offsets, off)
		// satAdd: maskKeyspace already saturates per-segment; accumulating
		// across segments (increment-mode masks, multi-length brute-force)
		// can itself overflow int64, so saturate here too.
		off = satAdd(off, maskKeyspace(seg))
	}
	l.total = off
	return l
}

// candidate decodes the global index i into its candidate string.
func (l *keyspaceLayout) candidate(i int64) string {
	if l.gen != nil {
		return l.gen(i)
	}
	seg := 0
	for seg+1 < len(l.offsets) && l.offsets[seg+1] <= i {
		seg++
	}
	return maskIdxToStr(i-l.offsets[seg], l.segments[seg])
}

// bruteLayout builds the layout for a brute-force run (one segment per length).
func bruteLayout(charset string, minLen, maxLen int) *keyspaceLayout {
	cs := []byte(charset)
	var segs [][][]byte
	for l := minLen; l <= maxLen; l++ {
		seg := make([][]byte, l)
		for i := range seg {
			seg[i] = cs
		}
		segs = append(segs, seg)
	}
	return newLayout(segs)
}

// maskLayout builds the layout for a mask run, expanding increment mode into one
// segment per prefix length.
func maskLayout(cfg *maskConfig) (*keyspaceLayout, error) {
	sets, err := parseMask(cfg)
	if err != nil {
		return nil, err
	}
	if !cfg.increment {
		return newLayout([][][]byte{sets}), nil
	}
	lo := cfg.incMin
	if lo < 1 {
		lo = 1
	}
	var segs [][][]byte
	for l := lo; l <= len(sets); l++ {
		segs = append(segs, sets[:l])
	}
	return newLayout(segs), nil
}

// runLayout enumerates [resumeFrom, resumeFrom+limit) — or [resumeFrom, total)
// when limit is 0 (unbounded) — across `workers` goroutines using a shared
// atomic chunk allocator. When `watermark` is non-nil it is continuously
// updated to the lowest global index not yet fully processed — a safe restore
// point (everything below it is guaranteed tested). verify returns true on a
// match, which cancels the run and yields the winning candidate.
func runLayout(ctx context.Context, l *keyspaceLayout, resumeFrom, limit int64,
	workers int, atomicAttempts *int64, watermark *int64,
	verify func(string) bool) (string, error) {

	if resumeFrom < 0 {
		resumeFrom = 0
	}
	// bound is the exclusive end of this run's slice of the layout: the whole
	// keyspace, or resumeFrom+limit when a positive limit narrows it — whichever
	// is smaller. satAdd guards resumeFrom+limit overflowing int64.
	bound := l.total
	if limit > 0 {
		if b := satAdd(resumeFrom, limit); b < bound {
			bound = b
		}
	}
	if bound == 0 || resumeFrom >= bound {
		return "", nil
	}
	if workers < 1 {
		workers = 1
	}

	innerCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	firstChunk := resumeFrom / keyspaceChunk
	nextChunk := firstChunk
	resultCh := make(chan string, 1)

	// cur[w] is the chunk worker w is currently processing (MaxInt64 once done),
	// so min(cur)*chunk is the safe restore watermark.
	cur := make([]int64, workers)
	for w := range cur {
		cur[w] = firstChunk
	}

	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(wID int) {
			defer wg.Done()
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
				// Count attempts in a worker-local accumulator and flush per
				// chunk, so the shared counter is not hammered once per candidate
				// (that cache-line contention otherwise caps multi-core scaling).
				var local int64
				iter := 0
				for idx := from; idx < end; idx++ {
					if iter++; iter >= ctxCheckEvery {
						iter = 0
						select {
						case <-innerCtx.Done():
							// Cancelled mid-chunk: leave cur[wID] at the current
							// chunk so the watermark reflects the true resume
							// point (this chunk is re-tested on resume — safe).
							atomic.AddInt64(atomicAttempts, local)
							return
						default:
						}
					}
					cand := l.candidate(idx)
					local++
					if verify(cand) {
						atomic.AddInt64(atomicAttempts, local)
						select {
						case resultCh <- cand:
						default:
						}
						cancel()
						atomic.StoreInt64(&cur[wID], math.MaxInt64)
						return
					}
				}
				atomic.AddInt64(atomicAttempts, local)
			}
		}(w)
	}

	// watermark updater
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
	select {
	case pw := <-resultCh:
		return pw, nil
	default:
		return "", nil
	}
}

// fastCtxCheckEvery returns the group cadence for the fast-path context poll,
// matched to ctxCheckEvery's candidate cadence (a group is shape.group()
// candidates), so cancellation responsiveness is comparable to the scalar
// path's per-candidate check. Derived from the shape rather than fixed, since
// cores differ in how many candidates they hash per call.
func fastCtxCheckEvery(shape vecShape) int {
	n := ctxCheckEvery / shape.group()
	if n < 1 {
		n = 1
	}
	return n
}

// fastAlgo describes one algorithm the NEON fast path can run: its encoding
// mode (how candidate bytes become message bytes — see encodeMode) and its
// vectorised group function (neonGroup candidates hashed per call).
type fastAlgo struct {
	name  string
	enc   encodeMode
	shape vecShape
	// group hashes shape.group() candidates per call. out is a slice rather
	// than a fixed-size array so the group size is data, not part of the
	// type: a 4-lane NEON core produces 20 digests per call and an 8-lane
	// AVX2 core produces 24, and one signature has to express both.
	group func(*transposedBatch, [][16]byte)
}

// vectorBackendName reports which vector core, if any, this process can
// dispatch fast-path candidates to: "neon" on arm64 (the core is always
// compiled in there — see md5neon_arm64.go / md4neon_arm64.go), "avx2" on
// amd64 when the running CPU actually reports AVX2 support (hasAVX2()), or
// ""  otherwise — amd64 without AVX2, or any other architecture, where only
// the scalar path exists.
//
// This replaces the old md5GroupAccelerated() gate. That flag only ever
// answered "does some vector core exist"; fastAlgoFor needs to know WHICH
// one, since the two backends have different shapes (20-way NEON vs 24-way
// AVX2) and could again diverge in which algorithms they cover — today both
// carry MD5 and MD4/NTLM cores, but nothing in the design requires that.
func vectorBackendName() string {
	switch runtime.GOARCH {
	case "arm64":
		return "neon"
	case "amd64":
		if hasAVX2() {
			return "avx2"
		}
	}
	return ""
}

// fastAlgoFor returns the fast-path descriptor for a hash type under the
// currently active vector backend (vectorBackendName), if one exists.
func fastAlgoFor(typ string) (*fastAlgo, bool) {
	return fastAlgoForBackend(vectorBackendName(), typ)
}

// fastAlgoForBackend is fastAlgoFor's backend-parameterised core. Splitting
// it out lets tests exercise the AVX2 (or NEON) selection logic directly —
// in particular, that md4/ntlm route to the MD4 core and never to the MD5
// one — without needing a machine (or Docker container) whose CPU actually
// reports AVX2 support; see TestAVX2BackendRoutesMD4AndNTLM in
// fastpath_test.go.
//
// Resolved through canonicalHashType so hashcat mode numbers (e.g. "900"
// for md4, "1000" for ntlm) and John labels route here too.
//
// On BOTH backends, md4 and ntlm run through that backend's MD4 core
// (md4Group on NEON, md4GroupAVX2 on AVX2) — NTLM is MD4 over UTF-16LE(pw)
// rather than a different digest function, so only the encoding mode
// differs between the two entries.
//
// What must never happen is md4 or ntlm falling through to an MD5 core:
// MD4 is a different algorithm from MD5, and NTLM is MD4-over-UTF-16LE, so
// hashing either through md5Group/md5GroupAVX2 would compute the wrong
// digest for every candidate — wrong, not merely unaccelerated, and with
// nothing to signal it beyond every crack silently coming back "not found".
// Each case names its group function explicitly for that reason; there is
// no fallthrough here and none should be added.
func fastAlgoForBackend(backend, typ string) (*fastAlgo, bool) {
	name := canonicalHashType(typ)
	switch backend {
	case "neon":
		switch name {
		case "md5":
			return &fastAlgo{name: "md5", enc: encRaw, shape: neonShape, group: md5Group}, true
		case "md4":
			return &fastAlgo{name: "md4", enc: encRaw, shape: neonShape, group: md4Group}, true
		case "ntlm":
			return &fastAlgo{name: "ntlm", enc: encUTF16LE, shape: neonShape, group: md4Group}, true
		}
	case "avx2":
		switch name {
		case "md5":
			return &fastAlgo{name: "md5", enc: encRaw, shape: avx2Shape, group: md5GroupAVX2}, true
		case "md4":
			return &fastAlgo{name: "md4", enc: encRaw, shape: avx2Shape, group: md4GroupAVX2}, true
		case "ntlm":
			return &fastAlgo{name: "ntlm", enc: encUTF16LE, shape: avx2Shape, group: md4GroupAVX2}, true
		}
	}
	return nil, false
}

// fastPathEligible reports whether l can be run through the vector-
// accelerated runLayoutFast instead of the scalar runLayout, and if so
// returns the algorithm descriptor to run it with. All of the following
// must hold:
//   - this build has an active vector backend (vectorBackendName() != "");
//   - the target type has a registered fast algorithm for that backend
//     (fastAlgoFor) with no salt — the only digests the vector core computes;
//   - l has no gen override: a Markov (or other) generator's candidates are
//     not mixed-radix decodable from segments, which fillFromSegment requires;
//   - every segment's length fits one block under the algorithm's encoding
//     mode (transposedFixedLenOK), since transposedBatch is fixed-length per
//     reset;
//   - for encUTF16LE (NTLM), every byte of every charset in every segment is
//     ASCII (< 0x80). Hashsmith's utf16le (hash.go) is a UTF-8 decode
//     followed by a UTF-16 encode, not a naive b,0x00 byte expansion: for a
//     non-ASCII byte the two diverge (e.g. []rune(string([]byte{0xC3})) is
//     U+FFFD, encoding to FD FF, not C3 00). fillFromSegment's encUTF16LE
//     path always does the naive b,0x00 expansion, so a charset containing a
//     high byte would make the fast path compute a different digest than
//     Hashsmith's own scalar path — silently. Declining keeps such masks on
//     the scalar path instead.
//
// One escape hatch, and it is a measurement tool rather than a feature:
// setting HASHSMITH_NO_FASTPATH to a non-empty value makes this decline
// unconditionally, so the very same binary can be timed on the scalar path.
// CI's fast-vs-scalar A/B needs that (it used to force the scalar path with
// --session, which no longer does so — see runBruteOrMaskLayout). It is
// checked here, at the single dispatch gate, so it can only ever change
// WHICH runner enumerates the keyspace, never which candidates are tried or
// what a session checkpoint means; both runners produce the same result at
// different speeds. Deliberately an env var and not a flag: no documented
// flag changes meaning, and nothing in the CLI surface grows a knob whose
// only honest use is benchmarking.
func fastPathEligible(typ, salt string, l *keyspaceLayout) (*fastAlgo, bool) {
	if os.Getenv("HASHSMITH_NO_FASTPATH") != "" {
		return nil, false
	}
	if vectorBackendName() == "" {
		return nil, false
	}
	algo, ok := fastAlgoFor(typ)
	if !ok {
		return nil, false
	}
	if salt != "" {
		return nil, false
	}
	if l == nil || l.gen != nil {
		return nil, false
	}
	// A descriptor with no shape would divide by zero deriving the context
	// cadence, inside a worker goroutine, far from the cause. Refuse here.
	if algo.shape.group() <= 0 {
		return nil, false
	}
	for _, seg := range l.segments {
		if !transposedFixedLenOK(len(seg), algo.enc) {
			return nil, false
		}
	}
	if algo.enc == encUTF16LE {
		for _, seg := range l.segments {
			for _, charset := range seg {
				for _, b := range charset {
					if b >= 0x80 {
						return nil, false
					}
				}
			}
		}
	}
	return algo, true
}

// runLayoutFast is runLayout's NEON-accelerated twin for a fast-path
// algorithm (see fastAlgo) over a fixed-length, unsalted keyspace. It mirrors
// runLayout's chunk allocator, watermark, attempt accounting and cancellation
// exactly, so a checkpoint written by one runner resumes correctly under the
// other — but each worker owns a transposedBatch and hashes neonGroup
// candidates per algo.group call instead of verifying one candidate at a
// time.
//
// Callers must have already confirmed fastPathEligible(typ, salt, l), and
// pass the resulting algo; this function does not re-check eligibility.
//
// Two correctness requirements this function upholds:
//   - a group never straddles a segment boundary: fillFromSegment already
//     clamps to its segment's own total, and the chunk's `end` additionally
//     clamps `used` so a group is never credited (or hashed for a hit) past
//     either boundary;
//   - only lanes 0..used-1 of a partial final group are considered for a
//     hit. Unused lanes hash the empty string and would otherwise falsely
//     match whenever the target is the algorithm's digest of "".
func runLayoutFast(ctx context.Context, l *keyspaceLayout, resumeFrom, limit int64,
	workers int, atomicAttempts *int64, watermark *int64,
	algo *fastAlgo, target [16]byte) (string, error) {

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
		return "", nil
	}
	if workers < 1 {
		workers = 1
	}

	innerCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	firstChunk := resumeFrom / keyspaceChunk
	nextChunk := firstChunk
	resultCh := make(chan string, 1)
	errCh := make(chan error, 1)

	// cur[w] is the chunk worker w is currently processing (MaxInt64 once
	// done), so min(cur)*chunk is the safe restore watermark — identical
	// meaning to runLayout's cur.
	cur := make([]int64, workers)
	for w := range cur {
		cur[w] = firstChunk
	}

	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(wID int) {
			defer wg.Done()
			tb := newTransposedBatch(algo.shape)
			ctxEvery := fastCtxCheckEvery(algo.shape)
			curLen := -1  // no length reset yet; forces a reset on first group
			lastSeg := -1 // no segment cached yet; forces a maskKeyspace on first group
			var segTotal int64
			out := make([][16]byte, algo.shape.group())
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
				groups := 0
				pos := from
				// Locate pos's segment once per chunk; advanced monotonically
				// below as pos crosses segment boundaries (pos only increases
				// within a chunk, so this never needs to re-scan from 0).
				seg := 0
				for seg+1 < len(l.offsets) && l.offsets[seg+1] <= pos {
					seg++
				}
				for pos < end {
					if groups++; groups >= ctxEvery {
						groups = 0
						select {
						case <-innerCtx.Done():
							// Cancelled mid-chunk: leave cur[wID] at the
							// current chunk so the watermark reflects the
							// true resume point (re-tested on resume — safe).
							atomic.AddInt64(atomicAttempts, local)
							return
						default:
						}
					}
					for seg+1 < len(l.offsets) && l.offsets[seg+1] <= pos {
						seg++
					}
					sets := l.segments[seg]
					segLen := len(sets)
					if seg != lastSeg {
						// maskKeyspace(sets) is invariant for this segment
						// but costs a multiply per position; the segment is
						// filled group-by-group across many calls, so cache
						// it here rather than recomputing on every group.
						segTotal = maskKeyspace(sets)
						lastSeg = seg
					}
					if segLen != curLen {
						// A group must never straddle a segment boundary:
						// segments can have different candidate lengths, and
						// the batch is fixed-length for its whole life
						// between resets. Reset whenever the length changes.
						if err := tb.reset(segLen, algo.enc); err != nil {
							// Cannot happen: fastPathEligible already
							// verified every segment length satisfies
							// transposedFixedLenOK. Bail rather than risk
							// hashing the wrong thing if it somehow did.
							atomic.AddInt64(atomicAttempts, local)
							select {
							case errCh <- err:
							default:
							}
							cancel()
							atomic.StoreInt64(&cur[wID], math.MaxInt64)
							return
						}
						curLen = segLen
					}
					localFrom := pos - l.offsets[seg]
					n := tb.fillFromSegment(sets, localFrom, segTotal)
					if n == 0 {
						// Segment exhausted; should not happen since end is
						// bounded by l.total and pos < end. Guard anyway.
						break
					}
					// fillFromSegment already clamps n to this segment's own
					// remaining candidates. Additionally clamp to this
					// chunk's `end` so a group is never credited (or hashed
					// for a hit) past the chunk boundary another worker may
					// already own — this is what keeps attempt accounting
					// exact and matches runLayout's per-candidate `idx < end`
					// bound.
					used := n
					if remaining := end - pos; int64(used) > remaining {
						used = int(remaining)
					}
					algo.group(tb, out)
					// Only lanes 0..used-1 are real candidates. Lanes beyond
					// that (including fillFromSegment's own padding of
					// unused lanes up to n, and anything past used) hash the
					// empty string and must never be treated as a hit.
					hit := -1
					for i := 0; i < used; i++ {
						if out[i] == target {
							hit = i
							break
						}
					}
					local += int64(used)
					if hit >= 0 {
						cand := string(tb.candidateAt(hit))
						atomic.AddInt64(atomicAttempts, local)
						select {
						case resultCh <- cand:
						default:
						}
						cancel()
						atomic.StoreInt64(&cur[wID], math.MaxInt64)
						return
					}
					pos += int64(used)
				}
				atomic.AddInt64(atomicAttempts, local)
			}
		}(w)
	}

	// watermark updater
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
	select {
	case err := <-errCh:
		return "", err
	default:
	}
	select {
	case pw := <-resultCh:
		return pw, nil
	default:
		return "", nil
	}
}

func updateWatermark(cur []int64, watermark *int64, total int64) {
	min := int64(math.MaxInt64)
	for w := range cur {
		if v := atomic.LoadInt64(&cur[w]); v < min {
			min = v
		}
	}
	if min == math.MaxInt64 {
		atomic.StoreInt64(watermark, total)
		return
	}
	pos := min * keyspaceChunk
	if pos > total {
		pos = total
	}
	atomic.StoreInt64(watermark, pos)
}
