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
		off += maskKeyspace(seg)
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

// runLayout enumerates [resumeFrom, total) across `workers` goroutines using a
// shared atomic chunk allocator. When `watermark` is non-nil it is continuously
// updated to the lowest global index not yet fully processed — a safe restore
// point (everything below it is guaranteed tested). verify returns true on a
// match, which cancels the run and yields the winning candidate.
func runLayout(ctx context.Context, l *keyspaceLayout, resumeFrom int64,
	workers int, atomicAttempts *int64, watermark *int64,
	verify func(string) bool) (string, error) {

	if l.total == 0 || resumeFrom >= l.total {
		return "", nil
	}
	if resumeFrom < 0 {
		resumeFrom = 0
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
				if start >= l.total {
					atomic.StoreInt64(&cur[wID], math.MaxInt64)
					return
				}
				atomic.StoreInt64(&cur[wID], c)
				end := start + keyspaceChunk
				if end > l.total {
					end = l.total
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
					updateWatermark(cur, watermark, l.total)
				}
			}
		}()
	}

	wg.Wait()
	if watermark != nil {
		updateWatermark(cur, watermark, l.total)
	}
	select {
	case pw := <-resultCh:
		return pw, nil
	default:
		return "", nil
	}
}

// fastCtxCheckEvery is the group cadence for the fast-path context poll,
// matched to ctxCheckEvery's candidate cadence (a group is neonGroup
// candidates), so cancellation responsiveness is comparable to the scalar
// path's per-candidate check.
const fastCtxCheckEvery = ctxCheckEvery / neonGroup

// fastPathEligible reports whether l can be run through the NEON-accelerated
// runLayoutFastMD5 instead of the scalar runLayout. All of the following must
// hold:
//   - this build has the vector core (md5GroupAccelerated());
//   - the target type is raw MD5 with no salt — the only digest the vector
//     core computes;
//   - l has no gen override: a Markov (or other) generator's candidates are
//     not mixed-radix decodable from segments, which fillFromSegment requires;
//   - every segment's length fits one MD5 block (transposedFixedLenOK), since
//     transposedBatch is fixed-length per reset.
func fastPathEligible(typ, salt string, l *keyspaceLayout) bool {
	if !md5GroupAccelerated() {
		return false
	}
	if canonicalHashType(typ) != "md5" {
		return false
	}
	if salt != "" {
		return false
	}
	if l == nil || l.gen != nil {
		return false
	}
	for _, seg := range l.segments {
		if !transposedFixedLenOK(len(seg)) {
			return false
		}
	}
	return true
}

// runLayoutFastMD5 is runLayout's NEON-accelerated twin for raw unsalted MD5
// over a fixed-length keyspace. It mirrors runLayout's chunk allocator,
// watermark, attempt accounting and cancellation exactly, so a checkpoint
// written by one runner resumes correctly under the other — but each worker
// owns a transposedBatch and hashes neonGroup candidates per md5Group call
// instead of verifying one candidate at a time.
//
// Callers must have already confirmed fastPathEligible(typ, salt, l); this
// function does not re-check it.
//
// Two correctness requirements this function upholds:
//   - a group never straddles a segment boundary: fillFromSegment already
//     clamps to its segment's own total, and the chunk's `end` additionally
//     clamps `used` so a group is never credited (or hashed for a hit) past
//     either boundary;
//   - only lanes 0..used-1 of a partial final group are considered for a
//     hit. Unused lanes hash the empty string and would otherwise falsely
//     match whenever the target is md5("").
func runLayoutFastMD5(ctx context.Context, l *keyspaceLayout, resumeFrom int64,
	workers int, atomicAttempts *int64, watermark *int64,
	target [16]byte) (string, error) {

	if l.total == 0 || resumeFrom >= l.total {
		return "", nil
	}
	if resumeFrom < 0 {
		resumeFrom = 0
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
			tb := newTransposedBatch()
			curLen := -1 // no length reset yet; forces a reset on first group
			var out [neonGroup][16]byte
			for {
				c := atomic.AddInt64(&nextChunk, 1) - 1
				start := c * keyspaceChunk
				if start >= l.total {
					atomic.StoreInt64(&cur[wID], math.MaxInt64)
					return
				}
				atomic.StoreInt64(&cur[wID], c)
				end := start + keyspaceChunk
				if end > l.total {
					end = l.total
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
					if groups++; groups >= fastCtxCheckEvery {
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
					if segLen != curLen {
						// A group must never straddle a segment boundary:
						// segments can have different candidate lengths, and
						// the batch is fixed-length for its whole life
						// between resets. Reset whenever the length changes.
						if err := tb.reset(segLen); err != nil {
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
					n := tb.fillFromSegment(sets, localFrom)
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
					md5Group(tb, &out)
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
					updateWatermark(cur, watermark, l.total)
				}
			}
		}()
	}

	wg.Wait()
	if watermark != nil {
		updateWatermark(cur, watermark, l.total)
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
