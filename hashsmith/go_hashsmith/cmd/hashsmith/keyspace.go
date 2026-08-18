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
