package smith

import (
	"context"
	"math"
	"sync"
	"sync/atomic"
	"time"
)

// ── Batched cores for a generated keyspace ───────────────────────────────────
//
// runLayoutFast and runLayoutStd decode a mixed-radix odometer, so they only
// serve layouts whose candidates ARE that odometer: brute force and masks.
// Every other mode — hybrid, combinator, markov, prince — carries a generator
// instead, and both fast paths refuse a layout with one (`l.gen != nil`).
// §4.1 of the roadmap confirmed the consequence by measurement: those modes
// never reached a batched core.
//
// The generator is not the obstacle. It is `func(i int64) string`: POSITIONAL,
// not a stream, so candidates can be drawn in index order exactly as the
// odometer's are. The obstacle is the same one a wordlist has — a batch is
// fixed-length between fills, and a generator emits whatever length it likes.
//
// So this is the dictionary engine's answer applied to a keyspace: draw the
// chunk's candidates, bucket them by length, hash each full bucket through a
// core. dictVectorLanes is reused unchanged; only the source differs.
//
// Everything a core refuses — a candidate too long for its layout, or
// non-ASCII under a UTF-16LE construction — falls back to the verify closure,
// which is where every candidate of these modes used to go.

// runLayoutBatched is runLayout's batched twin: identical bounds arithmetic,
// chunk striping, cur[] watermark tracking and watermark-updater goroutine, so
// a checkpoint written by one resumes correctly under the other. The only
// difference is the inner loop, which buckets candidates and hashes them in
// groups instead of calling verify once per candidate.
func runLayoutBatched(ctx context.Context, l *keyspaceLayout, resumeFrom, limit int64,
	workers int, atomicAttempts *int64, watermark *int64,
	newLanes func() *dictVectorLanes, verify func(string) bool) (string, error) {

	if resumeFrom < 0 {
		resumeFrom = 0
	}
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

	cur := make([]int64, workers)
	for w := range cur {
		cur[w] = firstChunk
	}

	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(wID int) {
			defer wg.Done()
			lanes := newLanes()
			if lanes == nil {
				// Cannot happen: the caller built one to decide eligibility.
				// Falling through to the closure would still be correct but
				// silently slow, so refuse the chunk loop rather than hide it.
				atomic.StoreInt64(&cur[wID], math.MaxInt64)
				return
			}

			// best is the earliest hit in THIS chunk, by index. A group is
			// hashed all at once, so a hit is known at group granularity
			// rather than per candidate, and two candidates in one group can
			// both match. runLayout returns the first match in index order
			// within a chunk; this keeps that.
			best := dictWord{seq: -1}
			sink := func(dw dictWord, _ []int) bool {
				if best.seq < 0 || dw.seq < best.seq {
					best = dw
				}
				return true
			}

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
				best = dictWord{seq: -1}
				iter := 0
				cancelled := false

				report := func() bool {
					if best.seq < 0 {
						return false
					}
					atomic.AddInt64(atomicAttempts, local)
					select {
					case resultCh <- best.word:
					default:
					}
					cancel()
					atomic.StoreInt64(&cur[wID], math.MaxInt64)
					return true
				}

				for idx := from; idx < end; idx++ {
					if iter++; iter >= ctxCheckEvery {
						iter = 0
						select {
						case <-innerCtx.Done():
							cancelled = true
						default:
						}
						if cancelled {
							break
						}
					}
					cand := l.candidate(idx)
					if !lanes.accepts(cand) {
						// The core cannot represent this candidate. The
						// closure decides, exactly as it did before.
						local++
						if verify(cand) {
							if best.seq < 0 || int(idx-from) < best.seq {
								best = dictWord{word: cand, seq: int(idx - from)}
							}
							break
						}
						continue
					}
					local += int64(lanes.add(cand, "", int(idx-from), sink))
					if best.seq >= 0 {
						// A group matched. Other buckets may hold an EARLIER
						// candidate, so empty them before reporting.
						local += int64(lanes.flushAll(sink))
						break
					}
				}

				// Anything still bucketed has not been hashed. This must run
				// on every exit from the chunk — a cancelled one included, so
				// the attempt count reflects what was actually tested.
				local += int64(lanes.flushAll(sink))

				if report() {
					return
				}
				atomic.AddInt64(atomicAttempts, local)
				if cancelled {
					// Leave cur[wID] at this chunk so the watermark reflects
					// the true resume point; the chunk is re-tested on resume.
					return
				}
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
	select {
	case pw := <-resultCh:
		return pw, nil
	default:
		return "", nil
	}
}
