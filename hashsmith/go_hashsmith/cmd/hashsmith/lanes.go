package main

import (
	"context"
	"math"
	"sync"
	"sync/atomic"
	"time"

	"hashsmith-go/internal/bcryptlane"
)

// newLaneHasher reports whether typ has an interleaved multi-candidate core for
// this target and, if so, returns a factory producing one hasher per worker.
//
// It returns a FACTORY rather than a shared *Hasher on purpose: the hasher owns
// reusable lane scratch so a batch allocates nothing, which makes it unsafe for
// concurrent use. One per worker, never one shared.
//
// bcrypt only, single target only. Every lane in a batch executes the same
// iteration count in lockstep, so they must share one cost and one salt - which
// is true of one target and false of a dump. Dumps keep the scalar path.
func newLaneHasher(typ, targetHash, salt, saltMode string) (func() *bcryptlane.Hasher, bool) {
	if canonicalHashType(typ) != "bcrypt" || salt != "" {
		return nil, false
	}
	if _, err := bcryptlane.NewHasher(targetHash); err != nil {
		return nil, false
	}
	return func() *bcryptlane.Hasher {
		h, err := bcryptlane.NewHasher(targetHash)
		if err != nil {
			return nil // caller falls back to the scalar verify
		}
		return h
	}, true
}

// runLayoutLanes is runLayout's bcrypt-laned twin: identical bounds
// arithmetic, chunk striping, cur[] watermark tracking and watermark-updater
// goroutine, so --session resume, --skip/--limit slicing and the progress
// counter behave identically to every other runner. The only difference is
// the per-chunk inner loop, which buffers candidates and flushes them through
// an interleaved multi-candidate bcrypt core (bcryptlane.Hasher) instead of
// calling a scalar verify closure once per candidate.
func runLayoutLanes(ctx context.Context, l *keyspaceLayout, resumeFrom, limit int64,
	workers int, atomicAttempts *int64, watermark *int64,
	newHasher func() *bcryptlane.Hasher) (string, error) {

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
			// Each worker owns one Hasher for the life of the run: it carries
			// reusable lane scratch and must never be shared (see lanes.go).
			var lh *bcryptlane.Hasher
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
				if lh == nil {
					lh = newHasher()
				}
				if lh == nil { // unparseable target; the dispatcher should have caught it
					return
				}

				var local int64
				iter := 0
				cands := make([]string, 0, bcryptlane.Lanes)
				pwBuf := make([][]byte, bcryptlane.Lanes)
				outBuf := make([]bool, bcryptlane.Lanes)

				// flush tests everything buffered, reporting the FIRST hit in
				// buffer order so a laned run reports the same candidate an
				// unlaned run would. Returns true when the run should stop.
				flush := func() bool {
					if len(cands) == 0 {
						return false
					}
					pw := pwBuf[:len(cands)]
					for i, c := range cands {
						pw[i] = []byte(c)
					}
					lh.Run(pw, outBuf[:len(cands)])
					local += int64(len(cands))
					for i, ok := range outBuf[:len(cands)] {
						if ok {
							hit := cands[i]
							atomic.AddInt64(atomicAttempts, local)
							select {
							case resultCh <- hit:
							default:
							}
							cancel()
							atomic.StoreInt64(&cur[wID], math.MaxInt64)
							return true
						}
					}
					cands = cands[:0]
					return false
				}

				for idx := from; idx < end; idx++ {
					if iter++; iter >= ctxCheckEvery {
						iter = 0
						select {
						case <-innerCtx.Done():
							// Cancelled mid-chunk: test what is buffered before
							// leaving, or those candidates are silently skipped.
							flush()
							atomic.AddInt64(atomicAttempts, local)
							return
						default:
						}
					}
					cands = append(cands, l.candidate(idx))
					if len(cands) == bcryptlane.Lanes {
						if flush() {
							return
						}
					}
				}
				// End of chunk: the tail is almost never a full lane width, and
				// dropping it would silently skip up to Lanes-1 candidates per
				// chunk. TestMaskLanesFindsAtEveryPosition covers exactly this.
				if flush() {
					return
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
