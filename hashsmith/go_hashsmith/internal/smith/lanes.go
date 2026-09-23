package smith

import (
	"context"
	"math"
	"sync"
	"sync/atomic"
	"time"

	"hashsmith-go/internal/bcryptlane"
)

// laneHasher verifies a batch of candidates against one target, several at a
// time, by advancing their independent computations together.
//
// Two implement it, for the same reason and by different means. bcrypt's core
// interleaves the Blowfish rounds of several candidates because a deliberately
// slow KDF has no other lever. descrypt's interleaves its DES chains because
// after the table work in descrypt_fast.go the loop is latency-bound on its
// own dependency chain rather than throughput-bound — round j cannot start
// addressing a load until round j-1 has resolved.
type laneHasher interface {
	// Run verifies len(pw) candidates, writing each verdict to out.
	Run(pw [][]byte, out []bool)
}

// newLaneHasher reports whether typ has an interleaved multi-candidate core for
// this target and, if so, returns a factory producing one hasher per worker
// and the number of candidates that core advances at a time.
//
// It returns a FACTORY rather than a shared hasher on purpose: a hasher owns
// reusable lane scratch so a batch allocates nothing, which makes it unsafe for
// concurrent use. One per worker, never one shared.
//
// Single target only, both types. Every lane in a batch runs in lockstep, so
// they must share one cost and one salt — true of one target, false of a dump.
// Dumps keep the scalar path.
func newLaneHasher(typ, targetHash, salt, saltMode string) (func() laneHasher, int, bool) {
	switch canonicalHashType(typ) {
	case "bcrypt":
		if salt != "" {
			return nil, 0, false
		}
		if _, err := bcryptlane.NewHasher(targetHash); err != nil {
			return nil, 0, false
		}
		return func() laneHasher {
			h, err := bcryptlane.NewHasher(targetHash)
			if err != nil {
				return nil // caller falls back to the scalar verify
			}
			return h
		}, bcryptlane.Lanes, true
	case "descrypt":
		if salt != "" {
			return nil, 0, false
		}
		if newDescryptLaneHasher(targetHash) == nil {
			return nil, 0, false
		}
		return func() laneHasher {
			if h := newDescryptLaneHasher(targetHash); h != nil {
				return h
			}
			return nil
		}, descryptLanes, true
	}
	return nil, 0, false
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
	newHasher func() laneHasher, lanes int) (string, error) {

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
			var lh laneHasher
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
				cands := make([]string, 0, lanes)
				pwBuf := make([][]byte, lanes)
				outBuf := make([]bool, lanes)

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
							// A hit here already accumulates atomicAttempts inside
							// flush() itself, so return immediately instead of
							// falling through to the unconditional add below, which
							// would double-count attempts. atomicAttempts is not
							// progress-only: doCrack's feasibility probe divides it
							// by elapsed time for the ETA/refuse-proceed verdict,
							// under a timeout context where cancellation is routine.
							if flush() {
								return
							}
							atomic.AddInt64(atomicAttempts, local)
							return
						default:
						}
					}
					cands = append(cands, l.candidate(idx))
					if len(cands) == lanes {
						if flush() {
							return
						}
					}
				}
				// End of chunk: keyspaceChunk (4096) is a multiple of
				// the lane width, so an interior chunk's tail is always
				// empty and this flush is a no-op there. It is load-bearing for
				// the run's FINAL chunk (whose end is bound, not lane-aligned)
				// and for a resume-start chunk whose from is not lane-aligned
				// either. Dropping it would silently skip up to Lanes-1
				// candidates in those chunks. See
				// TestLanesFlushFinalChunkTail and TestLanesRespectSessionWatermark.
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
