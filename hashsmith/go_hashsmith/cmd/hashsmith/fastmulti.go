package main

// Multi-target vector fast path.
//
// runLayoutFast (keyspace.go) hashes 20-24 candidates per core call but
// compares each digest against ONE target, because that is all a single-hash
// crack needs. Multi-hash mode (batch.go) is the normal professional
// workflow — a dump of hundreds of hashes, not one — and it used to call the
// SCALAR runner directly, so cracking a dump ran at roughly a seventh of the
// throughput of cracking one hash over the identical keyspace.
//
// The fix is the same shape the GPU kernels already use (the *maskmulti
// kernels in internal/gpubackend/opencl_kernels.cl): hash the group, then
// look each digest up in a SORTED target array by binary search, recording
// hits instead of returning on the first one. Relative to an MD5 compression
// a lookup is cheap — and cheaper still behind the bitmap prefilter below,
// which answers "definitely not a target" for essentially every candidate in
// two loads.
//
// runLayoutFast itself is deliberately left untouched: its `i < used`
// hit-detection bound and fillFromSegment's stale-lane cleaning are
// load-bearing, and the single-target path must stay exactly as fast as it
// is. runLayoutFastMulti below is a sibling, and a pass whose targets reduce
// to ONE distinct digest is still handed to runLayoutFast (see
// batchFastLayout), so the single-digest case never pays for the lookup.

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"math"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// digestKey is a 16-byte digest as two big-endian words. Ordering by
// (hi, lo) is byte-for-byte the same total order as comparing the 16 bytes
// lexicographically, but a comparison is two register compares instead of a
// call into bytes.Compare — and the binary search runs per candidate, on the
// hot path, so that difference is worth having.
type digestKey struct{ hi, lo uint64 }

func digestKeyOf(d *[16]byte) digestKey {
	return digestKey{binary.BigEndian.Uint64(d[0:8]), binary.BigEndian.Uint64(d[8:16])}
}

func (k digestKey) less(o digestKey) bool {
	return k.hi < o.hi || (k.hi == o.hi && k.lo < o.lo)
}

func (k digestKey) bytes() [16]byte {
	var d [16]byte
	binary.BigEndian.PutUint64(d[0:8], k.hi)
	binary.BigEndian.PutUint64(d[8:16], k.lo)
	return d
}

// fastTargets is the sorted target set the multi-target fast path searches.
//
// keys is sorted ascending and holds each DISTINCT digest once; idxs is
// parallel to it and carries every caller index that named that digest, in
// the caller's original order. Keeping duplicates collapsed into one key with
// a list of indices is what makes "the same hash listed twice" and "two
// accounts sharing a password" behave exactly as the map-based scalar path
// does: one lookup, every owner credited.
//
// bitmap is a prefilter, not a second source of truth. Bit
// (hi >> shift) is set for every target, so a clear bit proves the digest is
// not a target and the binary search is skipped; a set bit only means "maybe"
// and is always confirmed by the search. Correctness therefore depends solely
// on keys/idxs — a false positive costs a search and nothing else.
type fastTargets struct {
	keys   []digestKey
	idxs   [][]int
	bitmap []uint64
	shift  uint
}

// newFastTargets builds the lookup structure for hexDigests[i] owned by
// idxs[i]. It reports false — rather than dropping the offending entry — if
// any digest is not exactly 16 bytes of hex, so an unusable target set falls
// back wholesale to the scalar path instead of silently attacking a subset.
func newFastTargets(hexDigests []string, idxs []int) (*fastTargets, bool) {
	if len(hexDigests) == 0 || len(hexDigests) != len(idxs) {
		return nil, false
	}
	type entry struct {
		key digestKey
		idx int
	}
	es := make([]entry, 0, len(hexDigests))
	for i, h := range hexDigests {
		b, err := hex.DecodeString(strings.TrimSpace(h))
		if err != nil || len(b) != 16 {
			return nil, false
		}
		var d [16]byte
		copy(d[:], b)
		es = append(es, entry{digestKeyOf(&d), idxs[i]})
	}
	// Stable, so entries sharing a digest keep the caller's original order —
	// which is the order the scalar path's map slices are built in, and the
	// order runBatch reports results in.
	sort.SliceStable(es, func(i, j int) bool { return es[i].key.less(es[j].key) })

	ft := &fastTargets{}
	for _, e := range es {
		if n := len(ft.keys); n > 0 && ft.keys[n-1] == e.key {
			ft.idxs[n-1] = append(ft.idxs[n-1], e.idx)
			continue
		}
		ft.keys = append(ft.keys, e.key)
		ft.idxs = append(ft.idxs, []int{e.idx})
	}

	// Size the prefilter to roughly 256 bits per distinct target (a ~0.4%
	// false-positive rate), clamped to a table that stays cache-resident:
	// 4 KiB at the small end, 256 KiB at the large.
	bits := uint(15)
	for (uint64(1)<<bits) < uint64(len(ft.keys))*256 && bits < 21 {
		bits++
	}
	ft.shift = 64 - bits
	ft.bitmap = make([]uint64, (uint64(1)<<bits)/64)
	for _, k := range ft.keys {
		b := k.hi >> ft.shift
		ft.bitmap[b>>6] |= 1 << (b & 63)
	}
	return ft, true
}

// lookup returns the caller indices owning digest d, if it is a target.
func (ft *fastTargets) lookup(d *[16]byte) ([]int, bool) {
	hi := binary.BigEndian.Uint64(d[0:8])
	b := hi >> ft.shift
	if ft.bitmap[b>>6]&(1<<(b&63)) == 0 {
		return nil, false
	}
	k := digestKey{hi, binary.BigEndian.Uint64(d[8:16])}
	i, j := 0, len(ft.keys)
	for i < j {
		m := int(uint(i+j) >> 1)
		if ft.keys[m].less(k) {
			i = m + 1
		} else {
			j = m
		}
	}
	if i < len(ft.keys) && ft.keys[i] == k {
		return ft.idxs[i], true
	}
	return nil, false
}

// runLayoutFastMulti is runLayoutFast's multi-target twin: same chunk
// allocator, same watermark contract, same attempt accounting and
// cancellation, but every digest in a group is looked up in `targets` and
// EVERY hit in the group is reported, rather than the first one ending the
// run.
//
// onHit is called with the winning candidate and the indices owning the
// digest it matched; it returns true when nothing is left to find, which
// stops the whole run (the same signal batch.go's `verify` already uses).
// Reporting every hit in a group matters: a group is 20-24 candidates wide,
// so two targets whose plaintexts are adjacent in the keyspace land in the
// SAME group, and stopping at the first would silently lose the second.
//
// Callers must have confirmed fastPathEligible(typ, salt, saltMode, l) and
// pass the resulting algo — which carries the salt every message is wrapped in
// — exactly as for runLayoutFast. Every target in `targets` must be salted
// with THAT salt: a candidate is hashed once per group and compared against
// all of them, so a mixed-salt target set would file plaintexts against hashes
// they do not match. batchSaltGroups (batch.go) is what guarantees it. The two correctness
// requirements runLayoutFast documents hold here identically and for the same
// reasons: a group never straddles a segment boundary, and only lanes
// 0..used-1 are considered for a hit (unused lanes hash the empty string and
// would otherwise falsely match a target that is the digest of "").
func runLayoutFastMulti(ctx context.Context, l *keyspaceLayout, resumeFrom, limit int64,
	workers int, atomicAttempts *int64, watermark *int64,
	algo *fastAlgo, targets *fastTargets, onHit func(string, []int) bool) error {

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
		return nil
	}
	if workers < 1 {
		workers = 1
	}

	innerCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	firstChunk := resumeFrom / keyspaceChunk
	nextChunk := firstChunk
	errCh := make(chan error, 1)

	cur := make([]int64, workers)
	for w := range cur {
		cur[w] = firstChunk
	}

	// onHit is called from every worker, so it is serialised here rather than
	// leaving each caller to remember that its recorder must be thread-safe.
	var hitMu sync.Mutex

	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(wID int) {
			defer wg.Done()
			tb := newTransposedBatch(algo.shape)
			ctxEvery := fastCtxCheckEvery(algo.shape)
			curLen := -1
			lastSeg := -1
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
				seg := 0
				for seg+1 < len(l.offsets) && l.offsets[seg+1] <= pos {
					seg++
				}
				for pos < end {
					if groups++; groups >= ctxEvery {
						groups = 0
						select {
						case <-innerCtx.Done():
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
						segTotal = maskKeyspace(sets)
						lastSeg = seg
					}
					if segLen != curLen {
						if err := tb.resetSalted(segLen, algo.enc, algo.salt); err != nil {
							// Cannot happen: fastPathEligible already
							// verified every segment length for THIS salt.
							// Bail rather than risk hashing the wrong thing.
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
						break
					}
					used := n
					if remaining := end - pos; int64(used) > remaining {
						used = int(remaining)
					}
					algo.group(tb, out)
					// Every lane in 0..used-1 is checked, and a hit does NOT
					// break the loop: several distinct targets can match
					// inside one group.
					done := false
					for i := 0; i < used; i++ {
						idxs, ok := targets.lookup(&out[i])
						if !ok {
							continue
						}
						cand := string(tb.candidateAt(i))
						hitMu.Lock()
						stop := onHit(cand, idxs)
						hitMu.Unlock()
						if stop {
							done = true
						}
					}
					local += int64(used)
					pos += int64(used)
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
	select {
	case err := <-errCh:
		return err
	default:
	}
	return nil
}

// batchFastLayout runs one multi-hash brute/mask pass over `layout` on the
// vector fast path, reporting hits through `record` (batchRunType's
// CAS-guarded recorder, which returns true once every target is found).
//
// resumeFrom/limit are --skip/--limit's slice of the layout, with exactly the
// meaning they carry for a single target (see runLayout): candidate indices
// into the WHOLE layout, and limit a count rather than an end index. watermark
// (nil when nothing is checkpointing) is the session restore point the runner
// publishes into — the same pointer contract runLayoutFast documents, so a
// multi-target checkpoint means precisely what a single-target one does.
//
// It returns false when the pass is not eligible — no vector backend, a
// non-accelerated type, a salted construction the cores cannot reproduce
// exactly (a UTF-16LE password against a raw salt) or one whose salt does not
// leave the candidate inside a single block, a generator layout, an over-long
// segment, a target that is not 16 bytes of hex — in which case the caller
// must run the SAME layout on the scalar path, or offer it to the
// contiguous-batch path, exactly as before. Returning false is always safe:
// nothing has been recorded and no candidate has been counted.
//
// `salt`/`saltMode` are passed to fastPathEligible, which now RESOLVES them
// into the concatenation the cores wrap each candidate in rather than refusing
// the pass outright. They must be the salt this whole pass carries — every
// target in `active` shares it (batchSaltGroups) — because one candidate is
// hashed once for all of them.
//
// A pass whose targets collapse to a single distinct digest is handed to
// runLayoutFast, the single-target specialisation, so it pays nothing for
// multi-target lookup.
func batchFastLayout(ctx context.Context, typ, salt, saltMode string, layout *keyspaceLayout,
	active []int, batch []*batchTarget, resumeFrom, limit int64, workers int,
	atomicAttempts *int64, watermark *int64, record func(string, []int) bool) bool {

	if layout == nil || len(active) == 0 {
		return false
	}
	algo, ok := fastPathEligible(typ, salt, saltMode, layout)
	if !ok {
		return false
	}
	hexes := make([]string, len(active))
	for i, idx := range active {
		hexes[i] = batch[idx].key
	}
	ft, ok := newFastTargets(hexes, active)
	if !ok {
		return false
	}

	if len(ft.keys) == 1 {
		pw, err := runLayoutFast(ctx, layout, resumeFrom, limit, workers, atomicAttempts, watermark,
			algo, ft.keys[0].bytes())
		if err != nil {
			return false
		}
		if pw != "" {
			record(pw, ft.idxs[0])
		}
		return true
	}
	if err := runLayoutFastMulti(ctx, layout, resumeFrom, limit, workers, atomicAttempts, watermark,
		algo, ft, record); err != nil {
		return false
	}
	return true
}
