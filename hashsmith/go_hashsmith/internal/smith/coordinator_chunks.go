package smith

import "sync"

// chunkRange is one (skip, limit) slice of a keyspace, in the same units
// --skip/--limit already use (word index in dict mode, whole-layout index
// in brute/mask mode).
type chunkRange struct {
	skip, limit int64
}

// splitKeyspace divides [0, total) into chunkSize-sized pieces, the last
// one shorter if total is not an exact multiple. Returns nil for total<=0.
// chunkSize must be > 0 (the coordinate command's flag parsing enforces
// this before ever calling here).
func splitKeyspace(total, chunkSize int64) []chunkRange {
	if total <= 0 {
		return nil
	}
	var out []chunkRange
	for skip := int64(0); skip < total; skip += chunkSize {
		limit := chunkSize
		if skip+limit > total {
			limit = total - skip
		}
		out = append(out, chunkRange{skip: skip, limit: limit})
	}
	return out
}

// chunkQueue is a mutex-guarded FIFO of chunkRanges, safe for concurrent
// pull-based access from multiple worker-dispatch goroutines (Task 5).
type chunkQueue struct {
	mu    sync.Mutex
	items []chunkRange
}

func newChunkQueue(items []chunkRange) *chunkQueue {
	return &chunkQueue{items: items}
}

// next pops the next chunk, or returns ok=false if the queue is empty.
func (q *chunkQueue) next() (chunkRange, bool) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if len(q.items) == 0 {
		return chunkRange{}, false
	}
	c := q.items[0]
	q.items = q.items[1:]
	return c, true
}

// requeue pushes a chunk back onto the FRONT of the queue, so a chunk that
// just failed is retried soon rather than after every other chunk.
func (q *chunkQueue) requeue(c chunkRange) {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.items = append([]chunkRange{c}, q.items...)
}
