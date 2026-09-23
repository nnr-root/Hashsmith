package smith

// ── Batched cores for a wordlist ─────────────────────────────────────────────
//
// The batched cores hash a GROUP of candidates per call — 20 on the shipped
// NEON shape, 24 on AVX2, and a configurable group for the contiguous path.
// Brute and mask runs have always used them. A dictionary run did not, and the
// gap that left was measured: on one md5 target with the wordlist fully in
// page cache, brute ran at 78.4 MH/s and dict at 10.2 MH/s, and setting
// HASHSMITH_NO_FASTPATH halved brute while leaving dict alone.
//
// The reason is not allocation and it is not that a wordlist cannot be
// indexed. Both batch layouts are FIXED-LENGTH between fills: every slot of a
// group must hold a candidate of the same length, because the transposed
// layout carries one padded bit length for the whole group and the contiguous
// one carries a single stride. A mask segment produces same-length candidates
// by construction. A wordlist produces "cat", "password", "hunter2" in a row.
//
// So the words are bucketed by length, and each bucket is poured into a core
// when it has a group's worth. Everything a core refuses — a word too long for
// its layout, or one that its encoding cannot represent — falls back to the
// scalar verifier, which is where every dict candidate used to go.

// dictLaneCore is one batched hashing core a dictionary run can drive.
//
// Two implement it: the transposed VECTOR cores (md5, md4, ntlm and salted
// md5) and the CONTIGUOUS-batch path (sha1, sha256 and their salted forms,
// which have no vector core but do have a hardware-accelerated stdlib one).
// The bucketing above them is identical either way, so it is written once here
// and the core is the only thing that differs.
type dictLaneCore interface {
	// group is how many candidates one call hashes.
	group() int
	// accepts reports whether this word can go through this core at all.
	// Anything refused must be verified the scalar way, never dropped.
	accepts(word string) bool
	// fill prepares the batch for these words — all of one length — and
	// writes them, returning how many it wrote.
	fill(words []string) int
	// hash hashes the first n slots.
	hash(n int)
	// match reports the caller's target indices for slot i, if it matched.
	match(i int) ([]int, bool)
}

// dictWord is a pending candidate and where it appeared, so that a group
// producing two hits can report the earlier one.
type dictWord struct {
	word      string
	ruleLabel string
	seq       int
}

// hitSink is told about each candidate whose digest was one of the targets,
// with the caller's own indices for the targets it matched. Returning true
// stops the group being scanned any further — which is what a single-target
// run wants, and what a multi-hash run wants only once every target is found.
type hitSink func(dw dictWord, idxs []int) bool

// dictVectorLanes buckets wordlist candidates by length and hashes each full
// bucket through a batched core.
//
// One of these belongs to ONE worker goroutine. Its core owns reusable
// scratch, exactly like bcryptlane.Hasher, and is not safe for concurrent use.
type dictVectorLanes struct {
	core  dictLaneCore
	group int

	// buckets[n] holds pending words of length n, with the index each was
	// seen at so a hit can be resolved back to file order. Indexed directly
	// by length rather than through a map: the range is small and this sits
	// on the hot path.
	buckets [][]dictWord
	// maxLen is the longest candidate this run's core and salt leave room for.
	maxLen int
	// scratch is the group-sized []string handed to the core's fill. It is a
	// field rather than a local because flushBucket runs once per group —
	// hundreds of thousands of times over a wordlist — and allocating a slice
	// each time made this function 28% of the run's total allocated bytes in
	// a heap profile, second only to the reader.
	scratch []string
}

// newDictLanes wraps a core with the length bucketing.
func newDictLanes(core dictLaneCore, maxLen int) *dictVectorLanes {
	if core == nil || core.group() <= 0 || maxLen < 0 {
		return nil
	}
	return &dictVectorLanes{
		core:    core,
		group:   core.group(),
		buckets: make([][]dictWord, maxLen+1),
		maxLen:  maxLen,
		scratch: make([]string, 0, core.group()),
	}
}

// accepts reports whether this word can go through the core at all.
func (d *dictVectorLanes) accepts(word string) bool {
	return len(word) <= d.maxLen && d.core.accepts(word)
}

// add queues a word. When its bucket reaches a full group the group is hashed
// immediately, and any hit is handed to sink. Returns the number of candidates
// actually hashed, for attempt accounting.
func (d *dictVectorLanes) add(word, ruleLabel string, seq int, sink hitSink) int {
	n := len(word)
	d.buckets[n] = append(d.buckets[n], dictWord{word: word, ruleLabel: ruleLabel, seq: seq})
	if len(d.buckets[n]) < d.group {
		return 0
	}
	return d.flushBucket(n, sink)
}

// flushBucket hashes everything pending at length n and clears it.
func (d *dictVectorLanes) flushBucket(n int, sink hitSink) int {
	pending := d.buckets[n]
	if len(pending) == 0 {
		return 0
	}
	hashed := 0
	for off := 0; off < len(pending); off += d.group {
		end := off + d.group
		if end > len(pending) {
			end = len(pending)
		}
		chunk := pending[off:end]

		words := d.scratch[:0]
		for _, c := range chunk {
			words = append(words, c.word)
		}
		used := d.core.fill(words)
		if used == 0 {
			// The core refused this length after accepts() allowed it.
			// Hashing anyway would digest the wrong thing, so leave these
			// words for the scalar verifier rather than guess.
			break
		}
		d.core.hash(used)
		hashed += used
		// Only slots 0..used-1 hold real candidates; anything past that is
		// padding and must never count as a hit.
		for i := 0; i < used; i++ {
			idxs, ok := d.core.match(i)
			if !ok {
				continue
			}
			if sink(chunk[i], idxs) {
				break
			}
		}
	}
	d.buckets[n] = pending[:0]
	return hashed
}

// flushAll hashes every partial bucket. A batch is not finished until this has
// run: words still sitting in a bucket have not been tested, and dropping them
// would report a crackable password as not found.
func (d *dictVectorLanes) flushAll(sink hitSink) int {
	hashed := 0
	for n := range d.buckets {
		hashed += d.flushBucket(n, sink)
	}
	return hashed
}
