package smith

import "os"

// ── Vector lanes for a wordlist ───────────────────────────────────────────────
//
// The vector cores hash a GROUP of candidates per call — 20 on the shipped
// NEON shape, 24 on AVX2 — and brute/mask runs have always used them. A
// dictionary run did not, and the gap that left was measured: on one md5
// target with the wordlist fully in page cache, brute ran at 78.4 MH/s and
// dict at 10.2 MH/s, and setting HASHSMITH_NO_FASTPATH halved brute while
// leaving dict alone. Dict was never on the fast path at all.
//
// The reason is not allocation and it is not that a wordlist cannot be
// indexed. It is that a transposedBatch is FIXED-LENGTH between resets: every
// lane of a group must hold a candidate of the same length, because the padded
// block's word 14 carries one bit length for the whole group. A mask segment
// produces same-length candidates by construction. A wordlist produces
// "cat", "password", "hunter2" in a row.
//
// So the words are bucketed by length first, and each bucket is poured into
// the batch when it has a group's worth. Everything a bucket cannot take —
// a word too long for a single block under this salt — falls back to the
// scalar verifier, which is where every dict candidate used to go.

// dictVectorLanes hashes wordlist candidates through a vector core, bucketing
// by length so each group is uniform.
//
// One of these belongs to ONE worker goroutine. It owns a transposedBatch
// holding reusable scratch, exactly like bcryptlane.Hasher, and is not safe
// for concurrent use.
type dictVectorLanes struct {
	algo   *fastAlgo
	target [16]byte
	tb     *transposedBatch
	out    [][16]byte
	group  int

	// buckets[n] holds pending words of length n, with the index each was
	// seen at so a hit can be resolved back to file order. Indexed directly
	// by length rather than through a map: the range is 0..transposedMaxLen
	// and this sits on the hot path.
	buckets [][]dictWord
	// maxLen is the longest candidate this run's salt leaves room for.
	maxLen int
	// scratch is the group-sized []string handed to fillFromWords. It is a
	// field rather than a local because flushBucket runs once per SIMD group
	// — hundreds of thousands of times over a wordlist — and allocating a
	// slice each time made this function 28% of the run's total allocated
	// bytes in a heap profile, second only to the reader itself.
	scratch []string
	// curLen is the length the batch is currently reset to, or -1 when it
	// has never been reset. It cannot be inferred from tb.length: that field
	// is zero on a fresh batch, and zero is also a REAL bucket length — the
	// empty password is an ordinary wordlist entry. Inferring it meant a run
	// whose first bucket was the empty string skipped the only reset it would
	// ever get and hashed an uninitialised, unsalted batch, so `md5` with a
	// prefix salt found the empty password on the scalar path and missed it
	// here. runLayoutFast starts its own curLen at -1 for this exact reason.
	curLen int
}

// dictWord is a pending candidate and where it appeared in the batch, so that
// a group producing two hits reports the earlier one.
type dictWord struct {
	word      string
	ruleLabel string
	seq       int
}

// newDictVectorLanes returns a vector hasher for this target, or nil when the
// run is not eligible — no vector backend, a type with no core, a salt that
// leaves no room, or a target that is not a 16-byte digest.
//
// It deliberately does NOT take a keyspaceLayout. fastPathEligible needs one
// to check every mask segment's length; a wordlist has no segments, and the
// per-word length check that replaces it happens in add().
func newDictVectorLanes(typ, targetHash, salt, saltMode string) *dictVectorLanes {
	if vectorBackendName() == "" {
		return nil
	}
	// The same escape hatch the mask paths honour, so a forced-scalar
	// comparison measures every mode the same way.
	if os.Getenv("HASHSMITH_NO_FASTPATH") != "" {
		return nil
	}
	algo, ok := fastAlgoPlanFor(typ, salt, saltMode)
	if !ok || algo.shape.group() <= 0 {
		return nil
	}
	target, ok := md5TargetBytes(targetHash)
	if !ok {
		return nil
	}
	// The longest candidate whose SALTED message still fits one block. Found
	// by asking the same predicate the mask path asks, rather than
	// re-deriving the arithmetic here and risking the two drifting.
	maxLen := -1
	for n := 0; n <= transposedMaxLen; n++ {
		if transposedSaltedLenOK(n, algo.enc, algo.salt.width()) {
			maxLen = n
		}
	}
	if maxLen < 0 {
		return nil
	}
	return &dictVectorLanes{
		algo:    algo,
		target:  target,
		tb:      newTransposedBatch(algo.shape),
		out:     make([][16]byte, algo.shape.group()),
		group:   algo.shape.group(),
		buckets: make([][]dictWord, maxLen+1),
		maxLen:  maxLen,
		curLen:  -1,
		scratch: make([]string, 0, algo.shape.group()),
	}
}

// accepts reports whether this word can go through the vector core at all.
// Anything it refuses must be verified the scalar way, not dropped.
//
// The UTF-16LE check is not a nicety. The transposed fill expands each
// candidate byte b to the pair (b, 0x00), which equals utf16le(s) only while
// s is ASCII — the comment in fillFromSegment says so, and fastPathEligible
// enforces it for a mask run by refusing any charset byte >= 0x80 outright.
// A wordlist cannot be refused outright the same way: it is a file of
// arbitrary UTF-8 that the operator did not choose byte by byte, and one
// accented word in a hundred thousand is normal. So the check moves per word,
// and a word that fails it goes to the scalar verifier.
//
// Caught by testing it: `hash -t ntlm café` then cracking that digest from a
// one-word list found it on the scalar path and MISSED it on this one. A miss
// is the worst shape of bug this tool has — it reports "Not found" for a
// password that is right there in the wordlist, with nothing to indicate
// anything went wrong.
func (d *dictVectorLanes) accepts(word string) bool {
	if len(word) > d.maxLen {
		return false
	}
	if d.algo.enc == encUTF16LE {
		for i := 0; i < len(word); i++ {
			if word[i] >= 0x80 {
				return false
			}
		}
	}
	return true
}

// add queues a word. When its bucket reaches a full group the group is hashed
// immediately; hits are accumulated rather than returned, because a caller
// testing a whole batch wants the EARLIEST hit in that batch and cannot know
// it until the batch is done.
//
// hits is the running best: the lowest-seq hit seen so far, or seq < 0 for
// none. Returns the number of candidates actually hashed, for attempt
// accounting.
func (d *dictVectorLanes) add(word, ruleLabel string, seq int, best *dictWord) int {
	n := len(word)
	d.buckets[n] = append(d.buckets[n], dictWord{word: word, ruleLabel: ruleLabel, seq: seq})
	if len(d.buckets[n]) < d.group {
		return 0
	}
	return d.flushBucket(n, best)
}

// flushBucket hashes everything pending at length n and clears it.
func (d *dictVectorLanes) flushBucket(n int, best *dictWord) int {
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

		// Reset only when the length actually changes: a reset rewrites
		// every lane, and a bucket flush is usually the same length as the
		// last one.
		if d.curLen != n {
			if err := d.tb.resetSalted(n, d.algo.enc, d.algo.salt); err != nil {
				// accepts() already established this length fits. If it
				// somehow does not, hashing anyway would digest a message
				// of the wrong length, so skip the bucket and let the
				// scalar path take these words instead.
				return hashed
			}
			d.curLen = n
		}
		words := d.scratch[:0]
		for _, c := range chunk {
			words = append(words, c.word)
		}
		used := d.tb.fillFromWords(words)
		d.algo.group(d.tb, d.out)
		hashed += used
		// Only lanes 0..used-1 hold real candidates; the rest hash the empty
		// candidate under this salt and must never count as a hit.
		for i := 0; i < used; i++ {
			if d.out[i] == d.target {
				if best.seq < 0 || chunk[i].seq < best.seq {
					*best = chunk[i]
				}
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
func (d *dictVectorLanes) flushAll(best *dictWord) int {
	hashed := 0
	for n := range d.buckets {
		hashed += d.flushBucket(n, best)
	}
	return hashed
}
