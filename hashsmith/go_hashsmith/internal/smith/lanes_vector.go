package smith

import "os"

// ── The two cores ────────────────────────────────────────────────────────────
//
// See lanes_dict.go for the bucketing these sit under, and why it is needed.

// dictVectorCore drives the transposed vector cores: md5, md4, ntlm and the
// salted md5 constructions, on whichever SIMD backend this build has.
type dictVectorCore struct {
	algo *fastAlgo
	// ft holds every digest this run is looking for. A single-target run is
	// simply a set of one, which is what lets one implementation serve
	// `crack` and a multi-hash dump.
	ft     *fastTargets
	tb     *transposedBatch
	out    [][16]byte
	curLen int
}

func (c *dictVectorCore) group() int { return c.algo.shape.group() }

// accepts refuses what the transposed fill cannot represent.
//
// The UTF-16LE check is not a nicety. The fill expands each candidate byte b
// to the pair (b, 0x00), which equals utf16le(s) only while s is ASCII — the
// comment in fillFromSegment says so, and fastPathEligible enforces it for a
// mask run by refusing any charset byte >= 0x80. A wordlist cannot be refused
// outright the same way: it is a file of arbitrary UTF-8 that the operator did
// not choose byte by byte, and one accented word in a hundred thousand is
// normal. So the check moves per word, and a word that fails it goes to the
// scalar verifier.
//
// Caught by testing it: `hash -t ntlm café` then cracking that digest from a
// one-word list found it on the scalar path and MISSED it on this one. A miss
// is the worst shape of bug this tool has — "Not found" for a password sitting
// in the wordlist, with nothing to indicate anything went wrong.
func (c *dictVectorCore) accepts(word string) bool {
	if c.algo.enc != encUTF16LE {
		return true
	}
	for i := 0; i < len(word); i++ {
		if word[i] >= 0x80 {
			return false
		}
	}
	return true
}

func (c *dictVectorCore) fill(words []string) int {
	if len(words) == 0 {
		return 0
	}
	n := len(words[0])
	// Reset only when the length actually changes: a reset rewrites every
	// lane, and consecutive flushes are usually the same bucket.
	//
	// curLen starts at -1 rather than being inferred from tb.length, because
	// that field is zero on a fresh batch and zero is also a REAL bucket
	// length — the empty password is an ordinary wordlist entry. Inferring it
	// meant a run whose first bucket was the empty string skipped the only
	// reset it would ever get and hashed an uninitialised, unsalted batch, so
	// salted md5 found the empty password on the scalar path and missed it
	// here. runLayoutFast starts its own curLen at -1 for this exact reason.
	if c.curLen != n {
		if err := c.tb.resetSalted(n, c.algo.enc, c.algo.salt); err != nil {
			return 0
		}
		c.curLen = n
	}
	return c.tb.fillFromWords(words)
}

func (c *dictVectorCore) hash(n int) { c.algo.group(c.tb, c.out) }

func (c *dictVectorCore) match(i int) ([]int, bool) { return c.ft.lookup(&c.out[i]) }

// dictStdCore drives the contiguous-batch path: sha1, sha256 and their salted
// forms, which have no vector core but do have a hardware-accelerated stdlib
// implementation. It is pure Go and runs identically on every architecture.
type dictStdCore struct {
	algo *stdAlgo
	st   *stdTargets
	cb   *contigBatch
	grp  int
}

func (c *dictStdCore) group() int { return c.grp }

// accepts refuses the EMPTY candidate, which contigBatch.fillFromWords will
// not write: its length guard is `L < 1`, matching fillFromSegment, because a
// mask segment always has at least one position. A wordlist does not — an
// empty line is an ordinary entry, kept verbatim — and the empty string is a
// real password that real dumps contain.
//
// Caught by the differential test against the scalar path: sha1 found the
// empty password scalar-side and missed it here. Refusing it sends it to the
// scalar verifier, which is the same thing that happens to any other word this
// core cannot take.
//
// There is no encoding restriction otherwise: the candidate's bytes are
// copied verbatim into the message, so unlike the UTF-16LE vector core this
// one is byte-transparent.
func (c *dictStdCore) accepts(word string) bool { return len(word) >= 1 }

func (c *dictStdCore) fill(words []string) int { return c.cb.fillFromWords(words) }

func (c *dictStdCore) hash(n int) {
	c.algo.hashBatch(c.cb.messages(n), c.cb.stride, n, c.cb.out)
}

func (c *dictStdCore) match(i int) ([]int, bool) { return c.st.lookup(c.cb.digest(i)) }

// ── Construction ─────────────────────────────────────────────────────────────

// newDictVectorLanes returns lanes for a single target, or nil when no batched
// core applies.
func newDictVectorLanes(typ, targetHash, salt, saltMode string) *dictVectorLanes {
	return newDictVectorLanesMulti(typ, []string{targetHash}, []int{0}, salt, saltMode)
}

// newDictVectorLanesMulti is the multi-target form: every digest in hexes is
// looked for at once, and a hit reports the caller's own index for it.
//
// It deliberately does NOT take a keyspaceLayout. fastPathEligible and
// stdPathEligible both need one to check every mask segment's length; a
// wordlist has no segments, and the per-word length check that replaces it
// lives in dictVectorLanes.accepts.
//
// The vector cores are offered first, so md5, md4 and ntlm keep theirs;
// nothing routes to both. That mirrors the order doCrack uses for mask runs.
func newDictVectorLanesMulti(typ string, hexes []string, idxs []int, salt, saltMode string) *dictVectorLanes {
	// The same escape hatch the mask paths honour, so a forced-scalar
	// comparison measures every mode the same way.
	if os.Getenv("HASHSMITH_NO_FASTPATH") != "" {
		return nil
	}
	if len(hexes) == 0 || len(hexes) != len(idxs) {
		return nil
	}

	if vectorBackendName() != "" {
		if algo, ok := fastAlgoPlanFor(typ, salt, saltMode); ok && algo.shape.group() > 0 {
			if ft, ok := newFastTargets(hexes, idxs); ok {
				// The longest candidate whose SALTED message still fits one
				// block. Found by asking the same predicate the mask path
				// asks, rather than re-deriving the arithmetic here and
				// risking the two drifting.
				maxLen := -1
				for n := 0; n <= transposedMaxLen; n++ {
					if transposedSaltedLenOK(n, algo.enc, algo.salt.width()) {
						maxLen = n
					}
				}
				if maxLen >= 0 {
					return newDictLanes(&dictVectorCore{
						algo:   algo,
						ft:     ft,
						tb:     newTransposedBatch(algo.shape),
						out:    make([][16]byte, algo.shape.group()),
						curLen: -1,
					}, maxLen)
				}
			}
		}
	}

	// No vector core: try the contiguous batch, which covers sha1 and sha256.
	algo, sp, ok := stdSaltedPlanFor(typ, salt, saltMode)
	if !ok {
		return nil
	}
	if len(sp.pre) > stdMaxSaltLen || len(sp.suf) > stdMaxSaltLen {
		return nil
	}
	if algo.digLen < 8 || algo.digLen > stdMaxDigestLen {
		return nil
	}
	st, ok := newStdTargets(hexes, idxs, algo.digLen)
	if !ok {
		return nil
	}
	return newDictLanes(&dictStdCore{
		algo: algo,
		st:   st,
		cb:   newContigBatch(dictStdGroup, algo.digLen, sp),
		grp:  dictStdGroup,
	}, stdMaxCandidateLen)
}

// dictStdGroup is how many candidates the contiguous path hashes per call.
// The mask runners size their group from the keyspace; a wordlist has no such
// shape, so it is a constant here — large enough that the per-call overhead is
// amortised, small enough that a partial bucket at end of stream does not
// waste much.
const dictStdGroup = 64
