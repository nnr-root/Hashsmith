package main

// Allocation-free batch fast path for the STDLIB digests — unsalted SHA-1 and
// SHA-256, and the simple salted concatenations md5/sha1/sha256 of
// salt||password or password||salt (hashcat 10/20, 110/120, 1410/1420).
//
// Why this exists, and why it is not a second vector core:
//
// MD5/MD4/NTLM reach ~90-100 MH/s here because runLayoutFast (keyspace.go)
// hands 20 candidates at a time to a hand-written NEON/AVX2 core. SHA-1 and
// SHA-256 had no fast path at all, so every candidate took the generic scalar
// route through runLayout: locate the segment, mixed-radix decode with a
// division and modulo per position, allocate a string (maskIdxToStr), call an
// indirect verify closure, hash, compare. Measured on an M2 that left them at
// ~15 MH/s while one core calling crypto/sha256.Sum256 in a bare loop reaches
// ~10 MH/s and eight reach ~74 MH/s. The hashing was never the problem: Go's
// arm64 crypto/sha1 and crypto/sha256 already use the ARMv8 SHA instructions,
// which is why raw SHA-256 outruns raw MD5 on this machine. The loss was
// entirely per-candidate harness overhead.
//
// So this path deliberately does NOT vectorise anything. It keeps calling the
// stdlib digest — a hand-rolled SIMD SHA-256 would be competing against a
// hardware instruction and would lose — and removes everything around it:
//
//   - candidates are generated with the same decode-once-then-odometer trick
//     fillFromSegment uses, so there is no division per character position;
//   - they land CONTIGUOUSLY in a reused buffer (stride = message length),
//     which is the layout a stdlib hash wants, so no transposition and no
//     per-candidate string allocation;
//   - digests land in a reused slab, and only a hit ever allocates.
//
// Two structural notes:
//
//   - The layout is contiguous, NOT transposed. transposedBatch exists to feed
//     32-bit lanes to a vector core; with no vector core the interleave is pure
//     cost, and reading candidates back out of it would mean candidateAt, which
//     is documented as the slow reporting path. A contiguous batch is both
//     faster and simpler here, and candidateAt becomes a subslice.
//
//   - Digests are handled as variable-width byte slices, not as a fixed-size
//     array type. The 16-byte vector path (runLayoutFast's `target [16]byte`,
//     fastmulti.go's digestKey) is left completely untouched — widening it
//     would have put md5/md4/ntlm, including the adversarially reviewed
//     `i < used` hit-detection bound, back in play for a change they gain
//     nothing from. Everything here is parameterised by algo.digLen instead, so
//     sha224/384/512, blake2 and ripemd160 join by adding one stdAlgo case and
//     one hashBatch function — no second redesign.
//
// Salts, added in the same shape:
//
// Hashing salt||password is the same work as hashing password — 13 bytes and 5
// bytes are both one block — so a salted digest has no business being 14x
// slower than an unsalted one. It was, because every salted run fell out of
// both fast paths and paid the per-candidate harness the batch path exists to
// avoid. The fix is one field on the generator: the message written into the
// contiguous buffer becomes salt.pre || candidate || salt.suf instead of the
// candidate alone, and every other property — the odometer, the chunk
// allocator, the watermark, the sorted-target lookup — is untouched. The empty
// stdSalt reduces it byte for byte to what it was.
//
// What salts DO cost is candidate sharing. One hashed candidate answers for
// every target only while every target is salted the same; with distinct salts
// each target needs its own message, so runBatch groups targets by salt and
// runs one pass per distinct salt (batch.go). That is inherent — it is what
// salts are for — and this path never pretends otherwise: batchStdLayout
// refuses a group whose targets do not all carry the salt it was handed.

import (
	"bytes"
	"context"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"math"
	"os"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	// stdBatchGroup is how many candidates are generated, hashed and searched
	// per round. It exists to amortise the indirect call into algo.hashBatch
	// (and the per-round segment/bounds bookkeeping) over many candidates, so
	// the inner hashing loop stays monomorphic and branch-free. It divides
	// keyspaceChunk (4096), so a chunk is a whole number of rounds.
	stdBatchGroup = 64

	// stdMaxCandidateLen caps the candidate length this path accepts. Unlike
	// transposedBatch there is no one-block constraint — a stdlib hash takes
	// any length — this only bounds the reusable buffers and the odometer's
	// stack arrays. Longer masks simply fall back to the scalar path.
	stdMaxCandidateLen = 128

	// stdMaxDigestLen bounds the digest slab. 64 covers SHA-512/BLAKE2b, the
	// widest digests Hashsmith computes, so future algorithms need no change.
	stdMaxDigestLen = 64

	// stdMaxSaltLen caps the salt this path will materialise around each
	// candidate. It bounds nothing but the generation buffer — the salt is
	// copied into every slot, so a pathological salt would blow the per-worker
	// allocation up without buying any throughput. A longer salt simply falls
	// back to the scalar path, which has no such buffer. 256 comfortably covers
	// every real web-application salt (hashcat's own generic salted modes cap
	// well below this).
	stdMaxSaltLen = 256
)

// stdAlgo describes one stdlib digest this path can run.
//
// hashBatch is the whole extension seam: it hashes n messages of msgLen bytes
// each, packed contiguously in msgs (stride msgLen), writing n digests of
// digLen bytes into out (stride digLen). Batching the call is what keeps the
// per-candidate cost free of an indirect dispatch — one call covers
// stdBatchGroup candidates and the loop inside it is specialised to one
// concrete digest function.
type stdAlgo struct {
	name      string
	digLen    int
	hashBatch func(msgs []byte, msgLen, n int, out []byte)
}

// sha1HashBatch and sha256HashBatch are the two concrete cores wired up in
// this pass. Each writes straight into the caller's slab through a slice-to-
// array-pointer store, so nothing escapes and nothing is allocated.
func sha1HashBatch(msgs []byte, msgLen, n int, out []byte) {
	for i := 0; i < n; i++ {
		*(*[sha1.Size]byte)(out[i*sha1.Size : i*sha1.Size+sha1.Size]) =
			sha1.Sum(msgs[i*msgLen : i*msgLen+msgLen])
	}
}

func sha256HashBatch(msgs []byte, msgLen, n int, out []byte) {
	for i := 0; i < n; i++ {
		*(*[sha256.Size]byte)(out[i*sha256.Size : i*sha256.Size+sha256.Size]) =
			sha256.Sum256(msgs[i*msgLen : i*msgLen+msgLen])
	}
}

// md5HashBatch is the same shape for MD5. It exists ONLY for salted runs: an
// unsalted MD5 keyspace is enumerated by the NEON/AVX2 core through
// runLayoutFast, which is several times faster than crypto/md5 and must keep
// that traffic — see stdSaltedPlanFor, which refuses md5 when there is no salt.
func md5HashBatch(msgs []byte, msgLen, n int, out []byte) {
	for i := 0; i < n; i++ {
		*(*[md5.Size]byte)(out[i*md5.Size : i*md5.Size+md5.Size]) =
			md5.Sum(msgs[i*msgLen : i*msgLen+msgLen])
	}
}

// stdAlgoFor returns the contiguous-batch descriptor for a hash type, resolved
// through canonicalHashType so Hashcat mode numbers ("100", "1400") and John
// names ("raw-sha1", "raw-sha256") route here too.
//
// Only entries whose digest is exactly "the stdlib hash of the candidate
// bytes" belong here. The UTF-16LE variants (sha1-utf16le, sha256-utf16le) are
// deliberately absent: they hash a different message, and adding them means
// adding the encoding step and the ASCII guard fastPathEligible carries for
// NTLM — a later pass, not a silent fallthrough. Nothing falls through here.
func stdAlgoFor(typ string) (*stdAlgo, bool) {
	switch canonicalHashType(typ) {
	case "sha1":
		return &stdAlgo{name: "sha1", digLen: sha1.Size, hashBatch: sha1HashBatch}, true
	case "sha256":
		return &stdAlgo{name: "sha256", digLen: sha256.Size, hashBatch: sha256HashBatch}, true
	}
	return nil, false
}

// ── salted constructions ────────────────────────────────────────────────────

// stdSalt is the concatenation this path materialises around each candidate:
// the message hashed is pre || candidate || suf. Exactly one of the two is
// non-empty for every construction Hashsmith supports here (prefix or suffix),
// but keeping both fields makes the generator's arithmetic uniform and leaves
// the $salt.$pass.$salt family (hashcat 3800 and friends) a data change rather
// than a code change, should it ever be wired up.
//
// The empty stdSalt is the unsalted case, and reduces the generator to exactly
// the bytes it wrote before this type existed.
type stdSalt struct {
	pre []byte
	suf []byte
}

func (s stdSalt) width() int { return len(s.pre) + len(s.suf) }

// stdSaltedBaseFor returns the digest core for a simple salt||pass /
// pass||salt construction. Only md5, sha1 and sha256 are wired up: they are
// hashcat modes 10/20, 110/120 and 1410/1420, the salted digests real web
// applications actually store, and each has a stdlib core whose message is the
// raw concatenated bytes.
//
// Everything else stays on the scalar path on purpose. A UTF-16LE variant
// (md5-utf16le-pass-salt, …) hashes a re-encoded password, not these bytes;
// sha224/384/512 would be a one-line addition but would ship untested; and the
// structured-record formats (bcrypt, sha512crypt, PBKDF2, crack_frameworks.go)
// are not concatenations at all.
func stdSaltedBaseFor(name string) (*stdAlgo, bool) {
	switch name {
	case "md5":
		return &stdAlgo{name: "md5", digLen: md5.Size, hashBatch: md5HashBatch}, true
	case "sha1":
		return &stdAlgo{name: "sha1", digLen: sha1.Size, hashBatch: sha1HashBatch}, true
	case "sha256":
		return &stdAlgo{name: "sha256", digLen: sha256.Size, hashBatch: sha256HashBatch}, true
	}
	return nil, false
}

// stdSaltedPlanFor resolves (type, salt, salt mode) into the digest core and
// the concatenation to materialise, or false when this path cannot reproduce
// hashText's digest for that combination EXACTLY. That last word is the whole
// contract: every rule below is a transcription of hashText/hashCompatSaltedDigest,
// and TestStdSaltedPlanMatchesHashText enumerates both sides to keep it one.
//
// Three shapes reach here:
//
//   - a raw digest with -s/-S. hashText prepends or appends the salt to the
//     candidate text before hashing (only "suffix" appends — every other value
//     of -S prefixes, which this mirrors byte for byte rather than validating).
//   - a generic salted compat type (md5-salt-pass, sha1-pass-salt, hashcat
//     10/20/110/120/1410/1420 …). The type name fixes the order, so -S is
//     ignored exactly as hashCompatSaltedDigest ignores it; the salt is
//     required, and comes from -s or from the target's hash:salt field, which
//     is the caller's job to have resolved (compatSaltedTargetParts).
//   - no salt at all, which is stdAlgoFor's existing sha1/sha256 case.
//
// md5 is deliberately absent from the unsalted case: runLayoutFast's vector
// core owns unsalted MD5/MD4/NTLM and is several times faster, so routing them
// here would be a silent regression, not an acceleration.
func stdSaltedPlanFor(typ, salt, saltMode string) (*stdAlgo, stdSalt, bool) {
	canon := canonicalHashType(typ)
	if spec, ok := compatSaltedDigests[canon]; ok {
		if spec.passwordUTF16 || salt == "" {
			return nil, stdSalt{}, false
		}
		base, _, _ := strings.Cut(canon, "-")
		algo, ok := stdSaltedBaseFor(base)
		if !ok {
			return nil, stdSalt{}, false
		}
		if spec.saltFirst {
			return algo, stdSalt{pre: []byte(salt)}, true
		}
		return algo, stdSalt{suf: []byte(salt)}, true
	}
	if salt == "" {
		algo, ok := stdAlgoFor(canon)
		if !ok {
			return nil, stdSalt{}, false
		}
		return algo, stdSalt{}, true
	}
	// A raw digest carrying -s. hashText only applies the generic
	// concatenation to types that do not consume the salt themselves, so this
	// must not fire for anything in its saltInAlgorithms set — none of md5,
	// sha1 and sha256 is in it, and stdSaltedBaseFor admits nothing else.
	algo, ok := stdSaltedBaseFor(canon)
	if !ok {
		return nil, stdSalt{}, false
	}
	if saltMode == "suffix" {
		return algo, stdSalt{suf: []byte(salt)}, true
	}
	return algo, stdSalt{pre: []byte(salt)}, true
}

// stdPathEligible reports whether l can be enumerated by runLayoutStd, and if
// so returns the algorithm to run it with and the salt concatenation the
// generator must wrap each candidate in. It mirrors fastPathEligible's
// conditions minus the ones that are specific to a vector core:
//
//   - HASHSMITH_NO_FASTPATH disables it, exactly as it disables the vector
//     path, so the same binary can be timed on the scalar path and the A/B
//     stays a single switch;
//   - (typ, salt, saltMode) must resolve to a construction this path computes
//     identically to hashText — see stdSaltedPlanFor;
//   - the salt must fit stdMaxSaltLen, since it is copied into every slot of
//     the generation buffer;
//   - l must have no gen override — a Markov (or other) generator's candidates
//     are not mixed-radix decodable, which the odometer requires;
//   - every segment must have between 1 and stdMaxCandidateLen positions, each
//     with a non-empty character set.
//
// There is no vector-backend requirement: this path is pure Go and runs
// identically on every architecture.
func stdPathEligible(typ, salt, saltMode string, l *keyspaceLayout) (*stdAlgo, stdSalt, bool) {
	if os.Getenv("HASHSMITH_NO_FASTPATH") != "" {
		return nil, stdSalt{}, false
	}
	if l == nil || l.gen != nil || len(l.segments) == 0 {
		return nil, stdSalt{}, false
	}
	algo, sp, ok := stdSaltedPlanFor(typ, salt, saltMode)
	if !ok {
		return nil, stdSalt{}, false
	}
	if len(sp.pre) > stdMaxSaltLen || len(sp.suf) > stdMaxSaltLen {
		return nil, stdSalt{}, false
	}
	if algo.digLen < 8 || algo.digLen > stdMaxDigestLen {
		return nil, stdSalt{}, false
	}
	for _, seg := range l.segments {
		if len(seg) < 1 || len(seg) > stdMaxCandidateLen {
			return nil, stdSalt{}, false
		}
		for _, charset := range seg {
			if len(charset) == 0 {
				return nil, stdSalt{}, false
			}
		}
	}
	return algo, sp, true
}

// ── candidate generation ────────────────────────────────────────────────────

// contigBatch generates up to `group` MESSAGES of one fixed length into a
// single contiguous buffer, and holds the digest slab they hash into. A
// message is salt.pre || candidate || salt.suf; with the empty stdSalt it is
// the candidate alone and every byte written is identical to what this
// generator produced before salts existed.
//
// Unlike transposedBatch it has no stale-lane hazard to manage: only lanes
// 0..n-1 are ever hashed (hashBatch is passed n) and only 0..n-1 are ever
// searched, so bytes left behind by a longer previous fill are never read.
// That is a property of the contiguous layout, not an accident — the
// transposed batch has to scrub leftovers precisely because its core hashes
// the whole fixed-width group unconditionally.
//
// The salt costs nothing per candidate beyond the bytes themselves: the
// odometer already copies the previous slot forward, so widening that copy
// from the candidate to the whole message carries the salt along for free and
// there is no separate salt write after slot 0.
type contigBatch struct {
	msgs   []byte // group*maxStride; message i at [i*stride, (i+1)*stride)
	out    []byte // group*stdMaxDigestLen; digest i at [i*digLen, (i+1)*digLen)
	group  int
	digLen int
	pre    []byte // salt bytes before the candidate ("" for an unsalted run)
	suf    []byte // salt bytes after it
	length int    // candidate length of the current fill (0 before the first)
	stride int    // len(pre) + length + len(suf); the message length hashBatch is passed
}

func newContigBatch(group, digLen int, salt stdSalt) *contigBatch {
	return &contigBatch{
		msgs:   make([]byte, group*(stdMaxCandidateLen+salt.width())),
		out:    make([]byte, group*stdMaxDigestLen),
		group:  group,
		digLen: digLen,
		pre:    salt.pre,
		suf:    salt.suf,
	}
}

// fillFromSegment writes up to `want` candidates starting at index `from` of
// the mixed-radix segment `sets`, whose total keyspace is `total`
// (== maskKeyspace(sets), hoisted by the caller since it is invariant for a
// segment). It returns how many it wrote and allocates nothing.
//
// The arithmetic is fillFromSegment's (transposed.go), for the same reason:
// maskIdxInto is a division and a modulo per character position and profiling
// found it dominating generation. `from` is decoded once, in full, exactly as
// maskIdxInto would; every later candidate is the previous one with the last
// position's digit incremented and carried left on overflow. That must stay
// byte-identical to maskIdxInto/maskIdxToStr for every index — see
// TestContigFillMatchesMaskIdxToStr, which enumerates whole segments through
// both paths and compares.
//
// `want` is clamped both to the batch's group size and to the segment's own
// remaining candidates, so the returned count never runs past the segment
// boundary. The caller additionally passes a `want` already clamped to its
// chunk's end, which is what keeps a round from being credited past a chunk
// another worker owns.
func (cb *contigBatch) fillFromSegment(sets [][]byte, from, total int64, want int) int {
	if want > cb.group {
		want = cb.group
	}
	if rem := total - from; rem < int64(want) {
		if rem <= 0 {
			return 0
		}
		want = int(rem)
	}
	if want <= 0 {
		return 0
	}
	L := len(sets)
	if L < 1 || L > stdMaxCandidateLen {
		return 0
	}
	cb.length = L
	pre := len(cb.pre)
	stride := pre + L + len(cb.suf)
	cb.stride = stride

	// dig[i] is the current digit at position i (an index into sets[i]);
	// together with msgs[...] it encodes the candidate being emitted.
	var dig [stdMaxCandidateLen]int

	// Slot 0 is written in full: the salt around it, and a full decode of
	// `from` — identical arithmetic to maskIdxInto.
	copy(cb.msgs[0:pre], cb.pre)
	idx := from
	for i := L - 1; i >= 0; i-- {
		base := int64(len(sets[i]))
		d := int(idx % base)
		dig[i] = d
		cb.msgs[pre+i] = sets[i][d]
		idx /= base
	}
	copy(cb.msgs[pre+L:stride], cb.suf)

	for n := 1; n < want; n++ {
		prev := (n - 1) * stride
		cur := n * stride
		// The whole message, salt included: the previous slot already holds
		// the salt bytes in the right places, so this is the only write they
		// ever need. For an unsalted run stride == L and this is byte for byte
		// the copy that was here before.
		copy(cb.msgs[cur:cur+stride], cb.msgs[prev:prev+stride])
		// Advance the odometer by one: increment the last position, carrying
		// left on overflow. Mathematically identical to decoding from+n
		// independently, with no division at all.
		c := cur + pre
		for i := L - 1; i >= 0; i-- {
			dig[i]++
			if dig[i] < len(sets[i]) {
				cb.msgs[c+i] = sets[i][dig[i]]
				break
			}
			dig[i] = 0
			cb.msgs[c+i] = sets[i][0]
		}
	}
	return want
}

// candidate returns candidate i's bytes — the PASSWORD, without the salt
// around it — as a subslice of the generation buffer. No copy, valid only
// until the next fill. Reporting the message instead would file the salt as
// part of the recovered plaintext.
func (cb *contigBatch) candidate(i int) []byte {
	off := i*cb.stride + len(cb.pre)
	return cb.msgs[off : off+cb.length]
}

// messages returns the first n messages, packed contiguously at cb.stride —
// exactly the layout algo.hashBatch is documented to take.
func (cb *contigBatch) messages(n int) []byte {
	return cb.msgs[:n*cb.stride]
}

// digest returns digest i's bytes as a subslice of the digest slab.
func (cb *contigBatch) digest(i int) []byte {
	return cb.out[i*cb.digLen : (i+1)*cb.digLen]
}

// ── target lookup ───────────────────────────────────────────────────────────

// stdTargets is the sorted target set runLayoutStd searches. It is
// fastmulti.go's fastTargets generalised off the 16-byte digestKey: digests of
// any width live packed in one slab (`keys`, count*digLen bytes, sorted
// ascending lexicographically), with idxs parallel to it carrying every caller
// index that named that digest, in the caller's original order. Collapsing
// duplicates into one key with a list of owners is what makes "the same hash
// listed twice" and "two accounts sharing a password" behave exactly as the
// map-based scalar path does: one lookup, every owner credited.
//
// bitmap is a prefilter, not a second source of truth: bit (first 8 bytes as a
// big-endian uint64, >> shift) is set for every target, so a clear bit proves
// the digest is not a target and the search is skipped, while a set bit only
// means "maybe" and is always confirmed by a FULL digLen-byte comparison.
// Correctness rests solely on keys/idxs; a false positive costs one search.
//
// Every comparison in here is over the whole digLen bytes. A prefix compare
// would appear to work on essentially every input and be catastrophically
// wrong — see TestStdTargetsRejectsTruncatedMatch.
type stdTargets struct {
	digLen int
	count  int
	keys   []byte
	idxs   [][]int
	bitmap []uint64
	shift  uint
}

// newStdTargets builds the lookup structure for hexDigests[i] owned by
// idxs[i], for an algorithm whose digest is digLen bytes. It reports false —
// rather than dropping the offending entry — if any digest is not exactly
// digLen bytes of hex, so an unusable target set falls back wholesale to the
// scalar path instead of silently attacking a subset.
func newStdTargets(hexDigests []string, idxs []int, digLen int) (*stdTargets, bool) {
	if len(hexDigests) == 0 || len(hexDigests) != len(idxs) {
		return nil, false
	}
	// The prefilter reads 8 bytes of every digest, and the packed slab assumes
	// a fixed stride; both need a sane width.
	if digLen < 8 || digLen > stdMaxDigestLen {
		return nil, false
	}
	type entry struct {
		key []byte
		idx int
	}
	es := make([]entry, 0, len(hexDigests))
	for i, h := range hexDigests {
		b, err := hex.DecodeString(strings.TrimSpace(h))
		if err != nil || len(b) != digLen {
			return nil, false
		}
		es = append(es, entry{b, idxs[i]})
	}
	// Stable, so entries sharing a digest keep the caller's original order —
	// the order the scalar path's map slices are built in, and the order
	// runBatch reports results in.
	sort.SliceStable(es, func(i, j int) bool { return bytes.Compare(es[i].key, es[j].key) < 0 })

	st := &stdTargets{digLen: digLen}
	for _, e := range es {
		if st.count > 0 && bytes.Equal(st.keys[(st.count-1)*digLen:st.count*digLen], e.key) {
			st.idxs[st.count-1] = append(st.idxs[st.count-1], e.idx)
			continue
		}
		st.keys = append(st.keys, e.key...)
		st.idxs = append(st.idxs, []int{e.idx})
		st.count++
	}

	// Size the prefilter to roughly 256 bits per distinct target (a ~0.4%
	// false-positive rate), clamped to a table that stays cache-resident:
	// 4 KiB at the small end, 256 KiB at the large. Same sizing as
	// fastTargets', for the same reason.
	bits := uint(15)
	for (uint64(1)<<bits) < uint64(st.count)*256 && bits < 21 {
		bits++
	}
	st.shift = 64 - bits
	st.bitmap = make([]uint64, (uint64(1)<<bits)/64)
	for i := 0; i < st.count; i++ {
		b := binary.BigEndian.Uint64(st.keys[i*digLen:i*digLen+8]) >> st.shift
		st.bitmap[b>>6] |= 1 << (b & 63)
	}
	return st, true
}

// lookup returns the caller indices owning digest d, if it is a target. d must
// be exactly digLen bytes; the equality check that decides a hit compares all
// of them.
func (st *stdTargets) lookup(d []byte) ([]int, bool) {
	b := binary.BigEndian.Uint64(d[0:8]) >> st.shift
	if st.bitmap[b>>6]&(1<<(b&63)) == 0 {
		return nil, false
	}
	dl := st.digLen
	i, j := 0, st.count
	for i < j {
		m := int(uint(i+j) >> 1)
		if bytes.Compare(st.keys[m*dl:(m+1)*dl], d) < 0 {
			i = m + 1
		} else {
			j = m
		}
	}
	if i < st.count && bytes.Equal(st.keys[i*dl:(i+1)*dl], d) {
		return st.idxs[i], true
	}
	return nil, false
}

// ── the runner ──────────────────────────────────────────────────────────────

// runLayoutStd enumerates the same slice of a keyspace runLayout would, with
// the same chunk allocator, the same watermark contract, the same attempt
// accounting and the same cancellation behaviour — but generates candidates in
// contiguous batches and hashes them through algo.hashBatch instead of calling
// a verify closure once per candidate.
//
// It serves both the single-target and multi-target cases: a single target is
// simply a stdTargets holding one digest, whose lookup is one bitmap probe.
// Keeping one runner rather than two is deliberate — the chunk/watermark logic
// is the delicate part, and the vector path already demonstrates what a second
// hand-maintained copy costs in drift risk. The bitmap prefilter makes the
// one-target lookup indistinguishable in cost from a direct compare.
//
// onHit is called with the winning candidate and the indices owning the digest
// it matched, serialised across workers; it returns true when nothing is left
// to find, which stops the run. EVERY hit in a batch is reported: a batch is
// stdBatchGroup candidates wide, so two targets whose plaintexts are adjacent
// in the keyspace land in the same batch and stopping at the first would
// silently lose the second.
//
// Callers must have confirmed stdPathEligible(typ, salt, saltMode, l) and pass
// the resulting algo AND salt plan; this function does not re-check
// eligibility. `salt` is the concatenation wrapped around every candidate, so
// every target in `targets` must be salted with it — see batchStdLayout.
//
// Two correctness requirements, the same two the vector path documents:
//
//   - a batch never straddles a segment boundary — fillFromSegment clamps to
//     its segment's own total;
//   - a batch is never credited, or searched, past the chunk's `end` — `want`
//     is clamped to end-pos before the fill, so n is already within both
//     bounds and there are no lanes beyond n to mistake for candidates.
func runLayoutStd(ctx context.Context, l *keyspaceLayout, resumeFrom, limit int64,
	workers int, atomicAttempts *int64, watermark *int64,
	algo *stdAlgo, salt stdSalt, targets *stdTargets, onHit func(string, []int) bool) error {

	if resumeFrom < 0 {
		resumeFrom = 0
	}
	// bound mirrors runLayout's: the whole keyspace, or resumeFrom+limit when a
	// positive limit narrows it, whichever is smaller (satAdd guards overflow).
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

	// cur[w] is the chunk worker w is currently processing (MaxInt64 once
	// done), so min(cur)*chunk is the safe restore watermark — identical
	// meaning to runLayout's cur.
	cur := make([]int64, workers)
	for w := range cur {
		cur[w] = firstChunk
	}

	// onHit is called from every worker, so it is serialised here rather than
	// leaving each caller to remember that its recorder must be thread-safe.
	var hitMu sync.Mutex

	// Batches are stdBatchGroup candidates wide, so poll the context every
	// ctxCheckEvery/stdBatchGroup batches to match runLayout's per-candidate
	// cadence.
	ctxEvery := ctxCheckEvery / stdBatchGroup
	if ctxEvery < 1 {
		ctxEvery = 1
	}

	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(wID int) {
			defer wg.Done()
			cb := newContigBatch(stdBatchGroup, algo.digLen, salt)
			lastSeg := -1
			var segTotal int64
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
				rounds := 0
				pos := from
				// Locate pos's segment once per chunk; advanced monotonically
				// below as pos crosses segment boundaries.
				seg := 0
				for seg+1 < len(l.offsets) && l.offsets[seg+1] <= pos {
					seg++
				}
				for pos < end {
					if rounds++; rounds >= ctxEvery {
						rounds = 0
						select {
						case <-innerCtx.Done():
							// Cancelled mid-chunk: leave cur[wID] at the
							// current chunk so the watermark reflects the true
							// resume point (re-tested on resume — safe).
							atomic.AddInt64(atomicAttempts, local)
							return
						default:
						}
					}
					for seg+1 < len(l.offsets) && l.offsets[seg+1] <= pos {
						seg++
					}
					sets := l.segments[seg]
					if seg != lastSeg {
						// maskKeyspace(sets) is invariant for this segment but
						// costs a multiply per position; the segment is walked
						// batch by batch, so cache it here.
						segTotal = maskKeyspace(sets)
						lastSeg = seg
					}
					want := stdBatchGroup
					if remaining := end - pos; int64(want) > remaining {
						want = int(remaining)
					}
					n := cb.fillFromSegment(sets, pos-l.offsets[seg], segTotal, want)
					if n == 0 {
						// Segment exhausted; cannot happen while pos < end <=
						// l.total, but guard rather than spin.
						break
					}
					algo.hashBatch(cb.messages(n), cb.stride, n, cb.out)

					done := false
					for i := 0; i < n; i++ {
						idxs, ok := targets.lookup(cb.digest(i))
						if !ok {
							continue
						}
						cand := string(cb.candidate(i))
						hitMu.Lock()
						stop := onHit(cand, idxs)
						hitMu.Unlock()
						if stop {
							done = true
						}
					}
					local += int64(n)
					pos += int64(n)
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
	return nil
}

// ── dispatch helpers ────────────────────────────────────────────────────────

// runLayoutStdSingle adapts runLayoutStd to the single-target crack contract:
// return the first matching plaintext, or "" when the slice is exhausted.
// The recorder runs under runLayoutStd's own mutex and the read happens after
// every worker has returned, so no extra synchronisation is needed.
func runLayoutStdSingle(ctx context.Context, l *keyspaceLayout, resumeFrom, limit int64,
	workers int, atomicAttempts *int64, watermark *int64,
	algo *stdAlgo, salt stdSalt, targets *stdTargets) (string, error) {

	var found string
	err := runLayoutStd(ctx, l, resumeFrom, limit, workers, atomicAttempts, watermark,
		algo, salt, targets, func(cand string, _ []int) bool {
			if found == "" {
				found = cand
			}
			return true
		})
	if err != nil {
		return "", err
	}
	return found, nil
}

// batchStdLayout is batchFastLayout's stdlib-digest sibling: one multi-hash
// brute/mask pass over `layout`, reporting hits through `record` (batchRunType's
// CAS-guarded recorder, which returns true once every target is found).
//
// resumeFrom/limit are --skip/--limit's slice of the layout, with exactly the
// meaning they carry everywhere else; watermark (nil when nothing is
// checkpointing) is the session restore point the runner publishes into.
//
// It returns false when the pass is not eligible — a type/salt combination
// this path does not compute identically, a generator layout, an over-long
// segment, or a target that is not the right number of hex bytes — in which
// case the caller must run the SAME layout on the scalar path exactly as
// before. Returning false is always safe: nothing has been recorded and no
// candidate has been counted.
//
// `salt` is the salt EVERY target in `active` is hashed with. That is a real
// precondition, not a convenience: one hashed candidate can only be tested
// against targets sharing a salt, so the caller must have grouped them (see
// batchSaltGroups in batch.go). Passing a mixed group would file each
// plaintext against whichever target happened to collide under the first
// salt — the exact silent mis-attribution the grouping exists to prevent —
// so the digests are keyed by batchTarget.key, the per-target hash field
// the grouping fills in.
func batchStdLayout(ctx context.Context, typ string, layout *keyspaceLayout,
	active []int, batch []*batchTarget, salt, saltMode string, resumeFrom, limit int64, workers int,
	atomicAttempts *int64, watermark *int64, record func(string, []int) bool) bool {

	if layout == nil || len(active) == 0 {
		return false
	}
	algo, sp, ok := stdPathEligible(typ, salt, saltMode, layout)
	if !ok {
		return false
	}
	hexes := make([]string, len(active))
	for i, idx := range active {
		if batch[idx].salt != salt {
			return false
		}
		hexes[i] = batch[idx].key
	}
	st, ok := newStdTargets(hexes, active, algo.digLen)
	if !ok {
		return false
	}
	if err := runLayoutStd(ctx, layout, resumeFrom, limit, workers, atomicAttempts, watermark,
		algo, sp, st, record); err != nil {
		return false
	}
	return true
}
