package smith

// hmacSHA256InnerOuterIV returns the SHA-256 state after absorbing exactly
// one 64-byte ipad (or opad) block from sha256IV — the same "precompute
// once" state Go's stdlib crypto/internal/fips140/hmac keeps via
// MarshalBinary/UnmarshalBinary (see the design doc's §1). Given that
// state, continuing with the rest of the message via
// sha256ContinueAndFinalize reproduces HMAC's inner or outer hash exactly,
// without recomputing the key block on every call.
//
// key must already be the HMAC key block: exactly 64 bytes, either the
// original key zero-padded to blockSize (keys <= 64 bytes) or
// SHA-256(key) zero-padded (keys > 64 bytes) — hmacSHA256KeyBlock builds
// this. pad is 0x36 for the inner (ipad) state, 0x5c for the outer (opad).
func hmacSHA256InnerOuterIV(keyBlock [64]byte, pad byte) [8]uint32 {
	var block [64]byte
	for i := range block {
		block[i] = keyBlock[i] ^ pad
	}
	state := sha256IV
	var w [64]uint32
	sha256ExpandSchedule(&block, &w)
	sha256ScalarCompress(&state, &w)
	return state
}

// hmacSHA256KeyBlock builds the 64-byte, zero-padded HMAC key block for
// key, hashing it down first if it exceeds one block — FIPS 198-1's key
// preprocessing step, identical to what crypto/hmac.New does internally.
func hmacSHA256KeyBlock(key []byte) [64]byte {
	var block [64]byte
	if len(key) > 64 {
		sum := sha256ScalarSum(key)
		copy(block[:], sum[:])
		return block
	}
	copy(block[:], key)
	return block
}

// sha256ScalarSum computes SHA-256 of an arbitrary-length message using
// only this package's own scalar core — used here so the HMAC helpers
// don't reach for crypto/sha256 (which would be an odd asymmetry: the
// whole point of this file is to reproduce what crypto/sha256 does using
// primitives this package can also run through the AVX2 core), and small
// enough to be worth having as its own tested unit.
func sha256ScalarSum(message []byte) [32]byte {
	return sha256ContinueSum(sha256IV, 0, message)
}

// sha256ContinueSum processes an arbitrary-length message in full 64-byte
// blocks, continuing from a state that has already compressed `consumed`
// bytes, and finalizes with the tail (any remainder under 64 bytes, always
// present even when empty). This is the one place that loop lives:
// sha256ScalarSum calls it from sha256IV/consumed=0, and
// hmacSHA256FromInnerOuter calls it from an inner/outer state/consumed=64 —
// message length has no restriction in either case, unlike
// sha256FinalizeTail alone, which requires its tail argument be already
// under 64 bytes.
func sha256ContinueSum(state [8]uint32, consumed int, message []byte) [32]byte {
	for len(message) >= 64 {
		var w [64]uint32
		var block [64]byte
		copy(block[:], message[:64])
		sha256ExpandSchedule(&block, &w)
		sha256ScalarCompress(&state, &w)
		message = message[64:]
		consumed += 64
	}
	return sha256FinalizeTail(state, consumed, message)
}

// sha256FinalizeTail pads and compresses the final (possibly empty, always
// < 64-byte) tail of a message, given the state after `consumed` prior
// bytes were already compressed in full 64-byte blocks, and returns the
// digest. The tail may itself need one or two blocks once padding
// (0x80 + zero-fill + 8-byte bit length) is added: it needs two only when
// len(tail) > 55 (56..63 bytes), since 55 is the most padding-plus-length
// can share a block with.
//
// PRECONDITION: len(tail) < 64. A tail of 64 or more bytes means the
// caller skipped processing a full block first — sha256ContinueSum is the
// function that enforces this by constructon; nothing should call
// sha256FinalizeTail directly with an unbounded message. (An earlier
// version of hmacSHA256FromInnerOuter did exactly that and panicked on any
// message >= 64 bytes — caught by
// TestHMACSHA256ContinuationMatchesReference, which is why this
// precondition is written down rather than left implicit again.)
func sha256FinalizeTail(state [8]uint32, consumed int, tail []byte) [32]byte {
	if len(tail) >= 64 {
		panic("sha256FinalizeTail: tail must be under 64 bytes; call sha256ContinueSum instead")
	}
	totalLen := uint64(consumed+len(tail)) * 8
	var block [64]byte
	n := copy(block[:], tail)
	block[n] = 0x80
	if n >= 56 {
		// Padding and the length do not fit after this tail: compress this
		// block as-is (data + 0x80 + zero fill to 64), then start a fresh
		// all-zero block for the length field alone.
		var w [64]uint32
		sha256ExpandSchedule(&block, &w)
		sha256ScalarCompress(&state, &w)
		block = [64]byte{}
	}
	for i := 0; i < 8; i++ {
		block[63-i] = byte(totalLen >> (8 * i))
	}
	var w [64]uint32
	sha256ExpandSchedule(&block, &w)
	sha256ScalarCompress(&state, &w)
	var out [32]byte
	for i := 0; i < 8; i++ {
		out[i*4] = byte(state[i] >> 24)
		out[i*4+1] = byte(state[i] >> 16)
		out[i*4+2] = byte(state[i] >> 8)
		out[i*4+3] = byte(state[i])
	}
	return out
}

// hmacSHA256FromInnerOuter computes HMAC-SHA256(key, message) given the
// already-absorbed inner/outer states for that key (from
// hmacSHA256InnerOuterIV), so a caller that holds those two states for a
// fixed key can compute HMAC over many different messages without ever
// reprocessing the key block — exactly the optimization PBKDF2's iterated
// HMAC calls depend on, whether done here in scalar form (this function,
// used for the one-time, variable-length U1 step) or across 8 lanes at
// once via sha256Group8AVX2 (the PBKDF2 lane hasher's hot loop).
// sha256OneBlockPaddedSchedule builds and expands the schedule for a
// message that is short enough (<=55 bytes) to pad within a single 64-byte
// block, given priorBytes already compressed before it — the shape every
// PBKDF2 hot-loop iteration needs (a 32-byte U value, always preceded by
// exactly the one 64-byte ipad/opad block, so priorBytes is always 64
// there), pulled out as its own function so the lane hasher's hot loop
// reads as "pad and expand," not inlined padding arithmetic.
func sha256OneBlockPaddedSchedule(data []byte, priorBytes int, w *[64]uint32) {
	if len(data) > 55 {
		panic("sha256OneBlockPaddedSchedule: data too long to pad within one block")
	}
	var block [64]byte
	n := copy(block[:], data)
	block[n] = 0x80
	totalLen := uint64(priorBytes+len(data)) * 8
	for i := 0; i < 8; i++ {
		block[63-i] = byte(totalLen >> (8 * i))
	}
	sha256ExpandSchedule(&block, w)
}

// sha256ScheduleFromWords builds and expands the schedule for the PBKDF2
// hot-loop case directly from the previous compression's own state words —
// no byte encode/decode round trip. The "message" being padded there is
// always exactly one prior compression's 8-word (32-byte) digest, itself
// already a plain uint32 array with no meaningful byte order of its own
// (state[i] is not "big-endian" or "little-endian" as a number — it only
// becomes bytes when something chooses to serialize it, and this function
// chooses not to): w[0..7] = data verbatim, w[8] = 0x80000000 (the 0x80
// pad byte, as the high byte of the word immediately following the data —
// exactly where sha256OneBlockPaddedSchedule's byte-oriented version also
// puts it, just expressed as a word instead of a byte write), w[9..13] = 0,
// and the 64-bit bit-length split across w[14:15] is a fixed constant for
// every call this function is used for: priorBytes is always exactly 64
// (one absorbed ipad/opad block) and data is always exactly 32 bytes (one
// SHA-256 digest), so the total is always 96 bytes = 768 bits, always small
// enough that w[14] (the high 32 bits) is always 0.
//
// Benchmarked in isolation (BenchmarkSHA256ScheduleExpansionScalarX8):
// removing the byte round trip does not change the expansion loop's own
// cost, which is unavoidable scalar work by the design's own §4.2 choice —
// it removes the marshaling AROUND that loop, which CI's first real-
// hardware run showed accounted for roughly half of this hasher's total
// per-candidate time.
func sha256ScheduleFromWords(data *[8]uint32, w *[64]uint32) {
	copy(w[0:8], data[:])
	w[8] = 0x80000000
	w[9], w[10], w[11], w[12], w[13], w[14] = 0, 0, 0, 0, 0, 0
	w[15] = 768 // (64 + 32) * 8 bits, constant for every call — see doc comment
	sha256ExpandRemainingWords(w)
}

func hmacSHA256FromInnerOuter(innerState, outerState [8]uint32, message []byte) [32]byte {
	inner := sha256ContinueSum(innerState, 64, message)
	// The outer hash's own message (the inner digest, 32 bytes) is always
	// well under 64 bytes, so sha256FinalizeTail alone is correct and
	// exact here — sha256ContinueSum would do the same thing through an
	// empty loop, but calling the tail function directly says so.
	return sha256FinalizeTail(outerState, 64, inner[:])
}
