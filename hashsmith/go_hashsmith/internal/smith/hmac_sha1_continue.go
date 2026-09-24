package smith

// hmacSHA1InnerOuterIV, hmacSHA1KeyBlock, sha1ScalarSum, sha1ContinueSum,
// sha1OneBlockPaddedSchedule and hmacSHA1FromInnerOuter mirror
// hmac_sha256_continue.go's functions exactly, parametrized for SHA-1's
// block size (also 64 bytes — HMAC's key-block preprocessing is identical
// in shape for any hash with a 64-byte block) and 20-byte digest. See that
// file's comments for the reasoning; it is not repeated here.

func hmacSHA1InnerOuterIV(keyBlock [64]byte, pad byte) [5]uint32 {
	var block [64]byte
	for i := range block {
		block[i] = keyBlock[i] ^ pad
	}
	state := sha1IV
	var w [80]uint32
	sha1ExpandSchedule(&block, &w)
	sha1ScalarCompress(&state, &w)
	return state
}

func hmacSHA1KeyBlock(key []byte) [64]byte {
	var block [64]byte
	if len(key) > 64 {
		sum := sha1ScalarSum(key)
		copy(block[:], sum[:])
		return block
	}
	copy(block[:], key)
	return block
}

func sha1ScalarSum(message []byte) [20]byte {
	return sha1ContinueSum(sha1IV, 0, message)
}

// sha1ContinueSum is sha256ContinueSum's SHA-1 twin: processes an
// arbitrary-length message in full 64-byte blocks, continuing from a state
// that has already compressed `consumed` bytes, and finalizes the tail.
func sha1ContinueSum(state [5]uint32, consumed int, message []byte) [20]byte {
	for len(message) >= 64 {
		var w [80]uint32
		var block [64]byte
		copy(block[:], message[:64])
		sha1ExpandSchedule(&block, &w)
		sha1ScalarCompress(&state, &w)
		message = message[64:]
		consumed += 64
	}
	return sha1FinalizeTail(state, consumed, message)
}

// sha1FinalizeTail mirrors sha256FinalizeTail's padding logic exactly (the
// Merkle-Damgard padding scheme is identical for any 64-byte-block,
// 64-bit-length-field hash) with a 20-byte, 5-word digest output instead of
// 32/8.
func sha1FinalizeTail(state [5]uint32, consumed int, tail []byte) [20]byte {
	if len(tail) >= 64 {
		panic("sha1FinalizeTail: tail must be under 64 bytes; call sha1ContinueSum instead")
	}
	totalLen := uint64(consumed+len(tail)) * 8
	var block [64]byte
	n := copy(block[:], tail)
	block[n] = 0x80
	if n >= 56 {
		var w [80]uint32
		sha1ExpandSchedule(&block, &w)
		sha1ScalarCompress(&state, &w)
		block = [64]byte{}
	}
	for i := 0; i < 8; i++ {
		block[63-i] = byte(totalLen >> (8 * i))
	}
	var w [80]uint32
	sha1ExpandSchedule(&block, &w)
	sha1ScalarCompress(&state, &w)
	var out [20]byte
	for i := 0; i < 5; i++ {
		out[i*4] = byte(state[i] >> 24)
		out[i*4+1] = byte(state[i] >> 16)
		out[i*4+2] = byte(state[i] >> 8)
		out[i*4+3] = byte(state[i])
	}
	return out
}

// sha1OneBlockPaddedSchedule mirrors sha256OneBlockPaddedSchedule: builds
// and expands the schedule for a message short enough (<=55 bytes) to pad
// within one block, given priorBytes already compressed — the shape every
// PBKDF2 hot-loop iteration needs (a 20-byte U value, always preceded by
// exactly one 64-byte ipad/opad block).
func sha1OneBlockPaddedSchedule(data []byte, priorBytes int, w *[80]uint32) {
	if len(data) > 55 {
		panic("sha1OneBlockPaddedSchedule: data too long to pad within one block")
	}
	var block [64]byte
	n := copy(block[:], data)
	block[n] = 0x80
	totalLen := uint64(priorBytes+len(data)) * 8
	for i := 0; i < 8; i++ {
		block[63-i] = byte(totalLen >> (8 * i))
	}
	sha1ExpandSchedule(&block, w)
}

// sha1ScheduleFromWords is sha256ScheduleFromWords's SHA-1 twin: builds and
// expands the schedule directly from a previous compression's 5-word
// (20-byte) digest, no byte round trip. Layout differs from SHA-256's
// because 20 bytes is exactly 5 words (not a partial word): w[0..4] = data
// verbatim, w[5] = 0x80000000 (the pad byte starts a fresh word here,
// unlike SHA-256's case where it shares word 8 with no data), w[6..13] = 0,
// and the 64-bit bit length is again a fixed constant for every call this
// is used for — priorBytes is always 64 (one ipad/opad block) and data is
// always 20 bytes (one SHA-1 digest), so the total is always 84 bytes =
// 672 bits, always fitting in w[15] alone.
func sha1ScheduleFromWords(data *[5]uint32, w *[80]uint32) {
	copy(w[0:5], data[:])
	w[5] = 0x80000000
	w[6], w[7], w[8], w[9], w[10], w[11], w[12], w[13], w[14] = 0, 0, 0, 0, 0, 0, 0, 0, 0
	w[15] = 672 // (64 + 20) * 8 bits, constant for every call — see doc comment
	sha1ExpandRemainingWords(w)
}

func hmacSHA1FromInnerOuter(innerState, outerState [5]uint32, message []byte) [20]byte {
	inner := sha1ContinueSum(innerState, 64, message)
	return sha1FinalizeTail(outerState, 64, inner[:])
}
