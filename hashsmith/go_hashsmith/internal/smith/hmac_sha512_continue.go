package smith

// hmacSHA512InnerOuterIV, hmacSHA512KeyBlock, sha512ScalarSum,
// sha512ContinueSum, sha512OneBlockPaddedSchedule and
// hmacSHA512FromInnerOuter mirror hmac_sha256_continue.go's functions,
// parametrized for SHA-512's 128-byte block (not 64) and its 128-bit (not
// 64-bit) length field — the one genuine structural difference from the
// SHA-256/SHA-1 versions this file's shape otherwise matches exactly.

func hmacSHA512InnerOuterIV(keyBlock [128]byte, pad byte) [8]uint64 {
	var block [128]byte
	for i := range block {
		block[i] = keyBlock[i] ^ pad
	}
	state := sha512IV
	var w [80]uint64
	sha512ExpandSchedule(&block, &w)
	sha512ScalarCompress(&state, &w)
	return state
}

// hmacSHA512KeyBlock builds the 128-byte, zero-padded HMAC key block for
// key, hashing it down first if it exceeds one block.
func hmacSHA512KeyBlock(key []byte) [128]byte {
	var block [128]byte
	if len(key) > 128 {
		sum := sha512ScalarSum(key)
		copy(block[:], sum[:])
		return block
	}
	copy(block[:], key)
	return block
}

func sha512ScalarSum(message []byte) [64]byte {
	return sha512ContinueSum(sha512IV, 0, message)
}

// sha512ContinueSum processes an arbitrary-length message in full 128-byte
// blocks, continuing from a state that has already compressed `consumed`
// bytes, and finalizes with the tail.
func sha512ContinueSum(state [8]uint64, consumed int, message []byte) [64]byte {
	for len(message) >= 128 {
		var w [80]uint64
		var block [128]byte
		copy(block[:], message[:128])
		sha512ExpandSchedule(&block, &w)
		sha512ScalarCompress(&state, &w)
		message = message[128:]
		consumed += 128
	}
	return sha512FinalizeTail(state, consumed, message)
}

// sha512FinalizeTail mirrors sha256FinalizeTail, with SHA-512's 128-byte
// block and 128-bit length field: the field's upper 8 bytes are always
// zero here (see padOneBlockSHA512's own comment — no message this project
// will ever hash approaches 2^64 bits), so only the low 8 bytes of a
// 16-byte trailer are ever written, matching every real implementation's
// practical behaviour.
func sha512FinalizeTail(state [8]uint64, consumed int, tail []byte) [64]byte {
	if len(tail) >= 128 {
		panic("sha512FinalizeTail: tail must be under 128 bytes; call sha512ContinueSum instead")
	}
	totalLen := uint64(consumed+len(tail)) * 8
	var block [128]byte
	n := copy(block[:], tail)
	block[n] = 0x80
	// The 16-byte length field occupies the block's last 16 bytes
	// (indices 112-127), so 0x80 at index n needs n <= 111 to avoid
	// colliding with it; n >= 112 means this block is full and a second,
	// otherwise-empty block carries the length field alone.
	if n >= 112 {
		var w [80]uint64
		sha512ExpandSchedule(&block, &w)
		sha512ScalarCompress(&state, &w)
		block = [128]byte{}
	}
	for i := 0; i < 8; i++ {
		block[127-i] = byte(totalLen >> (8 * i))
	}
	var w [80]uint64
	sha512ExpandSchedule(&block, &w)
	sha512ScalarCompress(&state, &w)
	var out [64]byte
	for i := 0; i < 8; i++ {
		for b := 0; b < 8; b++ {
			out[i*8+b] = byte(state[i] >> (56 - 8*b))
		}
	}
	return out
}

// sha512OneBlockPaddedSchedule mirrors sha256OneBlockPaddedSchedule for
// SHA-512's 128-byte block: data must be <=111 bytes to pad within one
// block (128 - 1 for 0x80 - 16 for the length field), comfortably covering
// the 64-byte U value every PBKDF2-HMAC-SHA512 hot-loop iteration needs.
func sha512OneBlockPaddedSchedule(data []byte, priorBytes int, w *[80]uint64) {
	if len(data) > 111 {
		panic("sha512OneBlockPaddedSchedule: data too long to pad within one block")
	}
	var block [128]byte
	n := copy(block[:], data)
	block[n] = 0x80
	totalLen := uint64(priorBytes+len(data)) * 8
	for i := 0; i < 8; i++ {
		block[127-i] = byte(totalLen >> (8 * i))
	}
	sha512ExpandSchedule(&block, w)
}

// sha512ScheduleFromWords is sha256ScheduleFromWords's SHA-512 twin: builds
// and expands the schedule directly from a previous compression's 8-word
// (64-byte) digest, no byte round trip. w[0..7] = data verbatim, w[8] =
// 0x8000000000000000 (the pad byte as the top byte of the word immediately
// following the data — SHA-512's digest is exactly 8 64-bit words with no
// partial word, so this mirrors SHA-256's w[8] case rather than SHA-1's
// w[5] one), w[9..13] = 0, and SHA-512's 128-bit length field splits across
// w[14] (high 64 bits, always 0 — no message this project hashes
// approaches 2^64 bits) and w[15] (low 64 bits) — a fixed constant for
// every call this is used for: priorBytes is always 128 (one ipad/opad
// block) and data is always 64 bytes (one SHA-512 digest), so the total is
// always 192 bytes = 1536 bits.
func sha512ScheduleFromWords(data *[8]uint64, w *[80]uint64) {
	copy(w[0:8], data[:])
	w[8] = 0x8000000000000000
	w[9], w[10], w[11], w[12], w[13], w[14] = 0, 0, 0, 0, 0, 0
	w[15] = 1536 // (128 + 64) * 8 bits, constant for every call — see doc comment
	sha512ExpandRemainingWords(w)
}

// sha512ScheduleFirst16FromWords is sha512ScheduleFromWords's vectorized
// twin: populates the first 16 (of 80) schedule words for all
// pbkdf2Sha512Lanes lanes at once, in the [80][lanes]uint64 layout
// sha512Group4AVX2 and sha512ScheduleExpand4AVX2 both expect. Same fixed
// values for the same reason as sha512ScheduleFromWords — every call here
// is exactly one SHA-512 digest continuing one ipad/opad block — just
// written into every lane instead of one.
func sha512ScheduleFirst16FromWords(data *[pbkdf2Sha512Lanes][8]uint64, w *[80][pbkdf2Sha512Lanes]uint64) {
	for lane := 0; lane < pbkdf2Sha512Lanes; lane++ {
		for word := 0; word < 8; word++ {
			w[word][lane] = data[lane][word]
		}
		w[8][lane] = 0x8000000000000000
		w[9][lane], w[10][lane], w[11][lane], w[12][lane], w[13][lane] = 0, 0, 0, 0, 0
		w[14][lane] = 0
		w[15][lane] = 1536
	}
}

func hmacSHA512FromInnerOuter(innerState, outerState [8]uint64, message []byte) [64]byte {
	inner := sha512ContinueSum(innerState, 128, message)
	return sha512FinalizeTail(outerState, 128, inner[:])
}
