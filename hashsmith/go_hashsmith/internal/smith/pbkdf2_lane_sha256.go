package smith

import (
	"strconv"
	"strings"
)

// pbkdf2Sha256Lanes is the AVX2 core's lane width for SHA-256 (see
// sha256avx2_gen.py's register-budget derivation: 8 state + 4 scratch,
// N=1 chain, 8 lanes).
const pbkdf2Sha256Lanes = 8

// pbkdf2Sha256AVX2Eligible is the runtime gate the design doc's §4.4
// specifies: the new core may run only where AVX2 exists and hardware SHA
// acceleration does not. hasSHA256AVX2 is already false on every
// non-amd64 build (sha256avx2_generic.go), so this needs no build tag of
// its own — on any architecture but amd64 the first operand alone decides
// it, exactly like hasAVX2 already lets md5GroupAVX2's dispatch stay
// portable. Everywhere this returns false, newLaneHasher's "pbkdf2" case
// falls back to the scalar verifyPBKDF2 path, which is correct (just not
// vectorized) for every algorithm and hardware combination this excludes.
func pbkdf2Sha256AVX2Eligible() bool {
	return hasSHA256AVX2() && !hasSHANI()
}

// pbkdf2Sha256LaneHasher implements laneHasher for PBKDF2-HMAC-SHA256,
// batching pbkdf2Sha256Lanes independent candidate passwords through
// sha256Group8AVX2 per HMAC iteration. See the design doc's §4.3
// (docs/superpowers/specs/2026-09-24-pbkdf2-avx2-multibuffer-design.md)
// for the full data-flow this implements.
//
// v1 scope, matching the design's §3 non-goals: the target's derived key
// (dkLen) must fit in one hash output (<=32 bytes) — PBKDF2's multi-block
// T_1||T_2||... construction for a longer derived key is not implemented
// here, and newPBKDF2Sha256LaneHasher returns nil for such a target so the
// caller falls back to the scalar verifyPBKDF2 path, which handles it
// correctly (just not through this core).
type pbkdf2Sha256LaneHasher struct {
	salt []byte
	iter int
	want []byte // dkLen bytes, <= 32
}

// newPBKDF2Sha256LaneHasher parses targetHash (crack_pbkdf2.go's
// "algo:iter:salt:dk" record format) and returns a lane hasher for it, or
// nil when the record does not name plain "sha256" (any spelling
// pbkdf2HashFactory accepts, e.g. "SHA-256"), is malformed, or asks for a
// derived key longer than one SHA-256 output.
func newPBKDF2Sha256LaneHasher(targetHash string) *pbkdf2Sha256LaneHasher {
	f := strings.Split(targetHash, ":")
	if len(f) != 4 {
		return nil
	}
	if strings.ToLower(strings.ReplaceAll(f[0], "-", "")) != "sha256" {
		return nil
	}
	iter, err := strconv.Atoi(f[1])
	if err != nil || iter < 1 || iter > maxKDFIterations {
		return nil
	}
	salt, err := decodeBase64Flexible(f[2], false)
	if err != nil || len(salt) > maxKDFFieldSize {
		return nil
	}
	want, err := decodeBase64Flexible(f[3], false)
	if err != nil || len(want) == 0 || len(want) > 32 {
		return nil
	}
	return &pbkdf2Sha256LaneHasher{salt: salt, iter: iter, want: want}
}

// Run verifies up to len(pw) candidates, writing each verdict to out —
// matching bcryptlane.Hasher's and descryptLaneHasher's Run contract
// exactly, including the partial-group rule: a final group shorter than
// pbkdf2Sha256Lanes repeats its last real candidate into the unused lanes
// rather than leaving them holding a previous call's stale schedule (see
// descryptLaneHasher.Run's own comment for why: the result is never read,
// but a laned implementation whose cost depends on history is a bug this
// project has already fixed once).
func (h *pbkdf2Sha256LaneHasher) Run(pw [][]byte, out []bool) {
	i := 0
	for i < len(pw) {
		n := len(pw) - i
		if n > pbkdf2Sha256Lanes {
			n = pbkdf2Sha256Lanes
		}
		var lanes [pbkdf2Sha256Lanes][]byte
		for k := 0; k < n; k++ {
			lanes[k] = pw[i+k]
		}
		for k := n; k < pbkdf2Sha256Lanes; k++ {
			lanes[k] = lanes[n-1]
		}
		results := h.runGroup(&lanes)
		for k := 0; k < n; k++ {
			out[i+k] = bytesEqualCT(results[k][:len(h.want)], h.want)
		}
		i += n
	}
}

// runGroup calls the shared batched-derivation primitive with this
// hasher's own (salt, iter) — see pbkdf2HMACSHA256DeriveBatch for the
// actual work. Kept as its own method (rather than inlining the call at
// Run's call site) only because it is the name the generic-PBKDF2 lane
// hasher's own tests already know.
func (h *pbkdf2Sha256LaneHasher) runGroup(lanes *[pbkdf2Sha256Lanes][]byte) [pbkdf2Sha256Lanes][32]byte {
	return pbkdf2HMACSHA256DeriveBatch(lanes, h.salt, h.iter)
}

// pbkdf2HMACSHA256DeriveBatch computes PBKDF2-HMAC-SHA256(password, salt,
// iter, 32) for all pbkdf2Sha256Lanes passwords in passwords at once,
// returning each one's full 32-byte T_1 block (PBKDF2's first and only
// block for any derived-key length up to 32 bytes — a caller wanting fewer
// bytes truncates; a caller wanting more needs a second block, which this
// function does not compute — see the design doc's §3 non-goal on
// dkLen > hashLen).
//
// This is the reusable core every PBKDF2-HMAC-SHA256 format in this
// project can batch through, not only the generic "-t pbkdf2" crack type
// pbkdf2Sha256LaneHasher wraps it for: any format whose own verify
// function currently calls golang.org/x/crypto/pbkdf2.Key with sha256.New,
// a single shared salt across the batch, and a derived key of 32 bytes or
// fewer can call this directly and do its own (usually cheap — an XOR, an
// HMAC, a decrypt-and-check) per-lane post-processing on the result,
// exactly as its scalar verify function already does on one pbkdf2.Key
// call's output. See pbkdf2Sha1PasswordLaneHasher (crack_onepassword8.go)
// and the Dogechain wallet's lane hasher (crack_dogechain.go) for two
// worked examples — one needing no password transform, one needing a
// cheap per-lane one before this function is called at all.
//
// The hot loop stays entirely in uint32-word space from one compression's
// output to the next schedule's input, via sha256ScheduleFromWords — no
// per-iteration byte encode/decode. CI's first real-hardware run of this
// core found that round trip accounted for roughly half of measured
// per-candidate time, on top of the schedule expansion the design's own
// §4.2 already knew was scalar and unavoidable; this removes the half
// that wasn't.
func pbkdf2HMACSHA256DeriveBatch(passwords *[pbkdf2Sha256Lanes][]byte, salt []byte, iter int) [pbkdf2Sha256Lanes][32]byte {
	innerStates, outerStates := pbkdf2HMACSHA256KeySetup(passwords)
	return pbkdf2Sha256Block(&innerStates, &outerStates, salt, iter, 1)
}

// pbkdf2HMACSHA256KeySetup is PBKDF2's per-lane HMAC key setup — cheap
// (XOR only, see hmacSHA256KeyBlock/hmacSHA256InnerOuterIV) and, critically,
// independent of both the iteration count and the PBKDF2 block index. Split
// out so pbkdf2HMACSHA256DeriveBatchN (multi-block) computes it once and
// reuses it across every T_i, rather than repeating it once per block for
// no reason.
func pbkdf2HMACSHA256KeySetup(passwords *[pbkdf2Sha256Lanes][]byte) (innerStates, outerStates [8][pbkdf2Sha256Lanes]uint32) {
	for lane := 0; lane < pbkdf2Sha256Lanes; lane++ {
		kb := hmacSHA256KeyBlock(passwords[lane])
		inner := hmacSHA256InnerOuterIV(kb, 0x36)
		outer := hmacSHA256InnerOuterIV(kb, 0x5c)
		for w := 0; w < 8; w++ {
			innerStates[w][lane] = inner[w]
			outerStates[w][lane] = outer[w]
		}
	}
	return innerStates, outerStates
}

// pbkdf2Sha256Block computes one PBKDF2 block, T_block = U_1 XOR U_2 XOR
// ... XOR U_iter, for all pbkdf2Sha256Lanes lanes at once, given their
// already-computed HMAC key setup (pbkdf2HMACSHA256KeySetup) — the shared
// core both pbkdf2HMACSHA256DeriveBatch (block fixed at 1) and
// pbkdf2HMACSHA256DeriveBatchN (any block, for a multi-block derived key)
// call.
func pbkdf2Sha256Block(innerStates, outerStates *[8][pbkdf2Sha256Lanes]uint32, salt []byte, iter int, block uint32) [pbkdf2Sha256Lanes][32]byte {
	// Step 1: U_1 — one-time, variable length (salt || INT(block) can span
	// more than one block depending on salt length), computed scalar per
	// lane. Deliberately not vectorized: the hot loop below dominates by
	// orders of magnitude at any realistic iteration count, so U1's cost is
	// negligible however it is computed — see the design doc's §4.3. Its
	// byte-oriented result is converted to words ONCE here, at the
	// boundary into the word-native hot loop, not every iteration.
	var u, t [pbkdf2Sha256Lanes][8]uint32
	blockCounter := []byte{byte(block >> 24), byte(block >> 16), byte(block >> 8), byte(block)}
	saltAndCounter := make([]byte, 0, len(salt)+4)
	saltAndCounter = append(saltAndCounter, salt...)
	saltAndCounter = append(saltAndCounter, blockCounter...)
	for lane := 0; lane < pbkdf2Sha256Lanes; lane++ {
		var innerState, outerState [8]uint32
		for w := 0; w < 8; w++ {
			innerState[w] = innerStates[w][lane]
			outerState[w] = outerStates[w][lane]
		}
		u1Bytes := hmacSHA256FromInnerOuter(innerState, outerState, saltAndCounter)
		for w := 0; w < 8; w++ {
			v := uint32(u1Bytes[w*4])<<24 | uint32(u1Bytes[w*4+1])<<16 | uint32(u1Bytes[w*4+2])<<8 | uint32(u1Bytes[w*4+3])
			u[lane][w] = v
			t[lane][w] = v
		}
	}

	// Step 2: the hot loop, n = 2..iter. Every U_n is exactly one 32-byte
	// hash output — fixed length, always fitting padding in the very next
	// block after the precomputed ipad/opad block (32+1+23+8=64) — so both
	// the inner and outer continuation here are exactly one AVX2
	// compression per lane, batched across all 8 lanes at once.
	var innerSchedules, outerSchedules [64][pbkdf2Sha256Lanes]uint32
	for n := 2; n <= iter; n++ {
		for lane := 0; lane < pbkdf2Sha256Lanes; lane++ {
			var w [64]uint32
			sha256ScheduleFromWords(&u[lane], &w)
			for step := 0; step < 64; step++ {
				innerSchedules[step][lane] = w[step]
			}
		}
		innerOut := sha256Group8AVX2(innerStates, &innerSchedules)

		for lane := 0; lane < pbkdf2Sha256Lanes; lane++ {
			var innerDigest [8]uint32
			for word := 0; word < 8; word++ {
				innerDigest[word] = innerOut[word][lane]
			}
			var w [64]uint32
			sha256ScheduleFromWords(&innerDigest, &w)
			for step := 0; step < 64; step++ {
				outerSchedules[step][lane] = w[step]
			}
		}
		outerOut := sha256Group8AVX2(outerStates, &outerSchedules)

		for lane := 0; lane < pbkdf2Sha256Lanes; lane++ {
			for word := 0; word < 8; word++ {
				v := outerOut[word][lane]
				u[lane][word] = v
				t[lane][word] ^= v
			}
		}
	}

	// Convert to bytes exactly once, at the very end, for the caller's
	// byte-oriented comparison against the target's stored derived key.
	var result [pbkdf2Sha256Lanes][32]byte
	for lane := 0; lane < pbkdf2Sha256Lanes; lane++ {
		for word := 0; word < 8; word++ {
			v := t[lane][word]
			result[lane][word*4] = byte(v >> 24)
			result[lane][word*4+1] = byte(v >> 16)
			result[lane][word*4+2] = byte(v >> 8)
			result[lane][word*4+3] = byte(v)
		}
	}
	return result
}

// pbkdf2HMACSHA256DeriveBatchN computes PBKDF2-HMAC-SHA256(password, salt,
// iter, dkLen) for all pbkdf2Sha256Lanes passwords at once, for any dkLen —
// PBKDF2's multi-block T_1||T_2||...||T_l construction (RFC 8018 §5.2),
// generalizing pbkdf2HMACSHA256DeriveBatch (dkLen<=32 only, T_1 alone) to
// any length.
//
// The HMAC key setup is independent of the block index, so it runs once
// (pbkdf2HMACSHA256KeySetup) regardless of how many blocks dkLen needs;
// only the hot loop — pbkdf2Sha256Block's `iter` HMAC iterations — repeats
// per block, each restarting its own U_1 from the block's own big-endian
// counter appended to the salt.
func pbkdf2HMACSHA256DeriveBatchN(passwords *[pbkdf2Sha256Lanes][]byte, salt []byte, iter, dkLen int) [pbkdf2Sha256Lanes][]byte {
	innerStates, outerStates := pbkdf2HMACSHA256KeySetup(passwords)

	numBlocks := (dkLen + 31) / 32
	if numBlocks < 1 {
		numBlocks = 1
	}
	var out [pbkdf2Sha256Lanes][]byte
	for lane := range out {
		out[lane] = make([]byte, 0, numBlocks*32)
	}
	for block := 1; block <= numBlocks; block++ {
		blockBytes := pbkdf2Sha256Block(&innerStates, &outerStates, salt, iter, uint32(block))
		for lane := 0; lane < pbkdf2Sha256Lanes; lane++ {
			out[lane] = append(out[lane], blockBytes[lane][:]...)
		}
	}
	for lane := range out {
		out[lane] = out[lane][:dkLen]
	}
	return out
}
