package smith

import (
	"strconv"
	"strings"
)

// pbkdf2Sha512Lanes is the AVX2 core's lane width for SHA-512: 4, half of
// SHA-256/SHA-1's 8/16 — a 256-bit YMM register holds only 4 uint64s where
// it held 8 (or, for SHA-1's tighter register budget, 16 across two
// chains) uint32s. See sha512avx2_gen.py's own comment.
const pbkdf2Sha512Lanes = 4

// pbkdf2Sha512AVX2Eligible mirrors pbkdf2Sha256AVX2Eligible/
// pbkdf2Sha1AVX2Eligible: the same hash-independent runtime gate (AVX2
// present, hardware SHA acceleration absent), kept as its own per-hash
// name for consistency with hasSHA512AVX2's naming.
func pbkdf2Sha512AVX2Eligible() bool {
	return hasSHA512AVX2() && !hasSHANI()
}

// pbkdf2Sha512LaneHasher implements laneHasher for PBKDF2-HMAC-SHA512,
// batching pbkdf2Sha512Lanes independent candidate passwords through
// sha512Group4AVX2 per HMAC iteration. Structurally identical to
// pbkdf2Sha256LaneHasher — same design doc §4.3 data flow, same v1 scope
// (dkLen must fit in one hash output, <=64 bytes here) — parametrized for
// SHA-512's 64-byte digest and 4-lane width.
type pbkdf2Sha512LaneHasher struct {
	salt []byte
	iter int
	want []byte // dkLen bytes, <= 64
}

// newPBKDF2Sha512LaneHasher parses targetHash and returns a lane hasher for
// it, or nil when the record does not name plain "sha512" (any spelling
// pbkdf2HashFactory accepts), is malformed, or asks for a derived key
// longer than one SHA-512 output.
func newPBKDF2Sha512LaneHasher(targetHash string) *pbkdf2Sha512LaneHasher {
	f := strings.Split(targetHash, ":")
	if len(f) != 4 {
		return nil
	}
	if strings.ToLower(strings.ReplaceAll(f[0], "-", "")) != "sha512" {
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
	if err != nil || len(want) == 0 || len(want) > 64 {
		return nil
	}
	return &pbkdf2Sha512LaneHasher{salt: salt, iter: iter, want: want}
}

// Run mirrors pbkdf2Sha256LaneHasher.Run exactly.
func (h *pbkdf2Sha512LaneHasher) Run(pw [][]byte, out []bool) {
	i := 0
	for i < len(pw) {
		n := len(pw) - i
		if n > pbkdf2Sha512Lanes {
			n = pbkdf2Sha512Lanes
		}
		var lanes [pbkdf2Sha512Lanes][]byte
		for k := 0; k < n; k++ {
			lanes[k] = pw[i+k]
		}
		for k := n; k < pbkdf2Sha512Lanes; k++ {
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
// hasher's own (salt, iter) — see pbkdf2HMACSHA512DeriveBatch for the
// actual work. Kept as its own method for the same reason
// pbkdf2Sha256LaneHasher.runGroup is.
func (h *pbkdf2Sha512LaneHasher) runGroup(lanes *[pbkdf2Sha512Lanes][]byte) [pbkdf2Sha512Lanes][64]byte {
	return pbkdf2HMACSHA512DeriveBatch(lanes, h.salt, h.iter)
}

// pbkdf2HMACSHA512DeriveBatch computes PBKDF2-HMAC-SHA512(password, salt,
// iter, 64) for all pbkdf2Sha512Lanes passwords at once, returning each
// one's full 64-byte T_1 block — SHA-256's pbkdf2HMACSHA256DeriveBatch,
// parametrized for SHA-512's 8-word (64-bit) state, 64-byte digest,
// 128-byte HMAC block (priorBytes=128, not 64) and 4-lane width, with one
// further optimization SHA-256 has not needed: the diagnostic benchmark
// found schedule expansion, not compression, the larger remaining cost
// here after the word-native fix, so the schedule is expanded by
// sha512ScheduleExpand4AVX2 (all 4 lanes in one AVX2 call) rather than
// sha512ExpandRemainingWords run once per lane in Go — the fix that took
// this hash from losing to stdlib by 13% to beating it by roughly
// two-thirds on real hardware (see the project memory for the numbers).
//
// Like its SHA-256 twin, any format whose own verify function calls
// golang.org/x/crypto/pbkdf2.Key with sha512.New, a single shared salt
// across the batch, and a derived key of 64 bytes or fewer can call this
// directly. v1 scope only: dkLen > 64 needs a second block, which this
// does not compute (compare pbkdf2HMACSHA256DeriveBatch vs
// pbkdf2HMACSHA256DeriveBatchN — no SHA-512 multi-block primitive exists
// yet, since no wired format has needed one).
func pbkdf2HMACSHA512DeriveBatch(passwords *[pbkdf2Sha512Lanes][]byte, salt []byte, iter int) [pbkdf2Sha512Lanes][64]byte {
	var innerStates, outerStates [8][pbkdf2Sha512Lanes]uint64
	for lane := 0; lane < pbkdf2Sha512Lanes; lane++ {
		kb := hmacSHA512KeyBlock(passwords[lane])
		inner := hmacSHA512InnerOuterIV(kb, 0x36)
		outer := hmacSHA512InnerOuterIV(kb, 0x5c)
		for w := 0; w < 8; w++ {
			innerStates[w][lane] = inner[w]
			outerStates[w][lane] = outer[w]
		}
	}

	var u, t [pbkdf2Sha512Lanes][8]uint64
	blockCounter := []byte{0, 0, 0, 1}
	saltAndCounter := make([]byte, 0, len(salt)+4)
	saltAndCounter = append(saltAndCounter, salt...)
	saltAndCounter = append(saltAndCounter, blockCounter...)
	for lane := 0; lane < pbkdf2Sha512Lanes; lane++ {
		var innerState, outerState [8]uint64
		for w := 0; w < 8; w++ {
			innerState[w] = innerStates[w][lane]
			outerState[w] = outerStates[w][lane]
		}
		u1Bytes := hmacSHA512FromInnerOuter(innerState, outerState, saltAndCounter)
		for w := 0; w < 8; w++ {
			var v uint64
			for b := 0; b < 8; b++ {
				v = v<<8 | uint64(u1Bytes[w*8+b])
			}
			u[lane][w] = v
			t[lane][w] = v
		}
	}

	var innerSchedules, outerSchedules [80][pbkdf2Sha512Lanes]uint64
	for n := 2; n <= iter; n++ {
		sha512ScheduleFirst16FromWords(&u, &innerSchedules)
		sha512ScheduleExpand4AVX2(&innerSchedules)
		innerOut := sha512Group4AVX2(&innerStates, &innerSchedules)

		var innerDigest [pbkdf2Sha512Lanes][8]uint64
		for lane := 0; lane < pbkdf2Sha512Lanes; lane++ {
			for word := 0; word < 8; word++ {
				innerDigest[lane][word] = innerOut[word][lane]
			}
		}
		sha512ScheduleFirst16FromWords(&innerDigest, &outerSchedules)
		sha512ScheduleExpand4AVX2(&outerSchedules)
		outerOut := sha512Group4AVX2(&outerStates, &outerSchedules)

		for lane := 0; lane < pbkdf2Sha512Lanes; lane++ {
			for word := 0; word < 8; word++ {
				v := outerOut[word][lane]
				u[lane][word] = v
				t[lane][word] ^= v
			}
		}
	}

	var result [pbkdf2Sha512Lanes][64]byte
	for lane := 0; lane < pbkdf2Sha512Lanes; lane++ {
		for word := 0; word < 8; word++ {
			v := t[lane][word]
			for b := 0; b < 8; b++ {
				result[lane][word*8+b] = byte(v >> (56 - 8*b))
			}
		}
	}
	return result
}
