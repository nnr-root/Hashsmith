package smith

import (
	"strconv"
	"strings"
)

// pbkdf2Sha1Lanes is the AVX2 core's lane width for SHA-1: 16, not 8 —
// sha1avx2_gen.py's register-reuse derivation fits two 8-lane chains (5
// state + 3 scratch = 8 YMM/chain) where SHA-256's heavier round function
// only fits one.
const pbkdf2Sha1Lanes = 16

// pbkdf2Sha1AVX2Eligible mirrors pbkdf2Sha256AVX2Eligible's own comment:
// the runtime gate is hash-independent (AVX2 present, hardware SHA
// acceleration absent), kept as its own per-hash name for consistency with
// hasSHA1AVX2/hasSHA256AVX2's own naming rather than one shared
// hash-agnostic function.
func pbkdf2Sha1AVX2Eligible() bool {
	return hasSHA1AVX2() && !hasSHANI()
}

// pbkdf2Sha1LaneHasher implements laneHasher for PBKDF2-HMAC-SHA1,
// batching pbkdf2Sha1Lanes independent candidate passwords through
// sha1Group16AVX2 per HMAC iteration. Structurally identical to
// pbkdf2Sha256LaneHasher (pbkdf2_lane_sha256.go) — same design doc §4.3
// data flow, same v1 scope (dkLen must fit in one hash output, <=20 bytes
// here) — parametrized for SHA-1's 20-byte digest and 16-lane width
// instead of duplicating comments already given in full there.
type pbkdf2Sha1LaneHasher struct {
	salt []byte
	iter int
	want []byte // dkLen bytes, <= 20
}

// newPBKDF2Sha1LaneHasher parses targetHash and returns a lane hasher for
// it, or nil when the record does not name plain "sha1" (any spelling
// pbkdf2HashFactory accepts), is malformed, or asks for a derived key
// longer than one SHA-1 output. See newPBKDF2Sha256LaneHasher for the
// identical parsing logic this mirrors.
func newPBKDF2Sha1LaneHasher(targetHash string) *pbkdf2Sha1LaneHasher {
	f := strings.Split(targetHash, ":")
	if len(f) != 4 {
		return nil
	}
	if strings.ToLower(strings.ReplaceAll(f[0], "-", "")) != "sha1" {
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
	if err != nil || len(want) == 0 || len(want) > 20 {
		return nil
	}
	return &pbkdf2Sha1LaneHasher{salt: salt, iter: iter, want: want}
}

// Run mirrors pbkdf2Sha256LaneHasher.Run exactly — see that method's own
// comment for the partial-group rule this also follows.
func (h *pbkdf2Sha1LaneHasher) Run(pw [][]byte, out []bool) {
	i := 0
	for i < len(pw) {
		n := len(pw) - i
		if n > pbkdf2Sha1Lanes {
			n = pbkdf2Sha1Lanes
		}
		var lanes [pbkdf2Sha1Lanes][]byte
		for k := 0; k < n; k++ {
			lanes[k] = pw[i+k]
		}
		for k := n; k < pbkdf2Sha1Lanes; k++ {
			lanes[k] = lanes[n-1]
		}
		results := h.runGroup(&lanes)
		for k := 0; k < n; k++ {
			out[i+k] = bytesEqualCT(results[k][:len(h.want)], h.want)
		}
		i += n
	}
}

// runGroup mirrors pbkdf2Sha256LaneHasher.runGroup exactly, parametrized
// for SHA-1's 5-word state, 20-byte digest and 16-lane width.
func (h *pbkdf2Sha1LaneHasher) runGroup(lanes *[pbkdf2Sha1Lanes][]byte) [pbkdf2Sha1Lanes][20]byte {
	var innerStates, outerStates [5][pbkdf2Sha1Lanes]uint32
	for lane := 0; lane < pbkdf2Sha1Lanes; lane++ {
		kb := hmacSHA1KeyBlock(lanes[lane])
		inner := hmacSHA1InnerOuterIV(kb, 0x36)
		outer := hmacSHA1InnerOuterIV(kb, 0x5c)
		for w := 0; w < 5; w++ {
			innerStates[w][lane] = inner[w]
			outerStates[w][lane] = outer[w]
		}
	}

	var u [pbkdf2Sha1Lanes][20]byte
	var t [pbkdf2Sha1Lanes][20]byte
	blockCounter := []byte{0, 0, 0, 1}
	saltAndCounter := make([]byte, 0, len(h.salt)+4)
	saltAndCounter = append(saltAndCounter, h.salt...)
	saltAndCounter = append(saltAndCounter, blockCounter...)
	for lane := 0; lane < pbkdf2Sha1Lanes; lane++ {
		var innerState, outerState [5]uint32
		for w := 0; w < 5; w++ {
			innerState[w] = innerStates[w][lane]
			outerState[w] = outerStates[w][lane]
		}
		u[lane] = hmacSHA1FromInnerOuter(innerState, outerState, saltAndCounter)
		t[lane] = u[lane]
	}

	var innerSchedules, outerSchedules [80][pbkdf2Sha1Lanes]uint32
	for n := 2; n <= h.iter; n++ {
		for lane := 0; lane < pbkdf2Sha1Lanes; lane++ {
			var w [80]uint32
			sha1OneBlockPaddedSchedule(u[lane][:], 64, &w)
			for step := 0; step < 80; step++ {
				innerSchedules[step][lane] = w[step]
			}
		}
		innerOut := sha1Group16AVX2(&innerStates, &innerSchedules)

		for lane := 0; lane < pbkdf2Sha1Lanes; lane++ {
			var innerDigest [20]byte
			for word := 0; word < 5; word++ {
				v := innerOut[word][lane]
				innerDigest[word*4] = byte(v >> 24)
				innerDigest[word*4+1] = byte(v >> 16)
				innerDigest[word*4+2] = byte(v >> 8)
				innerDigest[word*4+3] = byte(v)
			}
			var w [80]uint32
			sha1OneBlockPaddedSchedule(innerDigest[:], 64, &w)
			for step := 0; step < 80; step++ {
				outerSchedules[step][lane] = w[step]
			}
		}
		outerOut := sha1Group16AVX2(&outerStates, &outerSchedules)

		for lane := 0; lane < pbkdf2Sha1Lanes; lane++ {
			for word := 0; word < 5; word++ {
				v := outerOut[word][lane]
				u[lane][word*4] = byte(v >> 24)
				u[lane][word*4+1] = byte(v >> 16)
				u[lane][word*4+2] = byte(v >> 8)
				u[lane][word*4+3] = byte(v)
				t[lane][word*4] ^= u[lane][word*4]
				t[lane][word*4+1] ^= u[lane][word*4+1]
				t[lane][word*4+2] ^= u[lane][word*4+2]
				t[lane][word*4+3] ^= u[lane][word*4+3]
			}
		}
	}

	return t
}
