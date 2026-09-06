package bcryptlane

import (
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"strconv"
)

// Lanes is the interleave width: the maximum number of candidates Run hashes in
// one pass. Tuned by measurement in docs/superpowers/notes/, not by guesswork.
const Lanes = 1

// bcrypt's own base64 alphabet, which is not the standard one.
const alphabet = "./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"

var bcEncoding = base64.NewEncoding(alphabet).WithPadding(base64.NoPadding)

// magicCipherData is the plaintext bcrypt encrypts 64 times:
// "OrpheanBeholderScryDoubt".
var magicCipherData = []byte{
	0x4f, 0x72, 0x70, 0x68, 0x65, 0x61, 0x6e, 0x42,
	0x65, 0x68, 0x6f, 0x6c, 0x64, 0x65, 0x72, 0x53,
	0x63, 0x72, 0x79, 0x44, 0x6f, 0x75, 0x62, 0x74,
}

var errInvalidHash = errors.New("bcryptlane: not a bcrypt crypt string")

// Hasher is one parsed bcrypt target. Parsing happens once; Run is the hot path.
type Hasher struct {
	cost   int
	csalt  [16]byte
	digest [23]byte
}

// NewHasher parses a $2?$cc$<22-char salt><31-char digest> crypt string.
//
// It accepts every major-version-2 bcrypt target x/crypto/bcrypt accepts
// (minor versions "", "a", "b", "x", "y" all included), and it deliberately
// rejects major versions below 2 (which are not bcrypt at all - "$1$" is
// md5crypt's prefix) even though x/crypto's own newFromHash lets them through
// as long as the major version is under "3". Refusing them here is not a
// behaviour change for the product: a later task treats a NewHasher error as
// "no lane core available for this target" and falls back to the existing
// scalar path, which still calls x/crypto and answers exactly as today. This
// is not exact parity with newFromHash - it is a stricter, safer subset.
func NewHasher(crypt string) (*Hasher, error) {
	if len(crypt) < 59 || crypt[0] != '$' || crypt[1] != '2' {
		return nil, errInvalidHash
	}
	i := 2
	if crypt[i] != '$' {
		i++ // minor version letter
	}
	if i >= len(crypt) || crypt[i] != '$' {
		return nil, errInvalidHash
	}
	i++
	if i+2 >= len(crypt) || crypt[i+2] != '$' {
		return nil, errInvalidHash
	}
	cost, err := strconv.Atoi(crypt[i : i+2])
	if err != nil {
		return nil, errInvalidHash
	}
	if cost < 4 || cost > 31 {
		return nil, errInvalidHash
	}
	rest := crypt[i+3:]
	if len(rest) != 53 {
		return nil, errInvalidHash
	}
	saltRaw, err := bcEncoding.DecodeString(rest[:22])
	if err != nil || len(saltRaw) < 16 {
		return nil, errInvalidHash
	}
	digRaw, err := bcEncoding.DecodeString(rest[22:])
	if err != nil || len(digRaw) < 23 {
		return nil, errInvalidHash
	}
	h := &Hasher{cost: cost}
	copy(h.csalt[:], saltRaw[:16])
	copy(h.digest[:], digRaw[:23])
	return h, nil
}

// Cost reports the target's cost factor.
func (h *Hasher) Cost() int { return h.cost }

// Run hashes each pw[i] against the target and writes the verdict to out[i].
// pw may be of ANY length - Lanes is the width callers should batch at for
// best throughput, not a hard cap Run enforces. len(out) must be >= len(pw).
// In this task Run is a simple loop over one, so it is naturally
// length-agnostic; interleaving arrives in a later task.
func (h *Hasher) Run(pw [][]byte, out []bool) {
	for i, p := range pw {
		out[i] = h.one(p)
	}
}

func (h *Hasher) one(pw []byte) bool {
	// Bug compatibility with C bcrypt, preserved by x/crypto: the trailing NUL
	// of the key string participates in expansion.
	ckey := make([]byte, len(pw)+1)
	copy(ckey, pw)

	c := newSaltedState(ckey, h.csalt[:])
	if c == nil {
		return false
	}
	for i, rounds := uint64(0), uint64(1)<<uint(h.cost); i < rounds; i++ {
		expandKey(ckey, c)
		expandKey(h.csalt[:], c)
	}

	var buf [24]byte
	copy(buf[:], magicCipherData)
	for i := 0; i < 24; i += 8 {
		l := uint32(buf[i])<<24 | uint32(buf[i+1])<<16 | uint32(buf[i+2])<<8 | uint32(buf[i+3])
		r := uint32(buf[i+4])<<24 | uint32(buf[i+5])<<16 | uint32(buf[i+6])<<8 | uint32(buf[i+7])
		for j := 0; j < 64; j++ {
			l, r = encryptBlock(l, r, c)
		}
		buf[i], buf[i+1], buf[i+2], buf[i+3] = byte(l>>24), byte(l>>16), byte(l>>8), byte(l)
		buf[i+4], buf[i+5], buf[i+6], buf[i+7] = byte(r>>24), byte(r>>16), byte(r>>8), byte(r)
	}
	// Only 23 of the 24 bytes are encoded, matching every C implementation.
	return subtle.ConstantTimeCompare(buf[:23], h.digest[:]) == 1
}
