package smith

// Sybase's PROP password hash — the one used by Replication Server, and a
// different thing entirely from the ASE hash crack_sybase.go reads.
//
//	0x<seed byte><05><28 bytes>
//
// It is built out of FEAL-8 and a linear congruential generator, and neither
// is doing what it looks like. The generator is seeded from the record's own
// first byte and its output is used as SALT BYTES — one per eight-byte block —
// so the "salt" is a deterministic function of a value stored in the clear.
// Sixteen bits of state and a published recurrence means the whole sequence
// follows from that byte.
//
// The construction is two passes. The first builds a sixty-four-byte key
// schedule: the password, padded to sixty-four bytes with 0x1D, is folded
// block by block through FEAL-8 with each block's key derived from the
// previous block's output and one generator byte. The second encrypts a fixed
// sentence under that schedule, chaining the blocks, and the last
// twenty-eight bytes of the result are the hash.
//
// The fixed sentence is a joke — literally; it is a joke about a fly — and it
// is the plaintext every Sybase PROP hash in the world is built from.

import (
	"crypto/hmac"
	"encoding/hex"
	"errors"
	"strings"
)

const (
	sybasePROPPrefix   = "0x"
	sybasePROPPwdLen   = 64
	sybasePROPSchedLen = 64
	sybasePROPHashLen  = 28
)

// sybasePROPJoke is the plaintext the second pass encrypts, exactly
// sixty-four characters of it.
const sybasePROPJoke = "Q:Whydidtheflydanceonthejar?A:Becausethelidsaidtwisttoopen.HaHa!"

// sybaseRand is the linear congruential generator Sybase seeds from the
// record's first byte. It is Microsoft's rand(), constants and all.
type sybaseRand uint32

func (s *sybaseRand) next() int {
	*s = sybaseRand(uint32(*s)*0x343FD + 0x269EC3)
	return int((uint32(*s) >> 0x10) & 0x7FFF)
}

// saltByte is what the generator is actually used for: a byte per block.
func (s *sybaseRand) saltByte() byte {
	return byte((s.next() >> 8) % 0xFF)
}

// sybaseApplySalt mixes one generator byte into an eight-byte block. Only the
// first two bytes take the salt directly; the rest chain off the second, which
// means a change in byte three or later of the password cannot affect byte
// zero of the key.
func sybaseApplySalt(salt byte, in []byte) []byte {
	out := make([]byte, 8)
	out[0] = salt ^ in[0]
	out[1] = out[0] ^ in[1]
	for i := 2; i < 8; i++ {
		out[i] = out[1] ^ in[i]
	}
	return out
}

func sybaseXOR8(a, b []byte) []byte {
	out := make([]byte, 8)
	for i := range out {
		out[i] = a[i] ^ b[i]
	}
	return out
}

// sybasePROPHash reproduces generate_hash.
func sybasePROPHash(password string, seed byte) []byte {
	// The password is padded to sixty-four bytes with 0x1D — an ASCII group
	// separator, chosen for no reason the format records.
	expanded := make([]byte, sybasePROPPwdLen)
	n := copy(expanded, password)
	for i := n; i < sybasePROPPwdLen; i++ {
		expanded[i] = 0x1D
	}

	rng := sybaseRand(seed)
	joke := []byte(sybasePROPJoke)
	sched := make([]byte, sybasePROPSchedLen)

	// Block zero: the padded password under a salted key, encrypting the
	// sentence from an offset the seed chooses.
	start := int(seed) % 0x30
	key := sybaseApplySalt(rng.saltByte(), expanded)
	newFEAL8(key).encrypt(sched[0:8], joke[start:start+8])

	// Block one: the previous output XORed with the password shifted one
	// byte, which is the only place the shift appears.
	xored := sybaseXOR8(sched[0:8], expanded[1:9])
	key = sybaseApplySalt(rng.saltByte(), xored)
	newFEAL8(key).encrypt(sched[8:16], joke[start+1:start+9])

	// Blocks two to seven are not encrypted at all — they are the salted XOR
	// itself, which is why the schedule is cheap to build and why the second
	// pass has to do the work.
	for b := 2; b < 8; b++ {
		xored = sybaseXOR8(sched[8*(b-1):8*b], expanded[b*8-7:b*8+1])
		copy(sched[8*b:8*b+8], sybaseApplySalt(rng.saltByte(), xored))
	}

	// Second pass: encrypt the sentence under each eight bytes of the
	// schedule, chaining.
	result := make([]byte, sybasePROPSchedLen)
	newFEAL8(sched[0:8]).encrypt(result[0:8], joke[0:8])
	for i := 1; i < 8; i++ {
		x := sybaseXOR8(joke[8*i:8*i+8], result[8*(i-1):8*i])
		newFEAL8(sched[8*i:8*i+8]).encrypt(result[8*i:8*i+8], x)
	}
	return result[sybasePROPSchedLen-sybasePROPHashLen:]
}

func sybasePROPFields(target string) (seed byte, digest []byte, err error) {
	t := strings.TrimSpace(target)
	if len(t) != 2+60 || !strings.HasPrefix(t, sybasePROPPrefix) || !isHex(t[2:]) {
		return 0, nil, errors.New("a Sybase PROP record is 0x and sixty hex characters")
	}
	b, err := hex.DecodeString(t[2:4])
	if err != nil {
		return 0, nil, errors.New("invalid Sybase PROP seed")
	}
	if digest, err = hex.DecodeString(t[6:]); err != nil || len(digest) != sybasePROPHashLen {
		return 0, nil, errors.New("invalid Sybase PROP digest")
	}
	return b[0], digest, nil
}

func verifySybasePROP(target, candidate string) (bool, error) {
	seed, want, err := sybasePROPFields(target)
	if err != nil {
		return false, err
	}
	if len(candidate) > sybasePROPPwdLen {
		return false, nil
	}
	return hmac.Equal(sybasePROPHash(candidate, seed), want), nil
}

func isSybasePROP(target string) bool {
	_, _, err := sybasePROPFields(target)
	return err == nil
}
