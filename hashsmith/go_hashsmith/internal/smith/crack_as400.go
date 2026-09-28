package smith

// AS/400 DES (IBM i user profile) — Hashcat 8501.
//
//	$as400$des$*<profile name>*<16 hex digits>
//
// IBM i hashes a user profile by encrypting the profile NAME under a DES key
// built from the password. Both go through EBCDIC first, which is the detail
// that makes the format unportable-looking: the same password produces a
// different hash on a machine that thinks in ASCII.
//
// Hashcat runs this on its RACF kernel (mode 8500) because the two formats
// share a core: password -> EBCDIC -> DES key, profile name -> EBCDIC -> DES
// block, sixteen rounds, no IP and no FP. The permutations are not skipped so
// much as moved — hashcat applies DES_IP to the block and to the expected
// digest on the host, then rotates both left by three, so the kernel can go
// straight into the rounds. This file does the same, because doing it any
// other way means a verifier that agrees with nothing.
//
// Profile names may be ten characters, but a DES block is eight. IBM's answer
// is to fold the two extra characters' high bit-pairs into the first eight
// bytes rather than truncate, so ABCDEFGHIJ and ABCDEFGH do not collide.
//
// That folding is implemented here but is NOT verified against hashcat, and
// cannot be: hashcat's tokenizer caps this field at eight characters and
// rejects a longer record with a token-length exception before its own
// folding code can run. So the branch below is dead code inside hashcat and
// reachable only from a record taken off a real system. It is transcribed
// from that unreachable code and agrees with IBM's documented rule, which is
// two derivations agreeing rather than a measurement — treat a nine- or
// ten-character profile name as the one part of this format still owed a
// real test vector.

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"strings"
)

const (
	as400Prefix       = "$as400$des$*"
	as400MaxProfile   = 10
	as400DigestHexLen = 16
)

// as400Block turns a profile name into the eight-byte DES block.
func as400Block(profile string) ([8]byte, error) {
	if len(profile) == 0 || len(profile) > as400MaxProfile {
		return [8]byte{}, errors.New("AS/400 profile name must be 1 to 10 characters")
	}
	// EBCDIC, blank-padded to the block size.
	var b [8]byte
	for i := range b {
		b[i] = as400ASCIIToEBCDIC[' ']
	}
	n := len(profile)
	if n > 8 {
		n = 8
	}
	for i := 0; i < n; i++ {
		b[i] = as400ASCIIToEBCDIC[profile[i]]
	}
	if len(profile) > 8 {
		// Characters nine and ten do not fit, so each contributes its four
		// high bit-pairs to the first eight bytes instead of being dropped.
		extra := [2]byte{as400ASCIIToEBCDIC[' '], as400ASCIIToEBCDIC[' ']}
		for i := 8; i < len(profile); i++ {
			extra[i-8] = as400ASCIIToEBCDIC[profile[i]]
		}
		for half := 0; half < 2; half++ {
			for i := 0; i < 4; i++ {
				b[half*4+i] ^= (extra[half] << (2 * i)) & 0xc0
			}
		}
	}
	return b, nil
}

// as400HostPermute is the DES initial permutation plus the three-bit rotate
// hashcat applies on the host to both the block and the expected digest.
func as400HostPermute(l, r uint32) (uint32, uint32) {
	r, l = desPermOp(r, l, 4, 0x0f0f0f0f)
	l, r = desPermOp(l, r, 16, 0x0000ffff)
	r, l = desPermOp(r, l, 2, 0x33333333)
	l, r = desPermOp(l, r, 8, 0x00ff00ff)
	r, l = desPermOp(r, l, 1, 0x55555555)
	return rotl32(l, 3), rotl32(r, 3)
}

func verifyAS400DES(target, candidate string) (bool, error) {
	t := strings.TrimSpace(target)
	// John spells the envelope "$as400des$" and keeps the same
	// "<profile>*<digest>" body; hashcat writes "$as400$des$*".
	const johnPrefix = "$as400des$"
	var rest string
	switch {
	case strings.HasPrefix(t, as400Prefix):
		rest = strings.TrimPrefix(t, as400Prefix)
	case strings.HasPrefix(t, johnPrefix):
		rest = strings.TrimPrefix(t, johnPrefix)
	default:
		return false, errors.New("not an AS/400 DES record")
	}
	i := strings.LastIndex(rest, "*")
	if i < 0 {
		return false, errors.New("AS/400 record must be $as400$des$*<profile>*<digest>")
	}
	profile, digestHex := rest[:i], rest[i+1:]
	if len(digestHex) != as400DigestHexLen {
		return false, errors.New("AS/400 digest must be 16 hex digits")
	}
	raw, err := hex.DecodeString(digestHex)
	if err != nil {
		return false, errors.New("AS/400 digest must be hex")
	}
	block, err := as400Block(profile)
	if err != nil {
		return false, err
	}

	bl, br := as400HostPermute(
		binary.LittleEndian.Uint32(block[0:4]),
		binary.LittleEndian.Uint32(block[4:8]),
	)
	want0, want1 := as400HostPermute(
		binary.LittleEndian.Uint32(raw[0:4]),
		binary.LittleEndian.Uint32(raw[4:8]),
	)
	got := racfDigestWords(bl, br, candidate)
	return got[0] == want0 && got[1] == want1, nil
}
