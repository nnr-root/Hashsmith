package smith

// Lotus Notes / Domino — the proprietary hash behind Hashcat 8600, and the two
// formats built on it, Hashcat 8700 and 9100.
//
// Domino does not use a standard digest. It runs a 256-byte substitution table
// through a Merkle-Damgard-shaped construction of its own, over a single
// 16-byte block, which is why passwords longer than sixteen characters simply
// do not exist as far as this format is concerned — the block IS the password,
// padded with the byte 16-len repeated, the same padding rule PKCS#7 uses.
//
// The table below is IBM's, transcribed from Hashcat's kernel, where it is
// stored twice so the mixing loop can index past 255 without wrapping. Once is
// enough here: the mix masks its index to a byte anyway.

import (
	"crypto/sha1"
	"crypto/subtle"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"strconv"
	"strings"

	"golang.org/x/crypto/pbkdf2"
)

// lotusMagicTable is Domino's substitution box.
var lotusMagicTable = [256]byte{
	0xbd, 0x56, 0xea, 0xf2, 0xa2, 0xf1, 0xac, 0x2a, 0xb0, 0x93, 0xd1, 0x9c,
	0x1b, 0x33, 0xfd, 0xd0, 0x30, 0x04, 0xb6, 0xdc, 0x7d, 0xdf, 0x32, 0x4b,
	0xf7, 0xcb, 0x45, 0x9b, 0x31, 0xbb, 0x21, 0x5a, 0x41, 0x9f, 0xe1, 0xd9,
	0x4a, 0x4d, 0x9e, 0xda, 0xa0, 0x68, 0x2c, 0xc3, 0x27, 0x5f, 0x80, 0x36,
	0x3e, 0xee, 0xfb, 0x95, 0x1a, 0xfe, 0xce, 0xa8, 0x34, 0xa9, 0x13, 0xf0,
	0xa6, 0x3f, 0xd8, 0x0c, 0x78, 0x24, 0xaf, 0x23, 0x52, 0xc1, 0x67, 0x17,
	0xf5, 0x66, 0x90, 0xe7, 0xe8, 0x07, 0xb8, 0x60, 0x48, 0xe6, 0x1e, 0x53,
	0xf3, 0x92, 0xa4, 0x72, 0x8c, 0x08, 0x15, 0x6e, 0x86, 0x00, 0x84, 0xfa,
	0xf4, 0x7f, 0x8a, 0x42, 0x19, 0xf6, 0xdb, 0xcd, 0x14, 0x8d, 0x50, 0x12,
	0xba, 0x3c, 0x06, 0x4e, 0xec, 0xb3, 0x35, 0x11, 0xa1, 0x88, 0x8e, 0x2b,
	0x94, 0x99, 0xb7, 0x71, 0x74, 0xd3, 0xe4, 0xbf, 0x3a, 0xde, 0x96, 0x0e,
	0xbc, 0x0a, 0xed, 0x77, 0xfc, 0x37, 0x6b, 0x03, 0x79, 0x89, 0x62, 0xc6,
	0xd7, 0xc0, 0xd2, 0x7c, 0x6a, 0x8b, 0x22, 0xa3, 0x5b, 0x05, 0x5d, 0x02,
	0x75, 0xd5, 0x61, 0xe3, 0x18, 0x8f, 0x55, 0x51, 0xad, 0x1f, 0x0b, 0x5e,
	0x85, 0xe5, 0xc2, 0x57, 0x63, 0xca, 0x3d, 0x6c, 0xb4, 0xc5, 0xcc, 0x70,
	0xb2, 0x91, 0x59, 0x0d, 0x47, 0x20, 0xc8, 0x4f, 0x58, 0xe0, 0x01, 0xe2,
	0x16, 0x38, 0xc4, 0x6f, 0x3b, 0x0f, 0x65, 0x46, 0xbe, 0x7e, 0x2d, 0x7b,
	0x82, 0xf9, 0x40, 0xb5, 0x1d, 0x73, 0xf8, 0xeb, 0x26, 0xc7, 0x87, 0x97,
	0x25, 0x54, 0xb1, 0x28, 0xaa, 0x98, 0x9d, 0xa5, 0x64, 0x6d, 0x7a, 0xd4,
	0x10, 0x81, 0x44, 0xef, 0x49, 0xd6, 0xae, 0x2e, 0xdd, 0x76, 0x5c, 0x2f,
	0xa7, 0x1c, 0xc9, 0x09, 0x69, 0x9a, 0x83, 0xcf, 0x29, 0x39, 0xb9, 0xe9,
	0x4c, 0xff, 0x43, 0xab,
}

// lotusMix is Domino's core permutation: eighteen passes over a 48-byte state,
// each byte replaced by a table lookup chained through a running index.
func lotusMix(in *[12]uint32) {
	var p uint32
	for i := 0; i < 18; i++ {
		s := uint32(48)
		for j := 0; j < 12; j++ {
			tmpIn := in[j]
			var tmpOut uint32
			for shift := uint(0); shift < 32; shift += 8 {
				p = (p + s) & 0xff
				s--
				p = ((tmpIn >> shift) & 0xff) ^ uint32(lotusMagicTable[p])
				tmpOut |= p << shift
			}
			in[j] = tmpOut
		}
	}
}

// lotusTransformPassword folds a block into the running checksum.
func lotusTransformPassword(in, out *[4]uint32) {
	t := out[3] >> 24
	for i := 0; i < 4; i++ {
		for shift := uint(0); shift < 32; shift += 8 {
			t ^= (in[i] >> shift) & 0xff
			out[i] ^= uint32(lotusMagicTable[t]) << shift
			t = (out[i] >> shift) & 0xff
		}
	}
}

// lotusMDTransformNoRecalc absorbs one block into the state.
func lotusMDTransformNoRecalc(state, block *[4]uint32) {
	var x [12]uint32
	for i := 0; i < 4; i++ {
		x[i] = state[i]
		x[4+i] = block[i]
		x[8+i] = state[i] ^ block[i]
	}
	lotusMix(&x)
	for i := 0; i < 4; i++ {
		state[i] = x[i]
	}
}

// dominoBigMD is Domino's digest over an arbitrary message.
//
// The message is padded to a whole number of 16-byte blocks with the byte
// giving how many were added. Unlike PKCS#7 there is NO padding at all when
// the message already fills its blocks: Hashcat's loop runs while
// `curpos + 16 < size`, strictly, so a 16-byte message is one block and the
// padding block it prepares is never hashed. Adding one anyway is invisible
// on Hashcat's own 7-character example and wrong for every password whose
// length is a multiple of sixteen.
//
// Each block is absorbed into the state and folded into a running checksum,
// and the checksum is absorbed last.
func dominoBigMD(msg []byte) []byte {
	pad := (16 - len(msg)%16) % 16
	if len(msg) == 0 {
		pad = 16
	}
	full := make([]byte, len(msg)+pad)
	copy(full, msg)
	for i := len(msg); i < len(full); i++ {
		full[i] = byte(pad)
	}
	var state, checksum [4]uint32
	for off := 0; off < len(full); off += 16 {
		var block [4]uint32
		for i := 0; i < 4; i++ {
			block[i] = binary.LittleEndian.Uint32(full[off+i*4:])
		}
		lotusMDTransformNoRecalc(&state, &block)
		lotusTransformPassword(&block, &checksum)
	}
	lotusMDTransformNoRecalc(&state, &checksum)

	out := make([]byte, 16)
	for i := 0; i < 4; i++ {
		binary.LittleEndian.PutUint32(out[i*4:], state[i])
	}
	return out
}

// dominoHash is the Domino 5 digest of a password. Domino 5 truncates at
// sixteen characters because the password IS the single block it hashes.
func dominoHash(candidate string) []byte {
	pw := []byte(candidate)
	if len(pw) > 16 {
		pw = pw[:16]
	}
	var padded [16]byte
	copy(padded[:], pw)
	fill := byte(16 - len(pw))
	for i := len(pw); i < 16; i++ {
		padded[i] = fill
	}
	var block, state, checksum [4]uint32
	for i := 0; i < 4; i++ {
		block[i] = binary.LittleEndian.Uint32(padded[i*4:])
	}
	lotusMDTransformNoRecalc(&state, &block)
	lotusTransformPassword(&block, &checksum)
	lotusMDTransformNoRecalc(&state, &checksum)

	out := make([]byte, 16)
	for i := 0; i < 4; i++ {
		binary.LittleEndian.PutUint32(out[i*4:], state[i])
	}
	return out
}

func verifyDomino5(target, candidate string) (bool, error) {
	want := strings.TrimSpace(target)
	if len(want) != 32 || !isHex(want) {
		return false, errors.New("Lotus Domino 5 hash must be 32 hex characters")
	}
	return strings.EqualFold(hex.EncodeToString(dominoHash(candidate)), want), nil
}

// Domino 6 — Hashcat 8700.
//
//	(G<lotus base64>)
//
// The record's body decodes to five bytes of salt and a nine-byte digest. Two
// details in there are pure archaeology and neither is guessable:
//
//   - the salt's FOURTH byte is stored four higher than its real value and
//     has to be decremented on the way in
//   - the message hashed in the second pass is the salt, then a literal '('
//     character, then the Domino 5 digest of the password in UPPERCASE hex
//     TRUNCATED to 28 of its 32 characters
//
// That is 5 + 1 + 28 = 34 bytes. The stray '(' is the opening parenthesis of
// the record itself, which Domino apparently never stopped including.

// lotusBase64Alphabet is Domino's own ordering: digits first, then upper case,
// then lower, then + and /. It is not RFC 4648's and the two do not agree on a
// single character's value.
const lotusBase64Alphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz+/"

const (
	domino6SaltLen   = 5
	domino6DigestLen = 9
	// The second pass keeps only 28 of the 32 hex characters.
	domino6HexLen = 28
)

func lotusBase64Decode(s string) ([]byte, error) {
	out := make([]byte, 0, len(s)*6/8)
	var buf, bits int
	for i := 0; i < len(s); i++ {
		v := strings.IndexByte(lotusBase64Alphabet, s[i])
		if v < 0 {
			return nil, errors.New("invalid character in Lotus base64")
		}
		buf = buf<<6 | v
		bits += 6
		if bits >= 8 {
			bits -= 8
			out = append(out, byte(buf>>bits))
		}
	}
	return out, nil
}

func verifyDomino6(target, candidate string) (bool, error) {
	t := strings.TrimSpace(target)
	if !strings.HasPrefix(t, "(G") || !strings.HasSuffix(t, ")") {
		return false, errors.New("not a Lotus Domino 6 record")
	}
	raw, err := lotusBase64Decode(strings.TrimSuffix(strings.TrimPrefix(t, "(G"), ")"))
	if err != nil {
		return false, err
	}
	if len(raw) < domino6SaltLen+domino6DigestLen {
		return false, errors.New("Lotus Domino 6 record is too short")
	}
	salt := append([]byte(nil), raw[:domino6SaltLen]...)
	salt[3] -= 4
	want := raw[domino6SaltLen : domino6SaltLen+domino6DigestLen]

	inner := strings.ToUpper(hex.EncodeToString(dominoBigMD([]byte(candidate))))
	msg := make([]byte, 0, domino6SaltLen+1+domino6HexLen)
	msg = append(msg, salt...)
	msg = append(msg, '(')
	msg = append(msg, inner[:domino6HexLen]...)

	return subtle.ConstantTimeCompare(dominoBigMD(msg)[:domino6DigestLen], want) == 1, nil
}

// looksLikeDomino6 reports whether a line is a Domino 6 record: parenthesised,
// tagged with G, and a body that decodes to at least a salt and a digest.
func looksLikeDomino6(s string) bool {
	_, err := verifyDomino6(s, "")
	return err == nil
}

// lotusBase64Encode is the inverse of lotusBase64Decode: three bytes to four
// characters, most significant first, in Domino's alphabet.
func lotusBase64Encode(in []byte) string {
	var sb strings.Builder
	for i := 0; i < len(in); i += 3 {
		var n uint32
		bits := 0
		for j := 0; j < 3 && i+j < len(in); j++ {
			n |= uint32(in[i+j]) << uint(16-8*j)
			bits += 8
		}
		for k := 0; k < (bits+5)/6; k++ {
			sb.WriteByte(lotusBase64Alphabet[(n>>uint(18-6*k))&0x3f])
		}
	}
	return sb.String()
}

// Domino 8 — Hashcat 9100.
//
//	(H<lotus base64>)
//
// Domino 8 runs Domino 6 and then puts the whole thing through PBKDF2-HMAC-
// SHA1 — but what it hands PBKDF2 as the PASSWORD is not a digest. It is the
// Domino 6 RECORD, rebuilt as text: the literal characters "(G", the salt and
// digest re-encoded in Lotus base64, and a closing ")". Twenty-two characters
// of ASCII, parentheses and all.
//
// The 36-byte body holds a 16-byte salt, the iteration count as TEN ASCII
// DIGITS rather than a number, two bytes that go unused here, and the 8-byte
// PBKDF2 output. The salt's fourth byte carries the same off-by-four as
// Domino 6 — stored high, decremented on the way in, and put back before the
// rebuild, which is why both forms appear below.
//
// One detail is worth the line it costs. The rebuilt record is nineteen
// base64 characters, which is fourteen bytes and two bits. Those last two bits
// are NOT padding: they come from the tenth byte of the Domino 6 digest, which
// the record does not otherwise carry. Encoding fourteen bytes and stopping
// gets every character but the last one right, and the last one wrong, and a
// wrong PBKDF2 password looks exactly like a wrong guess.

const (
	domino8SaltLen   = 16
	domino8IterLen   = 10
	domino8DigestLen = 8
	domino8BodyLen   = 36
	// Fifteen bytes in, twenty characters out, nineteen kept.
	domino8RebuildBytes = 15
	domino8RebuildChars = 19
)

func verifyDomino8(target, candidate string) (bool, error) {
	t := strings.TrimSpace(target)
	if !strings.HasPrefix(t, "(H") || !strings.HasSuffix(t, ")") {
		return false, errors.New("not a Lotus Domino 8 record")
	}
	raw, err := lotusBase64Decode(strings.TrimSuffix(strings.TrimPrefix(t, "(H"), ")"))
	if err != nil {
		return false, err
	}
	if len(raw) < domino8BodyLen {
		return false, errors.New("Lotus Domino 8 record is too short")
	}
	stored := append([]byte(nil), raw[:domino8SaltLen]...)
	stored[3] -= 4
	iterations, err := strconv.Atoi(strings.TrimSpace(string(raw[domino8SaltLen : domino8SaltLen+domino8IterLen])))
	if err != nil || iterations < 1 {
		return false, errors.New("Lotus Domino 8 iteration count is not a positive decimal")
	}
	want := raw[domino8BodyLen-domino8DigestLen : domino8BodyLen]

	// The Domino 6 stage, over the decremented salt exactly as 8700 does it.
	inner := strings.ToUpper(hex.EncodeToString(dominoBigMD([]byte(candidate))))
	msg := make([]byte, 0, domino6SaltLen+1+domino6HexLen)
	msg = append(msg, stored[:domino6SaltLen]...)
	msg = append(msg, '(')
	msg = append(msg, inner[:domino6HexLen]...)
	digest := dominoBigMD(msg)

	// Rebuild the Domino 6 record text. The salt byte goes back up by four,
	// and ten digest bytes are encoded so the nineteenth character is right.
	plain := make([]byte, 0, domino8RebuildBytes)
	plain = append(plain, raw[:domino6SaltLen]...)
	plain = append(plain, digest[:domino8RebuildBytes-domino6SaltLen]...)
	rebuilt := "(G" + lotusBase64Encode(plain)[:domino8RebuildChars] + ")"

	out := pbkdf2.Key([]byte(rebuilt), stored, iterations, domino8DigestLen, sha1.New)
	return subtle.ConstantTimeCompare(out, want) == 1, nil
}

// looksLikeDomino8 reports whether a line is a Domino 8 record.
func looksLikeDomino8(s string) bool {
	_, err := verifyDomino8(s, "")
	return err == nil
}
