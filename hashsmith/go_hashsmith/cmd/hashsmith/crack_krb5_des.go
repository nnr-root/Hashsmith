package main

// Kerberos 5's DES database keys, etypes 2 and 3.
//
//	$krb3$<realm+principal>$<8-byte key>
//
// This is the string-to-key RFC 3961 inherited from Kerberos 4, and it is the
// clearest illustration in the catalogue of what "56-bit key" means in
// practice. The password and salt are folded down to fifty-six bits by
// XOR-ing eight-byte blocks together — with every other block REVERSED, bit by
// bit as well as byte by byte, so the fold does not simply cancel repeated
// input — and the result is used as a DES key to CBC-MAC the same input. The
// MAC is the key.
//
// Everything after the fold is defence against DES's own quirks: parity bits
// are inserted (they carry no information and DES ignores them), and if the
// result happens to be one of the sixteen weak or semi-weak keys, the last
// byte is flipped. Those sixteen are the keys whose encryption is its own
// inverse or nearly so, and hitting one by accident is about a one in 2^52
// event — the check exists because "about never" is not "never".
//
// A key from this family is worth as much as any other 56-bit DES key, which
// since 1998 has meant: not much. That is why etypes 17 and 18 exist, and why
// finding a 3 in a modern KDC dump says something about the KDC.

import (
	"encoding/hex"
	"errors"
	"strings"
)

const krb5DESPrefix = "$krb3$"

// desWeakKeys are the four weak and twelve semi-weak DES keys, with parity.
var desWeakKeys = [16][8]byte{
	{0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01},
	{0xFE, 0xFE, 0xFE, 0xFE, 0xFE, 0xFE, 0xFE, 0xFE},
	{0xE0, 0xE0, 0xE0, 0xE0, 0xF1, 0xF1, 0xF1, 0xF1},
	{0x1F, 0x1F, 0x1F, 0x1F, 0x0E, 0x0E, 0x0E, 0x0E},
	{0x01, 0x1F, 0x01, 0x1F, 0x01, 0x0E, 0x01, 0x0E},
	{0x1F, 0x01, 0x1F, 0x01, 0x0E, 0x01, 0x0E, 0x01},
	{0x01, 0xE0, 0x01, 0xE0, 0x01, 0xF1, 0x01, 0xF1},
	{0xE0, 0x01, 0xE0, 0x01, 0xF1, 0x01, 0xF1, 0x01},
	{0x01, 0xFE, 0x01, 0xFE, 0x01, 0xFE, 0x01, 0xFE},
	{0xFE, 0x01, 0xFE, 0x01, 0xFE, 0x01, 0xFE, 0x01},
	{0x1F, 0xE0, 0x1F, 0xE0, 0x0E, 0xF1, 0x0E, 0xF1},
	{0xE0, 0x1F, 0xE0, 0x1F, 0xF1, 0x0E, 0xF1, 0x0E},
	{0x1F, 0xFE, 0x1F, 0xFE, 0x0E, 0xFE, 0x0E, 0xFE},
	{0xFE, 0x1F, 0xFE, 0x1F, 0xFE, 0x0E, 0xFE, 0x0E},
	{0xE0, 0xFE, 0xE0, 0xFE, 0xF1, 0xFE, 0xF1, 0xFE},
	{0xFE, 0xE0, 0xFE, 0xE0, 0xFE, 0xF1, 0xFE, 0xF1},
}

// desKeyCorrection sets odd parity and steps away from a weak key.
func desKeyCorrection(key []byte) {
	desSetOddParity(key)
	for _, weak := range desWeakKeys {
		if string(key) == string(weak[:]) {
			key[7] ^= 0xF0
			return
		}
	}
}

// reverseSevenBits reverses the low seven bits of a byte, which is what the
// fold does to every second block.
func reverseSevenBits(b byte) byte {
	return (b>>6)&0x01 |
		(b>>4)&0x02 |
		(b>>2)&0x04 |
		b&0x08 |
		(b<<2)&0x10 |
		(b<<4)&0x20 |
		(b<<6)&0x40
}

// desStringToKey is the Kerberos 4 and 5 DES derivation.
func desStringToKey(password, salt string) ([]byte, error) {
	input := []byte(password + salt)
	if n := len(input) % 8; n != 0 {
		input = append(input, make([]byte, 8-n)...)
	}
	original := append([]byte(nil), input...)

	folded := make([]byte, 8)
	work := append([]byte(nil), input...)
	for i := 0; i*8 < len(work); i++ {
		block := work[i*8 : i*8+8]
		// The high bit of each byte is dropped: DES takes seven bits per byte
		// and the eighth is parity.
		for j := range block {
			block[j] &^= 0x80
		}
		if i%2 == 1 {
			// Every second block is reversed, byte order and bit order both.
			for j := 0; j < 4; j++ {
				a, b := reverseSevenBits(block[j]), reverseSevenBits(block[7-j])
				block[j], block[7-j] = b, a
			}
		}
		for j := 0; j < 8; j++ {
			folded[j] ^= block[j]
		}
	}
	for j := range folded {
		folded[j] <<= 1
	}
	desKeyCorrection(folded)

	// The fold's result is now a DES key, and the key is the CBC-MAC of the
	// same input under it — with the key serving as its own initialisation
	// vector.
	mac, err := desCBCChecksum(original, folded, folded)
	if err != nil {
		return nil, err
	}
	out := append([]byte(nil), mac...)
	desKeyCorrection(out)
	return out, nil
}

func krb5DESFields(target string) (salt string, key []byte, err error) {
	t := strings.TrimSpace(target)
	if !strings.HasPrefix(t, krb5DESPrefix) {
		return "", nil, errors.New("not a Kerberos 5 DES key record")
	}
	salt, digest, ok := strings.Cut(t[len(krb5DESPrefix):], "$")
	if !ok || salt == "" || len(salt) > maxKDFFieldSize || strings.Contains(digest, "$") {
		return "", nil, errors.New("a $krb3$ record is <realm+principal>$<key>")
	}
	if key, err = decodeExactHex(digest, 8, "Kerberos DES key"); err != nil {
		return "", nil, err
	}
	return salt, key, nil
}

func verifyKrb5DES(target, candidate string) (bool, error) {
	salt, want, err := krb5DESFields(target)
	if err != nil {
		return false, err
	}
	got, err := desStringToKey(candidate, salt)
	if err != nil {
		return false, err
	}
	return hex.EncodeToString(got) == hex.EncodeToString(want), nil
}

func isKrb5DES(target string) bool {
	_, _, err := krb5DESFields(target)
	return err == nil
}
