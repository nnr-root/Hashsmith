package main

// PKWARE SecureZIP with AES — Hashcat 23001, 23002 and 23003.
//
//	$zip3$*<v>*<n>*<bits>*<x>*<salt>*<data>*<a>*<b>*<c>*<filename>
//
// The key derivation is HMAC's shape with HMAC removed. SHA-1 the password to
// twenty bytes, pad that out to a 64-byte block, and hash the block twice —
// once XORed with 0x36 and once with 0x5c. Concatenating the two digests gives
// forty bytes, and the cipher takes however many it needs from the front: 16
// for AES-128, 24 for AES-192, 32 for AES-256. There is no salt in the
// derivation and no iteration count, so the whole thing is two SHA-1 blocks
// per guess.
//
// A guess is settled on the last 32 bytes of the record's data blob: an IV
// followed by one ciphertext block, which under the right key decrypts to
// sixteen bytes of 0x10 — PKCS#7 padding for a message that ended exactly on a
// block boundary. Sixteen fixed bytes is a 2^-128 check.

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha1"
	"encoding/hex"
	"errors"
	"strconv"
	"strings"
)

// secureZIPTail is the IV plus one ciphertext block at the end of the blob.
const secureZIPTail = 32

// secureZIPPadBlock is the expected plaintext: a full block of PKCS#7 padding.
var secureZIPPadBlock = bytes.Repeat([]byte{0x10}, aes.BlockSize)

// secureZIPKey derives keyLen bytes the way SecureZIP does.
func secureZIPKey(candidate string, keyLen int) []byte {
	inner := sha1.Sum([]byte(candidate))
	pass := func(pad byte) []byte {
		var block [64]byte
		for i := range block {
			block[i] = pad
		}
		for i, b := range inner {
			block[i] = b ^ pad
		}
		d := sha1.Sum(block[:])
		return d[:]
	}
	return append(pass(0x36), pass(0x5c)...)[:keyLen]
}

func verifySecureZIP(target, candidate string) (bool, error) {
	t := strings.TrimSpace(target)
	if !strings.HasPrefix(t, "$zip3$*") {
		return false, errors.New("not a SecureZIP record")
	}
	p := strings.Split(t, "*")
	if len(p) < 7 {
		return false, errors.New("SecureZIP record is missing fields")
	}
	bits, err := strconv.Atoi(p[3])
	if err != nil {
		return false, errors.New("SecureZIP key size is not a number")
	}
	switch bits {
	case 128, 192, 256:
	default:
		return false, errors.New("SecureZIP key size must be 128, 192 or 256")
	}
	data, err := hex.DecodeString(p[6])
	if err != nil {
		return false, errors.New("SecureZIP data blob is not hex")
	}
	if len(data) < secureZIPTail {
		return false, errors.New("SecureZIP data blob is too short to carry an IV and a block")
	}

	block, err := aes.NewCipher(secureZIPKey(candidate, bits/8))
	if err != nil {
		return false, err
	}
	tail := data[len(data)-secureZIPTail:]
	plain := make([]byte, aes.BlockSize)
	cipher.NewCBCDecrypter(block, tail[:aes.BlockSize]).CryptBlocks(plain, tail[aes.BlockSize:])
	return bytes.Equal(plain, secureZIPPadBlock), nil
}
