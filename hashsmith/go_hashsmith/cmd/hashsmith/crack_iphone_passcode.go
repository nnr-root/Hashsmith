package main

// iPhone passcode (UID key + System Keybag) — Hashcat 26500.
//
//	$uido$<uid key>$<salt>$<iterations>$<wrapped class key>
//
// The passcode key derivation on an iOS device is deliberately not a large
// PBKDF2: the work factor lives in the Secure Enclave, not in the hash. So
// PBKDF2-HMAC-SHA1 runs for exactly ONE iteration to produce 32 bytes, and the
// iteration count in the record drives a second loop that encrypts under the
// device's hardware UID key — the part an attacker cannot do off-device unless
// the UID key has already been extracted, which is what this record assumes.
//
// The UID loop keeps a running IV and two accumulators seeded with the PBKDF2
// output. Each round, for each half, it encrypts (half ^ iv ^ round) and XORs
// the result into that half's accumulator; the IV carries across both halves
// and across rounds. The two accumulators concatenated are the AES-256 key
// that unwraps the class key under RFC 3394, and the 0xa6 integrity value
// settles the guess.
//
// Byte order is the one place this format punishes a reasonable assumption.
// Hashcat works in 32-bit words, and its AES helpers come in two spellings
// that differ only in how many times they byte-swap:
//
//	AES128_set_encrypt_key  swaps, then calls the lowercase form which swaps
//	                        again — so the key is in natural byte order
//	aes128_encrypt          swaps input and output exactly once — so the block
//	                        is reversed within each four-byte group
//	aes256_set_decrypt_key  swaps once — so that key is reversed per group
//	AES256_decrypt          swaps twice — so that block is natural again
//
// The result is a genuinely mixed convention: the UID key is natural, the loop
// blocks are group-reversed, the derived AES-256 key is group-reversed, and
// the class-key blocks are natural. Reading the capitalisation as decoration
// rather than as meaning produces a verifier that is wrong in a way no single
// test vector explains.

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha1"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"strconv"
	"strings"

	"golang.org/x/crypto/pbkdf2"
)

const (
	iPhonePasscodeUIDKeyLen   = 16
	iPhonePasscodeSaltLen     = 20
	iPhonePasscodeClassKeyLen = 40
	iPhonePasscodeMaxIter     = 10_000_000
)

// iPhoneWordsIn and iPhoneWordsOut convert between hashcat's u32 words and the
// bytes an AES block sees. Group-reversed order is hashcat's single-swap form.
func iPhoneWordsIn(w []uint32, reversed bool) []byte {
	b := make([]byte, len(w)*4)
	for i, x := range w {
		if reversed {
			binary.LittleEndian.PutUint32(b[i*4:], x)
		} else {
			binary.BigEndian.PutUint32(b[i*4:], x)
		}
	}
	return b
}

func iPhoneWordsOut(b []byte, reversed bool) [4]uint32 {
	var out [4]uint32
	for i := range out {
		if reversed {
			out[i] = binary.LittleEndian.Uint32(b[i*4:])
		} else {
			out[i] = binary.BigEndian.Uint32(b[i*4:])
		}
	}
	return out
}

func iPhoneBlock(f func(dst, src []byte), in [4]uint32, reversed bool) [4]uint32 {
	b := iPhoneWordsIn(in[:], reversed)
	f(b, b)
	return iPhoneWordsOut(b, reversed)
}

// iPhonePasscodeKey runs the PBKDF2 step and the UID-key loop, returning the
// 32-byte AES key that unwraps the class key.
func iPhonePasscodeKey(candidate string, uidKey, salt []byte, iter int) ([]byte, error) {
	uid, err := aes.NewCipher(uidKey)
	if err != nil {
		return nil, err
	}
	// One PBKDF2 iteration; the device's UID loop is the real cost.
	derived := pbkdf2.Key([]byte(candidate), salt, 1, 32, sha1.New)

	var key, acc [8]uint32
	for i := range key {
		// Hashcat byte-swaps the SHA-1 state words before use, which puts the
		// digest back in natural order once the loop's AES swaps them again.
		key[i] = binary.LittleEndian.Uint32(derived[i*4:])
		acc[i] = key[i]
	}

	var iv [4]uint32
	for round := uint32(1); round <= uint32(iter); round++ {
		for _, half := range [2]int{0, 4} {
			var in [4]uint32
			for i := range in {
				in[i] = key[half+i] ^ iv[i] ^ round
			}
			iv = iPhoneBlock(uid.Encrypt, in, true)
			for i := range iv {
				acc[half+i] ^= iv[i]
			}
		}
	}
	return iPhoneWordsIn(acc[:], true), nil
}

// iPhoneUnwrapOK is RFC 3394 key unwrap over four blocks, expressed in the
// same words hashcat uses so the class key needs no reordering.
func iPhoneUnwrapOK(block cipher.Block, wrapped []uint32) bool {
	c := [4]uint32{wrapped[0], wrapped[1], 0, 0}
	// Blocks run back to front: R4, R3, R2, R1.
	lsb := [8]uint32{wrapped[8], wrapped[9], wrapped[6], wrapped[7], wrapped[4], wrapped[5], wrapped[2], wrapped[3]}
	for j := uint32(5); ; j-- {
		for s := uint32(0); s < 4; s++ {
			c[1] ^= 4*j + 4 - s
			c[2], c[3] = lsb[s*2], lsb[s*2+1]
			c = iPhoneBlock(block.Decrypt, c, false)
			lsb[s*2], lsb[s*2+1] = c[2], c[3]
		}
		if j == 0 {
			break
		}
	}
	return c[0] == 0xa6a6a6a6 && c[1] == 0xa6a6a6a6
}

func verifyIPhonePasscode(target, candidate string) (bool, error) {
	t := strings.TrimSpace(target)
	if !strings.HasPrefix(t, "$uido$") {
		return false, errors.New("not an iPhone passcode record")
	}
	p := strings.Split(strings.TrimPrefix(t, "$uido$"), "$")
	if len(p) != 4 {
		return false, errors.New("iPhone passcode record must have 4 fields")
	}
	uidKey, err := hex.DecodeString(p[0])
	if err != nil || len(uidKey) != iPhonePasscodeUIDKeyLen {
		return false, errors.New("iPhone passcode UID key must be 16 hex-encoded bytes")
	}
	salt, err := hex.DecodeString(p[1])
	if err != nil || len(salt) != iPhonePasscodeSaltLen {
		return false, errors.New("iPhone passcode salt must be 20 hex-encoded bytes")
	}
	iter, err := strconv.Atoi(p[2])
	if err != nil || iter < 1 || iter > iPhonePasscodeMaxIter {
		return false, errors.New("iPhone passcode iteration count is out of range")
	}
	classKey, err := hex.DecodeString(p[3])
	if err != nil || len(classKey) != iPhonePasscodeClassKeyLen {
		return false, errors.New("iPhone passcode class key must be 40 hex-encoded bytes")
	}

	key, err := iPhonePasscodeKey(candidate, uidKey, salt, iter)
	if err != nil {
		return false, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return false, err
	}
	wrapped := make([]uint32, len(classKey)/4)
	for i := range wrapped {
		wrapped[i] = binary.BigEndian.Uint32(classKey[i*4:])
	}
	return iPhoneUnwrapOK(block, wrapped), nil
}
