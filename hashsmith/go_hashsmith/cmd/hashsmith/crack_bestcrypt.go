package main

// BestCrypt v3 Volume Encryption — Hashcat 23900.
//
//	$bcve$3$<salt length>$<salt>$<96 bytes of volume header>
//
// Jetico's key derivation is a home-grown stretch rather than PBKDF2. It
// builds a 128-byte buffer by repeating (salt || password), then hashes 64 KiB
// of material drawn from that buffer with SHA-256 — 1024 blocks, each a
// 64-byte window into the buffer at a rolling byte offset. The offsets step by
// 64 modulo the length of (salt || password), so the windows are unaligned
// copies of the same short secret, which is what gives the construction its
// cost without any memory hardness.
//
// The result is an AES-256 key. Decrypting the first 80 bytes of the header in
// CBC mode with a zero IV yields 64 bytes of key material followed by 16 bytes
// that must equal the first half of SHA-256 of those 64 bytes. That is a real
// authenticator, so a candidate is right or it is not — no heuristics here.
//
// A note on cost: 64 KiB of SHA-256 per candidate is roughly a thousand times
// a bare hash, so this format is slow by construction even though nothing in
// it is memory-hard.

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strconv"
	"strings"
)

const (
	bestCryptPrefix      = "$bcve$3$"
	bestCryptMaxPassword = 56
	bestCryptBufferLen   = 128
	bestCryptWindow      = 64
	bestCryptBlocks      = 1024
	bestCryptHeaderUsed  = 80
	bestCryptCheckLen    = 16
)

// bestCryptKey runs the 64 KiB SHA-256 stretch.
func bestCryptKey(candidate string, salt []byte) [sha256.Size]byte {
	pw := candidate
	if len(pw) > bestCryptMaxPassword {
		pw = pw[:bestCryptMaxPassword]
	}
	base := append(append(make([]byte, 0, len(salt)+len(pw)), salt...), pw...)
	step := len(base)

	// Four bytes of slack past 128 so the last window never runs off the end.
	buf := make([]byte, bestCryptBufferLen+4)
	for i := 0; i < bestCryptBufferLen; i += step {
		copy(buf[i:bestCryptBufferLen], base)
	}

	h := sha256.New()
	for b := 0; b < bestCryptBlocks; b++ {
		off := (bestCryptWindow * b) % step
		_, _ = h.Write(buf[off : off+bestCryptWindow])
	}
	var out [sha256.Size]byte
	copy(out[:], h.Sum(nil))
	return out
}

func verifyBestCryptV3(target, candidate string) (bool, error) {
	t := strings.TrimSpace(target)
	if !strings.HasPrefix(t, bestCryptPrefix) {
		return false, errors.New("not a BestCrypt v3 record")
	}
	f := strings.Split(strings.TrimPrefix(t, bestCryptPrefix), "$")
	if len(f) != 3 {
		return false, errors.New("BestCrypt v3 record must be $bcve$3$<length>$<salt>$<data>")
	}
	saltLen, err := strconv.Atoi(f[0])
	if err != nil || saltLen <= 0 {
		return false, errors.New("BestCrypt salt length must be a positive number")
	}
	salt, err := hex.DecodeString(f[1])
	if err != nil || len(salt) != saltLen {
		return false, errors.New("BestCrypt salt must be hex and match the stated length")
	}
	// The repeated unit has to fit the 128-byte buffer with a password on it.
	if saltLen+bestCryptMaxPassword > bestCryptBufferLen {
		return false, errors.New("BestCrypt salt is too long for the key-derivation buffer")
	}
	data, err := hex.DecodeString(f[2])
	if err != nil || len(data) < bestCryptHeaderUsed {
		return false, errors.New("BestCrypt volume header must be at least 80 hex-encoded bytes")
	}

	key := bestCryptKey(candidate, salt)
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return false, err
	}
	plain := make([]byte, bestCryptHeaderUsed)
	// Zero IV: BestCrypt chains from nothing.
	cipher.NewCBCDecrypter(block, make([]byte, aes.BlockSize)).CryptBlocks(plain, data[:bestCryptHeaderUsed])

	sum := sha256.Sum256(plain[:bestCryptWindow])
	return string(sum[:bestCryptCheckLen]) == string(plain[bestCryptWindow:bestCryptHeaderUsed]), nil
}
