package main

import (
	"crypto/sha512"
	"encoding/binary"
	"errors"

	"golang.org/x/crypto/blowfish"
)

// bcryptPBKDF implements OpenBSD's bcrypt_pbkdf, the KDF used by modern OpenSSH
// private keys (kdfname "bcrypt"). It is a PBKDF2-style construction whose inner
// hash is the "expensive" bcrypt hash, giving the same output as OpenSSH's
// sshkey_private_to_blob2 key derivation. Verified against keys produced by
// ssh-keygen.
func bcryptPBKDF(password, salt []byte, keyLen, rounds int) ([]byte, error) {
	if rounds < 1 {
		return nil, errors.New("bcrypt_pbkdf: rounds must be >= 1")
	}
	if len(password) == 0 || len(salt) == 0 {
		return nil, errors.New("bcrypt_pbkdf: empty password or salt")
	}
	if keyLen <= 0 || keyLen > 1024 {
		return nil, errors.New("bcrypt_pbkdf: invalid key length")
	}

	const blockSize = 32 // each bcryptHash produces 32 bytes
	numBlocks := (keyLen + blockSize - 1) / blockSize
	key := make([]byte, numBlocks*blockSize)

	// The password is pre-hashed once with SHA-512.
	sha2pass := sha512.Sum512(password)

	countSalt := make([]byte, len(salt)+4)
	copy(countSalt, salt)

	out := make([]byte, blockSize)
	for block := 1; block <= numBlocks; block++ {
		// sha2salt = SHA-512(salt || uint32be(block))
		binary.BigEndian.PutUint32(countSalt[len(salt):], uint32(block))
		h := sha512.New()
		h.Write(countSalt)
		sha2salt := h.Sum(nil)

		tmp := bcryptHash(sha2pass[:], sha2salt)
		copy(out, tmp)

		for i := 1; i < rounds; i++ {
			hh := sha512.New()
			hh.Write(tmp)
			sha2salt = hh.Sum(nil)
			tmp = bcryptHash(sha2pass[:], sha2salt)
			for j := range out {
				out[j] ^= tmp[j]
			}
		}

		// Distribute this block's bytes across the key with the OpenBSD stride.
		for i := 0; i < blockSize; i++ {
			dest := i*numBlocks + (block - 1)
			if dest < len(key) {
				key[dest] = out[i]
			}
		}
	}
	return key[:keyLen], nil
}

// bcryptHash is OpenBSD's bcrypt_hash: a 64-round Blowfish key schedule over the
// SHA-512-hashed password and salt, followed by 64 encryptions of a fixed magic
// constant. Output is 32 bytes.
func bcryptHash(sha2pass, sha2salt []byte) []byte {
	c, err := blowfish.NewSaltedCipher(sha2pass, sha2salt)
	if err != nil {
		panic(err) // inputs are fixed-length SHA-512 digests; this cannot fail
	}
	for i := 0; i < 64; i++ {
		blowfish.ExpandKey(sha2salt, c)
		blowfish.ExpandKey(sha2pass, c)
	}

	// "OxychromaticBlowfishSwatDynamite" as eight big-endian uint32 words.
	cdata := []uint32{
		0x4f787963, 0x68726f6d, 0x61746963, 0x426c6f77,
		0x66697368, 0x53776174, 0x44796e61, 0x6d697465,
	}
	blk := make([]byte, 8)
	for i := 0; i < 64; i++ {
		for j := 0; j < len(cdata); j += 2 {
			binary.BigEndian.PutUint32(blk[0:4], cdata[j])
			binary.BigEndian.PutUint32(blk[4:8], cdata[j+1])
			c.Encrypt(blk, blk)
			cdata[j] = binary.BigEndian.Uint32(blk[0:4])
			cdata[j+1] = binary.BigEndian.Uint32(blk[4:8])
		}
	}

	// Output words are stored little-endian (OpenBSD convention).
	out := make([]byte, 32)
	for i, v := range cdata {
		binary.LittleEndian.PutUint32(out[4*i:], v)
	}
	return out
}
