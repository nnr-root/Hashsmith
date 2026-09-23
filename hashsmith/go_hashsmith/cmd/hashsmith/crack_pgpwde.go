package main

// PGP Whole Disk Encryption.
//
//	$pgpwde$<version>*<cipher>*<s2k type>*<log2 bytes>*<16-byte salt>*<128-byte ESK>
//
// Unlike the SDA and Disk records, this one does not store a verifier at all.
// It stores the encrypted session key, and a password is right when what comes
// out of it is correctly OAEP-padded. That is a much stronger check than a
// verifier — the padding has a twenty-byte hash of the empty label inside it,
// so a wrong password has to reproduce those twenty bytes by accident — and it
// costs nothing extra, because the key had to be decrypted anyway.
//
// The derivation is OpenPGP's iterated-and-salted S2K done properly this time:
// a stream of salt-then-password repeated until a byte count is reached. The
// count is stored as a power of two and is usually 2^17, which is 128KB of
// SHA-1 input — still a fixed cost per candidate rather than a real work
// factor, but the largest of the three PGP formats here.
//
// The initialisation vector is not stored either. It is sixteen zero bytes
// with the first set to 8, which PGP's own source calls
// kPGPdiskUserWithSymType — a constant standing in for a nonce.

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha1"
	"encoding/binary"
	"errors"
	"strings"
)

const pgpWDEPrefix = "$pgpwde$"

type pgpWDERecord struct {
	bytes int // the S2K byte count
	salt  []byte
	esk   []byte
}

func pgpWDEFields(target string) (pgpWDERecord, error) {
	var r pgpWDERecord
	t := strings.TrimSpace(target)
	if !strings.HasPrefix(t, pgpWDEPrefix) {
		return r, errors.New("not a PGP WDE record")
	}
	f := strings.Split(t[len(pgpWDEPrefix):], "*")
	if len(f) != 6 || f[0] != "0" {
		return r, errors.New("a PGP WDE record has six fields")
	}
	log2, err := boundedPositiveInt(f[3], "PGP WDE byte count", 32)
	if err != nil {
		// A stored zero means the default, which the helper rejects as
		// non-positive.
		if f[3] == "0" {
			log2 = 16
		} else {
			return r, err
		}
	}
	r.bytes = 1 << uint(log2)
	if r.salt, err = decodeExactHex(f[4], 16, "PGP WDE salt"); err != nil {
		return r, err
	}
	if r.esk, err = decodeExactHex(f[5], 128, "PGP WDE session key"); err != nil {
		return r, err
	}
	return r, nil
}

// pgpWDES2K is the salted-and-iterated string-to-key: salt then password,
// repeated until the byte count is used up, with the tail truncated rather
// than rounded. Each 20-byte block of output prefixes the stream with one more
// zero byte than the last.
func pgpWDES2K(password string, salt []byte, want, keyLen int) []byte {
	pw := []byte(password)
	if want < len(pw)+len(salt) {
		want = len(pw) + len(salt)
	}
	blocks := (keyLen + sha1.Size - 1) / sha1.Size
	out := make([]byte, 0, blocks*sha1.Size)
	for i := 0; i < blocks; i++ {
		h := sha1.New()
		for j := 0; j < i; j++ {
			_, _ = h.Write([]byte{0})
		}
		remaining := want
		for remaining > len(pw)+len(salt) {
			_, _ = h.Write(salt)
			_, _ = h.Write(pw)
			remaining -= len(pw) + len(salt)
		}
		if remaining <= len(salt) {
			_, _ = h.Write(salt[:remaining])
		} else {
			_, _ = h.Write(salt)
			_, _ = h.Write(pw[:remaining-len(salt)])
		}
		out = h.Sum(out)
	}
	return out[:keyLen]
}

// oaepMGF1Unpack undoes PKCS#1 OAEP with SHA-1 and an empty label, reporting
// only whether the padding is well formed. The recovered message is not wanted
// here: the question is whether the key was right, and correct padding is the
// answer to it.
func oaepMGF1Unpack(in []byte) bool {
	const hashLen = sha1.Size
	if len(in) < 2*hashLen+2 || in[0] != 0 {
		return false
	}
	// The buffer is one byte longer than the data because the mask is applied
	// in four-byte words and the last word runs past the end, exactly as the
	// original does.
	msg := make([]byte, len(in))
	copy(msg, in[1:])

	seedMask := sha1.New()
	_, _ = seedMask.Write(msg[hashLen : len(in)-1])
	_, _ = seedMask.Write([]byte{0, 0, 0, 0})
	mask := seedMask.Sum(nil)
	for i := 0; i < hashLen; i++ {
		msg[i] ^= mask[i]
	}

	var counterBytes [4]byte
	for i, counter := hashLen, uint32(0); i < len(in); i += hashLen {
		h := sha1.New()
		_, _ = h.Write(msg[:hashLen])
		binary.BigEndian.PutUint32(counterBytes[:], counter)
		counter++
		_, _ = h.Write(counterBytes[:])
		m := h.Sum(nil)
		for j := 0; j < hashLen && i+j < len(in); j++ {
			msg[i+j] ^= m[j]
		}
	}

	// What is left is seed || hash(label) || zeros || 0x01 || message.
	i := 2 * hashLen
	for ; i < len(in)-1; i++ {
		if msg[i] != 0 {
			break
		}
	}
	if i == len(in)-1 || msg[i] != 1 {
		return false
	}
	empty := sha1.Sum(nil)
	for j := 0; j < hashLen; j++ {
		if msg[hashLen+j] != empty[j] {
			return false
		}
	}
	return true
}

func verifyPGPWDE(target, candidate string) (bool, error) {
	r, err := pgpWDEFields(target)
	if err != nil {
		return false, err
	}
	key := pgpWDES2K(candidate, r.salt, r.bytes, 32)
	block, err := aes.NewCipher(key)
	if err != nil {
		return false, err
	}
	iv := make([]byte, aes.BlockSize)
	iv[0] = 8
	out := make([]byte, len(r.esk))
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(out, r.esk)
	return oaepMGF1Unpack(out), nil
}

func isPGPWDE(target string) bool {
	_, err := pgpWDEFields(target)
	return err == nil
}
