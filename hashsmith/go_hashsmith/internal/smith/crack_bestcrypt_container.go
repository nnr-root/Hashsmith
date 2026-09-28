package smith

// Jetico BestCrypt container (.jbc) — John's "BestCrypt".
//
//	$BestCrypt$<version>$<key gen id>$<wVersion>$<iterations>$<alg id>
//	           $<mode id>$<hash id>$<salt size>$<salt>$<active slots>$<key slot>
//
// This is the CONTAINER format. crack_bestcrypt.go next door reads BestCrypt
// Volume Encryption v3 ($bcve$3$, Hashcat 23900), which is a different product
// with a different, home-grown stretch. They share a vendor and nothing else.
//
// The derivation is PKCS#12's, from RFC 7292 appendix B — the one designed for
// .pfx files in 1996 and kept alive because certificate tooling never replaced
// it. BestCrypt did not take it unmodified, and the two changes are the whole
// reason this needs its own key derivation rather than crack_pkcs12.go's:
//
//   - The block width v is 64 for EVERY hash, including SHA-512, whose real
//     block is 128. PKCS#12 defines v as the hash's block size, so a
//     conforming implementation and BestCrypt disagree on SHA-512 containers
//     and neither is reading the other's files.
//
//   - Because v is 64 and the password buffer is filled to v rather than to a
//     multiple of the password's own length, a password longer than 31
//     characters is TRUNCATED for the SHA-512 and Whirlpool hashes: the buffer
//     holds 64 bytes of UTF-16, which is 32 characters, and the rest never
//     reaches the hash. The SHA-256 path does grow the buffer, so the same
//     password is stronger in a SHA-256 container than in a Whirlpool one.
//
// Neither is a property a user could discover from the interface. Both are
// transcribed from John's bestcrypt_fmt_plug.c and pkcs12_plug.c, which are
// what defines the format in practice.
//
// What the key opens is a 256-byte key slot: 96 bytes of key material, a
// 32-byte digest of those 96 (well, of the first 90 of them — the struct is
// 90 bytes and the rest is padding the digest does not cover), and an eight-
// byte IV in the clear. Decrypting the slot and hashing its first 90 bytes
// either reproduces the stored digest or does not, so the check is exact.
//
// The IV is eight bytes where the cipher wants sixteen, and the two modes
// disagree about what to do with that. CBC repeats it; XTS zero-fills it.
// John's source says "isn't BestCrypt great?" at that line, which is as close
// to a specification as this part of the format gets.

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"hash"
	"strconv"
	"strings"
)

const (
	bestCryptContainerPrefix = "$BestCrypt$"
	bestCryptContainerFields = 11
	bestCryptKeyGenID        = 5
	bestCryptAlgAES          = 240
	bestCryptModeCBC         = 0xBC000002
	bestCryptModeXTS         = 0xBC000004
	bestCryptHashSHA256      = 0x80
	bestCryptHashWhirlpool   = 0x81
	bestCryptHashSHA512      = 10
	bestCryptSlotSize        = 256
	// bestCryptDigested is how much of the decrypted slot the digest covers.
	// The struct it describes is 90 bytes; the six bytes between it and the
	// digest at offset 96 are padding, and they are NOT hashed.
	bestCryptDigested  = 90
	bestCryptDigestAt  = 96
	bestCryptDigestLen = 32
	// bestCryptBlockWidth is PKCS#12's v, which BestCrypt fixes at 64
	// regardless of the hash. See the note above.
	bestCryptBlockWidth = 64
	bestCryptMaxIter    = 10_000_000
)

// bestCryptDeriveKey is PKCS#12 appendix B.2 as BestCrypt runs it.
//
// grow says whether the password buffer may exceed one block: true for
// SHA-256, false for SHA-512 and Whirlpool, which is where the truncation
// described at the top of the file comes from.
func bestCryptDeriveKey(newHash func() hash.Hash, password string, salt []byte, iterations, keyLen int, grow bool) []byte {
	v := bestCryptBlockWidth
	pwd := pkcs12BMPString(password)

	v2 := v
	if grow {
		v2 = v * ((len(pwd) + v - 1) / v)
	}

	diversifier := make([]byte, v)
	for i := range diversifier {
		diversifier[i] = pkcs12IDKey
	}
	saltBlock := bestCryptFillExact(salt, v)
	pwdBlock := bestCryptFillExact(pwd, v2)

	h := newHash()
	hlen := h.Size()
	out := make([]byte, 0, keyLen+hlen)
	for len(out) < keyLen {
		h.Reset()
		h.Write(diversifier)
		h.Write(saltBlock)
		h.Write(pwdBlock)
		digest := h.Sum(nil)
		for i := 1; i < iterations; i++ {
			h.Reset()
			h.Write(digest)
			digest = h.Sum(digest[:0])
		}
		out = append(out, digest...)
		if len(out) >= keyLen {
			break
		}

		// B is the digest repeated to v bytes, incremented by one, and
		// added into the salt and password buffers as a big-endian
		// integer. Only the FIRST v bytes of each are touched, even when
		// the password buffer is longer.
		b := bestCryptFillExact(digest, v)
		for i := v - 1; i >= 0; i-- {
			b[i]++
			if b[i] != 0 {
				break
			}
		}
		bestCryptAddInto(saltBlock, b)
		bestCryptAddInto(pwdBlock[:v], b)
	}
	return out[:keyLen]
}

// bestCryptFillExact repeats src until it is exactly n bytes, truncating when
// src is longer. PKCS#12's own filler rounds up to a whole block instead,
// which is why this cannot be pkcs12Fill.
func bestCryptFillExact(src []byte, n int) []byte {
	out := make([]byte, n)
	if len(src) == 0 {
		return out
	}
	for i := 0; i < n; i += len(src) {
		copy(out[i:], src)
	}
	return out
}

func bestCryptAddInto(dst, add []byte) {
	carry := 0
	for i := len(dst) - 1; i >= 0; i-- {
		sum := int(dst[i]) + int(add[i]) + carry
		dst[i] = byte(sum)
		carry = sum >> 8
	}
}

// bestCryptXTSDecrypt is AES-XTS with the tweak taken straight from the
// record's IV rather than from a sector number. Standard XTS derives the tweak
// from the block's position on disk; this is a single key slot, so there is no
// position, and BestCrypt encrypts the stored IV under the second half of the
// key instead.
func bestCryptXTSDecrypt(doubleKey, iv, dst, src []byte) error {
	dataKey, err := aes.NewCipher(doubleKey[:32])
	if err != nil {
		return err
	}
	tweakKey, err := aes.NewCipher(doubleKey[32:64])
	if err != nil {
		return err
	}
	var tweak [16]byte
	tweakKey.Encrypt(tweak[:], iv)

	var buf [16]byte
	for off := 0; off+16 <= len(src) && off+16 <= len(dst); off += 16 {
		for i := 0; i < 16; i++ {
			buf[i] = src[off+i] ^ tweak[i]
		}
		dataKey.Decrypt(dst[off:off+16], buf[:])
		for i := 0; i < 16; i++ {
			dst[off+i] ^= tweak[i]
		}
		// Double the tweak in GF(2^128) with the low-bit-first
		// convention XTS uses.
		var carry byte
		for i := 0; i < 16; i++ {
			next := (tweak[i] >> 7) & 1
			tweak[i] = (tweak[i] << 1) | carry
			carry = next
		}
		if carry != 0 {
			tweak[0] ^= 0x87
		}
	}
	return nil
}

func verifyBestCryptContainer(target, candidate string) (bool, error) {
	t := strings.TrimSpace(target)
	if !strings.HasPrefix(t, bestCryptContainerPrefix) {
		return false, errors.New("not a BestCrypt container record")
	}
	f := strings.Split(strings.TrimPrefix(t, bestCryptContainerPrefix), "$")
	if len(f) != bestCryptContainerFields {
		return false, errors.New("BestCrypt container record must have 11 fields")
	}
	if n, err := strconv.Atoi(f[1]); err != nil || n != bestCryptKeyGenID {
		return false, errors.New("BestCrypt key generator id must be 5")
	}
	iterations, err := strconv.Atoi(f[3])
	if err != nil || iterations < 1 || iterations > bestCryptMaxIter {
		return false, errors.New("BestCrypt iteration count is out of range")
	}
	if n, err := strconv.Atoi(f[4]); err != nil || n != bestCryptAlgAES {
		return false, errors.New("BestCrypt cipher must be AES")
	}
	mode, err := strconv.ParseUint(f[5], 10, 32)
	if err != nil || (mode != bestCryptModeCBC && mode != bestCryptModeXTS) {
		return false, errors.New("BestCrypt mode must be CBC or XTS")
	}
	hashID, err := strconv.Atoi(f[6])
	if err != nil {
		return false, errors.New("BestCrypt hash id must be a number")
	}
	saltSize, err := strconv.Atoi(f[7])
	if err != nil || saltSize < 1 || saltSize > 64 {
		return false, errors.New("BestCrypt salt size must be 1 to 64")
	}
	salt, err := hex.DecodeString(f[8])
	if err != nil || len(salt) != saltSize {
		return false, errors.New("BestCrypt salt must be hex of the stated size")
	}
	if n, err := strconv.Atoi(f[9]); err != nil || n != 1 {
		return false, errors.New("BestCrypt record must carry exactly one active key slot")
	}
	slot, err := hex.DecodeString(f[10])
	if err != nil || len(slot) != bestCryptSlotSize {
		return false, errors.New("BestCrypt key slot must be 256 bytes of hex")
	}

	// The digest width decides where the IV sits: a 32-byte digest leaves a
	// 128-byte key block before it, a 64-byte digest a 160-byte one. Only
	// the first 128 bytes are ever read, but the IV's offset moves.
	var (
		newHash func() hash.Hash
		ivAt    int
		grow    bool
	)
	switch hashID {
	case bestCryptHashSHA256:
		newHash, ivAt, grow = sha256.New, 128, true
	case bestCryptHashWhirlpool:
		newHash, ivAt, grow = newWhirlpool, 160, false
	case bestCryptHashSHA512:
		newHash, ivAt, grow = sha512.New, 160, false
	default:
		return false, errors.New("BestCrypt hash must be SHA-256, SHA-512 or Whirlpool-512")
	}

	keyLen := 32
	if mode == bestCryptModeXTS {
		keyLen = 64
	}
	key := bestCryptDeriveKey(newHash, candidate, salt, iterations, keyLen, grow)

	iv := make([]byte, aes.BlockSize)
	copy(iv, slot[ivAt:ivAt+8])
	out := make([]byte, bestCryptDigestAt+bestCryptDigestLen)

	if mode == bestCryptModeXTS {
		// iv[8:16] stays zero.
		if err := bestCryptXTSDecrypt(key, iv, out, slot); err != nil {
			return false, err
		}
	} else {
		copy(iv[8:16], slot[ivAt:ivAt+8])
		block, err := aes.NewCipher(key)
		if err != nil {
			return false, err
		}
		cipher.NewCBCDecrypter(block, iv).CryptBlocks(out, slot[:len(out)])
	}

	h := newHash()
	h.Write(out[:bestCryptDigested])
	got := h.Sum(nil)
	want := out[bestCryptDigestAt : bestCryptDigestAt+bestCryptDigestLen]
	return subtle.ConstantTimeCompare(got[:bestCryptDigestLen], want) == 1, nil
}
