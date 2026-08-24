package main

// AES-CTS-HMAC-SHA1-96 Kerberos (etypes 17/18) key derivation and verification,
// per RFC 3961 / RFC 3962. Used to crack AES TGS-REP and AS-REQ pre-auth blobs.
// Each primitive (n-fold, DK, string-to-key, AES-CTS, HMAC-SHA1-96) is pinned to
// its published test vectors in the tests.

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/hex"
	"errors"
	"strconv"
	"strings"

	"golang.org/x/crypto/pbkdf2"
)

// nfold implements the RFC 3961 n-fold operation, distributing len(in)*8 input
// bits over `outBytes`*8 output bits (MIT krb5 byte-oriented algorithm).
func nfold(in []byte, outBytes int) []byte {
	inBytes := len(in)
	// gcd
	a, b := outBytes, inBytes
	for b != 0 {
		a, b = b, a%b
	}
	lcm := outBytes * inBytes / a

	out := make([]byte, outBytes)
	carry := 0
	for i := lcm - 1; i >= 0; i-- {
		msbit := ((inBytes*8 - 1) +
			(((inBytes * 8) + 13) * (i / inBytes)) +
			((inBytes - (i % inBytes)) * 8)) % (inBytes * 8)
		b := ((int(in[((inBytes-1)-(msbit>>3))%inBytes]) << 8) |
			int(in[(inBytes-(msbit>>3))%inBytes])) >> ((msbit & 7) + 1)
		carry += b & 0xff
		carry += int(out[i%outBytes])
		out[i%outBytes] = byte(carry & 0xff)
		carry >>= 8
	}
	if carry != 0 {
		for i := outBytes - 1; i >= 0; i-- {
			carry += int(out[i])
			out[i] = byte(carry & 0xff)
			carry >>= 8
		}
	}
	return out
}

// aesDR/DK: for AES the random-to-key is the identity, so DK == DR.
// DR encrypts the (n-folded) constant with the key, chaining blocks until enough
// key material is produced.
func aesDK(key, constant []byte, keyLen int) []byte {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil
	}
	bs := aes.BlockSize
	ki := nfold(constant, bs)
	out := make([]byte, 0, keyLen)
	tmp := make([]byte, bs)
	for len(out) < keyLen {
		block.Encrypt(tmp, ki)
		out = append(out, tmp...)
		ki = append(ki[:0], tmp...)
	}
	return out[:keyLen]
}

// aesString2Key derives the base protocol key from a passphrase and salt.
func aesString2Key(password, salt string, keyLen int) []byte {
	tkey := pbkdf2.Key([]byte(password), []byte(salt), 4096, keyLen, sha1.New)
	return aesDK(tkey, []byte("kerberos"), keyLen)
}

// aesUsageKey derives the Ke (variant 0xAA) or Ki (0x55) key for a key usage.
func aesUsageKey(base []byte, usage int, variant byte, keyLen int) []byte {
	c := []byte{byte(usage >> 24), byte(usage >> 16), byte(usage >> 8), byte(usage), variant}
	return aesDK(base, c, keyLen)
}

// aesCTSDecrypt decrypts an AES-CBC ciphertext-stealing blob (RFC 3962 / CS3)
// with a zero IV.
func aesCTSDecrypt(key, ct []byte) []byte {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil
	}
	bs := aes.BlockSize
	n := len(ct)
	if n < bs {
		return nil
	}
	if n == bs {
		out := make([]byte, bs)
		block.Decrypt(out, ct) // IV is zero
		return out
	}

	lastLen := n % bs
	if lastLen == 0 {
		lastLen = bs
	}
	cbcLen := n - bs - lastLen // full CBC region (multiple of bs, may be 0)
	out := make([]byte, n)
	iv := make([]byte, bs)
	if cbcLen > 0 {
		cipher.NewCBCDecrypter(block, iv).CryptBlocks(out[:cbcLen], ct[:cbcLen])
		copy(iv, ct[cbcLen-bs:cbcLen])
	}

	cn1 := ct[cbcLen : cbcLen+bs] // full second-to-last ciphertext block
	cn := ct[cbcLen+bs : n]       // final (partial) ciphertext block, lastLen bytes

	dn := make([]byte, bs)
	block.Decrypt(dn, cn1)

	// Last plaintext block (lastLen bytes): Cn XOR Dn[:lastLen].
	pLast := make([]byte, lastLen)
	for i := 0; i < lastLen; i++ {
		pLast[i] = cn[i] ^ dn[i]
	}
	// Reconstruct the full final ciphertext block: Cn || Dn[lastLen:].
	full := make([]byte, bs)
	copy(full, cn)
	copy(full[lastLen:], dn[lastLen:])
	pPen := make([]byte, bs)
	block.Decrypt(pPen, full)
	for i := 0; i < bs; i++ {
		pPen[i] ^= iv[i]
	}

	copy(out[cbcLen:cbcLen+bs], pPen)
	copy(out[cbcLen+bs:], pLast)
	return out
}

// hmacSHA196 is HMAC-SHA1 truncated to 96 bits (12 bytes).
func hmacSHA196(key, msg []byte) []byte {
	m := hmac.New(sha1.New, key)
	m.Write(msg)
	return m.Sum(nil)[:12]
}

// verifyKrb5AES checks a candidate against an AES-CTS-HMAC-SHA1-96 Kerberos blob
// (etype 17 = AES-128, etype 18 = AES-256) for a given key usage. checksum is the
// 12-byte integrity tag; edata is the AES-CTS ciphertext.
func verifyKrb5AES(candidate, realm, user string, etype, usage int, edata, checksum []byte) bool {
	keyLen := 16
	if etype == 18 {
		keyLen = 32
	}
	salt := strings.ToUpper(realm) + user
	base := aesString2Key(candidate, salt, keyLen)
	ke := aesUsageKey(base, usage, 0xAA, keyLen)
	ki := aesUsageKey(base, usage, 0x55, keyLen)

	plain := aesCTSDecrypt(ke, edata)
	if plain == nil {
		return false
	}
	return hmac.Equal(hmacSHA196(ki, plain), checksum)
}

// isKrb5AES reports whether a Kerberos hash uses an AES etype (17/18) rather
// than RC4 (23).
func isKrb5AES(s string) bool {
	return strings.HasPrefix(s, "$krb5pa$17$") || strings.HasPrefix(s, "$krb5pa$18$") ||
		strings.HasPrefix(s, "$krb5tgs$17$") || strings.HasPrefix(s, "$krb5tgs$18$") ||
		strings.HasPrefix(s, "$krb5asrep$17$") || strings.HasPrefix(s, "$krb5asrep$18$")
}

// verifyKrb5AESHash parses an AES Kerberos hash and verifies a candidate.
//
//	$krb5pa$<17|18>$<user>$<realm>$<edata+checksum>          (usage 1)
//	$krb5tgs$<17|18>$<user>$<realm>$<checksum>$<edata>       (usage 2)
func verifyKrb5AESHash(target, candidate string) (bool, error) {
	var body string
	var usage int
	isPA := strings.HasPrefix(target, "$krb5pa$")
	isASREP := strings.HasPrefix(target, "$krb5asrep$")
	if isPA {
		body = target[len("$krb5pa$"):]
		usage = 1
	} else if isASREP {
		body = target[len("$krb5asrep$"):]
		usage = 3
	} else if strings.HasPrefix(target, "$krb5tgs$") {
		body = target[len("$krb5tgs$"):]
		usage = 2
	} else {
		return false, errors.New("not an AES Kerberos hash")
	}
	f := strings.Split(body, "$")
	if len(f) < 4 {
		return false, errors.New("invalid AES Kerberos hash")
	}
	etype, err := strconv.Atoi(f[0])
	if err != nil || (etype != 17 && etype != 18) {
		return false, errors.New("unsupported Kerberos etype (want 17 or 18)")
	}
	user, realm := f[1], f[2]

	var edata, checksum []byte
	if isPA {
		blob, err := hex.DecodeString(f[3])
		if err != nil || len(blob) < 12 {
			return false, errors.New("invalid krb5pa data")
		}
		edata, checksum = blob[:len(blob)-12], blob[len(blob)-12:]
	} else {
		if len(f) < 5 {
			return false, errors.New("invalid Kerberos AES hash")
		}
		checksum, err = hex.DecodeString(f[3])
		if err != nil || len(checksum) != 12 {
			return false, errors.New("invalid krb5tgs checksum")
		}
		edata, err = hex.DecodeString(f[4])
		if err != nil {
			return false, errors.New("invalid krb5tgs edata")
		}
	}
	return verifyKrb5AES(candidate, realm, user, etype, usage, edata, checksum), nil
}
