package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha1"
	"crypto/sha512"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"hash"
	"strings"
)

// ── Microsoft Office document encryption ───────────────────────────────────────
//
// Cracks the verifier blobs from encrypted Office files (the $office$ hash
// produced by office2john / hashcat modes 9400/9500/9600):
//
//   $office$*<version>*<spinCount>*<keySizeBits>*<saltSize>*<salt>*<encVerifier>*<encVerifierHash>
//
//   2007 (9400): SHA-1, AES-128, 50000 spins
//   2010 (9500): SHA-1, AES-128, 100000 spins
//   2013 (9600): SHA-512, AES-256, 100000 spins
//
// Verified against hashcat's example hash for mode 9600.

// Agile (2013) block keys (MS-OFFCRYPTO §2.3.4.15).
var (
	officeBlockVerifierInput = []byte{0xfe, 0xa7, 0xd2, 0x76, 0x3b, 0x4b, 0x9e, 0x79}
	officeBlockVerifierValue = []byte{0xd7, 0xaa, 0x0f, 0x6d, 0x30, 0x61, 0x34, 0x4e}
)

// verifyOffice checks an Office document password against the stored verifier.
func verifyOffice(targetHash, candidate string) (bool, error) {
	// $office$*<ver>*<spin>*<keybits>*<saltsize>*<salt>*<encVerifier>*<encVerifierHash>
	parts := strings.Split(targetHash, "*")
	if len(parts) != 8 || parts[0] != "$office$" {
		return false, errors.New("invalid office hash format")
	}
	version := atoiDefault(parts[1], 0)
	keyBits := atoiDefault(parts[3], 0)
	salt, err := hex.DecodeString(parts[5])
	if err != nil {
		return false, errors.New("invalid office salt")
	}
	encVerifier, err := hex.DecodeString(parts[6])
	if err != nil || len(encVerifier) < 16 {
		return false, errors.New("invalid office encrypted verifier")
	}
	encVerifierHash, err := hex.DecodeString(parts[7])
	if err != nil {
		return false, errors.New("invalid office encrypted verifier hash")
	}
	keyLen := keyBits / 8

	switch version {
	case 2013:
		// Agile encryption: SHA-512 + AES-256-CBC. Field 2 is the spin count.
		return officeAgileVerify(candidate, salt, encVerifier, encVerifierHash, atoiDefault(parts[2], 100000), keyLen)
	case 2010:
		// Standard encryption, 100000 SHA-1 iterations (field 2).
		return officeStandardVerify(candidate, salt, encVerifier, encVerifierHash, atoiDefault(parts[2], 100000), keyLen)
	case 2007:
		// Standard encryption, fixed 50000 iterations (field 2 is verifier size).
		return officeStandardVerify(candidate, salt, encVerifier, encVerifierHash, 50000, keyLen)
	}
	return false, errors.New("unsupported office version (want 2007/2010/2013)")
}

// officeAgileVerify implements the 2013 agile scheme (SHA-512 + AES-256-CBC).
func officeAgileVerify(password string, salt, encVerifier, encVerifierHash []byte, spinCount, keyLen int) (bool, error) {
	h := officeIteratedHash(sha512.New, salt, password, spinCount)

	keyIn := officeDeriveKey(sha512.New, h, officeBlockVerifierInput, keyLen)
	keyVal := officeDeriveKey(sha512.New, h, officeBlockVerifierValue, keyLen)

	verifier, err := aesCBCDecrypt(keyIn, salt, encVerifier)
	if err != nil {
		return false, err
	}
	verifierHash, err := aesCBCDecrypt(keyVal, salt, encVerifierHash)
	if err != nil {
		return false, err
	}

	sum := sha512.Sum512(verifier)
	n := len(verifierHash)
	if n > len(sum) {
		n = len(sum)
	}
	return equalConst(sum[:n], verifierHash[:n]), nil
}

// officeStandardVerify implements the 2007/2010 ECMA-376 standard scheme
// (SHA-1 + AES-ECB), mirroring the reference msoffcrypto-tool derivation.
func officeStandardVerify(password string, salt, encVerifier, encVerifierHash []byte, spinCount, keyLen int) (bool, error) {
	h := officeIteratedHash(sha1.New, salt, password, spinCount)

	// hfinal = SHA1(H || blockNumber(0)); key = (X1 || X2)[:keyLen] where
	// X1 = SHA1(hfinal ⊕ 0x36×64), X2 = SHA1(hfinal ⊕ 0x5C×64).
	hf := sha1.New()
	hf.Write(h)
	hf.Write([]byte{0, 0, 0, 0})
	hfinal := hf.Sum(nil)
	key := officeStandardKey(hfinal, keyLen)

	verifier, err := aesECBDecrypt(key, encVerifier)
	if err != nil {
		return false, err
	}
	// The stored verifier hash may be truncated (2007 keeps 20 bytes); decrypt
	// only whole blocks and compare the bytes that are available.
	hashBlocks := len(encVerifierHash) - len(encVerifierHash)%16
	if hashBlocks == 0 {
		return false, errors.New("office verifier hash too short")
	}
	verifierHash, err := aesECBDecrypt(key, encVerifierHash[:hashBlocks])
	if err != nil {
		return false, err
	}
	sum := sha1.Sum(verifier)
	n := len(sum)
	if n > len(verifierHash) {
		n = len(verifierHash)
	}
	return equalConst(sum[:n], verifierHash[:n]), nil
}

// officeStandardKey performs the ECMA-376 standard key derivation from hfinal.
func officeStandardKey(hfinal []byte, keyLen int) []byte {
	x1 := officeXorSHA1(hfinal, 0x36)
	x2 := officeXorSHA1(hfinal, 0x5c)
	x3 := append(x1, x2...)
	if keyLen > len(x3) {
		keyLen = len(x3)
	}
	return x3[:keyLen]
}

// officeXorSHA1 returns SHA1( (pad×64) with its first len(h) bytes XOR'd by h ).
func officeXorSHA1(h []byte, pad byte) []byte {
	buf := make([]byte, 64)
	for i := range buf {
		buf[i] = pad
	}
	for i := 0; i < len(h) && i < 64; i++ {
		buf[i] ^= h[i]
	}
	sum := sha1.Sum(buf)
	return sum[:]
}

// aesECBDecrypt decrypts ct in AES-ECB mode (block-by-block, no IV).
func aesECBDecrypt(key, ct []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	bs := block.BlockSize()
	if len(ct) == 0 || len(ct)%bs != 0 {
		return nil, errors.New("office ECB ciphertext not block-aligned")
	}
	out := make([]byte, len(ct))
	for off := 0; off < len(ct); off += bs {
		block.Decrypt(out[off:off+bs], ct[off:off+bs])
	}
	return out, nil
}

// officeIteratedHash computes H = hash(salt || UTF16LE(pw)) then the spin loop
// H = hash(LE32(i) || H).
func officeIteratedHash(newHash func() hash.Hash, salt []byte, password string, spinCount int) []byte {
	h := newHash()
	h.Write(salt)
	h.Write(utf16le(password))
	cur := h.Sum(nil)

	var idx [4]byte
	for i := 0; i < spinCount; i++ {
		binary.LittleEndian.PutUint32(idx[:], uint32(i))
		hh := newHash()
		hh.Write(idx[:])
		hh.Write(cur)
		cur = hh.Sum(nil)
	}
	return cur
}

// officeDeriveKey returns hash(H || blockKey) truncated (or zero-padded) to keyLen.
func officeDeriveKey(newHash func() hash.Hash, h, blockKey []byte, keyLen int) []byte {
	hh := newHash()
	hh.Write(h)
	hh.Write(blockKey)
	sum := hh.Sum(nil)
	key := make([]byte, keyLen)
	copy(key, sum) // truncate; if hash < keyLen the remainder stays zero (0x00 pad)
	return key
}

func aesCBCDecrypt(key, iv, ct []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	bs := block.BlockSize()
	if len(ct) == 0 || len(ct)%bs != 0 || len(iv) < bs {
		return nil, errors.New("office ciphertext not block-aligned")
	}
	out := make([]byte, len(ct))
	cipher.NewCBCDecrypter(block, iv[:bs]).CryptBlocks(out, ct)
	return out, nil
}

func equalConst(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var v byte
	for i := range a {
		v |= a[i] ^ b[i]
	}
	return v == 0
}

func atoiDefault(s string, def int) int {
	n := 0
	for _, c := range s {
		if c < '0' || c > '9' {
			return def
		}
		n = n*10 + int(c-'0')
	}
	if s == "" {
		return def
	}
	return n
}
