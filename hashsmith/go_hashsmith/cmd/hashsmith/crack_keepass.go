package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"strings"

	"hashsmith-go/internal/argon2d"
)

// ── KeePass database (KDBX 1 & 2, AES-KDF) ─────────────────────────────────────
//
// Cracks the $keepass$ hash produced by keepass2john / hashcat mode 13400 for
// AES-KDF databases (KDBX4's Argon2 KDF is not covered here).
//
//   KDBX1: $keepass$*1*<rounds>*<algo>*<masterSeed>*<transformSeed>*<encIV>*
//          <contentsHash>*<inline>*<dataSize>*<encData>
//   KDBX2: $keepass$*2*<rounds>*<?>*<masterSeed>*<transformSeed>*<encIV>*
//          <expectedStartBytes>*<firstEncryptedBytes>
//
// Verified against hashcat's mode-13400 example hashes.

func verifyKeePass(targetHash, candidate string) (bool, error) {
	p := strings.Split(targetHash, "*")
	if len(p) < 8 || p[0] != "$keepass$" {
		return false, errors.New("invalid keepass hash format")
	}
	switch p[1] {
	case "1":
		return verifyKeePass1(p, candidate)
	case "2":
		return verifyKeePass2(p, candidate)
	case "4":
		return verifyKeePass4(p, candidate)
	}
	return false, errors.New("unsupported keepass version (want 1, 2 or 4)")
}

// keepassMasterKey performs the AES-KDF: transform the composite key with
// transformSeed for `rounds`, hash it, then combine with the master seed.
func keepassMasterKey(composite, transformSeed, masterSeed []byte, rounds int) ([]byte, error) {
	block, err := aes.NewCipher(transformSeed)
	if err != nil {
		return nil, errors.New("invalid keepass transform seed")
	}
	transformed := make([]byte, len(composite))
	copy(transformed, composite)
	// AES-ECB encrypt both 16-byte halves, `rounds` times.
	for i := 0; i < rounds; i++ {
		block.Encrypt(transformed[0:16], transformed[0:16])
		block.Encrypt(transformed[16:32], transformed[16:32])
	}
	th := sha256.Sum256(transformed)

	h := sha256.New()
	h.Write(masterSeed)
	h.Write(th[:])
	return h.Sum(nil), nil
}

// verifyKeePass1 decrypts the payload and compares SHA-256 of the plaintext to
// the stored contents hash.
func verifyKeePass1(p []string, candidate string) (bool, error) {
	// $keepass$*1*rounds*algo*masterSeed*transformSeed*encIV*contentsHash*inline*size*data
	if len(p) < 11 {
		return false, errors.New("invalid keepass1 hash format")
	}
	rounds := atoiDefault(p[2], 0)
	algo := atoiDefault(p[3], 0)
	if algo != 0 {
		return false, errors.New("keepass1: only AES (algo 0) is supported")
	}
	masterSeed, e1 := hex.DecodeString(p[4])
	transformSeed, e2 := hex.DecodeString(p[5])
	encIV, e3 := hex.DecodeString(p[6])
	contentsHash, e4 := hex.DecodeString(p[7])
	encData, e5 := hex.DecodeString(p[10])
	if e1 != nil || e2 != nil || e3 != nil || e4 != nil || e5 != nil {
		return false, errors.New("invalid keepass1 hex fields")
	}
	if len(encData) == 0 || len(encData)%16 != 0 || len(encIV) < 16 {
		return false, errors.New("keepass1 encrypted data not block-aligned")
	}

	// KDBX1 password-only composite key = SHA256(password).
	pw := sha256.Sum256([]byte(candidate))
	master, err := keepassMasterKey(pw[:], transformSeed, masterSeed, rounds)
	if err != nil {
		return false, err
	}

	block, err := aes.NewCipher(master)
	if err != nil {
		return false, err
	}
	pt := make([]byte, len(encData))
	cipher.NewCBCDecrypter(block, encIV[:16]).CryptBlocks(pt, encData)

	// Strip PKCS#7 padding, then SHA-256 the content.
	pad := int(pt[len(pt)-1])
	if pad < 1 || pad > 16 || pad > len(pt) {
		return false, nil
	}
	content := pt[:len(pt)-pad]
	sum := sha256.Sum256(content)
	return equalConst(sum[:], contentsHash), nil
}

// verifyKeePass4 derives the Argon2 transformed key and checks the KDBX4 header
// HMAC — no payload decryption required.
func verifyKeePass4(p []string, candidate string) (bool, error) {
	// $keepass$*4*<argon>*<t>*<m_bytes>*<p>*<v>*<salt>*<masterSeed>*<header>*<headerHMAC>
	if len(p) < 11 {
		return false, errors.New("invalid keepass4 hash format")
	}
	argon := p[2]
	t := atoiDefault(p[3], 0)
	memBytes := atoiDefault(p[4], 0)
	par := atoiDefault(p[5], 0)
	salt, e1 := hex.DecodeString(p[7])
	masterSeed, e2 := hex.DecodeString(p[8])
	header, e3 := hex.DecodeString(p[9])
	headerHMAC, e4 := hex.DecodeString(p[10])
	if e1 != nil || e2 != nil || e3 != nil || e4 != nil {
		return false, errors.New("invalid keepass4 hex fields")
	}
	if t < 1 || memBytes < 1024 || par < 1 {
		return false, errors.New("invalid keepass4 KDF parameters")
	}

	// composite key = SHA256(SHA256(password))
	inner := sha256.Sum256([]byte(candidate))
	composite := sha256.Sum256(inner[:])

	memKiB := uint32(memBytes / 1024)
	var transformed []byte
	switch argon {
	case "d":
		transformed = argon2d.DKey(composite[:], salt, uint32(t), memKiB, uint8(par), 32)
	case "id":
		transformed = argon2d.IDKey(composite[:], salt, uint32(t), memKiB, uint8(par), 32)
	default:
		return false, errors.New("unsupported keepass4 argon variant")
	}

	// HMAC base key = SHA512(masterSeed || transformedKey || 0x01)
	hb := sha512.New()
	hb.Write(masterSeed)
	hb.Write(transformed)
	hb.Write([]byte{0x01})
	hmacBase := hb.Sum(nil)

	// Header block key = SHA512(LE64(0xFFFFFFFFFFFFFFFF) || hmacBase)
	var idx [8]byte
	binary.LittleEndian.PutUint64(idx[:], 0xFFFFFFFFFFFFFFFF)
	bk := sha512.New()
	bk.Write(idx[:])
	bk.Write(hmacBase)
	blockKey := bk.Sum(nil)

	mac := hmac.New(sha256.New, blockKey)
	mac.Write(header)
	return hmac.Equal(mac.Sum(nil), headerHMAC), nil
}

// verifyKeePass2 decrypts the first block and compares it to the expected
// stream-start bytes.
func verifyKeePass2(p []string, candidate string) (bool, error) {
	// $keepass$*2*rounds*?*masterSeed*transformSeed*encIV*expectedStart*firstEnc
	if len(p) < 9 {
		return false, errors.New("invalid keepass2 hash format")
	}
	rounds := atoiDefault(p[2], 0)
	masterSeed, e1 := hex.DecodeString(p[4])
	transformSeed, e2 := hex.DecodeString(p[5])
	encIV, e3 := hex.DecodeString(p[6])
	expectedStart, e4 := hex.DecodeString(p[7])
	firstEnc, e5 := hex.DecodeString(p[8])
	if e1 != nil || e2 != nil || e3 != nil || e4 != nil || e5 != nil {
		return false, errors.New("invalid keepass2 hex fields")
	}
	if len(firstEnc) < 16 || len(firstEnc)%16 != 0 || len(encIV) < 16 {
		return false, errors.New("keepass2 first block not aligned")
	}

	// KDBX2 password-only composite key = SHA256(SHA256(password)).
	inner := sha256.Sum256([]byte(candidate))
	composite := sha256.Sum256(inner[:])
	master, err := keepassMasterKey(composite[:], transformSeed, masterSeed, rounds)
	if err != nil {
		return false, err
	}

	block, err := aes.NewCipher(master)
	if err != nil {
		return false, err
	}
	n := len(expectedStart)
	if n > len(firstEnc) {
		n = len(firstEnc)
	}
	// Round down to a whole number of blocks.
	n -= n % 16
	if n == 0 {
		return false, errors.New("keepass2 expected-start too short")
	}
	pt := make([]byte, n)
	cipher.NewCBCDecrypter(block, encIV[:16]).CryptBlocks(pt, firstEnc[:n])
	return equalConst(pt, expectedStart[:n]), nil
}
