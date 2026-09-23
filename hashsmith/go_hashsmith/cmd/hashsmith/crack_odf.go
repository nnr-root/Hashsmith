package main

// OpenDocument Format (ODF) — Hashcat 18400 (ODF 1.2) and 18600 (ODF 1.1).
//
//	$odf$*<cipher>*<checksum type>*<iterations>*<key size>*<checksum>
//	     *<IV length>*<IV>*<salt length>*<salt>*<unique id>*<encrypted data>
//
// Both versions share a shape and differ only in primitives:
//
//	ODF 1.1  SHA-1 of the password, PBKDF2-HMAC-SHA1, Blowfish-CFB, SHA-1 check
//	ODF 1.2  SHA-256 of the password, PBKDF2-HMAC-SHA1, AES-256-CBC, SHA-256
//
// Note that ODF 1.2 hashes the password with SHA-256 but still stretches with
// PBKDF2-HMAC-SHA1. The two hash choices are independent and it is tempting to
// assume the newer version moved both.
//
// The verification is a checksum over the DECRYPTED stream, not a MAC over the
// ciphertext, so it is exact: a wrong password gives a wrong checksum with
// probability 1 - 2^-256.
//
// Worth stating because it cost several earlier attempts at this format: the
// decrypted bytes look like noise, and that is correct. ODF stores each part
// deflate-compressed and then encrypts the compressed bytes, so a successful
// decryption produces a DEFLATE stream with no readable header — no "PK", no
// XML, nothing. Judging the key by whether the plaintext looks like a document
// concludes the key is wrong when it is right. The checksum is the only signal
// this format offers, and it is a sufficient one.

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"strconv"
	"strings"

	"golang.org/x/crypto/blowfish"
	"golang.org/x/crypto/pbkdf2"
)

const (
	odfPrefix = "$odf$*"
	// John writes the same format under StarOffice's older name, with one
	// extra field: the decrypted content's length is written out rather than
	// left to be counted, because the checksum covers fewer bytes than the
	// ciphertext holds.
	odfStarOfficePrefix = "$sxc$*"
	odfFieldCount       = 11
	odfStarFieldCount   = 12
	odfMaxIter          = 10_000_000
	odfCipherBlowfish   = 0
	odfCipherAES        = 1
)

func verifyODF(target, candidate string) (bool, error) {
	t := strings.TrimSpace(target)
	var f []string
	switch {
	case strings.HasPrefix(t, odfPrefix):
		f = strings.Split(strings.TrimPrefix(t, odfPrefix), "*")
		if len(f) != odfFieldCount {
			return false, errors.New("ODF record must have 11 fields")
		}
	case strings.HasPrefix(t, odfStarOfficePrefix):
		f = strings.Split(strings.TrimPrefix(t, odfStarOfficePrefix), "*")
		if len(f) != odfStarFieldCount {
			return false, errors.New("StarOffice record must have 12 fields")
		}
	default:
		return false, errors.New("not an ODF record")
	}
	cipherType, err := strconv.Atoi(f[0])
	if err != nil || (cipherType != odfCipherBlowfish && cipherType != odfCipherAES) {
		return false, errors.New("ODF cipher must be 0 (Blowfish) or 1 (AES)")
	}
	iter, err := strconv.Atoi(f[2])
	if err != nil || iter < 1 || iter > odfMaxIter {
		return false, errors.New("ODF iteration count is out of range")
	}
	keyLen, err := strconv.Atoi(f[3])
	if err != nil || (keyLen != 16 && keyLen != 32) {
		return false, errors.New("ODF key size must be 16 or 32")
	}
	checksum, err := hex.DecodeString(f[4])
	if err != nil {
		return false, errors.New("ODF checksum must be hex")
	}
	iv, err := hex.DecodeString(f[6])
	if err != nil {
		return false, errors.New("ODF IV must be hex")
	}
	salt, err := hex.DecodeString(f[8])
	if err != nil {
		return false, errors.New("ODF salt must be hex")
	}
	content, err := hex.DecodeString(f[len(f)-1])
	if err != nil || len(content) == 0 {
		return false, errors.New("ODF encrypted data must be hex")
	}
	// The StarOffice spelling states how much of the decrypted stream the
	// checksum covers, and it is not always all of it: the ciphertext is
	// padded to the cipher's block and the checksum is not.
	checked := len(content)
	if len(f) == odfStarFieldCount {
		n, err := strconv.Atoi(f[9])
		if err != nil || n < 0 || n > len(content) {
			return false, errors.New("StarOffice content length is out of range")
		}
		if n > 0 {
			checked = n
		}
	}

	// The password hash and the checksum hash move together; the PBKDF2 PRF
	// stays SHA-1 in both versions.
	var (
		pwHash []byte
		want   int
	)
	if cipherType == odfCipherAES {
		sum := sha256.Sum256([]byte(candidate))
		pwHash, want = sum[:], sha256.Size
	} else {
		sum := sha1.Sum([]byte(candidate))
		pwHash, want = sum[:], sha1.Size
	}
	if len(checksum) != want {
		return false, errors.New("ODF checksum length does not match the cipher")
	}

	key := pbkdf2.Key(pwHash, salt, iter, keyLen, sha1.New)
	plain := make([]byte, len(content))

	if cipherType == odfCipherAES {
		if len(iv) != aes.BlockSize || len(content)%aes.BlockSize != 0 {
			return false, errors.New("ODF AES data must be a whole number of 16-byte blocks")
		}
		block, err := aes.NewCipher(key)
		if err != nil {
			return false, err
		}
		cipher.NewCBCDecrypter(block, iv).CryptBlocks(plain, content)
		got := sha256.Sum256(plain[:checked])
		return subtle.ConstantTimeCompare(got[:], checksum) == 1, nil
	}

	if len(iv) != blowfish.BlockSize {
		return false, errors.New("ODF Blowfish IV must be 8 bytes")
	}
	block, err := blowfish.NewCipher(key)
	if err != nil {
		return false, err
	}
	// ODF 1.1 uses full-block (64-bit) CFB, not the byte-at-a-time variant.
	cipher.NewCFBDecrypter(block, iv).XORKeyStream(plain, content)
	got := sha1.Sum(plain[:checked])
	if subtle.ConstantTimeCompare(got[:], checksum) == 1 {
		return true, nil
	}
	// And the same bytes under OpenOffice's own SHA-1, which differs from the
	// real one for one message length in sixteen. See sha1_openoffice.go.
	return subtle.ConstantTimeCompare(sha1OpenOfficeBuggy(plain[:checked]), checksum) == 1, nil
}
