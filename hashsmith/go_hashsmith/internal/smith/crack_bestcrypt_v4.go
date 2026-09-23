package smith

// BestCrypt v4 Volume Encryption — Hashcat 24000.
//
//	$bcve$4$<cipher>$<salt>$<96 bytes of volume header>
//
// Shares only its prefix with v3. Jetico replaced the home-grown stretch with
// scrypt at N=32768, r=16, p=1 — 64 MiB of working memory per candidate — and
// made the cipher selectable. The cipher lives in the second character of the
// third field, as an ASCII digit rather than a number:
//
//	08  AES-256        09  Twofish-256
//	0a  Serpent-256    0f  Camellia-256
//
// Past the KDF the check is v3's: decrypt the first 80 bytes in CBC mode with
// a zero IV, and the SHA-256 of the first 64 must begin with the 16 that
// follow. An exact authenticator, not a heuristic.
//
// The salt is stored hex-encoded but is ASCII: the published record's salt
// decodes to the digits "261558323204609954823950", and those 24 characters
// are the salt bytes scrypt sees — not the 12 bytes a second hex decode would
// produce.
//
// Serpent and Camellia are refused rather than guessed at. Go has AES and
// Twofish; the other two would each be a table-heavy transcription that
// nothing here could verify, since hashcat's published record uses AES and a
// wrong cipher would fail identically to a wrong password.

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"

	"golang.org/x/crypto/scrypt"
)

const (
	bestCryptV4Prefix = "$bcve$4$"
	bestCryptV4N      = 32768
	bestCryptV4R      = 16
	bestCryptV4P      = 1
	bestCryptV4KeyLen = 32
	// 128 * N * r, the working set one scrypt call needs.
	bestCryptV4Memory = 128 * bestCryptV4N * bestCryptV4R
)

// bestCryptV4Cipher builds the block cipher a record names.
func bestCryptV4Cipher(selector string, key []byte) (cipher.Block, error) {
	if len(selector) != 2 {
		return nil, errors.New("BestCrypt v4 cipher field must be two characters")
	}
	switch selector[1] {
	case '8':
		return aes.NewCipher(key)
	case '9':
		return newTwofishCipher(key)
	case 'a':
		return nil, errors.New("BestCrypt v4 with Serpent is not implemented")
	case 'f':
		return nil, errors.New("BestCrypt v4 with Camellia is not implemented")
	default:
		return nil, errors.New("unknown BestCrypt v4 cipher " + selector)
	}
}

func verifyBestCryptV4(target, candidate string) (bool, error) {
	t := strings.TrimSpace(target)
	if !strings.HasPrefix(t, bestCryptV4Prefix) {
		return false, errors.New("not a BestCrypt v4 record")
	}
	f := strings.Split(strings.TrimPrefix(t, bestCryptV4Prefix), "$")
	if len(f) != 3 {
		return false, errors.New("BestCrypt v4 record must be $bcve$4$<cipher>$<salt>$<data>")
	}
	salt, err := hex.DecodeString(f[1])
	if err != nil || len(salt) == 0 {
		return false, errors.New("BestCrypt v4 salt must be hex")
	}
	data, err := hex.DecodeString(f[2])
	if err != nil || len(data) < bestCryptHeaderUsed {
		return false, errors.New("BestCrypt v4 volume header must be at least 80 hex-encoded bytes")
	}

	key, err := scrypt.Key([]byte(candidate), salt, bestCryptV4N, bestCryptV4R, bestCryptV4P, bestCryptV4KeyLen)
	if err != nil {
		return false, err
	}
	block, err := bestCryptV4Cipher(f[0], key)
	if err != nil {
		return false, err
	}
	if block.BlockSize() != aes.BlockSize {
		return false, errors.New("BestCrypt v4 cipher must have a 16-byte block")
	}
	plain := make([]byte, bestCryptHeaderUsed)
	cipher.NewCBCDecrypter(block, make([]byte, aes.BlockSize)).CryptBlocks(plain, data[:bestCryptHeaderUsed])
	sum := sha256.Sum256(plain[:bestCryptWindow])
	return string(sum[:bestCryptCheckLen]) == string(plain[bestCryptWindow:bestCryptHeaderUsed]), nil
}
