package smith

// OpenBSD's softraid CRYPTO volume.
//
//	$openbsd-softraid$<iterations>$<salt>$<masked keys>$<mac>[$<kdf>]
//
// The disk's real keys are not derived from the password. Thirty-two
// AES-XTS-256 keys — sixty-four bytes each, two thousand and forty-eight in
// all — sit on disk encrypted ("masked") under a key that IS derived from it,
// with AES-256 in ECB and no chaining whatever. Changing the passphrase
// re-masks those keys rather than re-encrypting the volume, which is why it is
// instant.
//
// The check is an HMAC-SHA1 over the unmasked keys, keyed on the SHA-1 of the
// masking key. Twenty bytes have to agree, so an answer here is an answer.
//
// Two key derivations are in the wild and the record says which: PBKDF2-SHA1,
// and bcrypt_pbkdf — the same construction OpenSSH uses for its private keys,
// which OpenBSD moved to because PBKDF2-SHA1 is too friendly to a GPU.

import (
	"crypto/aes"
	"crypto/hmac"
	"crypto/sha1"
	"errors"
	"strings"

	"golang.org/x/crypto/pbkdf2"
)

const (
	softraidPrefix     = "$openbsd-softraid$"
	softraidSaltLen    = 128
	softraidKeys       = 32
	softraidKeyLen     = 64
	softraidMaskedSize = softraidKeys * softraidKeyLen
)

type softraidRecord struct {
	iterations int
	salt       []byte
	masked     []byte
	mac        []byte
	kdf        int
}

func softraidFields(target string) (softraidRecord, error) {
	var r softraidRecord
	t := strings.TrimSpace(target)
	if !strings.HasPrefix(t, softraidPrefix) {
		return r, errors.New("not an OpenBSD softraid record")
	}
	f := strings.Split(t[len(softraidPrefix):], "$")
	if len(f) != 4 && len(f) != 5 {
		return r, errors.New("a softraid record is <iterations>$<salt>$<masked keys>$<mac>[$<kdf>]")
	}
	var err error
	if r.iterations, err = boundedPositiveInt(f[0], "softraid iteration count", 1<<24); err != nil {
		return r, err
	}
	if r.salt, err = decodeExactHex(f[1], softraidSaltLen, "softraid salt"); err != nil {
		return r, err
	}
	if r.masked, err = decodeExactHex(f[2], softraidMaskedSize, "softraid masked keys"); err != nil {
		return r, err
	}
	if r.mac, err = decodeExactHex(f[3], sha1.Size, "softraid MAC"); err != nil {
		return r, err
	}
	// An older record carries no KDF field and means PBKDF2.
	r.kdf = 1
	if len(f) == 5 {
		if r.kdf, err = boundedPositiveInt(f[4], "softraid KDF type", 16); err != nil {
			return r, err
		}
	}
	if r.kdf != 1 && r.kdf != 3 {
		return r, errors.New("this softraid record names a key derivation Hashsmith does not run")
	}
	return r, nil
}

func verifySoftraid(target, candidate string) (bool, error) {
	r, err := softraidFields(target)
	if err != nil {
		return false, err
	}
	var mask []byte
	if r.kdf == 3 {
		if mask, err = bcryptPBKDF([]byte(candidate), r.salt, 32, r.iterations); err != nil {
			return false, err
		}
	} else {
		mask = pbkdf2.Key([]byte(candidate), r.salt, r.iterations, 32, sha1.New)
	}

	block, err := aes.NewCipher(mask)
	if err != nil {
		return false, err
	}
	unmasked := make([]byte, softraidMaskedSize)
	for i := 0; i < softraidMaskedSize; i += aes.BlockSize {
		block.Decrypt(unmasked[i:i+aes.BlockSize], r.masked[i:i+aes.BlockSize])
	}

	keyHash := sha1.Sum(mask)
	mac := hmac.New(sha1.New, keyHash[:])
	_, _ = mac.Write(unmasked)
	return hmac.Equal(mac.Sum(nil), r.mac), nil
}

func isSoftraid(target string) bool {
	_, err := softraidFields(target)
	return err == nil
}
