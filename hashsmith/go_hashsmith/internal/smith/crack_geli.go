package smith

// FreeBSD's GELI full-disk encryption.
//
//	$geli$<version>$<?>$<ealgo>$<keylen>$<?>$<keys bitmap>$<iterations>$<salt>$<master keys>
//
// GELI does not encrypt the disk under the passphrase. It encrypts a MASTER
// KEY under it, and stores up to two independently wrapped copies so that a
// volume can have two passphrases. The bitmap says which slots are in use, and
// a candidate is checked against each in turn — so a hit tells you which slot
// it opened as well as that it opened one.
//
// The derivation is PBKDF2-HMAC-SHA512 over the passphrase, and then TWO steps
// that are easy to skip, each of which turns a correct password into what
// looks exactly like a wrong one.
//
// First, the PBKDF2 output is not the user key: the user key is HMAC-SHA512 of
// it under an EMPTY key. GELI does this because a passphrase and a key file
// are folded together by HMAC in the general case, and a volume with no key
// file still goes through the fold with nothing in it.
//
// Second, the user key is not the key either. Two keys come out of it by
// HMAC-SHA512 under the user key of a single byte — 0x01 for the one that
// decrypts the slot, 0x00 for the one that authenticates it.
//
// The slot's contents are a data key, an IV key, and an HMAC-SHA512 over the
// two of them. Only the first sixteen bytes of that HMAC are compared, which
// is GELI's own choice and is still 128 bits.

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"strings"

	"golang.org/x/crypto/pbkdf2"
)

const (
	geliPrefix        = "$geli$"
	geliSaltLen       = 64
	geliUserKeyLen    = 64
	geliDataIVKeyLen  = 128
	geliMasterKeyLen  = geliDataIVKeyLen + sha512.Size
	geliMaxMasterKeys = 2
)

type geliRecord struct {
	keyBits    int
	keysBitmap int
	iterations int
	salt       []byte
	masters    []byte
}

func geliFields(target string) (geliRecord, error) {
	var r geliRecord
	t := strings.TrimSpace(target)
	if !strings.HasPrefix(t, geliPrefix) {
		return r, errors.New("not a GELI record")
	}
	f := strings.Split(t[len(geliPrefix):], "$")
	if len(f) != 9 {
		return r, errors.New("a GELI record has nine fields")
	}
	var err error
	if r.keyBits, err = boundedPositiveInt(f[3], "GELI key length", 512); err != nil {
		return r, err
	}
	switch r.keyBits {
	case 128, 192, 256:
	default:
		return r, errors.New("a GELI key length is 128, 192 or 256 bits")
	}
	if r.keysBitmap, err = boundedPositiveInt(f[5], "GELI key slots", 3); err != nil {
		return r, err
	}
	if r.iterations, err = boundedPositiveInt(f[6], "GELI iteration count", 1<<24); err != nil {
		return r, err
	}
	if r.salt, err = decodeExactHex(f[7], geliSaltLen, "GELI salt"); err != nil {
		return r, err
	}
	if r.masters, err = hex.DecodeString(f[8]); err != nil || len(r.masters) < geliMasterKeyLen {
		return r, errors.New("a GELI record carries at least one wrapped master key")
	}
	return r, nil
}

func verifyGELI(target, candidate string) (bool, error) {
	r, err := geliFields(target)
	if err != nil {
		return false, err
	}
	pass := pbkdf2.Key([]byte(candidate), r.salt, r.iterations, geliUserKeyLen, sha512.New)
	// The fold that would mix in a key file, run with nothing to mix.
	fold := hmac.New(sha512.New, nil)
	_, _ = fold.Write(pass)
	derived := fold.Sum(nil)

	// The two keys the user key is only the seed for.
	enc := hmac.New(sha512.New, derived)
	_, _ = enc.Write([]byte{1})
	encKey := enc.Sum(nil)
	mac := hmac.New(sha512.New, derived)
	_, _ = mac.Write([]byte{0})
	macKey := mac.Sum(nil)

	block, err := aes.NewCipher(encKey[:r.keyBits/8])
	if err != nil {
		return false, err
	}
	for slot := 0; slot < geliMaxMasterKeys; slot++ {
		if r.keysBitmap&(1<<uint(slot)) == 0 {
			continue
		}
		off := slot * geliMasterKeyLen
		if off+geliMasterKeyLen > len(r.masters) {
			continue
		}
		out := make([]byte, geliMasterKeyLen)
		iv := make([]byte, aes.BlockSize)
		cipher.NewCBCDecrypter(block, iv).CryptBlocks(out, r.masters[off:off+geliMasterKeyLen])

		h := hmac.New(sha512.New, macKey)
		_, _ = h.Write(out[:geliDataIVKeyLen])
		// GELI compares sixteen bytes of the HMAC, not all sixty-four.
		if hmac.Equal(h.Sum(nil)[:16], out[geliDataIVKeyLen:geliDataIVKeyLen+16]) {
			return true, nil
		}
	}
	return false, nil
}

func isGELI(target string) bool {
	_, err := geliFields(target)
	return err == nil
}
