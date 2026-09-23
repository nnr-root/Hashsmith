package smith

// Bouncy Castle's keystore, in its two formats.
//
//	$bks$<format>$<version>$<MAC key bits>$<iterations>$<salt len>$<salt>$<store>$<MAC>
//
// Format 0 is the BKS keystore proper: a PKCS#12 derivation produces an HMAC
// key and the store's HMAC-SHA1 is checked against it. Format 1 is UBER, where
// the store is Twofish-encrypted and carries its own SHA-1 at the end.
//
// The BKS one has a flaw worth stating because it changes what a hit means.
// The MAC key's length is in the record, and Bouncy Castle wrote it in BITS —
// so a keystore saying 20 has a TWO-BYTE MAC key. Sixteen bits of key over a
// twenty-byte HMAC means many passwords produce the right MAC, and John marks
// such a record inexact for exactly that reason. A match on a store with a
// short MAC key says the candidate is one of a large family the keystore would
// accept, not that it is the password; a match on format 1, where the check is
// a full SHA-1 of the decrypted store, says the latter.

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/hex"
	"errors"
	"strconv"
	"strings"

	"golang.org/x/crypto/twofish"
)

const bksPrefix = "$bks$"

type bksRecord struct {
	format     int
	macKeyLen  int
	iterations int
	salt       []byte
	store      []byte
	mac        []byte
}

func bksFields(target string) (bksRecord, error) {
	var r bksRecord
	t := strings.TrimSpace(target)
	if !strings.HasPrefix(t, bksPrefix) {
		return r, errors.New("not a BKS keystore record")
	}
	f := strings.Split(t[len(bksPrefix):], "$")
	if len(f) < 7 {
		return r, errors.New("a BKS record is <format>$<version>$<mac bits>$<iterations>$<salt len>$<salt>$<store>[$<mac>]")
	}
	var err error
	if r.format, err = strconv.Atoi(f[0]); err != nil || (r.format != 0 && r.format != 1) {
		return r, errors.New("a BKS record's format is 0 (BKS) or 1 (UBER)")
	}
	macBits, err := boundedPositiveInt(f[2], "BKS MAC key size", 1<<16)
	if err != nil {
		return r, err
	}
	// Written in bits, and small enough in practice to be the reason a BKS
	// match is weak evidence.
	r.macKeyLen = macBits / 8
	if r.macKeyLen == 0 {
		return r, errors.New("a BKS MAC key is at least one byte")
	}
	if r.iterations, err = boundedPositiveInt(f[3], "BKS iteration count", 1<<24); err != nil {
		return r, err
	}
	saltLen, err := boundedPositiveInt(f[4], "BKS salt length", 256)
	if err != nil {
		return r, err
	}
	if r.salt, err = decodeExactHex(f[5], saltLen, "BKS salt"); err != nil {
		return r, err
	}
	if r.store, err = hex.DecodeString(f[6]); err != nil || len(r.store) == 0 {
		return r, errors.New("invalid BKS store data")
	}
	if r.format == 0 {
		if len(f) < 8 {
			return r, errors.New("a BKS keystore record carries its store MAC")
		}
		if r.mac, err = decodeExactHex(f[7][:min(len(f[7]), 40)], sha1.Size, "BKS store MAC"); err != nil {
			return r, err
		}
	} else if len(r.store) <= sha1.Size {
		return r, errors.New("an UBER store is longer than its trailing checksum")
	}
	return r, nil
}

func verifyBKS(target, candidate string) (bool, error) {
	r, err := bksFields(target)
	if err != nil {
		return false, err
	}
	if r.format == 0 {
		// Diversifier 3 is PKCS#12's "MAC key" purpose.
		key := pkcs12KDF(candidate, r.salt, r.iterations, 3, r.macKeyLen, sha1.New)
		mac := hmac.New(sha1.New, key)
		_, _ = mac.Write(r.store)
		return hmac.Equal(mac.Sum(nil), r.mac), nil
	}

	iv := pkcs12KDF(candidate, r.salt, r.iterations, 2, 16, sha1.New)
	key := pkcs12KDF(candidate, r.salt, r.iterations, 1, 32, sha1.New)
	c, err := twofish.NewCipher(key)
	if err != nil {
		return false, err
	}
	if len(r.store)%c.BlockSize() != 0 {
		return false, nil
	}
	out := make([]byte, len(r.store))
	// CBC by hand, because the padding has to be read before the plaintext can
	// be trusted and Go's CBC decrypter does not report it.
	prev := iv
	for off := 0; off < len(out); off += c.BlockSize() {
		c.Decrypt(out[off:off+c.BlockSize()], r.store[off:off+c.BlockSize()])
		for i := 0; i < c.BlockSize(); i++ {
			out[off+i] ^= prev[i]
		}
		prev = r.store[off : off+c.BlockSize()]
	}
	pad := int(out[len(out)-1])
	if pad < 1 || pad > c.BlockSize() || pad > len(out) {
		return false, nil
	}
	plain := out[:len(out)-pad]
	if len(plain) <= sha1.Size {
		return false, nil
	}
	want := plain[len(plain)-sha1.Size:]
	got := sha1.Sum(plain[:len(plain)-sha1.Size])
	return hmac.Equal(got[:], want), nil
}

func isBKS(target string) bool {
	_, err := bksFields(target)
	return err == nil
}
