package main

// The Java keystore's own password, as distinct from the password on a key
// inside it.
//
//	$keystore$0$<length>$<the store bytes>$<20-byte digest>$…
//
// A JKS file ends with a SHA-1 over the password and everything before it,
// which is how the tooling tells a wrong store password from a corrupt file.
// That makes it the cheapest possible check — one SHA-1 over a few kilobytes,
// no key derivation at all — and it is the password that opens the whole
// store rather than one entry in it.
//
// The constant in the middle is Sun's, verbatim and undocumented beyond the
// source it appears in: the password is hashed as UTF-16BE, then the ASCII
// bytes of "Mighty Aphrodite", then the store.

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/hex"
	"errors"
	"strconv"
	"strings"
)

const (
	keystorePrefix = "$keystore$"
	// keystoreSalt is Sun's constant, spelled as it is in the JDK source.
	keystoreSalt = "Mighty Aphrodite"
)

// keystoreFields reads the store bytes and the digest that closes the file.
func keystoreFields(target string) (store, digest []byte, err error) {
	t := strings.TrimSpace(target)
	if !strings.HasPrefix(t, keystorePrefix) {
		return nil, nil, errors.New("not a Java keystore record")
	}
	f := strings.Split(t[len(keystorePrefix):], "$")
	if len(f) < 4 || f[0] != "0" {
		return nil, nil, errors.New("a Java keystore record is $keystore$0$<length>$<store>$<digest>")
	}
	n, err := strconv.Atoi(f[1])
	if err != nil || n < 1 || n > 1<<24 {
		return nil, nil, errors.New("invalid Java keystore length")
	}
	if store, err = hex.DecodeString(f[2]); err != nil || len(store) != n {
		return nil, nil, errors.New("invalid Java keystore data")
	}
	if digest, err = decodeExactHex(f[3], sha1.Size, "Java keystore digest"); err != nil {
		return nil, nil, err
	}
	return store, digest, nil
}

// verifyKeystore checks a keystore password.
func verifyKeystore(target, candidate string) (bool, error) {
	store, digest, err := keystoreFields(target)
	if err != nil {
		return false, err
	}
	h := sha1.New()
	_, _ = h.Write(utf16be(candidate))
	_, _ = h.Write([]byte(keystoreSalt))
	_, _ = h.Write(store)
	return hmac.Equal(h.Sum(nil), digest), nil
}

func isKeystore(target string) bool {
	_, _, err := keystoreFields(target)
	return err == nil
}
