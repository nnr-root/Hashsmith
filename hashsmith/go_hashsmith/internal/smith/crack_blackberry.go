package smith

// BlackBerry Enterprise Server 10.
//
//	$bbes10$<digest>$<salt>
//
// One hash of the password and the salt, then ninety-nine more of the digest
// alone — a hundred rounds in total, with the salt never touched again. That
// is the entire work factor: a hundred SHA-512s is about a microsecond, so
// the salt is doing all of the work here and it is only stopping a rainbow
// table.
//
// The digest's length says which hash: BES10 used SHA-512, and the SHA-256
// spelling of the same record is read the same way.

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"hash"
	"strings"
)

const (
	blackberryPrefix = "$bbes10$"
	blackberryRounds = 100
)

func blackberryFields(target string) (newHash func() hash.Hash, salt string, digest []byte, err error) {
	t := strings.TrimSpace(target)
	if !strings.HasPrefix(t, blackberryPrefix) {
		return nil, "", nil, errors.New("not a BlackBerry ES10 record")
	}
	f := strings.Split(t[len(blackberryPrefix):], "$")
	if len(f) != 2 || f[1] == "" || len(f[1]) > maxKDFFieldSize {
		return nil, "", nil, errors.New("a BlackBerry ES10 record is $bbes10$<digest>$<salt>")
	}
	if digest, err = hex.DecodeString(f[0]); err != nil {
		return nil, "", nil, errors.New("invalid BlackBerry ES10 digest")
	}
	switch len(digest) {
	case sha512.Size:
		newHash = sha512.New
	case sha256.Size:
		newHash = sha256.New
	default:
		return nil, "", nil, errors.New("a BlackBerry ES10 digest is a SHA-256 or a SHA-512")
	}
	return newHash, f[1], digest, nil
}

// verifyBlackberryES10 checks a BES10 password.
func verifyBlackberryES10(target, candidate string) (bool, error) {
	newHash, salt, want, err := blackberryFields(target)
	if err != nil {
		return false, err
	}
	h := newHash()
	_, _ = h.Write([]byte(candidate))
	_, _ = h.Write([]byte(salt))
	d := h.Sum(nil)
	for i := 1; i < blackberryRounds; i++ {
		h.Reset()
		_, _ = h.Write(d)
		d = h.Sum(d[:0])
	}
	return hmac.Equal(d, want), nil
}

func isBlackberryES10(target string) bool {
	_, _, _, err := blackberryFields(target)
	return err == nil
}
