package main

// Enpass, which is a SQLCipher database with a password on it.
//
//	$enpass$<version>$<iterations>$<the database's first page>
//
// SQLCipher stores the salt as the first sixteen bytes of the file, in the
// clear, and closes every page with an HMAC over the page's ciphertext, its
// IV and its page number. That MAC is what a password is checked against:
// nothing is decrypted, so a candidate costs one PBKDF2 and one HMAC over a
// kilobyte.
//
// Two details of SQLCipher's layout decide where those bytes are. The HMAC
// key is derived from the ENCRYPTION key — not the password — with a salt
// that is the file's salt with every byte XORed by 0x3a, and two iterations.
// And the last 48 bytes of each page are reserved: sixteen for the IV, twenty
// for the MAC, and twelve of padding that carry nothing.

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"strconv"
	"strings"

	"golang.org/x/crypto/pbkdf2"
)

const (
	enpassPrefix = "$enpass$"
	// sqlCipherReserve is what SQLCipher keeps at the end of every page: the
	// IV, the MAC, and padding to a cipher-block boundary.
	sqlCipherReserve = 48
	sqlCipherSaltLen = 16
	// sqlCipherHMACSaltMask is the byte SQLCipher XORs the file's salt with to
	// get the salt for the MAC key.
	sqlCipherHMACSaltMask = 0x3a
)

type enpassRecord struct {
	iterations int
	page       []byte
}

func parseEnpass(target string) (*enpassRecord, error) {
	t := strings.TrimSpace(target)
	if !strings.HasPrefix(t, enpassPrefix) {
		return nil, errors.New("not an Enpass record")
	}
	f := strings.Split(t[len(enpassPrefix):], "$")
	if len(f) != 3 {
		return nil, errors.New("an Enpass record is $enpass$<version>$<iterations>$<page>")
	}
	if f[0] != "0" {
		return nil, errors.New("unsupported Enpass record version " + f[0])
	}
	r := &enpassRecord{}
	var err error
	if r.iterations, err = strconv.Atoi(f[1]); err != nil ||
		r.iterations < 1 || r.iterations > maxKDFIterations {
		return nil, errors.New("invalid Enpass iteration count")
	}
	if r.page, err = hex.DecodeString(f[2]); err != nil ||
		len(r.page) < sqlCipherSaltLen+sqlCipherReserve {
		return nil, errors.New("invalid Enpass database page")
	}
	return r, nil
}

// verifyEnpass checks a password against the first page of the database.
func verifyEnpass(target, candidate string) (bool, error) {
	r, err := parseEnpass(target)
	if err != nil {
		return false, err
	}
	salt := r.page[:sqlCipherSaltLen]
	key := pbkdf2.Key([]byte(candidate), salt, r.iterations, 32, sha1.New)

	hmacSalt := make([]byte, len(salt))
	for i, b := range salt {
		hmacSalt[i] = b ^ sqlCipherHMACSaltMask
	}
	hmacKey := pbkdf2.Key(key, hmacSalt, 2, 32, sha1.New)

	n := len(r.page)
	data := r.page[sqlCipherSaltLen : n-sqlCipherReserve]
	iv := r.page[n-sqlCipherReserve : n-sqlCipherReserve+16]
	want := r.page[n-sqlCipherReserve+16 : n-sqlCipherReserve+16+sha1.Size]

	mac := hmac.New(sha1.New, hmacKey)
	_, _ = mac.Write(data)
	_, _ = mac.Write(iv)
	var pageNo [4]byte
	// The page this record carries is the first one.
	binary.LittleEndian.PutUint32(pageNo[:], 1)
	_, _ = mac.Write(pageNo[:])
	return hmac.Equal(mac.Sum(nil), want), nil
}

func isEnpass(target string) bool {
	_, err := parseEnpass(target)
	return err == nil
}
