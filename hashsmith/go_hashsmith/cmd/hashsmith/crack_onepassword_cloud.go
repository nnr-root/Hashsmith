package main

// 1Password cloud keychain — Hashcat 8200.
//
//	<expected HMAC>:<salt>:<iterations>:<data>
//
// PBKDF2-HMAC-SHA512 produces 64 bytes, used in halves: the first half is the
// encryption key, which cracking never needs, and the second is the key to an
// HMAC-SHA256 over the keychain payload. The record stores that MAC, so a
// guess is settled by recomputing it — no decryption, no plaintext heuristics.
//
// Hashcat compares the first 16 bytes of the MAC; the record carries all 32
// and there is no reason not to check them all.

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"strconv"
	"strings"

	"golang.org/x/crypto/pbkdf2"
)

type onePasswordCloudRecord struct {
	want       []byte
	salt       []byte
	iterations int
	data       []byte
}

func parseOnePasswordCloud(target string) (*onePasswordCloudRecord, error) {
	if rewritten, ok := johnCloudKeychainRecord(target); ok {
		target = rewritten
	}
	p := strings.Split(strings.TrimSpace(target), ":")
	if len(p) != 4 {
		return nil, errors.New("1Password cloud keychain record must be <hmac>:<salt>:<iterations>:<data>")
	}
	r := &onePasswordCloudRecord{}
	var err error
	if r.want, err = hex.DecodeString(p[0]); err != nil || len(r.want) != sha256.Size {
		return nil, errors.New("1Password cloud keychain HMAC must be 32 hex-encoded bytes")
	}
	if r.salt, err = hex.DecodeString(p[1]); err != nil || len(r.salt) == 0 {
		return nil, errors.New("1Password cloud keychain salt is not hex")
	}
	if r.iterations, err = strconv.Atoi(p[2]); err != nil || r.iterations < 1 {
		return nil, errors.New("1Password cloud keychain iterations must be a positive integer")
	}
	// The payload is the keychain itself; anything short enough to be a stray
	// field is not one.
	if r.data, err = hex.DecodeString(p[3]); err != nil || len(r.data) < 64 {
		return nil, errors.New("1Password cloud keychain payload is too short or not hex")
	}
	return r, nil
}

func verifyOnePasswordCloud(target, candidate string) (bool, error) {
	r, err := parseOnePasswordCloud(target)
	if err != nil {
		return false, err
	}
	derived := pbkdf2.Key([]byte(candidate), r.salt, r.iterations, 64, sha512.New)
	mac := hmac.New(sha256.New, derived[32:])
	_, _ = mac.Write(r.data)
	return hmac.Equal(mac.Sum(nil), r.want), nil
}

// looksLikeOnePasswordCloud reports whether a line is a 1Password cloud
// keychain record.
//
// The format carries no prefix — it is four colon-separated fields — so this
// is a structural claim rather than a signature one, and it is deliberately
// strict about the shape: a 32-byte MAC, a non-empty hex salt, a plain decimal
// iteration count, and a payload long enough to be a keychain rather than a
// stray field. `user:hash` lines and other colon-separated records fail on the
// first field's length alone.
func looksLikeOnePasswordCloud(s string) bool {
	_, err := parseOnePasswordCloud(s)
	return err == nil
}
