package main

// Red Hat / 389 Directory Server's legacy PBKDF2_SHA256 password-storage
// scheme. The Base64 payload is fixed-width:
//
//   uint32be(iterations) || salt[64] || PBKDF2-HMAC-SHA256(password)[256]

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"strings"

	"golang.org/x/crypto/pbkdf2"
)

const (
	redHat389Prefix     = "{PBKDF2_SHA256}"
	redHat389SaltLen    = 64
	redHat389DigestLen  = 256
	redHat389PayloadLen = 4 + redHat389SaltLen + redHat389DigestLen
)

type redHat389Hash struct {
	iterations int
	salt       []byte
	digest     []byte
}

func parseRedHat389PBKDF2(target string) (*redHat389Hash, error) {
	if len(target) < len(redHat389Prefix) || !strings.EqualFold(target[:len(redHat389Prefix)], redHat389Prefix) {
		return nil, errors.New("invalid 389-DS PBKDF2 prefix")
	}
	raw, err := base64.StdEncoding.DecodeString(target[len(redHat389Prefix):])
	if err != nil || len(raw) != redHat389PayloadLen {
		return nil, errors.New("invalid 389-DS PBKDF2 payload")
	}
	iterations := int(binary.BigEndian.Uint32(raw[:4]))
	if iterations < 2048 || iterations > maxKDFIterations {
		return nil, errors.New("invalid 389-DS PBKDF2 iteration count")
	}
	return &redHat389Hash{
		iterations: iterations,
		salt:       raw[4 : 4+redHat389SaltLen],
		digest:     raw[4+redHat389SaltLen:],
	}, nil
}

func verifyRedHat389PBKDF2(target, candidate string) (bool, error) {
	parsed, err := parseRedHat389PBKDF2(target)
	if err != nil {
		return false, err
	}
	got := pbkdf2.Key([]byte(candidate), parsed.salt, parsed.iterations, len(parsed.digest), sha256.New)
	return bytesEqualCT(got, parsed.digest), nil
}

func isRedHat389PBKDF2(target string) bool {
	_, err := parseRedHat389PBKDF2(target)
	return err == nil
}

func encodeRedHat389PBKDF2(password string, salt []byte, iterations int) (string, error) {
	if len(salt) != redHat389SaltLen {
		return "", errors.New("389-DS PBKDF2 requires exactly 64 salt bytes")
	}
	if iterations < 2048 || iterations > maxKDFIterations {
		return "", errors.New("389-DS PBKDF2 iterations must be between 2048 and 100000000")
	}
	raw := make([]byte, redHat389PayloadLen)
	binary.BigEndian.PutUint32(raw[:4], uint32(iterations))
	copy(raw[4:], salt)
	copy(raw[4+redHat389SaltLen:], pbkdf2.Key(
		[]byte(password), salt, iterations, redHat389DigestLen, sha256.New,
	))
	return redHat389Prefix + base64.StdEncoding.EncodeToString(raw), nil
}
