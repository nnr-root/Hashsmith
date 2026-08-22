package main

// Apache Shiro 1 SHA-512:
//
//   $shiro1$SHA-512$<iterations>$<base64 salt>$<base64 digest>
//
// The first round hashes salt || password. Every later round hashes the raw
// 64-byte result of the preceding round.

import (
	"crypto/sha512"
	"encoding/base64"
	"errors"
	"strconv"
	"strings"
)

type shiro1Hash struct {
	iterations int
	salt       []byte
	digest     []byte
}

func parseShiro1(target string) (*shiro1Hash, error) {
	parts := strings.Split(strings.TrimSpace(target), "$")
	if len(parts) != 6 || parts[0] != "" || parts[1] != "shiro1" || parts[2] != "SHA-512" {
		return nil, errors.New("invalid Apache Shiro 1 SHA-512 record")
	}
	iterations, err := strconv.Atoi(parts[3])
	if err != nil || iterations < 1 || iterations > maxKDFIterations {
		return nil, errors.New("invalid Apache Shiro 1 iteration count")
	}
	salt, err := base64.StdEncoding.DecodeString(parts[4])
	if err != nil || len(salt) == 0 || len(salt) > maxKDFFieldSize {
		return nil, errors.New("invalid Apache Shiro 1 salt")
	}
	digest, err := base64.StdEncoding.DecodeString(parts[5])
	if err != nil || len(digest) != sha512.Size {
		return nil, errors.New("invalid Apache Shiro 1 digest")
	}
	return &shiro1Hash{iterations: iterations, salt: salt, digest: digest}, nil
}

func verifyShiro1(target, candidate string) (bool, error) {
	parsed, err := parseShiro1(target)
	if err != nil {
		return false, err
	}
	input := make([]byte, 0, len(parsed.salt)+len(candidate))
	input = append(input, parsed.salt...)
	input = append(input, candidate...)
	sum := sha512.Sum512(input)
	digest := sum[:]
	for i := 1; i < parsed.iterations; i++ {
		next := sha512.Sum512(digest)
		digest = next[:]
	}
	return bytesEqualCT(digest, parsed.digest), nil
}

func isShiro1(target string) bool {
	_, err := parseShiro1(target)
	return err == nil
}
