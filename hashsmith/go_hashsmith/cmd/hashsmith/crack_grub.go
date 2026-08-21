package main

// GRUB 2 password hashes:
//
//	grub.pbkdf2.sha512.<iterations>.<salt_hex>.<derived_key_hex>

// The optional leading '$' accepted here is emitted by a few conversion tools.

import (
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"strconv"
	"strings"

	"golang.org/x/crypto/pbkdf2"
)

type grub2Hash struct {
	iterations int
	salt       []byte
	digest     []byte
}

func parseGRUB2Hash(target string) (*grub2Hash, error) {
	value := strings.TrimPrefix(strings.TrimSpace(target), "$")
	parts := strings.Split(value, ".")
	if len(parts) != 6 || !strings.EqualFold(parts[0], "grub") ||
		!strings.EqualFold(parts[1], "pbkdf2") || !strings.EqualFold(parts[2], "sha512") {
		return nil, errors.New("invalid GRUB2 hash format")
	}
	iterations, err := strconv.Atoi(parts[3])
	if err != nil || iterations < 1 || iterations > 100_000_000 {
		return nil, errors.New("invalid GRUB2 iteration count")
	}
	salt, err := hex.DecodeString(parts[4])
	if err != nil || len(salt) == 0 {
		return nil, errors.New("invalid GRUB2 salt")
	}
	digest, err := hex.DecodeString(parts[5])
	if err != nil || len(digest) == 0 || len(digest) > 128 {
		return nil, errors.New("invalid GRUB2 derived key")
	}
	return &grub2Hash{iterations: iterations, salt: salt, digest: digest}, nil
}

func verifyGRUB2(target, candidate string) (bool, error) {
	parsed, err := parseGRUB2Hash(target)
	if err != nil {
		return false, err
	}
	got := pbkdf2.Key([]byte(candidate), parsed.salt, parsed.iterations, len(parsed.digest), sha512.New)
	return bytesEqualCT(got, parsed.digest), nil
}

func isGRUB2(target string) bool {
	_, err := parseGRUB2Hash(target)
	return err == nil
}
