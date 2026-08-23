package main

// Hashcat composite records that carry two independent salts or fixed literal
// separators and therefore do not fit the single-salt expression evaluator.

import (
	"crypto/md5"
	"crypto/sha1"
	"encoding/hex"
	"errors"
	"strings"
)

func verifyHashcatDualSaltComposite(target, candidate, variant string) (bool, error) {
	parts := strings.Split(target, ":")
	if len(parts) != 3 || len([]byte(candidate)) > 256 || len(parts[1]) > 256 || len(parts[2]) > 256 {
		return false, errors.New("invalid dual-salt composite record")
	}
	digest, salt1, salt2 := parts[0], parts[1], parts[2]
	var got string
	switch variant {
	case "sha1-salt1-pass-salt2":
		if len(digest) != 40 || !isHex(digest) {
			return false, errors.New("invalid SHA-1 dual-salt record")
		}
		sum := sha1.Sum([]byte(salt1 + candidate + salt2))
		got = hex.EncodeToString(sum[:])
	case "md5-salt1-sha1salt2pass":
		if len(digest) != 32 || !isHex(digest) {
			return false, errors.New("invalid MD5/SHA-1 dual-salt record")
		}
		inner := sha1.Sum([]byte(salt2 + candidate))
		outer := md5.Sum([]byte(salt1 + hex.EncodeToString(inner[:])))
		got = hex.EncodeToString(outer[:])
	case "md5-triple-passsalt-dual":
		if len(digest) != 32 || !isHex(digest) {
			return false, errors.New("invalid triple-MD5 dual-salt record")
		}
		first := md5.Sum([]byte(candidate + salt1))
		second := md5.Sum([]byte(hex.EncodeToString(first[:])))
		outer := md5.Sum([]byte(hex.EncodeToString(second[:]) + salt2))
		got = hex.EncodeToString(outer[:])
	default:
		return false, errors.New("unknown dual-salt composite variant")
	}
	return strings.EqualFold(got, digest), nil
}

func verifyRailsRestfulAuthOneRound(target, candidate string) (bool, error) {
	parts := strings.Split(target, ":")
	if len(parts) != 2 || len(parts[0]) != 40 || !isHex(parts[0]) ||
		len(parts[1]) != 40 || !isHex(parts[1]) || len([]byte(candidate)) > 256 {
		return false, errors.New("invalid one-round Rails Restful-Authentication record")
	}
	sum := sha1.Sum([]byte("--" + parts[1] + "--" + candidate + "--"))
	return strings.EqualFold(hex.EncodeToString(sum[:]), parts[0]), nil
}
