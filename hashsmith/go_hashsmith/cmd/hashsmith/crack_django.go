package main

// Django password hashes. Supported records mirror Django's built-in hashers:
//
//	pbkdf2_sha256$<iterations>$<salt>$<base64(dk)>
//	pbkdf2_sha1$<iterations>$<salt>$<base64(dk)>
//	scrypt$<N>$<salt>$<r>$<p>$<base64(dk)>
//	argon2$argon2id$...
//	bcrypt_sha256$$2b$...
//	md5$<salt>$<hex digest> / sha1$<salt>$<hex digest>
//
// The derived-key length is taken from the stored digest, and the salt is used
// verbatim (not decoded). Verification recomputes PBKDF2 and compares.

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"hash"
	"strconv"
	"strings"

	"golang.org/x/crypto/bcrypt"
	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/crypto/scrypt"
)

// verifyDjango checks a candidate against a built-in Django password record.
func verifyDjango(targetHash, candidate string) (bool, error) {
	parts := strings.Split(targetHash, "$")
	if len(parts) == 0 {
		return false, errors.New("invalid Django password hash")
	}
	switch parts[0] {
	case "pbkdf2_sha256":
		return verifyDjangoPBKDF2(parts, candidate, sha256.New)
	case "pbkdf2_sha1":
		return verifyDjangoPBKDF2(parts, candidate, sha1.New)
	case "scrypt":
		return verifyDjangoScrypt(parts, candidate)
	case "argon2":
		if len(parts) != 6 || !strings.HasPrefix(targetHash, "argon2$argon2") {
			return false, errors.New("invalid Django Argon2 hash")
		}
		return verifyArgon2(strings.TrimPrefix(targetHash, "argon2"), candidate), nil
	case "bcrypt_sha256", "bcrypt":
		prefix := parts[0] + "$"
		encoded := strings.TrimPrefix(targetHash, prefix)
		if !strings.HasPrefix(encoded, "$2") {
			return false, errors.New("invalid Django bcrypt hash")
		}
		password := []byte(candidate)
		if parts[0] == "bcrypt_sha256" {
			digest := sha256.Sum256(password)
			password = []byte(hex.EncodeToString(digest[:]))
		}
		return bcrypt.CompareHashAndPassword([]byte(encoded), password) == nil, nil
	case "md5", "sha1":
		if len(parts) != 3 || parts[1] == "" || len(parts[1]) > maxKDFFieldSize {
			return false, errors.New("invalid legacy Django salted hash")
		}
		var got string
		if parts[0] == "md5" {
			digest := md5.Sum([]byte(parts[1] + candidate))
			got = hex.EncodeToString(digest[:])
		} else {
			digest := sha1.Sum([]byte(parts[1] + candidate))
			got = hex.EncodeToString(digest[:])
		}
		if len(parts[2]) != len(got) || !isHex(parts[2]) {
			return false, errors.New("invalid legacy Django digest")
		}
		return bytesEqualCT([]byte(strings.ToLower(parts[2])), []byte(got)), nil
	default:
		return false, errors.New("unsupported Django algorithm " + parts[0])
	}
}

func verifyDjangoPBKDF2(parts []string, candidate string, newHash func() hash.Hash) (bool, error) {
	if len(parts) != 4 || parts[2] == "" || len(parts[2]) > maxKDFFieldSize {
		return false, errors.New("invalid Django PBKDF2 hash")
	}
	iter, err := strconv.Atoi(parts[1])
	if err != nil || iter < 1 || iter > maxKDFIterations {
		return false, errors.New("invalid Django iteration count")
	}
	want, err := base64.StdEncoding.DecodeString(parts[3])
	if err != nil || len(want) != newHash().Size() {
		return false, errors.New("invalid Django base64 digest")
	}
	got := pbkdf2.Key([]byte(candidate), []byte(parts[2]), iter, len(want), newHash)
	return bytesEqualCT(got, want), nil
}

func verifyDjangoScrypt(parts []string, candidate string) (bool, error) {
	if len(parts) != 6 || parts[2] == "" || len(parts[2]) > maxKDFFieldSize {
		return false, errors.New("invalid Django scrypt hash")
	}
	n, errN := strconv.Atoi(parts[1])
	r, errR := strconv.Atoi(parts[3])
	p, errP := strconv.Atoi(parts[4])
	if errN != nil || errR != nil || errP != nil || n < 2 || n&(n-1) != 0 || r < 1 || p < 1 ||
		r > 1<<20 || p > 1<<20 || uint64(132)*uint64(n)*uint64(r)*uint64(p) > maxScryptMemory {
		return false, errors.New("unsafe Django scrypt parameters")
	}
	want, err := base64.StdEncoding.DecodeString(parts[5])
	if err != nil || len(want) != 64 {
		return false, errors.New("invalid Django scrypt digest")
	}
	got, err := scrypt.Key([]byte(candidate), []byte(parts[2]), n, r, p, len(want))
	if err != nil {
		return false, err
	}
	return bytesEqualCT(got, want), nil
}

// isDjangoHash reports whether s has a supported Django envelope and passes
// cheap structural validation. Verification still performs the cost checks.
func isDjangoHash(s string) bool {
	parts := strings.Split(s, "$")
	if len(parts) == 0 {
		return false
	}
	switch parts[0] {
	case "pbkdf2_sha256", "pbkdf2_sha1":
		return len(parts) == 4
	case "scrypt":
		return len(parts) == 6
	case "argon2":
		return len(parts) == 6 && strings.HasPrefix(s, "argon2$argon2")
	case "bcrypt_sha256", "bcrypt":
		return strings.HasPrefix(s, parts[0]+"$$2")
	case "md5":
		return len(parts) == 3 && len(parts[2]) == 32 && isHex(parts[2])
	case "sha1":
		return len(parts) == 3 && len(parts[2]) == 40 && isHex(parts[2])
	default:
		return false
	}
}
