package main

// Password formats used by Python frameworks and ASP.NET Identity.

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"strconv"
	"strings"

	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/crypto/scrypt"
)

const (
	maxKDFIterations = 100_000_000
	maxKDFFieldSize  = 1024
	maxScryptMemory  = 512 << 20
)

func pbkdf2HashFactory(name string) (func() hash.Hash, bool) {
	switch strings.ToLower(strings.ReplaceAll(name, "-", "")) {
	case "md5":
		return md5.New, true
	case "sha1":
		return sha1.New, true
	case "sha224":
		return sha256.New224, true
	case "sha256":
		return sha256.New, true
	case "sha384":
		return sha512.New384, true
	case "sha512":
		return sha512.New, true
	default:
		return nil, false
	}
}

func decodePasslibBase64(text string) ([]byte, error) {
	return decodeBase64Flexible(strings.ReplaceAll(text, ".", "+"), false)
}

type passlibPBKDF2Hash struct {
	rounds  int
	salt    []byte
	digest  []byte
	newHash func() hash.Hash
}

func parsePasslibPBKDF2(target string) (*passlibPBKDF2Hash, error) {
	parts := strings.Split(target, "$")
	if len(parts) != 5 || parts[0] != "" {
		return nil, errors.New("invalid Passlib PBKDF2 format")
	}
	name := strings.ToLower(parts[1])
	if !strings.HasPrefix(name, "pbkdf2-") {
		return nil, errors.New("invalid Passlib PBKDF2 identifier")
	}
	newHash, ok := pbkdf2HashFactory(strings.TrimPrefix(name, "pbkdf2-"))
	if !ok || (name != "pbkdf2-sha1" && name != "pbkdf2-sha256" && name != "pbkdf2-sha512") {
		return nil, errors.New("unsupported Passlib PBKDF2 digest")
	}
	rounds, err := strconv.Atoi(parts[2])
	if err != nil || rounds < 1 || rounds > maxKDFIterations {
		return nil, errors.New("invalid Passlib PBKDF2 round count")
	}
	salt, err := decodePasslibBase64(parts[3])
	if err != nil || len(salt) == 0 || len(salt) > maxKDFFieldSize {
		return nil, errors.New("invalid Passlib PBKDF2 salt")
	}
	digest, err := decodePasslibBase64(parts[4])
	if err != nil || len(digest) != newHash().Size() {
		return nil, errors.New("invalid Passlib PBKDF2 checksum")
	}
	return &passlibPBKDF2Hash{rounds: rounds, salt: salt, digest: digest, newHash: newHash}, nil
}

func verifyPasslibPBKDF2(target, candidate string) (bool, error) {
	parsed, err := parsePasslibPBKDF2(target)
	if err != nil {
		return false, err
	}
	got := pbkdf2.Key([]byte(candidate), parsed.salt, parsed.rounds, len(parsed.digest), parsed.newHash)
	return bytesEqualCT(got, parsed.digest), nil
}

func isPasslibPBKDF2(target string) bool {
	_, err := parsePasslibPBKDF2(target)
	return err == nil
}

type werkzeugHash struct {
	method  string
	newHash func() hash.Hash
	rounds  int
	n, r, p int
	salt    []byte
	digest  []byte
}

func parseWerkzeugHash(target string) (*werkzeugHash, error) {
	parts := strings.SplitN(target, "$", 3)
	if len(parts) != 3 || parts[1] == "" || len(parts[1]) > maxKDFFieldSize {
		return nil, errors.New("invalid Werkzeug password hash")
	}
	w := &werkzeugHash{method: parts[0], salt: []byte(parts[1])}
	method := strings.Split(parts[0], ":")
	switch method[0] {
	case "pbkdf2":
		if len(method) != 3 {
			return nil, errors.New("invalid Werkzeug PBKDF2 parameters")
		}
		var ok bool
		w.newHash, ok = pbkdf2HashFactory(method[1])
		if !ok {
			return nil, errors.New("unsupported Werkzeug PBKDF2 digest")
		}
		var err error
		w.rounds, err = strconv.Atoi(method[2])
		if err != nil || w.rounds < 1 || w.rounds > maxKDFIterations {
			return nil, errors.New("invalid Werkzeug PBKDF2 iteration count")
		}
	case "scrypt":
		if len(method) != 4 {
			return nil, errors.New("invalid Werkzeug scrypt parameters")
		}
		var err error
		if w.n, err = strconv.Atoi(method[1]); err != nil {
			return nil, errors.New("invalid Werkzeug scrypt N")
		}
		if w.r, err = strconv.Atoi(method[2]); err != nil {
			return nil, errors.New("invalid Werkzeug scrypt r")
		}
		if w.p, err = strconv.Atoi(method[3]); err != nil {
			return nil, errors.New("invalid Werkzeug scrypt p")
		}
		if w.n < 2 || w.n&(w.n-1) != 0 || w.r < 1 || w.p < 1 ||
			w.r > 1<<20 || w.p > 1<<20 || uint64(132)*uint64(w.n)*uint64(w.r)*uint64(w.p) > maxScryptMemory {
			return nil, errors.New("unsafe Werkzeug scrypt parameters")
		}
	default:
		return nil, errors.New("unsupported Werkzeug password method")
	}
	digest, err := hex.DecodeString(parts[2])
	if err != nil || len(digest) == 0 || len(digest) > maxKDFFieldSize {
		return nil, errors.New("invalid Werkzeug password checksum")
	}
	if w.newHash != nil && len(digest) != w.newHash().Size() {
		return nil, errors.New("invalid Werkzeug PBKDF2 checksum length")
	}
	if method[0] == "scrypt" && len(digest) != 64 {
		return nil, errors.New("invalid Werkzeug scrypt checksum length")
	}
	w.digest = digest
	return w, nil
}

func verifyWerkzeug(target, candidate string) (bool, error) {
	w, err := parseWerkzeugHash(target)
	if err != nil {
		return false, err
	}
	var got []byte
	if w.newHash != nil {
		got = pbkdf2.Key([]byte(candidate), w.salt, w.rounds, len(w.digest), w.newHash)
	} else {
		got, err = scrypt.Key([]byte(candidate), w.salt, w.n, w.r, w.p, len(w.digest))
		if err != nil {
			return false, err
		}
	}
	return bytesEqualCT(got, w.digest), nil
}

func isWerkzeug(target string) bool {
	_, err := parseWerkzeugHash(target)
	return err == nil
}

type aspNetIdentityHash struct {
	iterations int
	salt       []byte
	digest     []byte
	newHash    func() hash.Hash
	version    int
}

func parseASPNetIdentity(target string) (*aspNetIdentityHash, error) {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(target))
	if err != nil || len(raw) == 0 {
		return nil, errors.New("invalid ASP.NET Identity Base64")
	}
	switch raw[0] {
	case 0:
		if len(raw) != 49 {
			return nil, errors.New("invalid ASP.NET Identity v2 payload")
		}
		return &aspNetIdentityHash{
			iterations: 1000, salt: raw[1:17], digest: raw[17:], newHash: sha1.New, version: 2,
		}, nil
	case 1:
		if len(raw) < 13+16+16 {
			return nil, errors.New("invalid ASP.NET Identity v3 payload")
		}
		prf := binary.BigEndian.Uint32(raw[1:5])
		iterations := int(binary.BigEndian.Uint32(raw[5:9]))
		saltLen := int(binary.BigEndian.Uint32(raw[9:13]))
		if iterations < 1 || iterations > maxKDFIterations || saltLen < 16 || saltLen > maxKDFFieldSize ||
			13+saltLen > len(raw) {
			return nil, errors.New("invalid ASP.NET Identity v3 parameters")
		}
		var newHash func() hash.Hash
		switch prf {
		case 0:
			newHash = sha1.New
		case 1:
			newHash = sha256.New
		case 2:
			newHash = sha512.New
		default:
			return nil, fmt.Errorf("unsupported ASP.NET Identity PRF %d", prf)
		}
		digest := raw[13+saltLen:]
		if len(digest) < 16 || len(digest) > maxKDFFieldSize {
			return nil, errors.New("invalid ASP.NET Identity v3 subkey")
		}
		return &aspNetIdentityHash{
			iterations: iterations, salt: raw[13 : 13+saltLen], digest: digest, newHash: newHash, version: 3,
		}, nil
	default:
		return nil, errors.New("unknown ASP.NET Identity format marker")
	}
}

func verifyASPNetIdentity(target, candidate string) (bool, error) {
	parsed, err := parseASPNetIdentity(target)
	if err != nil {
		return false, err
	}
	got := pbkdf2.Key([]byte(candidate), parsed.salt, parsed.iterations, len(parsed.digest), parsed.newHash)
	return bytesEqualCT(got, parsed.digest), nil
}

func isASPNetIdentity(target string) bool {
	_, err := parseASPNetIdentity(target)
	return err == nil
}
