package main

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"hash"
	"strings"

	"golang.org/x/crypto/blake2b"
)

type compatDigestSpec struct {
	newHash       func() hash.Hash
	passwordUTF16 bool
	saltFirst     bool
}

var compatSaltedDigests = map[string]compatDigestSpec{
	"md5-pass-salt":            {md5.New, false, false},
	"md5-salt-pass":            {md5.New, false, true},
	"md5-utf16le-pass-salt":    {md5.New, true, false},
	"md5-salt-utf16le-pass":    {md5.New, true, true},
	"sha1-pass-salt":           {sha1.New, false, false},
	"sha1-salt-pass":           {sha1.New, false, true},
	"sha1-utf16le-pass-salt":   {sha1.New, true, false},
	"sha1-salt-utf16le-pass":   {sha1.New, true, true},
	"sha224-pass-salt":         {sha256.New224, false, false},
	"sha224-salt-pass":         {sha256.New224, false, true},
	"sha256-pass-salt":         {sha256.New, false, false},
	"sha256-salt-pass":         {sha256.New, false, true},
	"sha256-utf16le-pass-salt": {sha256.New, true, false},
	"sha256-salt-utf16le-pass": {sha256.New, true, true},
	"sha384-pass-salt":         {sha512.New384, false, false},
	"sha384-salt-pass":         {sha512.New384, false, true},
	"sha384-utf16le-pass-salt": {sha512.New384, true, false},
	"sha384-salt-utf16le-pass": {sha512.New384, true, true},
	"sha512-pass-salt":         {sha512.New, false, false},
	"sha512-salt-pass":         {sha512.New, false, true},
	"sha512-utf16le-pass-salt": {sha512.New, true, false},
	"sha512-salt-utf16le-pass": {sha512.New, true, true},
	"blake2b-pass-salt":        {newBlake2b512Hash, false, false},
	"blake2b-salt-pass":        {newBlake2b512Hash, false, true},
	"blake2b256-pass-salt":     {newBlake2b256Hash, false, false},
	"blake2b256-salt-pass":     {newBlake2b256Hash, false, true},
}

func newBlake2b512Hash() hash.Hash {
	h, _ := blake2b.New512(nil)
	return h
}

func newBlake2b256Hash() hash.Hash {
	h, _ := blake2b.New256(nil)
	return h
}

func hashCompatSaltedDigest(text, algorithm, salt string) (string, error) {
	spec, ok := compatSaltedDigests[algorithm]
	if !ok {
		return "", errors.New("unsupported compatibility digest")
	}
	if salt == "" {
		return "", errors.New(algorithm + " requires a salt")
	}
	password := []byte(text)
	if spec.passwordUTF16 {
		password = utf16le(text)
	}
	h := spec.newHash()
	if spec.saltFirst {
		_, _ = h.Write([]byte(salt))
		_, _ = h.Write(password)
	} else {
		_, _ = h.Write(password)
		_, _ = h.Write([]byte(salt))
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// verifyCompatSaltedDigest accepts the hash:salt input syntax used by Hashcat
// and John, while retaining -s for callers that keep the fields separate.
func verifyCompatSaltedDigest(candidate, target, algorithm, salt string) (bool, error) {
	effectiveTarget, effectiveSalt := target, salt
	if effectiveSalt == "" {
		i := strings.LastIndexByte(target, ':')
		if i < 1 || i == len(target)-1 {
			return false, errors.New(algorithm + " requires a hash:salt target or -s")
		}
		effectiveTarget, effectiveSalt = target[:i], target[i+1:]
	}
	effectiveTarget = strings.TrimPrefix(effectiveTarget, "$BLAKE2$")
	got, err := hashCompatSaltedDigest(candidate, algorithm, effectiveSalt)
	return err == nil && strings.EqualFold(got, effectiveTarget), err
}

func compatSaltedHashParts(target string) (digest, salt string, ok bool) {
	i := strings.LastIndexByte(target, ':')
	if i < 1 || i == len(target)-1 || !isHex(target[:i]) {
		return "", "", false
	}
	switch len(target[:i]) {
	case 32, 40, 56, 64, 96, 128:
		return target[:i], target[i+1:], true
	default:
		return "", "", false
	}
}

// detectCompatSaltedTypes returns every generic construction compatible with
// a digest's byte length.  They are necessarily ambiguous without metadata,
// so the auto-cracker tries them in the conventional Hashcat order.
func detectCompatSaltedTypes(target string) []string {
	digest, salt, ok := compatSaltedHashParts(target)
	if !ok {
		return nil
	}
	var simple []string
	switch len(digest) {
	case 32:
		simple = []string{"md5-pass-salt", "md5-salt-pass", "md5-utf16le-pass-salt", "md5-salt-utf16le-pass"}
	case 40:
		simple = []string{"sha1-pass-salt", "sha1-salt-pass", "sha1-utf16le-pass-salt", "sha1-salt-utf16le-pass"}
		if len(salt) == 40 && isHex(salt) {
			simple = append(simple, "rails-restful-auth-one-round")
		}
	case 56:
		return []string{"sha224-pass-salt", "sha224-salt-pass"}
	case 64:
		simple = []string{"sha256-pass-salt", "sha256-salt-pass", "sha256-utf16le-pass-salt", "sha256-salt-utf16le-pass"}
	case 96:
		return []string{"sha384-pass-salt", "sha384-salt-pass", "sha384-utf16le-pass-salt", "sha384-salt-utf16le-pass"}
	case 128:
		simple = []string{"sha512-pass-salt", "sha512-salt-pass", "sha512-utf16le-pass-salt", "sha512-salt-utf16le-pass"}
	default:
		return nil
	}
	// The composite constructions share this ciphertext shape, so they are
	// equally plausible — but they are rarer and cost more per candidate, so
	// they go behind the plain concatenations rather than ahead of them.
	return append(simple, compositeTypesForDigestLength(len(digest))...)
}

func detectBlake2HashcatTypes(target string) []string {
	if !strings.HasPrefix(target, "$BLAKE2$") {
		return nil
	}
	body := strings.TrimPrefix(target, "$BLAKE2$")
	digest, salted := body, false
	if i := strings.LastIndexByte(body, ':'); i >= 0 {
		if i == 0 || i == len(body)-1 {
			return nil
		}
		digest, salted = body[:i], true
	}
	if !isHex(digest) {
		return nil
	}
	switch {
	case len(digest) == 128 && salted:
		return []string{"blake2b-pass-salt", "blake2b-salt-pass"}
	case len(digest) == 128:
		return []string{"blake2b"}
	case len(digest) == 64 && salted:
		return []string{"blake2b256-pass-salt", "blake2b256-salt-pass"}
	case len(digest) == 64:
		return []string{"blake2s", "blake2b256"}
	default:
		return nil
	}
}

func hashUTF16Digest(text, algorithm string) (string, error) {
	var newHash func() hash.Hash
	switch algorithm {
	case "md5-utf16le":
		newHash = md5.New
	case "sha1-utf16le":
		newHash = sha1.New
	case "sha256-utf16le":
		newHash = sha256.New
	case "sha384-utf16le":
		newHash = sha512.New384
	case "sha512-utf16le":
		newHash = sha512.New
	default:
		return "", errors.New("unsupported UTF-16LE digest")
	}
	h := newHash()
	_, _ = h.Write(utf16le(text))
	return hex.EncodeToString(h.Sum(nil)), nil
}

func nestedCrossHex(innerHash, outerHash func() hash.Hash, text string, upper bool) string {
	inner := innerHash()
	_, _ = inner.Write([]byte(text))
	innerHex := hex.EncodeToString(inner.Sum(nil))
	if upper {
		innerHex = strings.ToUpper(innerHex)
	}
	outer := outerHash()
	_, _ = outer.Write([]byte(innerHex))
	return hex.EncodeToString(outer.Sum(nil))
}

func tripleMD5Hex(text string) string {
	first := md5.Sum([]byte(text))
	second := md5.Sum([]byte(hex.EncodeToString(first[:])))
	third := md5.Sum([]byte(hex.EncodeToString(second[:])))
	return hex.EncodeToString(third[:])
}
