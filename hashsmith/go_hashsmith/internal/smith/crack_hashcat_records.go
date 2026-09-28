package smith

// Compact application records added for Hashcat/John interoperability. These
// are kept together because they are all self-contained digest/KDF envelopes
// rather than encrypted containers.

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"fmt"
	"golang.org/x/crypto/md4"
	"hash"
	"strconv"
	"strings"

	"golang.org/x/crypto/pbkdf2"
)

func verifyDANESHA256(target, candidate string) (bool, error) {
	if len(target) != 56 || !isHex(target) {
		return false, errors.New("invalid DANE SHA2-256 digest (need 56 hex chars)")
	}
	sum := sha256.Sum256([]byte(candidate))
	return strings.EqualFold(hex.EncodeToString(sum[:28]), target), nil
}

func verifySamsungAndroid(target, candidate string) (bool, error) {
	parts := strings.Split(target, ":")
	if len(parts) != 2 || len(parts[0]) != 40 || !isHex(parts[0]) ||
		len(parts[1]) == 0 || len(parts[1]) > 16 {
		return false, errors.New("invalid Samsung Android password/PIN record")
	}
	salt := parts[1]
	first := sha1.Sum([]byte("0" + candidate + salt))
	digest := first[:]
	for i := 1; i < 1024; i++ {
		h := sha1.New()
		_, _ = h.Write(digest)
		_, _ = fmt.Fprintf(h, "%d%s%s", i, candidate, salt)
		digest = h.Sum(nil)
	}
	return strings.EqualFold(hex.EncodeToString(digest), parts[0]), nil
}

func verifySSPR(target, candidate string) (bool, error) {
	parts := strings.Split(target, "$")
	if len(parts) != 6 || parts[0] != "" || parts[1] != "sspr" {
		return false, errors.New("invalid NetIQ/Adobe SSPR record")
	}
	version, err := strconv.Atoi(parts[2])
	if err != nil || version < 0 || version > 4 {
		return false, errors.New("unsupported SSPR version")
	}
	iterations, err := strconv.Atoi(parts[3])
	if err != nil || iterations < 1 || iterations > maxKDFIterations {
		return false, errors.New("invalid SSPR iteration count")
	}
	if len(parts[4]) == 0 || len(parts[4]) > maxKDFFieldSize {
		return false, errors.New("invalid SSPR salt")
	}
	var newHash func() hash.Hash
	switch version {
	case 0:
		newHash = md5.New
	case 1, 2:
		newHash = sha1.New
	case 3:
		newHash = sha256.New
	case 4:
		newHash = sha512.New
	}
	if (version < 2 && parts[4] != "NONE") || (version >= 2 && parts[4] == "NONE") {
		return false, errors.New("invalid SSPR salt for version")
	}
	want, err := hex.DecodeString(parts[5])
	if err != nil || len(want) != newHash().Size() {
		return false, errors.New("invalid SSPR checksum")
	}
	initial := candidate
	if version >= 2 {
		// NetIQ hashes the serialized Base64 salt text; Adobe AEM hashes its
		// serialized hexadecimal salt. In both records that is parts[4].
		initial = parts[4] + candidate
	}
	h := newHash()
	_, _ = h.Write([]byte(initial))
	digest := h.Sum(nil)
	for i := 1; i < iterations; i++ {
		h = newHash()
		_, _ = h.Write(digest)
		digest = h.Sum(nil)
	}
	return bytesEqualCT(digest, want), nil
}

func isSSPR(target string) bool {
	return strings.HasPrefix(target, "$sspr$")
}

// pbkdf2HMACAlgos are the hashes that appear in a "$pbkdf2-hmac-<alg>$"
// record. hashcat reaches this family through NetIQ SSPR and publishes only
// SHA-1 and SHA-512; John writes the same envelope for MD4 and MD5 too.
var pbkdf2HMACAlgos = map[string]func() hash.Hash{
	"md4":    md4.New,
	"md5":    md5.New,
	"sha1":   sha1.New,
	"sha256": sha256.New,
	"sha512": sha512.New,
}

// verifyNetIQPBKDF2 reads a "$pbkdf2-hmac-<alg>$<iterations><sep><salt><sep><digest>"
// record, where salt and digest are hex.
//
// The separator is not consistent, and not between tools but WITHIN them:
// hashcat's SHA-1 record uses '$' while its SHA-512 record uses '.', and
// John's SHA-1 record uses '.'. This used to hard-code one separator per
// algorithm, which meant hashcat's SHA-1 and John's SHA-512 both parsed and
// John's SHA-1 did not. Either separator is accepted for any algorithm now;
// nothing else distinguishes them, so nothing is lost by not caring.
func verifyNetIQPBKDF2(target, candidate string) (bool, error) {
	algo, body, ok := splitPBKDF2HMACPrefix(target)
	if !ok {
		return false, errors.New("invalid PBKDF2-HMAC record")
	}
	newHash := pbkdf2HMACAlgos[algo]

	fields := strings.Split(body, "$")
	if len(fields) != 3 {
		fields = strings.Split(body, ".")
	}
	if len(fields) != 3 {
		return false, errors.New("invalid PBKDF2-HMAC record fields")
	}
	iterations, err := strconv.Atoi(fields[0])
	if err != nil {
		return false, errors.New("invalid PBKDF2-HMAC iteration count")
	}
	salt, err := hex.DecodeString(fields[1])
	if err != nil {
		return false, errors.New("invalid PBKDF2-HMAC salt")
	}
	want, err := hex.DecodeString(fields[2])
	if err != nil {
		return false, errors.New("invalid PBKDF2-HMAC digest")
	}
	if iterations < 1 || iterations > maxKDFIterations ||
		len(salt) == 0 || len(salt) > maxKDFFieldSize || len(want) != newHash().Size() {
		return false, errors.New("invalid PBKDF2-HMAC parameters")
	}
	got := pbkdf2.Key([]byte(candidate), salt, iterations, len(want), newHash)
	return bytesEqualCT(got, want), nil
}

// splitPBKDF2HMACPrefix reads the "$pbkdf2-hmac-<alg>$" envelope.
func splitPBKDF2HMACPrefix(target string) (algo, body string, ok bool) {
	const prefix = "$pbkdf2-hmac-"
	if !strings.HasPrefix(target, prefix) {
		return "", "", false
	}
	rest := target[len(prefix):]
	i := strings.IndexByte(rest, '$')
	if i <= 0 {
		return "", "", false
	}
	algo = rest[:i]
	if _, known := pbkdf2HMACAlgos[algo]; !known {
		return "", "", false
	}
	return algo, rest[i+1:], true
}

func isNetIQPBKDF2(target string) bool {
	_, _, ok := splitPBKDF2HMACPrefix(target)
	return ok
}

func verifyAS400SSHA1(target, candidate string) (bool, error) {
	const prefix = "$as400$ssha1$*"
	const johnPrefix = "$as400ssha1$"
	var parts []string
	switch {
	case strings.HasPrefix(target, prefix):
		parts = strings.Split(strings.TrimPrefix(target, prefix), "*")
	case strings.HasPrefix(target, johnPrefix):
		// John writes "<digest>$<user>" — the fields in the opposite order
		// from hashcat's "<user>*<digest>", and separated by '$'. Reorder
		// rather than duplicate the verification below.
		f := strings.Split(strings.TrimPrefix(target, johnPrefix), "$")
		if len(f) != 2 {
			return false, errors.New("invalid AS/400 SSHA1 record")
		}
		parts = []string{f[1], f[0]}
	default:
		return false, errors.New("invalid AS/400 SSHA1 record")
	}
	if len(parts) != 2 || parts[0] == "" || len([]rune(parts[0])) > 10 ||
		len(parts[1]) != 40 || !isHex(parts[1]) {
		return false, errors.New("invalid AS/400 username or checksum")
	}
	username := []rune(strings.ToUpper(parts[0]))
	for len(username) < 10 {
		username = append(username, ' ')
	}
	input := append(utf16be(string(username[:10])), utf16be(candidate)...)
	sum := sha1.Sum(input)
	return strings.EqualFold(hex.EncodeToString(sum[:]), parts[1]), nil
}

func isAS400SSHA1(target string) bool {
	return strings.HasPrefix(target, "$as400$ssha1$*")
}

func verifyAuthMeSHA256(target, candidate string) (bool, error) {
	parts := strings.Split(target, "$")
	if len(parts) != 4 || parts[0] != "" || parts[1] != "SHA" ||
		len(parts[2]) != 16 || len(parts[3]) != 64 || !isHex(parts[3]) {
		return false, errors.New("invalid AuthMe SHA256 record")
	}
	inner := sha256.Sum256([]byte(candidate))
	outer := sha256.Sum256([]byte(hex.EncodeToString(inner[:]) + parts[2]))
	return strings.EqualFold(hex.EncodeToString(outer[:]), parts[3]), nil
}

func isAuthMeSHA256(target string) bool {
	return strings.HasPrefix(target, "$SHA$")
}

func verifyPHPS(target, candidate string) (bool, error) {
	parts := strings.Split(target, "$")
	if len(parts) != 4 || parts[0] != "" || parts[1] != "PHPS" ||
		len(parts[2]) == 0 || len(parts[2]) > maxKDFFieldSize*2 ||
		len(parts[3]) != 32 || !isHex(parts[3]) {
		return false, errors.New("invalid PHPS record")
	}
	salt, err := hex.DecodeString(parts[2])
	if err != nil {
		return false, errors.New("invalid PHPS hexadecimal salt")
	}
	inner := md5.Sum([]byte(candidate))
	h := md5.New()
	_, _ = h.Write([]byte(hex.EncodeToString(inner[:])))
	_, _ = h.Write(salt)
	return strings.EqualFold(hex.EncodeToString(h.Sum(nil)), parts[3]), nil
}

func isPHPS(target string) bool {
	return strings.HasPrefix(target, "$PHPS$")
}
