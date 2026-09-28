package smith

// Password formats used by Python frameworks and ASP.NET Identity.

import (
	"crypto/hmac"
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
	if name == "pbkdf2" {
		name = "pbkdf2-sha1"
	}
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

// passlibPBKDF2SHA256Record holds one parsed $pbkdf2-sha256$ target — the
// one Passlib PBKDF2 digest the AVX2 lane hasher (pbkdf2_lane_passlib.go)
// accelerates. parsePasslibPBKDF2/verifyPasslibPBKDF2 stay generic over
// sha1/sha256/sha512 and are untouched; this is a second, narrower entry
// point used only by the lane hasher, whose own tests check it against
// verifyPasslibPBKDF2 on every candidate.
type passlibPBKDF2SHA256Record struct {
	rounds int
	salt   []byte
	digest []byte
}

// parsePasslibPBKDF2SHA256 parses target, refusing anything that is not a
// $pbkdf2-sha256$ record, with the same field checks parsePasslibPBKDF2 uses.
func parsePasslibPBKDF2SHA256(target string) (passlibPBKDF2SHA256Record, error) {
	parts := strings.Split(target, "$")
	if len(parts) != 5 || parts[0] != "" || strings.ToLower(parts[1]) != "pbkdf2-sha256" {
		return passlibPBKDF2SHA256Record{}, errors.New("not a Passlib PBKDF2-SHA256 record")
	}
	rounds, err := strconv.Atoi(parts[2])
	if err != nil || rounds < 1 || rounds > maxKDFIterations {
		return passlibPBKDF2SHA256Record{}, errors.New("invalid Passlib PBKDF2 round count")
	}
	salt, err := decodePasslibBase64(parts[3])
	if err != nil || len(salt) == 0 || len(salt) > maxKDFFieldSize {
		return passlibPBKDF2SHA256Record{}, errors.New("invalid Passlib PBKDF2 salt")
	}
	digest, err := decodePasslibBase64(parts[4])
	if err != nil || len(digest) != sha256.Size {
		return passlibPBKDF2SHA256Record{}, errors.New("invalid Passlib PBKDF2 checksum")
	}
	return passlibPBKDF2SHA256Record{rounds: rounds, salt: salt, digest: digest}, nil
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
	// legacyHMAC marks the pre-2.3 Werkzeug methods, which are a bare digest
	// name rather than "pbkdf2:..." or "scrypt:...", and are HMAC of the
	// password KEYED BY THE SALT rather than any KDF. Hashcat gives them their
	// own modes (30000 md5, 30120 sha256, and the sha1/sha512 siblings).
	legacyHMAC bool
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
	case "md5", "sha1", "sha224", "sha256", "sha384", "sha512":
		// Werkzeug before 2.3 wrote generate_password_hash(method="md5") and
		// friends as "<digest>$<salt>$<hmac>", with no iteration count. These
		// were rejected outright as an unsupported method, so every -m 30000
		// and -m 30120 target failed at parse time.
		if len(method) != 1 {
			return nil, errors.New("invalid Werkzeug legacy method parameters")
		}
		var ok bool
		w.newHash, ok = pbkdf2HashFactory(method[0])
		if !ok {
			return nil, errors.New("unsupported Werkzeug legacy digest")
		}
		w.legacyHMAC = true
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

// werkzeugPBKDF2SHA256Record holds one parsed "pbkdf2:sha256:..." target —
// the one Werkzeug method the AVX2 lane hasher (pbkdf2_lane_werkzeug.go)
// accelerates. parseWerkzeugHash/verifyWerkzeug stay generic over every
// digest, scrypt, and the legacy HMAC methods, and are untouched.
type werkzeugPBKDF2SHA256Record struct {
	rounds int
	salt   []byte
	digest []byte
}

// parseWerkzeugPBKDF2SHA256 parses target, refusing anything that is not a
// "pbkdf2:sha256:<rounds>$<salt>$<hex digest>" record.
func parseWerkzeugPBKDF2SHA256(target string) (werkzeugPBKDF2SHA256Record, error) {
	parts := strings.SplitN(target, "$", 3)
	if len(parts) != 3 || parts[1] == "" || len(parts[1]) > maxKDFFieldSize {
		return werkzeugPBKDF2SHA256Record{}, errors.New("invalid Werkzeug password hash")
	}
	method := strings.Split(parts[0], ":")
	if len(method) != 3 || method[0] != "pbkdf2" || strings.ToLower(method[1]) != "sha256" {
		return werkzeugPBKDF2SHA256Record{}, errors.New("not a Werkzeug PBKDF2-SHA256 record")
	}
	rounds, err := strconv.Atoi(method[2])
	if err != nil || rounds < 1 || rounds > maxKDFIterations {
		return werkzeugPBKDF2SHA256Record{}, errors.New("invalid Werkzeug PBKDF2 iteration count")
	}
	digest, err := hex.DecodeString(parts[2])
	if err != nil || len(digest) != sha256.Size {
		return werkzeugPBKDF2SHA256Record{}, errors.New("invalid Werkzeug password checksum")
	}
	return werkzeugPBKDF2SHA256Record{rounds: rounds, salt: []byte(parts[1]), digest: digest}, nil
}

func verifyWerkzeug(target, candidate string) (bool, error) {
	w, err := parseWerkzeugHash(target)
	if err != nil {
		return false, err
	}
	var got []byte
	switch {
	case w.legacyHMAC:
		mac := hmac.New(w.newHash, w.salt)
		mac.Write([]byte(candidate))
		got = mac.Sum(nil)
	case w.newHash != nil:
		got = pbkdf2.Key([]byte(candidate), w.salt, w.rounds, len(w.digest), w.newHash)
	default:
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

// aspNetIdentitySHA256Record holds one parsed ASP.NET Identity v3 target
// whose PRF is SHA-256 and whose subkey is short enough for a single PBKDF2
// block — the one shape the AVX2 lane hasher (pbkdf2_lane_aspnetidentity.go)
// accelerates. parseASPNetIdentity/verifyASPNetIdentity stay generic over
// v2 (fixed SHA-1), and v3's SHA-1/SHA-512 PRFs, and are untouched.
type aspNetIdentitySHA256Record struct {
	iterations int
	salt       []byte
	digest     []byte
}

// parseASPNetIdentitySHA256 parses target, refusing anything that is not a
// v3 record with PRF=SHA-256 and a subkey no longer than one SHA-256 block
// (32 bytes) — a longer subkey needs multi-block PBKDF2, which the batch
// primitive does not compute.
func parseASPNetIdentitySHA256(target string) (aspNetIdentitySHA256Record, error) {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(target))
	if err != nil || len(raw) == 0 || raw[0] != 1 {
		return aspNetIdentitySHA256Record{}, errors.New("not an ASP.NET Identity v3 record")
	}
	if len(raw) < 13+16+16 {
		return aspNetIdentitySHA256Record{}, errors.New("invalid ASP.NET Identity v3 payload")
	}
	if binary.BigEndian.Uint32(raw[1:5]) != 1 {
		return aspNetIdentitySHA256Record{}, errors.New("not an ASP.NET Identity SHA-256 record")
	}
	iterations := int(binary.BigEndian.Uint32(raw[5:9]))
	saltLen := int(binary.BigEndian.Uint32(raw[9:13]))
	if iterations < 1 || iterations > maxKDFIterations || saltLen < 16 || saltLen > maxKDFFieldSize ||
		13+saltLen > len(raw) {
		return aspNetIdentitySHA256Record{}, errors.New("invalid ASP.NET Identity v3 parameters")
	}
	digest := raw[13+saltLen:]
	if len(digest) < 16 || len(digest) > sha256.Size {
		return aspNetIdentitySHA256Record{}, errors.New("invalid ASP.NET Identity v3 subkey")
	}
	return aspNetIdentitySHA256Record{
		iterations: iterations, salt: raw[13 : 13+saltLen], digest: digest,
	}, nil
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
