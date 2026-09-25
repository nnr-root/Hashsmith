package smith

// Oracle 11g/12c (the "S:" verifier):
//
//	<40-hex sha1><20-hex salt>   — sha1(password . salt), salt = 10 bytes
//
// (60 hex chars total: the SHA-1 digest followed by the salt.)

import (
	"crypto/sha1"
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"strings"

	"golang.org/x/crypto/pbkdf2"
)

func verifyOracle11g(targetHash, candidate string) (bool, error) {
	targetHash = oracle11gCanonical(targetHash)
	if len(targetHash) != 60 || !isHex(targetHash) {
		return false, errors.New("invalid Oracle 11g hash (need 60 hex chars, or 40:20 hex)")
	}
	salt, err := hex.DecodeString(targetHash[40:])
	if err != nil {
		return false, errors.New("invalid Oracle 11g salt")
	}
	h := sha1.New()
	h.Write([]byte(candidate))
	h.Write(salt)
	return strings.EqualFold(hex.EncodeToString(h.Sum(nil)), targetHash[:40]), nil
}

func isOracle11g(s string) bool { s = oracle11gCanonical(s); return len(s) == 60 && isHex(s) }

// oracle11gCanonical folds hashcat's -m 112 spelling, which separates the
// 40-hex SHA-1 from the 20-hex salt with a colon, onto the concatenated
// 60-hex form this verifier works in. A record already in that form is
// returned unchanged.
func oracle11gCanonical(s string) string {
	i := strings.IndexByte(s, ':')
	if i != 40 || len(s) != 61 {
		return s
	}
	return s[:40] + s[41:]
}

// oracle12cIterations is fixed by the format. Shared between the scalar
// path and the lane hasher (pbkdf2_lane_oracle12c.go) so the two never
// drift.
const oracle12cIterations = 4096

// oracle12cRecord holds one parsed Oracle 12c "T:" target, shared by the
// scalar verifyOracle12c and the AVX2-batched lane hasher.
type oracle12cRecord struct {
	pbkdf2Salt []byte // salt . "AUTH_PBKDF2_SPEEDY_KEY" — the actual PBKDF2 salt
	salt       []byte // the record's own 16-byte salt, appended after the key
	want       string
}

// parseOracle12c parses target, or returns an error identical in wording
// and condition to what verifyOracle12c always returned before this was
// split out.
func parseOracle12c(targetHash string) (oracle12cRecord, error) {
	if len(targetHash) != 160 || !isHex(targetHash) {
		return oracle12cRecord{}, errors.New("invalid Oracle 12c hash (need 160 hex chars)")
	}
	salt, err := hex.DecodeString(targetHash[128:])
	if err != nil {
		return oracle12cRecord{}, errors.New("invalid Oracle 12c salt")
	}
	pbkdf2Salt := append(append([]byte(nil), salt...), []byte("AUTH_PBKDF2_SPEEDY_KEY")...)
	return oracle12cRecord{pbkdf2Salt: pbkdf2Salt, salt: salt, want: targetHash[:128]}, nil
}

// oracle12cMatches is the shared "does this derived key reach the stored
// digest" check. Used by verifyOracle12c for its single derived key and by
// the lane hasher for each of a batch's.
func oracle12cMatches(r *oracle12cRecord, key []byte) bool {
	h := sha512.Sum512(append(append([]byte(nil), key...), r.salt...))
	return strings.EqualFold(hex.EncodeToString(h[:]), r.want)
}

// verifyOracle12c checks a candidate against an Oracle 12c "T:" verifier (160
// hex = 64-byte SHA-512 digest + 16-byte salt):
//
//	key = PBKDF2-HMAC-SHA512(password, salt . "AUTH_PBKDF2_SPEEDY_KEY", 4096, 64)
//	H   = SHA-512(key . salt)   (compared against the first 128 hex chars)
func verifyOracle12c(targetHash, candidate string) (bool, error) {
	r, err := parseOracle12c(targetHash)
	if err != nil {
		return false, err
	}
	key := pbkdf2.Key([]byte(candidate), r.pbkdf2Salt, oracle12cIterations, 64, sha512.New)
	return oracle12cMatches(&r, key), nil
}

func isOracle12c(s string) bool { return len(s) == 160 && isHex(s) }
