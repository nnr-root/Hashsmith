package smith

import (
	"crypto/subtle"
	"errors"
	"strings"

	"hashsmith-go/internal/bcryptlane"
)

// WoltLab Burning Board 4, Hashcat mode 33800: bcrypt(bcrypt($pass)).
//
// The record is an ordinary bcrypt crypt string and gives no hint that it is
// nested — which is the whole difficulty. A $2a$08$… record from WBB4 is
// indistinguishable from a plain bcrypt one, so auto-detection cannot tell
// them apart and this format is reachable only with -t wbb4 or -m 33800. A
// user who tries plain bcrypt on a WBB4 record gets "not found" from a correct
// password, and nothing says why; the catalogue entry does.
//
// Both rounds use the SAME salt and cost, the record's own. The inner round's
// full crypt string — prefix and all, not just its digest — is what the outer
// round hashes, because that is what WoltLab's PHP passes to password_hash a
// second time.
func verifyWBB4(targetHash, candidate string) (bool, error) {
	target := strings.TrimSpace(targetHash)
	h, err := bcryptlane.NewHasher(target)
	if err != nil {
		return false, errors.New("invalid WBB4 record: it must be a bcrypt crypt string")
	}
	// "$2?$cc$" plus the 22-character salt. Everything after it is the digest
	// field, which is what Digest recomputes.
	cut := len(target) - 31
	if cut < 7 || cut > len(target) {
		return false, errors.New("invalid WBB4 record length")
	}
	prefix, want := target[:cut], target[cut:]

	inner := prefix + h.Digest([]byte(candidate))
	outer := h.Digest([]byte(inner))
	return subtle.ConstantTimeCompare([]byte(outer), []byte(want)) == 1, nil
}
