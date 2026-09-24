package smith

// 1Password 8 mobile keychain — Hashcat 31800.
//
//	$mobilekeychain$<email>$<salt>$<second key>$<iterations>$<iv>$<ciphertext>$<tag>
//
// 1Password's two-secret key derivation combines something the user knows with
// something their device holds. PBKDF2-HMAC-SHA256 turns the password into one
// 256-bit half, the account's secret key supplies the other already derived,
// and the master unlock key is the two XORed together. Neither half alone
// opens anything — which is the point of the design, and the reason this mode
// needs the record's second key as well as the password.
//
// Unlike most of this tool's formats there is no plaintext heuristic: the
// payload is AES-256-GCM and the stored tag settles it at 2^-128. A correct
// guess decrypts to a JWK — Hashcat's example record yields
// `{'key_ops': ['decrypt', 'encrypt'], 'kty': 'oct' ...}`.
//
// The IV is sixteen bytes rather than GCM's usual twelve, so the counter block
// comes from GHASH rather than from the nonce directly; Go expresses that with
// NewGCMWithNonceSize.

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strconv"
	"strings"

	"golang.org/x/crypto/pbkdf2"
)

const onePassword8KeyLen = 32

// onePassword8Record holds one parsed $mobilekeychain$ target, shared by
// the scalar verifyOnePassword8 and the AVX2-batched lane hasher
// (pbkdf2_lane_onepassword8.go) so the two never parse the record two
// different ways — a parsing discrepancy between a fast path and its
// scalar fallback is exactly the kind of thing that would surface only as
// silent false negatives on whichever path a given target happened not to
// exercise in testing.
type onePassword8Record struct {
	salt      []byte
	secondKey []byte
	iter      int
	iv        []byte
	ct        []byte
	tag       []byte
}

// parseOnePassword8Record parses target, or returns an error identical in
// wording and condition to what verifyOnePassword8 always returned before
// this was split out — this refactor changes nothing about which records
// are accepted or rejected, only where the parsing logic lives.
func parseOnePassword8Record(target string) (onePassword8Record, error) {
	t := strings.TrimSpace(target)
	if !strings.HasPrefix(t, "$mobilekeychain$") {
		return onePassword8Record{}, errors.New("not a 1Password 8 mobile keychain record")
	}
	f := strings.Split(strings.TrimPrefix(t, "$mobilekeychain$"), "$")
	if len(f) != 7 {
		return onePassword8Record{}, errors.New("1Password 8 record must have 7 fields")
	}
	unhex := func(s string, want int) ([]byte, error) {
		b, err := hex.DecodeString(s)
		if err != nil {
			return nil, errors.New("1Password 8 field is not hex")
		}
		if want > 0 && len(b) != want {
			return nil, errors.New("1Password 8 field has the wrong length")
		}
		return b, nil
	}
	var r onePassword8Record
	var err error
	r.salt, err = unhex(f[1], onePassword8KeyLen)
	if err != nil {
		return onePassword8Record{}, err
	}
	r.secondKey, err = unhex(f[2], onePassword8KeyLen)
	if err != nil {
		return onePassword8Record{}, err
	}
	r.iter, err = strconv.Atoi(f[3])
	if err != nil || r.iter < 1 {
		return onePassword8Record{}, errors.New("1Password 8 iterations must be a positive integer")
	}
	r.iv, err = unhex(f[4], 0)
	if err != nil || len(r.iv) == 0 {
		return onePassword8Record{}, errors.New("1Password 8 IV is not hex")
	}
	r.ct, err = unhex(f[5], 0)
	if err != nil || len(r.ct) == 0 {
		return onePassword8Record{}, errors.New("1Password 8 ciphertext is not hex")
	}
	r.tag, err = unhex(f[6], 0)
	if err != nil || len(r.tag) == 0 {
		return onePassword8Record{}, errors.New("1Password 8 tag is not hex")
	}
	return r, nil
}

func verifyOnePassword8(target, candidate string) (bool, error) {
	r, err := parseOnePassword8Record(target)
	if err != nil {
		return false, err
	}
	derived := pbkdf2.Key([]byte(candidate), r.salt, r.iter, onePassword8KeyLen, sha256.New)
	return onePassword8Decrypts(&r, derived)
}

// onePassword8Decrypts is the shared "does this derived key open the
// record" check: XOR in the second key, build the AES-256-GCM cipher, and
// attempt to open the stored ciphertext+tag under the record's IV. Used by
// verifyOnePassword8 for its single derived key and by the lane hasher for
// each of a batch's derived keys — the expensive part (PBKDF2) is what
// batching helps; this per-candidate tail is cheap regardless.
func onePassword8Decrypts(r *onePassword8Record, derived []byte) (bool, error) {
	muk := make([]byte, onePassword8KeyLen)
	for i := range muk {
		muk[i] = derived[i] ^ r.secondKey[i]
	}
	block, err := aes.NewCipher(muk)
	if err != nil {
		return false, err
	}
	gcm, err := cipher.NewGCMWithNonceSize(block, len(r.iv))
	if err != nil {
		return false, err
	}
	if _, err := gcm.Open(nil, r.iv, append(append([]byte(nil), r.ct...), r.tag...), nil); err != nil {
		return false, nil
	}
	return true, nil
}
