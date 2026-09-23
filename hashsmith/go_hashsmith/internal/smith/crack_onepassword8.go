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

func verifyOnePassword8(target, candidate string) (bool, error) {
	t := strings.TrimSpace(target)
	if !strings.HasPrefix(t, "$mobilekeychain$") {
		return false, errors.New("not a 1Password 8 mobile keychain record")
	}
	f := strings.Split(strings.TrimPrefix(t, "$mobilekeychain$"), "$")
	if len(f) != 7 {
		return false, errors.New("1Password 8 record must have 7 fields")
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
	salt, err := unhex(f[1], onePassword8KeyLen)
	if err != nil {
		return false, err
	}
	secondKey, err := unhex(f[2], onePassword8KeyLen)
	if err != nil {
		return false, err
	}
	iterations, err := strconv.Atoi(f[3])
	if err != nil || iterations < 1 {
		return false, errors.New("1Password 8 iterations must be a positive integer")
	}
	iv, err := unhex(f[4], 0)
	if err != nil || len(iv) == 0 {
		return false, errors.New("1Password 8 IV is not hex")
	}
	ct, err := unhex(f[5], 0)
	if err != nil || len(ct) == 0 {
		return false, errors.New("1Password 8 ciphertext is not hex")
	}
	tag, err := unhex(f[6], 0)
	if err != nil || len(tag) == 0 {
		return false, errors.New("1Password 8 tag is not hex")
	}

	derived := pbkdf2.Key([]byte(candidate), salt, iterations, onePassword8KeyLen, sha256.New)
	muk := make([]byte, onePassword8KeyLen)
	for i := range muk {
		muk[i] = derived[i] ^ secondKey[i]
	}
	block, err := aes.NewCipher(muk)
	if err != nil {
		return false, err
	}
	gcm, err := cipher.NewGCMWithNonceSize(block, len(iv))
	if err != nil {
		return false, err
	}
	if _, err := gcm.Open(nil, iv, append(append([]byte(nil), ct...), tag...), nil); err != nil {
		return false, nil
	}
	return true, nil
}
