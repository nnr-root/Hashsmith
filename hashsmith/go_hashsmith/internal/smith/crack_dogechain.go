package smith

// Dogechain.info wallet — Hashcat 32500.
//
//	$dogechain$0*<iterations>*<payload, base64>*<salt, base64>
//
// The payload is an AES-256-CBC blob whose first block is the IV. What makes
// this one worth a comment is the key derivation: the password is NOT what
// PBKDF2 sees. Dogechain hashes it with SHA-256, base64-encodes that digest,
// and hands the resulting 44-character TEXT to PBKDF2-HMAC-SHA256 as the
// password. Feeding PBKDF2 the password, or the raw digest, both derive the
// wrong key.
//
// The wallet plaintext is JSON, so a guess is judged by every decrypted byte
// having its high bit clear. The final block is left out of that test: it
// carries PKCS#7 padding, which is not ASCII and would fail a check it has no
// business being part of.

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"strconv"
	"strings"

	"golang.org/x/crypto/pbkdf2"
)

// dogechainRecord holds one parsed $dogechain$ target, shared by the
// scalar verifyDogechain and the AVX2-batched lane hasher
// (pbkdf2_lane_dogechain.go) — see onePassword8Record's own comment for
// why sharing the parser between a fast path and its scalar fallback
// matters.
type dogechainRecord struct {
	payload []byte
	salt    []byte
	iter    int
}

// parseDogechainRecord parses target, or returns an error identical in
// wording and condition to what verifyDogechain always returned before
// this was split out.
func parseDogechainRecord(target string) (dogechainRecord, error) {
	t := strings.TrimSpace(target)
	if !strings.HasPrefix(t, "$dogechain$") {
		return dogechainRecord{}, errors.New("not a Dogechain wallet record")
	}
	p := strings.Split(strings.TrimPrefix(t, "$dogechain$"), "*")
	if len(p) != 4 {
		return dogechainRecord{}, errors.New("Dogechain record must be $dogechain$<v>*<iter>*<payload>*<salt>")
	}
	var r dogechainRecord
	var err error
	r.iter, err = strconv.Atoi(p[1])
	if err != nil || r.iter < 1 {
		return dogechainRecord{}, errors.New("Dogechain iterations must be a positive integer")
	}
	r.payload, err = base64.StdEncoding.DecodeString(p[2])
	if err != nil {
		return dogechainRecord{}, errors.New("Dogechain payload must be base64")
	}
	r.salt, err = base64.StdEncoding.DecodeString(p[3])
	if err != nil || len(r.salt) == 0 {
		return dogechainRecord{}, errors.New("Dogechain salt must be base64")
	}
	// The IV, at least one block to judge, and a padding block to leave out.
	if len(r.payload) < 3*aes.BlockSize || len(r.payload)%aes.BlockSize != 0 {
		return dogechainRecord{}, errors.New("Dogechain payload is not a whole number of AES blocks")
	}
	return r, nil
}

// dogechainPasswordText applies Dogechain's password transform — SHA-256
// the candidate, base64-encode that digest, and THAT text (not the
// password, not the raw digest) is what PBKDF2 actually sees. Depends only
// on the candidate, never on the target record, so it can run once per
// candidate before that candidate ever reaches a shared salt/iteration
// batch — exactly what the lane hasher does, and exactly what the scalar
// path already did inline.
func dogechainPasswordText(candidate string) string {
	digest := sha256.Sum256([]byte(candidate))
	return base64.StdEncoding.EncodeToString(digest[:])
}

// dogechainDecrypts is the shared "does this derived key open the wallet"
// check: AES-256-CBC decrypt the body under the payload's own IV (its
// first block) and require every plaintext byte outside the final
// (padding) block to have its high bit clear.
func dogechainDecrypts(r *dogechainRecord, key []byte) (bool, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return false, err
	}
	body := r.payload[aes.BlockSize : len(r.payload)-aes.BlockSize]
	plain := make([]byte, len(body))
	cipher.NewCBCDecrypter(block, r.payload[:aes.BlockSize]).CryptBlocks(plain, body)
	for _, c := range plain {
		if c&0x80 != 0 {
			return false, nil
		}
	}
	return true, nil
}

func verifyDogechain(target, candidate string) (bool, error) {
	r, err := parseDogechainRecord(target)
	if err != nil {
		return false, err
	}
	key := pbkdf2.Key([]byte(dogechainPasswordText(candidate)), r.salt, r.iter, 32, sha256.New)
	return dogechainDecrypts(&r, key)
}
