package main

// Two more vaults, at opposite ends of the care taken.
//
//	$andotp$0*<iv>*<ciphertext>*<tag>        andOTP's encrypted backup
//	$clipperz$<verifier>$<salt>*<account>    Clipperz's SRP-6a verifier
//
// andOTP encrypts its backup under SHA-256 of the password — once, unsalted,
// uniterated. A candidate therefore costs one SHA-256 and one GCM tag check,
// which is as cheap as a bare digest, on a file holding every TOTP secret its
// owner has. The tag is what says a password is right, and a GCM tag is not
// something a wrong key produces by accident.
//
// Clipperz does the opposite and still ends up somewhere odd. Its verifier is
// four SHA-256s deep, the account name and salt both folded in, and the result
// raised as an exponent — but the modulus is 256 bits, which is small enough
// that the discrete log is not the hard part. That does not help an attacker
// here either: x is the exponent, and recovering x is not recovering the
// password that produced it.

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"math/big"
	"strings"
)

// ── andOTP ────────────────────────────────────────────────────────────────────

const andOTPPrefix = "$andotp$"

const (
	andOTPIVLen  = 12
	andOTPTagLen = 16
)

type andOTPRecord struct {
	iv, ct, tag []byte
}

func andOTPFields(target string) (andOTPRecord, error) {
	var r andOTPRecord
	t := strings.TrimSpace(target)
	if !strings.HasPrefix(t, andOTPPrefix) {
		return r, errors.New("not an andOTP record")
	}
	f := strings.Split(t[len(andOTPPrefix):], "*")
	if len(f) != 4 || f[0] != "0" {
		return r, errors.New("an andOTP record is $andotp$0*<iv>*<ciphertext>*<tag>")
	}
	var err error
	if r.iv, err = decodeExactHex(f[1], andOTPIVLen, "andOTP IV"); err != nil {
		return r, err
	}
	if r.ct, err = hex.DecodeString(f[2]); err != nil || len(r.ct) == 0 {
		return r, errors.New("invalid andOTP ciphertext")
	}
	if r.tag, err = decodeExactHex(f[3], andOTPTagLen, "andOTP tag"); err != nil {
		return r, err
	}
	return r, nil
}

func verifyAndOTP(target, candidate string) (bool, error) {
	r, err := andOTPFields(target)
	if err != nil {
		return false, err
	}
	key := sha256.Sum256([]byte(candidate))
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return false, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return false, err
	}
	sealed := make([]byte, 0, len(r.ct)+len(r.tag))
	sealed = append(sealed, r.ct...)
	sealed = append(sealed, r.tag...)
	if _, err := gcm.Open(nil, r.iv, sealed, nil); err != nil {
		return false, nil
	}
	return true, nil
}

func isAndOTP(target string) bool {
	_, err := andOTPFields(target)
	return err == nil
}

// ── Clipperz ──────────────────────────────────────────────────────────────────

const clipperzPrefix = "$clipperz$"

var (
	clipperzModulus, _ = new(big.Int).SetString(
		"125617018995153554710546479714086468244499594888726646874671447258204721048803", 10)
	clipperzGenerator = big.NewInt(2)
)

type clipperzRecord struct {
	verifier *big.Int
	salt     string
	user     string
}

func clipperzFields(target string) (clipperzRecord, error) {
	var r clipperzRecord
	t := strings.TrimSpace(target)
	if !strings.HasPrefix(t, clipperzPrefix) {
		return r, errors.New("not a Clipperz record")
	}
	v, rest, ok := strings.Cut(t[len(clipperzPrefix):], "$")
	if !ok {
		return r, errors.New("a Clipperz record is $clipperz$<verifier>$<salt>*<account>")
	}
	salt, user, ok := strings.Cut(rest, "*")
	if !ok || salt == "" || user == "" {
		return r, errors.New("a Clipperz record is $clipperz$<verifier>$<salt>*<account>")
	}
	if len(v) == 0 || len(v) > 128 || !isHex(v) {
		return r, errors.New("a Clipperz verifier is hex")
	}
	r.verifier, ok = new(big.Int).SetString(v, 16)
	if !ok {
		return r, errors.New("a Clipperz verifier is hex")
	}
	r.salt, r.user = salt, user
	return r, nil
}

func verifyClipperz(target, candidate string) (bool, error) {
	r, err := clipperzFields(target)
	if err != nil {
		return false, err
	}
	// sha256(password || account), hashed again; then the salt with the HEX of
	// that digest, hashed again. The hex is not an encoding step here — those
	// sixty-four characters are what goes into the third hash.
	first := sha256.Sum256([]byte(candidate + r.user))
	second := sha256.Sum256(first[:])
	third := sha256.New()
	_, _ = third.Write([]byte(r.salt))
	_, _ = third.Write([]byte(hex.EncodeToString(second[:])))
	fourth := sha256.Sum256(third.Sum(nil))

	x := new(big.Int).SetBytes(fourth[:])
	got := new(big.Int).Exp(clipperzGenerator, x, clipperzModulus)
	return got.Cmp(r.verifier) == 0, nil
}

func isClipperz(target string) bool {
	_, err := clipperzFields(target)
	return err == nil
}
