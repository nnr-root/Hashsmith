package main

// Ethereum wallet (Web3 Secret Storage / Geth keystore v3) cracking.
//
// A keystore derives a symmetric key from the passphrase and stores a MAC that
// authenticates it:
//
//	derivedKey = KDF(passphrase, salt)            (scrypt or PBKDF2-HMAC-SHA256)
//	mac        = keccak256(derivedKey[16:32] || ciphertext)
//
// so a passphrase can be verified without decrypting anything. Accepted formats
// (the keystore fields packed into a single line):
//
//	$ethereum$p*<iterations>*<salt>*<ciphertext>*<mac>          (PBKDF2)
//	$ethereum$s*<N>*<r>*<p>*<salt>*<ciphertext>*<mac>           (scrypt)

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strconv"
	"strings"

	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/crypto/scrypt"
	xsha3 "golang.org/x/crypto/sha3"
)

// keccak256 is the original Keccak (pre-NIST-padding) digest Ethereum uses —
// distinct from SHA3-256.
func keccak256(parts ...[]byte) []byte {
	h := xsha3.NewLegacyKeccak256()
	for _, p := range parts {
		h.Write(p)
	}
	return h.Sum(nil)
}

// verifyEthereum checks a passphrase against a $ethereum$ target.
func verifyEthereum(targetHash, candidate string) (bool, error) {
	if !strings.HasPrefix(targetHash, "$ethereum$") {
		return false, errors.New("invalid ethereum hash (missing $ethereum$ prefix)")
	}
	f := strings.Split(targetHash[len("$ethereum$"):], "*")
	if len(f) < 1 {
		return false, errors.New("invalid ethereum hash")
	}

	var derivedKey []byte
	var ciphertext, mac []byte
	switch f[0] {
	case "p":
		// p*<iterations>*<salt>*<ciphertext>*<mac>
		if len(f) != 5 {
			return false, errors.New("invalid ethereum PBKDF2 hash (need p*iter*salt*ct*mac)")
		}
		iter, err := strconv.Atoi(f[1])
		if err != nil || iter <= 0 {
			return false, errors.New("invalid ethereum PBKDF2 iteration count")
		}
		salt, ct, m, err := decodeEthParts(f[2], f[3], f[4])
		if err != nil {
			return false, err
		}
		ciphertext, mac = ct, m
		derivedKey = pbkdf2.Key([]byte(candidate), salt, iter, 32, sha256.New)
	case "s":
		// s*<N>*<r>*<p>*<salt>*<ciphertext>*<mac>
		if len(f) != 7 {
			return false, errors.New("invalid ethereum scrypt hash (need s*N*r*p*salt*ct*mac)")
		}
		n, err1 := strconv.Atoi(f[1])
		r, err2 := strconv.Atoi(f[2])
		p, err3 := strconv.Atoi(f[3])
		if err1 != nil || err2 != nil || err3 != nil || n <= 1 || r <= 0 || p <= 0 {
			return false, errors.New("invalid ethereum scrypt parameters")
		}
		salt, ct, m, err := decodeEthParts(f[4], f[5], f[6])
		if err != nil {
			return false, err
		}
		ciphertext, mac = ct, m
		derivedKey, err = scrypt.Key([]byte(candidate), salt, n, r, p, 32)
		if err != nil {
			return false, err
		}
	default:
		return false, errors.New("unsupported ethereum KDF marker " + f[0] + " (want p or s)")
	}

	got := keccak256(derivedKey[16:32], ciphertext)
	return bytesEqualCT(got, mac), nil
}

// decodeEthParts hex-decodes the salt, ciphertext, and mac fields.
func decodeEthParts(saltHex, ctHex, macHex string) (salt, ct, mac []byte, err error) {
	if salt, err = hex.DecodeString(saltHex); err != nil {
		return nil, nil, nil, errors.New("invalid ethereum salt")
	}
	if ct, err = hex.DecodeString(ctHex); err != nil {
		return nil, nil, nil, errors.New("invalid ethereum ciphertext")
	}
	if mac, err = hex.DecodeString(macHex); err != nil {
		return nil, nil, nil, errors.New("invalid ethereum mac")
	}
	return salt, ct, mac, nil
}

// bytesEqualCT is a constant-time byte-slice comparison.
func bytesEqualCT(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var v byte
	for i := range a {
		v |= a[i] ^ b[i]
	}
	return v == 0
}
