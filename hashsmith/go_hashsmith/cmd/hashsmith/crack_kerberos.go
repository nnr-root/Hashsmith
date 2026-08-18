package main

import (
	"crypto/hmac"
	"crypto/md5"
	"crypto/rc4"
	"encoding/hex"
	"errors"
	"strings"
)

// ── Kerberos 5 etype 23 (RC4-HMAC) ─────────────────────────────────────────────
//
// AS-REP roasting and Kerberoasting both yield RC4-HMAC encrypted blobs that are
// cracked offline against the account's NT hash. These are captured as text
// lines, so there is no *2smith extractor.
//
//   AS-REP : $krb5asrep$23$user@REALM:<checksum>$<edata>
//   TGS-REP: $krb5tgs$23$*user$realm$spn*$<checksum>$<edata>
//
// Key usage numbers (RFC 4757 / MS-KILE): AS-REP enc-part = 8, TGS-REP
// enc-part = 8. The service-ticket TGS variant uses 2, so both are tried.

// verifyKrb5 dispatches on the $krb5asrep$ / $krb5tgs$ / $krb5pa$ prefix. AES
// etypes (17/18) route to the AES-CTS engine; etype 23 is RC4-HMAC below.
func verifyKrb5(targetHash, candidate string) (bool, error) {
	if isKrb5AES(targetHash) {
		return verifyKrb5AESHash(targetHash, candidate)
	}
	checksum, edata, usages, err := parseKrb5(targetHash)
	if err != nil {
		return false, err
	}
	key := ntHash(candidate)
	for _, u := range usages {
		if krb5RC4Check(key, checksum, edata, u) {
			return true, nil
		}
	}
	return false, nil
}

// parseKrb5 extracts the 16-byte checksum, the RC4 ciphertext, and the candidate
// key-usage numbers for the given Kerberos hash line.
func parseKrb5(h string) (checksum, edata []byte, usages []int, err error) {
	switch {
	case strings.HasPrefix(h, "$krb5asrep$"):
		body := strings.TrimPrefix(h, "$krb5asrep$")
		body = strings.TrimPrefix(body, "23$") // etype 23 only
		// body = user@REALM:<checksum>$<edata>
		colon := strings.LastIndex(body, ":")
		if colon < 0 {
			return nil, nil, nil, errors.New("invalid krb5asrep format (missing ':')")
		}
		rest := body[colon+1:]
		dollar := strings.Index(rest, "$")
		if dollar < 0 {
			return nil, nil, nil, errors.New("invalid krb5asrep format (missing checksum/edata separator)")
		}
		checksum, err = hex.DecodeString(rest[:dollar])
		if err != nil {
			return nil, nil, nil, errors.New("invalid krb5asrep checksum")
		}
		edata, err = hex.DecodeString(rest[dollar+1:])
		if err != nil {
			return nil, nil, nil, errors.New("invalid krb5asrep edata")
		}
		return checksum, edata, []int{8, 3}, nil

	case strings.HasPrefix(h, "$krb5tgs$"):
		body := strings.TrimPrefix(h, "$krb5tgs$")
		body = strings.TrimPrefix(body, "23$")
		// body = *user$realm$spn*$<checksum>$<edata>  (the *...* part is metadata)
		if star := strings.LastIndex(body, "*"); star >= 0 {
			body = body[star+1:]
			body = strings.TrimPrefix(body, "$")
		}
		dollar := strings.Index(body, "$")
		if dollar < 0 {
			return nil, nil, nil, errors.New("invalid krb5tgs format (missing checksum/edata separator)")
		}
		checksum, err = hex.DecodeString(body[:dollar])
		if err != nil {
			return nil, nil, nil, errors.New("invalid krb5tgs checksum")
		}
		edata, err = hex.DecodeString(body[dollar+1:])
		if err != nil {
			return nil, nil, nil, errors.New("invalid krb5tgs edata")
		}
		return checksum, edata, []int{2, 8}, nil
	}
	return nil, nil, nil, errors.New("unrecognised Kerberos hash format")
}

// krb5RC4Check performs the RC4-HMAC (etype 23) decryption check for one key
// usage. Returns true when the recomputed HMAC matches the stored checksum.
func krb5RC4Check(key, checksum, edata []byte, usage int) bool {
	if len(checksum) != 16 || len(edata) == 0 {
		return false
	}
	// K1 = HMAC-MD5(key, LE32(usage))
	usageBytes := []byte{byte(usage), byte(usage >> 8), byte(usage >> 16), byte(usage >> 24)}
	m := hmac.New(md5.New, key)
	m.Write(usageBytes)
	k1 := m.Sum(nil)

	// K3 = HMAC-MD5(K1, checksum)
	m2 := hmac.New(md5.New, k1)
	m2.Write(checksum)
	k3 := m2.Sum(nil)

	c, err := rc4.NewCipher(k3)
	if err != nil {
		return false
	}
	plain := make([]byte, len(edata))
	c.XORKeyStream(plain, edata)

	// Valid if HMAC-MD5(K1, plaintext) == checksum.
	m3 := hmac.New(md5.New, k1)
	m3.Write(plain)
	return hmac.Equal(m3.Sum(nil), checksum)
}
