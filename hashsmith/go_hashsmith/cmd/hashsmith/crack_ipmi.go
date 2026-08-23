package main

// IPMI2 RAKP HMAC-SHA1 and Half-MD5.
//
//	<salt_hex>:<hmac_sha1_hex>   IPMI2 RAKP — HMAC-SHA1(password, salt)
//	<16 hex>                     Half-MD5   — first 8 bytes of md5(password)

import (
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha1"
	"encoding/hex"
	"errors"
	"strings"
)

func verifyIPMI(targetHash, candidate string) (bool, error) {
	f := strings.SplitN(targetHash, ":", 2)
	if len(f) != 2 || len(f[1]) != 40 {
		return false, errors.New("invalid IPMI hash (need salt:hmac-sha1)")
	}
	salt, err := hex.DecodeString(f[0])
	if err != nil {
		return false, errors.New("invalid IPMI salt")
	}
	mac := hmac.New(sha1.New, []byte(candidate))
	mac.Write(salt)
	return strings.EqualFold(hex.EncodeToString(mac.Sum(nil)), f[1]), nil
}

func verifyIPMIMD5(targetHash, candidate string) (bool, error) {
	f := strings.Split(targetHash, ":")
	if len(f) != 2 || len(f[0]) != 32 || !isHex(f[0]) || len(f[1]) < 116 || len(f[1]) > 148 ||
		len(f[1])%2 != 0 || !isHex(f[1]) || len([]byte(candidate)) > 256 {
		return false, errors.New("invalid IPMI HMAC-MD5 record")
	}
	salt, _ := hex.DecodeString(f[1])
	mac := hmac.New(md5.New, []byte(candidate))
	_, _ = mac.Write(salt)
	return strings.EqualFold(hex.EncodeToString(mac.Sum(nil)), f[0]), nil
}

func isIPMIMD5(s string) bool {
	f := strings.Split(s, ":")
	return len(f) == 2 && len(f[0]) == 32 && isHex(f[0]) && len(f[1]) >= 116 && len(f[1]) <= 148 &&
		len(f[1])%2 == 0 && isHex(f[1])
}

// isIPMI: <hex-salt>:<40-char sha1>, salt longer than 40 (a RAKP blob) to avoid
// colliding with Redmine's sha1:salt shape.
func isIPMI(s string) bool {
	f := strings.SplitN(s, ":", 2)
	return len(f) == 2 && len(f[1]) == 40 && isHex(f[1]) &&
		len(f[0]) > 40 && len(f[0])%2 == 0 && isHex(f[0])
}

func verifyHalfMD5(targetHash, candidate string) (bool, error) {
	if len(targetHash) != 16 {
		return false, errors.New("invalid Half-MD5 hash (need 16 hex chars)")
	}
	d := md5.Sum([]byte(candidate))
	return strings.EqualFold(hex.EncodeToString(d[:])[:16], targetHash), nil
}
