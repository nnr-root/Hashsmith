package main

// CMS / web-app password formats built from unsalted MD5/SHA-1 primitives:
//
//	$B$<salt>$<md5>          MediaWiki B  — md5(salt . "-" . md5(pass))
//	<md5>:<salt>             vBulletin    — md5(md5(pass) . salt)
//	<sha1>:<salt>            Redmine      — sha1(salt . sha1(pass))

import (
	"crypto/md5"
	"crypto/sha1"
	"encoding/hex"
	"errors"
	"strings"
)

func md5Hex(parts ...[]byte) string {
	h := md5.New()
	for _, p := range parts {
		h.Write(p)
	}
	return hex.EncodeToString(h.Sum(nil))
}

func sha1Hex(parts ...[]byte) string {
	h := sha1.New()
	for _, p := range parts {
		h.Write(p)
	}
	return hex.EncodeToString(h.Sum(nil))
}

// verifyMediaWiki checks a candidate against a $B$<salt>$<md5> hash.
func verifyMediaWiki(targetHash, candidate string) (bool, error) {
	if !strings.HasPrefix(targetHash, "$B$") {
		return false, errors.New("invalid MediaWiki hash (missing $B$ prefix)")
	}
	f := strings.Split(targetHash[len("$B$"):], "$")
	if len(f) != 2 || len(f[1]) != 32 {
		return false, errors.New("invalid MediaWiki hash (need salt$md5)")
	}
	inner := md5Hex([]byte(candidate))
	got := md5Hex([]byte(f[0] + "-" + inner))
	return got == f[1], nil
}

// verifyVBulletin checks a candidate against a <md5>:<salt> vBulletin hash.
func verifyVBulletin(targetHash, candidate string) (bool, error) {
	f := strings.SplitN(targetHash, ":", 2)
	if len(f) != 2 || len(f[0]) != 32 {
		return false, errors.New("invalid vBulletin hash (need md5:salt)")
	}
	inner := md5Hex([]byte(candidate))
	got := md5Hex([]byte(inner + f[1]))
	return strings.EqualFold(got, f[0]), nil
}

// verifyRedmine checks a candidate against a <sha1>:<salt> Redmine hash.
func verifyRedmine(targetHash, candidate string) (bool, error) {
	f := strings.SplitN(targetHash, ":", 2)
	if len(f) != 2 || len(f[0]) != 40 {
		return false, errors.New("invalid Redmine hash (need sha1:salt)")
	}
	inner := sha1Hex([]byte(candidate))
	got := sha1Hex([]byte(f[1] + inner))
	return strings.EqualFold(got, f[0]), nil
}

// Detection helpers.
func isMediaWiki(s string) bool {
	if !strings.HasPrefix(s, "$B$") {
		return false
	}
	f := strings.Split(s[len("$B$"):], "$")
	return len(f) == 2 && len(f[1]) == 32 && isHex(f[1])
}

func isVBulletin(s string) bool {
	f := strings.SplitN(s, ":", 2)
	return len(f) == 2 && len(f[0]) == 32 && isHex(f[0]) && f[1] != "" && !strings.Contains(f[1], ":")
}

func isRedmine(s string) bool {
	f := strings.SplitN(s, ":", 2)
	return len(f) == 2 && len(f[0]) == 40 && isHex(f[0]) && len(f[1]) == 32 && isHex(f[1])
}
