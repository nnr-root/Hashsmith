package main

// Salted LDAP / directory password schemes (RFC 2307 / OpenLDAP):
//
//	{SSHA}<b64(sha1(pass.salt) . salt)>
//	{SSHA256}<b64(sha256(pass.salt) . salt)>
//	{SSHA512}<b64(sha512(pass.salt) . salt)>
//	{SMD5}<b64(md5(pass.salt) . salt)>
//
// The digest length is fixed by the scheme; whatever follows in the decoded
// blob is the salt.

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"errors"
	"hash"
	"strings"
)

type ldapScheme struct {
	tag     string
	newHash func() hash.Hash
	dLen    int
}

var ldapSchemes = []ldapScheme{
	{"{SSHA512}", sha512.New, 64},
	{"{SSHA256}", sha256.New, 32},
	{"{SSHA}", sha1.New, 20},
	{"{SMD5}", md5.New, 16},
}

func ldapSchemeFor(s string) *ldapScheme {
	for i := range ldapSchemes {
		if strings.HasPrefix(s, ldapSchemes[i].tag) {
			return &ldapSchemes[i]
		}
	}
	return nil
}

func verifyLDAP(targetHash, candidate string) (bool, error) {
	sc := ldapSchemeFor(targetHash)
	if sc == nil {
		return false, errors.New("invalid LDAP hash (need {SSHA}/{SSHA256}/{SSHA512}/{SMD5})")
	}
	raw, err := base64.StdEncoding.DecodeString(targetHash[len(sc.tag):])
	if err != nil || len(raw) < sc.dLen {
		return false, errors.New("invalid LDAP base64 blob")
	}
	want := raw[:sc.dLen]
	salt := raw[sc.dLen:]
	h := sc.newHash()
	h.Write([]byte(candidate))
	h.Write(salt)
	return bytesEqualCT(h.Sum(nil), want), nil
}

func isLDAP(s string) bool { return ldapSchemeFor(s) != nil }
