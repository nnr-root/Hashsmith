package main

// Salted LDAP / directory password schemes (RFC 2307 / OpenLDAP):
//
//	{SSHA}<b64(sha1(pass.salt) . salt)>
//	{SSHA256}<b64(sha256(pass.salt) . salt)>
//	{SSHA384}<b64(sha384(pass.salt) . salt)>
//	{SSHA512}<b64(sha512(pass.salt) . salt)>
//	{SMD5}<b64(md5(pass.salt) . salt)>
//	{SHA}/{SHA256}/{SHA384}/{SHA512}/{MD5}<b64(digest(pass))>
//	{CRYPT}<crypt(3) hash>
//
// The digest length is fixed by the scheme; whatever follows in the decoded
// blob is the salt.

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"errors"
	"hash"
	"strings"
)

type ldapScheme struct {
	tag     string
	newHash func() hash.Hash
	dLen    int
	salted  bool
}

var ldapSchemes = []ldapScheme{
	{"{SSHA512}", sha512.New, 64, true},
	{"{SSHA384}", sha512.New384, 48, true},
	{"{SSHA256}", sha256.New, 32, true},
	{"{SSHA}", sha1.New, 20, true},
	{"{SMD5}", md5.New, 16, true},
	{"{SHA512}", sha512.New, 64, false},
	{"{SHA384}", sha512.New384, 48, false},
	{"{SHA256}", sha256.New, 32, false},
	{"{SHA}", sha1.New, 20, false},
	{"{MD5}", md5.New, 16, false},
}

func ldapSchemeFor(s string) *ldapScheme {
	for i := range ldapSchemes {
		if len(s) >= len(ldapSchemes[i].tag) && strings.EqualFold(s[:len(ldapSchemes[i].tag)], ldapSchemes[i].tag) {
			return &ldapSchemes[i]
		}
	}
	return nil
}

func verifyLDAP(targetHash, candidate string) (bool, error) {
	if len(targetHash) >= len("{CRYPT}") && strings.EqualFold(targetHash[:len("{CRYPT}")], "{CRYPT}") {
		cryptHash := targetHash[len("{CRYPT}"):]
		if !looksLikeCryptHash(cryptHash) {
			return false, errors.New("invalid LDAP {CRYPT} hash")
		}
		for _, typ := range detectHashTypes(cryptHash) {
			ok, err := verifyCandidate(candidate, cryptHash, typ, "", "prefix")
			if err == nil && ok {
				return true, nil
			}
		}
		return false, nil
	}
	sc := ldapSchemeFor(targetHash)
	if sc == nil {
		return false, errors.New("invalid LDAP hash scheme")
	}
	raw, err := decodeBase64Flexible(targetHash[len(sc.tag):], false)
	if err != nil || len(raw) < sc.dLen || (!sc.salted && len(raw) != sc.dLen) {
		return false, errors.New("invalid LDAP base64 blob")
	}
	want := raw[:sc.dLen]
	salt := raw[sc.dLen:]
	h := sc.newHash()
	h.Write([]byte(candidate))
	h.Write(salt)
	return bytesEqualCT(h.Sum(nil), want), nil
}

func isLDAP(s string) bool {
	return ldapSchemeFor(s) != nil || (len(s) >= len("{CRYPT}") &&
		strings.EqualFold(s[:len("{CRYPT}")], "{CRYPT}") && looksLikeCryptHash(s[len("{CRYPT}"):]))
}
