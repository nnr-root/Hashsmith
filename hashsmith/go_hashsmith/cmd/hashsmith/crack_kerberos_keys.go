package main

// The long-term keys a Kerberos KDC stores, rather than a ticket encrypted
// with one.
//
//	$krb17$<salt>$<16-byte key>   aes128-cts-hmac-sha1-96
//	$krb18$<salt>$<32-byte key>   aes256-cts-hmac-sha1-96
//
// A ticket is evidence that a key was used; a database key IS the key, which
// is what a dump of the KDC — or of a domain controller — yields. The
// derivation is the same string-to-key the ticket formats already use, so
// checking one is one PBKDF2 and one key-derivation step with nothing to
// decrypt afterwards.
//
// The salt is not a random value: Kerberos builds it from the principal, as
// the realm followed by the username with no separator, which is why
// "TEST.LOCAL" and "test" appear in the record run together. It is stored
// rather than derived because a KDC may have been told to use something else.

import (
	"crypto/hmac"
	"errors"
	"strings"
)

// krbDBKeySizes maps John's format numbers to the key length each etype has.
var krbDBKeySizes = map[string]int{"krb17": 16, "krb18": 32}

// krbDBKeyFields reads one of those records.
func krbDBKeyFields(target string) (etype string, salt string, key []byte, err error) {
	t := strings.TrimSpace(target)
	if !strings.HasPrefix(t, "$krb1") {
		return "", "", nil, errors.New("not a Kerberos database key record")
	}
	f := strings.SplitN(t[1:], "$", 3)
	if len(f) != 3 {
		return "", "", nil, errors.New("a Kerberos key record is $krb17$<salt>$<key>")
	}
	size, ok := krbDBKeySizes[f[0]]
	if !ok {
		return "", "", nil, errors.New("unsupported Kerberos key etype " + f[0])
	}
	if f[1] == "" || len(f[1]) > maxKDFFieldSize {
		return "", "", nil, errors.New("a Kerberos key record must carry its salt")
	}
	key, err = decodeExactHex(f[2], size, "Kerberos key")
	if err != nil {
		return "", "", nil, err
	}
	return f[0], f[1], key, nil
}

// verifyKrbDBKey checks a stored Kerberos key.
func verifyKrbDBKey(target, candidate string) (bool, error) {
	etype, salt, key, err := krbDBKeyFields(target)
	if err != nil {
		return false, err
	}
	return hmac.Equal(aesString2Key(candidate, salt, krbDBKeySizes[etype]), key), nil
}

func isKrbDBKey(target string) bool {
	_, _, _, err := krbDBKeyFields(target)
	return err == nil
}

// johnMSKrb5Record reads John's "$mskrb5$<user>$<realm>$<checksum>$<edata>"
// as the "$krb5pa$23$..." record the RC4 pre-authentication reader expects.
//
// Both hold the same AS-REQ timestamp, encrypted under the NTLM hash. The two
// disagree about order: John writes the checksum before the encrypted data,
// hashcat runs the data and the checksum together into one field with the
// checksum last. The user and realm are along for the ride in both — RC4's
// string-to-key is the NTLM hash and uses no salt, so neither field affects
// the answer.
func johnMSKrb5Record(target string) (string, bool) {
	const prefix = "$mskrb5$"
	t := strings.TrimSpace(target)
	if !strings.HasPrefix(t, prefix) {
		return "", false
	}
	f := strings.Split(t[len(prefix):], "$")
	if len(f) != 4 {
		return "", false
	}
	user, realm, checksum, edata := f[0], f[1], f[2], f[3]
	if len(checksum) != 32 || !isHex(checksum) || len(edata) != 72 || !isHex(edata) {
		return "", false
	}
	if strings.ContainsAny(user+realm, "$") {
		return "", false
	}
	return "$krb5pa$23$" + user + "$" + realm + "$$" + edata + checksum, true
}

func isJohnMSKrb5(target string) bool {
	_, ok := johnMSKrb5Record(target)
	return ok
}
