package main

// Four small formats John reads and Hashsmith did not.
//
//	azuread      what Azure AD Connect synchronises to the cloud: the NTLM
//	             hash, written as upper-case hex in UTF-16LE, run through
//	             PBKDF2-HMAC-SHA256. Cracking one recovers the on-premises
//	             domain password, which is the point of the format existing.
//	known_hosts  the hashed host entries OpenSSH writes with HashKnownHosts.
//	             The "password" is a hostname or address, so cracking one
//	             turns an anonymised known_hosts file back into a list of
//	             machines the account has reached.
//	zipmonster   MD5 applied fifty thousand times over its own upper-case hex.
//	dummy        the password itself, in hex. John ships it to exercise a
//	             cracker's plumbing without any cryptography in the way, and
//	             it serves the same purpose here.

import (
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"strconv"
	"strings"

	"golang.org/x/crypto/pbkdf2"
)

// ── Azure AD ──────────────────────────────────────────────────────────────────

const azureADPrefix = "v1;PPH1_MD4,"

// azureADFields reads "v1;PPH1_MD4,<salt hex>,<rounds>,<digest hex>" — with or
// without the semicolon John's records end with.
func azureADFields(target string) (salt []byte, rounds int, digest []byte, err error) {
	t := strings.TrimSuffix(strings.TrimSpace(target), ";")
	if !strings.HasPrefix(t, azureADPrefix) {
		return nil, 0, nil, errors.New("not an Azure AD record")
	}
	f := strings.Split(t[len(azureADPrefix):], ",")
	if len(f) != 3 {
		return nil, 0, nil, errors.New("an Azure AD record needs a salt, a round count and a digest")
	}
	if salt, err = hex.DecodeString(f[0]); err != nil || len(salt) == 0 {
		return nil, 0, nil, errors.New("invalid Azure AD salt")
	}
	rounds, err = strconv.Atoi(f[1])
	if err != nil || rounds < 1 || rounds > maxKDFIterations {
		return nil, 0, nil, errors.New("invalid Azure AD round count")
	}
	if digest, err = hex.DecodeString(f[2]); err != nil || len(digest) != sha256.Size {
		return nil, 0, nil, errors.New("invalid Azure AD digest")
	}
	return salt, rounds, digest, nil
}

// verifyAzureAD checks a synchronised Azure AD credential.
//
// The password never reaches PBKDF2 directly. Azure AD Connect takes the NTLM
// hash, writes it as thirty-two upper-case hex characters, encodes those as
// UTF-16LE, and uses that as the PBKDF2 password — so what protects the
// account is one PBKDF2-SHA256 pass over a value an attacker with the
// on-premises hash already has.
func verifyAzureAD(target, candidate string) (bool, error) {
	salt, rounds, digest, err := azureADFields(target)
	if err != nil {
		return false, err
	}
	key := utf16le(strings.ToUpper(hex.EncodeToString(ntHash(candidate))))
	got := pbkdf2.Key(key, salt, rounds, sha256.Size, sha256.New)
	return hmac.Equal(got, digest), nil
}

func isAzureAD(target string) bool {
	_, _, _, err := azureADFields(target)
	return err == nil
}

// ── OpenSSH known_hosts ───────────────────────────────────────────────────────

const knownHostsPrefix = "$known_hosts$"

// knownHostsFields reads "$known_hosts$|1|<salt>|<digest>", the line
// HashKnownHosts writes with the leading marker John keeps.
func knownHostsFields(target string) (salt, digest []byte, err error) {
	t := strings.TrimSpace(target)
	if strings.HasPrefix(t, knownHostsPrefix) {
		t = t[len(knownHostsPrefix):]
	}
	f := strings.Split(t, "|")
	// "", "1", salt, digest — the line starts with the separator.
	if len(f) != 4 || f[0] != "" || f[1] != "1" {
		return nil, nil, errors.New("a hashed known_hosts entry is |1|<salt>|<digest>")
	}
	if salt, err = base64.StdEncoding.DecodeString(f[2]); err != nil || len(salt) == 0 {
		return nil, nil, errors.New("invalid known_hosts salt")
	}
	if digest, err = base64.StdEncoding.DecodeString(f[3]); err != nil || len(digest) != sha1.Size {
		return nil, nil, errors.New("invalid known_hosts digest")
	}
	return salt, digest, nil
}

// verifyKnownHosts checks a hashed known_hosts entry: HMAC-SHA1 keyed by the
// salt over the hostname. The candidate is the hostname or address, which is
// why a wordlist of names or an address-shaped mask is what cracks one.
func verifyKnownHosts(target, candidate string) (bool, error) {
	salt, digest, err := knownHostsFields(target)
	if err != nil {
		return false, err
	}
	mac := hmac.New(sha1.New, salt)
	_, _ = mac.Write([]byte(candidate))
	return hmac.Equal(mac.Sum(nil), digest), nil
}

func isKnownHosts(target string) bool {
	_, _, err := knownHostsFields(target)
	return err == nil
}

// ── ZipMonster ────────────────────────────────────────────────────────────────

const (
	zipMonsterPrefix = "$zipmonster$"
	zipMonsterRounds = 50000
)

// verifyZipMonster checks a ZipMonster password: MD5, then MD5 again over the
// upper-case hex of the result, fifty thousand times in all. The case matters
// — the same loop over lower-case hex produces a different answer.
//
// The "$zipmonster$" prefix is this tool's own; John writes the digest bare,
// so both spellings are read. The bare one is accepted only when -t names
// this type, and ZipMonster is deliberately NOT among the types a bare
// 32-character digest is offered as.
//
// That is a judgement about cost, not about likelihood. Every other candidate
// for that width is one hash per password; this is fifty thousand. Adding it
// to the shape table would end every unsuccessful auto-attack on an MD5-shaped
// digest — the common case — in a run four orders of magnitude slower than
// the ones before it, or in a feasibility refusal. Naming the type is one
// flag, and it is the right place for that decision to be made.
func verifyZipMonster(target, candidate string) (bool, error) {
	t := strings.TrimSpace(target)
	want := strings.TrimPrefix(t, zipMonsterPrefix)
	if len(want) != 2*md5.Size || !isHex(want) {
		return false, errors.New("a ZipMonster record is one MD5, with or without the $zipmonster$ prefix")
	}
	sum := md5.Sum([]byte(candidate))
	h := strings.ToUpper(hex.EncodeToString(sum[:]))
	for i := 1; i < zipMonsterRounds; i++ {
		sum = md5.Sum([]byte(h))
		h = strings.ToUpper(hex.EncodeToString(sum[:]))
	}
	return strings.EqualFold(h, want), nil
}

// ── John's dummy format ───────────────────────────────────────────────────────

const dummyPrefix = "$dummy$"

// verifyDummy checks John's dummy format, which is the password in hex. It
// exists to exercise a cracker's plumbing — wordlists, rules, masks, session
// handling — with no cryptography in the way, so that a failure there is
// unambiguous.
func verifyDummy(target, candidate string) (bool, error) {
	t := strings.TrimSpace(target)
	if !strings.HasPrefix(t, dummyPrefix) {
		return false, errors.New("not a dummy record")
	}
	return strings.EqualFold(hex.EncodeToString([]byte(candidate)), t[len(dummyPrefix):]), nil
}

func isDummy(target string) bool {
	t := strings.TrimSpace(target)
	return strings.HasPrefix(t, dummyPrefix) && isHex(t[len(dummyPrefix):]) &&
		len(t) > len(dummyPrefix) && len(t)%2 == len(dummyPrefix)%2
}

// ── Post.Office ───────────────────────────────────────────────────────────────

// Post.Office was Software.com's mail server through the late 1990s, and the
// one still in the wild is a preserved installation rather than a running
// product. Its password record is a digest and a salt run together with no
// separator at all:
//
//	<32 hex digest><32-character salt>
//
// which is indistinguishable from a bare SHA-256 by shape, so it is offered
// as one more scarce reading of that width rather than asserted.
//
// The construction is
//
//	md5(salt || 'Y' || password || 0xF7 || salt)
//
// and the two separators are the whole of what makes it its own format. They
// were settled by search rather than taken on trust: a bounded sweep of
// orderings and single-byte separators against John's own vector returned
// this one and nothing else. The salt is used as the ASCII it is, not
// hex-decoded, even though John's vector happens to be all 'a'.
const postOfficeSaltLen = 32

func postOfficeFields(target string) (digest, salt string, err error) {
	t := strings.TrimSpace(target)
	if len(t) != 2*md5.Size+postOfficeSaltLen {
		return "", "", errors.New("a Post.Office record is a 32-character digest followed by a 32-character salt")
	}
	digest, salt = t[:2*md5.Size], t[2*md5.Size:]
	if !isHex(digest) {
		return "", "", errors.New("a Post.Office record starts with an MD5")
	}
	for i := 0; i < len(salt); i++ {
		if salt[i] < 0x20 || salt[i] > 0x7e {
			return "", "", errors.New("a Post.Office salt is printable ASCII")
		}
	}
	return digest, salt, nil
}

func verifyPostOffice(target, candidate string) (bool, error) {
	digest, salt, err := postOfficeFields(target)
	if err != nil {
		return false, err
	}
	h := md5.New()
	_, _ = h.Write([]byte(salt))
	_, _ = h.Write([]byte{'Y'})
	_, _ = h.Write([]byte(candidate))
	_, _ = h.Write([]byte{0xF7})
	_, _ = h.Write([]byte(salt))
	return strings.EqualFold(hex.EncodeToString(h.Sum(nil)), digest), nil
}

func isPostOffice(target string) bool {
	_, _, err := postOfficeFields(target)
	return err == nil
}
