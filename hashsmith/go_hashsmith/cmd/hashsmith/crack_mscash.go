package main

// Domain Cached Credentials (MS Cache):
//
//	DCC  (mscash)  : <md4>:<username>
//	   dcc = md4( md4(utf16le(pass)) . utf16le(lower(user)) )
//	DCC2 (mscash2) : $DCC2$<iter>#<username>#<hash>
//	   dcc2 = PBKDF2-HMAC-SHA1(dcc, utf16le(lower(user)), iter, 16)

import (
	"crypto/sha1"
	"encoding/hex"
	"errors"
	"strconv"
	"strings"

	"golang.org/x/crypto/md4"
	"golang.org/x/crypto/pbkdf2"
)

// dccKey computes the DCC (mscash) value for a password and username.
func dccKey(password, username string) []byte {
	nt := md4.New()
	nt.Write(utf16le(password))
	return dccKeyFromNTHash(nt.Sum(nil), username)
}

func dccKeyFromNTHash(ntHash []byte, username string) []byte {
	d := md4.New()
	d.Write(ntHash)
	d.Write(utf16le(strings.ToLower(username)))
	return d.Sum(nil)
}

// verifyDCC checks a candidate against a <md4>:<username> DCC hash.
// verifyDCC reads both spellings of a Domain Cached Credentials record.
//
// hashcat writes "<md4>:<username>". John writes "M$<username>#<md4>" — the
// same two fields, named, reordered and with a different separator. A John
// user's mscash record is in the second form, so both are read.
func verifyDCC(targetHash, candidate string) (bool, error) {
	if user, digest, ok := johnMSCashFields(targetHash); ok {
		got := hex.EncodeToString(dccKey(candidate, user))
		return strings.EqualFold(got, digest), nil
	}
	f := strings.SplitN(targetHash, ":", 2)
	if len(f) != 2 || len(f[0]) != 32 {
		return false, errors.New("invalid DCC hash (need md4:username)")
	}
	got := hex.EncodeToString(dccKey(candidate, f[1]))
	return strings.EqualFold(got, f[0]), nil
}

// johnMSCashFields reads John's "M$<username>#<md4>" spelling. The username
// may contain anything except the '#' that ends it, so the split is on the
// LAST one.
func johnMSCashFields(target string) (user, digest string, ok bool) {
	const prefix = "M$"
	t := strings.TrimSpace(target)
	if !strings.HasPrefix(t, prefix) {
		return "", "", false
	}
	body := t[len(prefix):]
	i := strings.LastIndexByte(body, '#')
	if i <= 0 || len(body)-i-1 != 32 || !isHex(body[i+1:]) {
		return "", "", false
	}
	return body[:i], body[i+1:], true
}

// isJohnMSCash reports whether a record uses John's spelling, for detection.
func isJohnMSCash(s string) bool {
	_, _, ok := johnMSCashFields(s)
	return ok
}

// verifyDCC2 checks a candidate against a $DCC2$iter#user#hash hash.
func verifyDCC2(targetHash, candidate string) (bool, error) {
	if !strings.HasPrefix(targetHash, "$DCC2$") {
		return false, errors.New("invalid DCC2 hash (missing $DCC2$ prefix)")
	}
	f := strings.Split(targetHash[len("$DCC2$"):], "#")
	if len(f) != 3 {
		return false, errors.New("invalid DCC2 hash (need iter#user#hash)")
	}
	iter, err := strconv.Atoi(f[0])
	if err != nil || iter < 1 {
		return false, errors.New("invalid DCC2 iteration count")
	}
	want, err := hex.DecodeString(f[2])
	if err != nil || len(want) != 16 {
		return false, errors.New("invalid DCC2 digest")
	}
	dcc := dccKey(candidate, f[1])
	got := pbkdf2.Key(dcc, utf16le(strings.ToLower(f[1])), iter, 16, sha1.New)
	return bytesEqualCT(got, want), nil
}

// isDCC2 detects the $DCC2$ format. (Bare DCC shares the <md5>:<salt> shape with
// vBulletin, so detection offers both candidates there.)
func isDCC2(s string) bool { return strings.HasPrefix(s, "$DCC2$") }
