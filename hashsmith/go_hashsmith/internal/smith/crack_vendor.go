package smith

// Vendor and platform password formats that are a thin wrapper over primitives
// Hashsmith already implements.  Each one is a documented construction plus a
// distinctive ciphertext encoding, so the work here is parsing the record and
// feeding the right bytes to an existing digest or KDF.

import (
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"strconv"
	"strings"

	"golang.org/x/crypto/md4"
	"golang.org/x/crypto/pbkdf2"
)

// ── PeopleSoft ────────────────────────────────────────────────────────────────

// verifyPeopleSoft checks a PeopleSoft PS_TOKEN password (Hashcat 133):
//
//	base64(sha1(utf16le($pass)))
//
// The record is the bare base64 digest, with no salt and no iteration count.
func verifyPeopleSoft(targetHash, candidate string) (bool, error) {
	want, err := base64.StdEncoding.DecodeString(strings.TrimSpace(targetHash))
	if err != nil || len(want) != sha1.Size {
		return false, errors.New("invalid PeopleSoft hash (need base64 of a 20-byte SHA-1)")
	}
	sum := sha1.Sum(utf16le(candidate))
	return bytesEqualCT(sum[:], want), nil
}

func isPeopleSoft(s string) bool {
	s = strings.TrimSpace(s)
	if len(s) != 28 || !strings.HasSuffix(s, "=") {
		return false
	}
	raw, err := base64.StdEncoding.DecodeString(s)
	return err == nil && len(raw) == sha1.Size
}

// ── Episerver ─────────────────────────────────────────────────────────────────

// verifyEpiserver checks an Episerver CMS password (Hashcat 141 and 1441):
//
//	version 0: base64(sha1($salt . utf16le($pass)))     — Episerver 6.x < .NET 4
//	version 1: base64(sha256($salt . utf16le($pass)))   — Episerver 6.x >= .NET 4
//
// Record: $episerver$*<version>*<base64 salt>*<base64 digest>.  The salt is the
// decoded base64 used as raw bytes, not its textual form.
func verifyEpiserver(targetHash, candidate string) (bool, error) {
	version, salt, want, err := parseEpiserver(targetHash)
	if err != nil {
		return false, err
	}
	var got []byte
	if version == 0 {
		sum := sha1.Sum(append(salt, utf16le(candidate)...))
		got = sum[:]
	} else {
		sum := sha256.Sum256(append(salt, utf16le(candidate)...))
		got = sum[:]
	}
	return bytesEqualCT(got, want), nil
}

func parseEpiserver(target string) (version int, salt, digest []byte, err error) {
	if !strings.HasPrefix(target, "$episerver$*") {
		return 0, nil, nil, errors.New("invalid Episerver hash (missing $episerver$ prefix)")
	}
	f := strings.Split(target[len("$episerver$*"):], "*")
	if len(f) != 3 {
		return 0, nil, nil, errors.New("invalid Episerver hash (need version*salt*digest)")
	}
	version, err = strconv.Atoi(f[0])
	if err != nil || (version != 0 && version != 1) {
		return 0, nil, nil, errors.New("unsupported Episerver version (need 0 or 1)")
	}
	// hashcat -m 141 / -m 1441 publish these fields WITHOUT base64 padding
	// (e.g. "ZUgAmuaYTqAvisD0A427FA3oaWU", 27 characters). Padded records from
	// other sources stay valid; base64Flexible accepts either.
	if salt, err = episerverB64(f[1]); err != nil || len(salt) == 0 || len(salt) > maxKDFFieldSize {
		return 0, nil, nil, errors.New("invalid Episerver salt")
	}
	if digest, err = episerverB64(f[2]); err != nil {
		return 0, nil, nil, errors.New("invalid Episerver digest")
	}
	wantLen := sha1.Size
	if version == 1 {
		wantLen = sha256.Size
	}
	if len(digest) != wantLen {
		return 0, nil, nil, errors.New("Episerver digest length does not match the version")
	}
	return version, salt, digest, nil
}

func isEpiserver(s string) bool {
	_, _, _, err := parseEpiserver(s)
	return err == nil
}

// ── MS-AzureSync / Azure AD Connect ───────────────────────────────────────────

// verifyAzureSync checks an MS-AzureSync password blob (Hashcat 12800):
//
//	PBKDF2-HMAC-SHA256(utf16le(UPPERCASE_HEX(MD4(utf16le($pass)))), $salt, $iter, 32)
//
// The PBKDF2 password is NOT the raw 16-byte NT hash. Azure AD Connect renders
// that hash as 32 uppercase hexadecimal characters and then encodes THAT as
// UTF-16LE — a 64-byte key — before handing it to PBKDF2. Using the raw digest
// instead produced a different derived key for every candidate, so every
// -m 12800 target ran the full KDF and reported the correct password as not
// found. Confirmed against hashcat's own example record, where the raw form,
// both plain-ASCII hex forms and the lowercase UTF-16LE form all disagree with
// the published digest and this one reproduces it exactly.
//
// The security consequence is unchanged: the input is still a deterministic
// function of the NT hash alone, so an attacker holding the NT hash does not
// need the cleartext.
//
// Record: v1;PPH1_MD4,<hex salt>,<iterations>,<hex digest>
func verifyAzureSync(targetHash, candidate string) (bool, error) {
	salt, iter, want, err := parseAzureSync(targetHash)
	if err != nil {
		return false, err
	}
	nt := md4.New()
	_, _ = nt.Write(utf16le(candidate))
	key := utf16le(strings.ToUpper(hex.EncodeToString(nt.Sum(nil))))
	got := pbkdf2.Key(key, salt, iter, len(want), sha256.New)
	return bytesEqualCT(got, want), nil
}

func parseAzureSync(target string) (salt []byte, iter int, digest []byte, err error) {
	const prefix = "v1;PPH1_MD4,"
	if !strings.HasPrefix(target, prefix) {
		return nil, 0, nil, errors.New("invalid MS-AzureSync hash (missing v1;PPH1_MD4, prefix)")
	}
	f := strings.Split(target[len(prefix):], ",")
	if len(f) != 3 {
		return nil, 0, nil, errors.New("invalid MS-AzureSync hash (need salt,iterations,digest)")
	}
	if salt, err = hex.DecodeString(f[0]); err != nil || len(salt) == 0 || len(salt) > maxKDFFieldSize {
		return nil, 0, nil, errors.New("invalid MS-AzureSync salt")
	}
	if iter, err = strconv.Atoi(f[1]); err != nil || iter < 1 || iter > maxKDFIterations {
		return nil, 0, nil, errors.New("invalid MS-AzureSync iteration count")
	}
	if digest, err = hex.DecodeString(f[2]); err != nil || len(digest) == 0 || len(digest) > maxKDFFieldSize {
		return nil, 0, nil, errors.New("invalid MS-AzureSync digest")
	}
	return salt, iter, digest, nil
}

func isAzureSync(s string) bool {
	_, _, _, err := parseAzureSync(s)
	return err == nil
}

// ── hMailServer ───────────────────────────────────────────────────────────────

// verifyHMailServer checks an hMailServer password (Hashcat 1421):
//
//	sha256($salt . $pass)
//
// The record is unusual in that the six-character salt is not a separate field
// — it is simply the first six characters of the stored string, with the
// SHA-256 hex digest following it.
func verifyHMailServer(targetHash, candidate string) (bool, error) {
	if len(targetHash) != 6+64 || !isHex(targetHash[6:]) {
		return false, errors.New("invalid hMailServer hash (need a 6-char salt then 64 hex chars)")
	}
	sum := sha256.Sum256([]byte(targetHash[:6] + candidate))
	return strings.EqualFold(hex.EncodeToString(sum[:]), targetHash[6:]), nil
}

func isHMailServer(s string) bool {
	if len(s) != 70 || !isHex(s[6:]) {
		return false
	}
	// A record opening with a format envelope this tool recognises is that
	// format, not an hMailServer hash whose six-character salt happens to
	// look like one. "$gost$" is six non-hex characters followed by 64 hex,
	// which is exactly this shape — and it is John's spelling of a GOST
	// digest. The envelope is a signature; this predicate is only a shape,
	// so it yields.
	if _, _, ok := johnWrapperFor(s); ok {
		return false
	}
	return true
}

// episerverB64 decodes a standard-alphabet base64 field with or without its
// trailing padding. hashcat's -m 141 and -m 1441 example records omit the
// padding; records from other sources carry it.
func episerverB64(s string) ([]byte, error) {
	if n := len(s) % 4; n != 0 {
		s += strings.Repeat("=", 4-n)
	}
	return base64.StdEncoding.DecodeString(s)
}
