package main

import (
	"bytes"
	"crypto/des"
	"crypto/hmac"
	"crypto/md5"
	"encoding/hex"
	"errors"
	"strings"

	"golang.org/x/crypto/md4"
)

// ── NetNTLM (captured challenge/response) ──────────────────────────────────────
//
// These are the credentials captured by tools like Responder and by SMB/HTTP
// relay attacks. They are already text lines, so there is no *2smith extractor —
// paste the captured line straight into `crack`.
//
//   NetNTLMv2:
//       user::domain:serverchallenge:ntproof:blob
//   NetNTLMv1:
//       user::domain:lmresponse:ntresponse:serverchallenge

// ntHash returns the NTLM hash MD4(UTF-16LE(password)).
func ntHash(password string) []byte {
	h := md4.New()
	_, _ = h.Write(utf16le(password))
	return h.Sum(nil)
}

// isNetNTLMLine reports whether s has the shape user::domain:hex:hex:hex, the
// common structure of both NetNTLMv1 and NetNTLMv2 captures.
func isNetNTLMLine(s string) bool {
	f := strings.Split(s, ":")
	if len(f) != 6 || f[1] != "" {
		return false
	}
	for _, part := range f[3:] {
		if part == "" || !isHex(part) {
			return false
		}
	}
	return true
}

// verifyNetNTLMv2 checks a captured NetNTLMv2 response against a candidate.
func verifyNetNTLMv2(targetHash, candidate string) (bool, error) {
	return verifyNetNTLMv2NTHash(targetHash, ntHash(candidate))
}

// verifyNetNTLMv2NTHash checks the response from an already-computed NT hash.
// Hashcat mode 27100 exposes this input directly, while mode 5600 calls it
// through verifyNetNTLMv2 after deriving MD4(UTF-16LE(password)).
func verifyNetNTLMv2NTHash(targetHash string, nt []byte) (bool, error) {
	fields := strings.Split(targetHash, ":")
	if len(fields) != 6 {
		return false, errors.New("invalid NetNTLMv2 format (want user::domain:srvchal:ntproof:blob)")
	}
	user, domain := fields[0], fields[2]
	srvChal, err := hex.DecodeString(fields[3])
	if err != nil {
		return false, errors.New("invalid NetNTLMv2 server challenge")
	}
	ntProof, err := hex.DecodeString(fields[4])
	if err != nil || len(ntProof) != 16 {
		return false, errors.New("invalid NetNTLMv2 NT proof")
	}
	blob, err := hex.DecodeString(fields[5])
	if err != nil {
		return false, errors.New("invalid NetNTLMv2 blob")
	}

	// NTLMv2 key = HMAC-MD5(NThash, UTF16LE(UPPER(user) + domain)).
	// The username is uppercased; the domain is used verbatim.
	ident := utf16le(strings.ToUpper(user) + domain)
	mac := hmac.New(md5.New, nt)
	mac.Write(ident)
	v2key := mac.Sum(nil)

	// NTProof = HMAC-MD5(v2key, serverChallenge || blob).
	mac2 := hmac.New(md5.New, v2key)
	mac2.Write(srvChal)
	mac2.Write(blob)
	return hmac.Equal(mac2.Sum(nil), ntProof), nil
}

// verifyNetNTLMv1 checks a captured NetNTLMv1 response against a candidate.
func verifyNetNTLMv1(targetHash, candidate string) (bool, error) {
	fields := strings.Split(targetHash, ":")
	if len(fields) != 6 {
		return false, errors.New("invalid NetNTLMv1 format (want user::domain:lm:nt:srvchal)")
	}
	lmResp, err := hex.DecodeString(fields[3])
	if err != nil {
		return false, errors.New("invalid NetNTLMv1 LM response")
	}
	ntResp, err := hex.DecodeString(fields[4])
	if err != nil || len(ntResp) != 24 {
		return false, errors.New("invalid NetNTLMv1 NT response (need 24 bytes)")
	}
	srvChal, err := hex.DecodeString(fields[5])
	if err != nil || len(srvChal) != 8 {
		return false, errors.New("invalid NetNTLMv1 server challenge (need 8 bytes)")
	}

	// Extended Session Security (NTLMv1-ESS): the LM field holds an 8-byte client
	// challenge followed by 16 zero bytes; the effective challenge is then
	// MD5(serverChallenge || clientChallenge)[:8].
	challenge := srvChal
	if len(lmResp) == 24 && bytes.Equal(lmResp[8:], make([]byte, 16)) &&
		!bytes.Equal(lmResp[:8], make([]byte, 8)) {
		sum := md5.Sum(append(append([]byte{}, srvChal...), lmResp[:8]...))
		challenge = sum[:8]
	}

	// NT hash padded to 21 bytes → three 7-byte DES keys, each encrypting the
	// 8-byte server challenge; the concatenation is the 24-byte NT response.
	key := make([]byte, 21)
	copy(key, ntHash(candidate))

	got := make([]byte, 0, 24)
	for i := 0; i < 3; i++ {
		block, err := des.NewCipher(desKeyFrom7(key[i*7 : i*7+7]))
		if err != nil {
			return false, err
		}
		out := make([]byte, 8)
		block.Encrypt(out, challenge)
		got = append(got, out...)
	}
	return hmac.Equal(got, ntResp), nil
}

// desKeyFrom7 expands a 7-byte value into an 8-byte DES key by inserting a bit
// after every 7 bits (the parity bits, which crypto/des ignores).
func desKeyFrom7(k7 []byte) []byte {
	k := make([]byte, 8)
	k[0] = k7[0]
	k[1] = (k7[0] << 7) | (k7[1] >> 1)
	k[2] = (k7[1] << 6) | (k7[2] >> 2)
	k[3] = (k7[2] << 5) | (k7[3] >> 3)
	k[4] = (k7[3] << 4) | (k7[4] >> 4)
	k[5] = (k7[4] << 3) | (k7[5] >> 5)
	k[6] = (k7[5] << 2) | (k7[6] >> 6)
	k[7] = k7[6] << 1
	return k
}
