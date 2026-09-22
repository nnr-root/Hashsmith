package main

// The rest of the NetNTLM family: the LM-based responses, and MS-CHAPv2.
//
// crack_netntlm.go covers the two captures worth having — NetNTLMv1 and
// NetNTLMv2. The others are what a capture yields when the client is older or
// the protocol is not SMB at all, and they arrive from the same tools:
//
//	netlm      the LM response: the LM hash, padded to 21 bytes, as three DES
//	           keys over the server's challenge. The LM hash upper-cases the
//	           password and cuts it at fourteen characters, so cracking one
//	           recovers a password that is already most of the way to plain.
//	nethalflm  the same, but only the first eight bytes of the response are
//	           checked, which depends on only the first seven characters. It
//	           is the half of an LM response a capture may be all that is left
//	           of, and it recovers those seven characters on their own.
//	netlmv2    the LMv2 response: the NTLMv2 key over the server challenge and
//	           an eight-byte client challenge. Same derivation as NTLMv2, a
//	           different message.
//	mschapv2   PPP and RADIUS rather than SMB — the authentication behind
//	           PPTP, and behind PEAP-MSCHAPv2 on wireless. Its challenge is
//	           derived rather than given: SHA-1 over the peer's challenge, the
//	           authenticator's, and the username, cut to eight bytes. After
//	           that it is the NTLMv1 computation exactly.
//
// Each is written two ways, as a captured "user:::a:b:c" line and as one of
// John's envelopes, and both are read here.

import (
	"crypto/des"
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha1"
	"encoding/hex"
	"errors"
	"strings"
)

// lmHashBytes returns the 16-byte LM hash: the password upper-cased, cut to
// fourteen characters, NUL-padded, and used as two DES keys over "KGS!@#$%".
func lmHashBytes(password string) []byte {
	plain := []byte(strings.ToUpper(password))
	if len(plain) > 14 {
		plain = plain[:14]
	}
	padded := make([]byte, 14)
	copy(padded, plain)
	out := make([]byte, 16)
	magic := []byte("KGS!@#$%")
	for half := 0; half < 2; half++ {
		key := expandLMKey(padded[half*7 : half*7+7])
		block, err := des.NewCipher(key[:])
		if err != nil {
			return nil
		}
		block.Encrypt(out[half*8:half*8+8], magic)
	}
	return out
}

// netResponse24 is the response both NTLMv1 and the LM protocols compute: a
// 16-byte hash padded to 21 bytes, split into three 7-byte DES keys, each
// encrypting the 8-byte challenge.
func netResponse24(hash16, challenge []byte) ([]byte, error) {
	key := make([]byte, 21)
	copy(key, hash16)
	out := make([]byte, 0, 24)
	for i := 0; i < 3; i++ {
		block, err := des.NewCipher(desKeyFrom7(key[i*7 : i*7+7]))
		if err != nil {
			return nil, err
		}
		buf := make([]byte, 8)
		block.Encrypt(buf, challenge)
		out = append(out, buf...)
	}
	return out, nil
}

// netIdentity builds the NTLMv2 identity, which is upper(user) followed by the
// domain verbatim. A captured line that leaves the domain field empty carries
// it inside the user field instead, written "DOMAIN\user", which is how John
// spells a capture where the two were never separate.
func netIdentity(user, domain string) string {
	if domain == "" {
		if i := strings.IndexByte(user, '\\'); i >= 0 {
			domain, user = user[:i], user[i+1:]
		}
	}
	return strings.ToUpper(user) + domain
}

// netCaptureFields reads the six-field captured line every one of these
// formats is written as, returning the three fields that carry the exchange.
func netCaptureFields(target string) (user, domain, a, b, c string, ok bool) {
	f := strings.Split(strings.TrimSpace(target), ":")
	if len(f) != 6 || f[1] != "" {
		return "", "", "", "", "", false
	}
	return f[0], f[2], f[3], f[4], f[5], true
}

// johnNetEnvelope splits one of John's "$NAME$a$b$..." records.
func johnNetEnvelope(target, prefix string, want int) ([]string, bool) {
	t := strings.TrimSpace(target)
	if len(t) < len(prefix) || !strings.EqualFold(t[:len(prefix)], prefix) {
		return nil, false
	}
	f := strings.Split(t[len(prefix):], "$")
	if len(f) != want {
		return nil, false
	}
	return f, true
}

// ── the LM response ───────────────────────────────────────────────────────────

// verifyNetLM checks an LM response, written either as
// "$NETLM$<challenge>$<response>" or as "user:::<response>:<nt>:<challenge>".
func verifyNetLM(target, candidate string) (bool, error) {
	var challenge, response string
	if f, ok := johnNetEnvelope(target, "$NETLM$", 2); ok {
		challenge, response = f[0], f[1]
	} else if _, _, a, _, c, ok := netCaptureFields(target); ok {
		challenge, response = c, a
	} else {
		return false, errors.New("invalid NetLM record")
	}
	chal, err := decodeExactHex(challenge, 8, "NetLM server challenge")
	if err != nil {
		return false, err
	}
	want, err := decodeExactHex(response, 24, "NetLM response")
	if err != nil {
		return false, err
	}
	got, err := netResponse24(lmHashBytes(candidate), chal)
	if err != nil {
		return false, err
	}
	return hmac.Equal(got, want), nil
}

// verifyNetHalfLM checks the first eight bytes of an LM response, which depend
// on only the first seven characters of the password. Anything the record
// holds beyond those eight bytes is not evidence about them and is ignored,
// which is the whole point of the format: it answers for the half it can.
func verifyNetHalfLM(target, candidate string) (bool, error) {
	var challenge, response string
	if f, ok := johnNetEnvelope(target, "$NETHALFLM$", 2); ok {
		challenge, response = f[0], f[1]
	} else if _, _, a, b, c, ok := netCaptureFields(target); ok && b == "" {
		challenge, response = c, a
	} else {
		return false, errors.New("invalid half-LM record")
	}
	chal, err := decodeExactHex(challenge, 8, "half-LM server challenge")
	if err != nil {
		return false, err
	}
	want, err := hex.DecodeString(response)
	if err != nil || len(want) < 8 {
		return false, errors.New("invalid half-LM response")
	}
	lm := lmHashBytes(candidate)
	block, err := des.NewCipher(desKeyFrom7(lm[:7]))
	if err != nil {
		return false, err
	}
	got := make([]byte, 8)
	block.Encrypt(got, chal)
	return hmac.Equal(got, want[:8]), nil
}

// ── the LMv2 response ─────────────────────────────────────────────────────────

// verifyNetLMv2 checks an LMv2 response: the NTLMv2 key over the server
// challenge followed by an eight-byte client challenge.
func verifyNetLMv2(target, candidate string) (bool, error) {
	var ident, challenge, response, client string
	if f, ok := johnNetEnvelope(target, "$NETLMv2$", 4); ok {
		ident, challenge, response, client = f[0], f[1], f[2], f[3]
	} else if user, domain, a, b, c, ok := netCaptureFields(target); ok {
		ident, challenge, response, client = netIdentity(user, domain), a, b, c
	} else {
		return false, errors.New("invalid NetLMv2 record")
	}
	if ident == "" {
		return false, errors.New("a NetLMv2 record must name the account")
	}
	chal, err := decodeExactHex(challenge, 8, "NetLMv2 server challenge")
	if err != nil {
		return false, err
	}
	want, err := decodeExactHex(response, 16, "NetLMv2 response")
	if err != nil {
		return false, err
	}
	clientChal, err := decodeExactHex(client, 8, "NetLMv2 client challenge")
	if err != nil {
		return false, err
	}
	mac := hmac.New(md5.New, ntHash(candidate))
	mac.Write(utf16le(ident))
	inner := hmac.New(md5.New, mac.Sum(nil))
	inner.Write(chal)
	inner.Write(clientChal)
	return hmac.Equal(inner.Sum(nil), want), nil
}

// ── MS-CHAPv2 ─────────────────────────────────────────────────────────────────

// verifyMSCHAPv2 checks an MS-CHAPv2 exchange. The challenge the NTLMv1
// computation runs over is not in the record: RFC 2759 derives it from the
// peer's challenge, the authenticator's, and the username, which is why both
// challenges and the account name all have to be right for the check to mean
// anything.
func verifyMSCHAPv2(target, candidate string) (bool, error) {
	var user, authChal, response, peerChal string
	if f, ok := johnNetEnvelope(target, "$MSCHAPv2$", 4); ok {
		authChal, response, peerChal, user = f[0], f[1], f[2], f[3]
	} else if u, _, a, b, c, ok := netCaptureFields(target); ok {
		user, authChal, response, peerChal = u, a, b, c
	} else {
		return false, errors.New("invalid MS-CHAPv2 record")
	}
	auth, err := decodeExactHex(authChal, 16, "MS-CHAPv2 authenticator challenge")
	if err != nil {
		return false, err
	}
	peer, err := decodeExactHex(peerChal, 16, "MS-CHAPv2 peer challenge")
	if err != nil {
		return false, err
	}
	want, err := decodeExactHex(response, 24, "MS-CHAPv2 response")
	if err != nil {
		return false, err
	}
	// The username is hashed as written: this is the one place in the family
	// where the account name is neither upper-cased nor UTF-16.
	if i := strings.IndexByte(user, '\\'); i >= 0 {
		user = user[i+1:]
	}
	h := sha1.New()
	h.Write(peer)
	h.Write(auth)
	h.Write([]byte(user))
	got, err := netResponse24(ntHash(candidate), h.Sum(nil)[:8])
	if err != nil {
		return false, err
	}
	return hmac.Equal(got, want), nil
}

// ── which format a capture is ─────────────────────────────────────────────────

// netCaptureTypes reads the shape of a captured line and names the formats it
// can be. All six formats share one layout, so the field lengths are what
// tell them apart: a 16-byte response is v2's, a 24-byte one the LM or NTLMv1
// computation, and a trailing field longer than a challenge is a blob.
//
// Where the shape leaves a real ambiguity the candidates are offered in order
// rather than guessed between; the verifiers are cryptographically distinct,
// so trying both costs a hash and cannot produce a wrong answer.
func netCaptureTypes(s string) []string {
	f := strings.Split(strings.TrimSpace(s), ":")
	if len(f) != 6 || f[1] != "" {
		return nil
	}
	// A field that is not hex is a placeholder John writes where it has
	// nothing to record ("lm-hash", "ntlm-hash"); it is not a length.
	size := func(x string) int {
		if x != "" && !isHex(x) {
			return -1
		}
		return len(x)
	}
	a, b, c := size(f[3]), size(f[4]), size(f[5])
	switch {
	case a == 32 && b == 48 && c == 32:
		return []string{"mschapv2"}
	case a == 16 && b == 32 && c == 16:
		return []string{"netlmv2"}
	case a == 16 && b == 32 && c > 16:
		return []string{"netntlmv2"}
	case a == 48 && b == 0 && c == 16:
		return []string{"nethalflm"}
	case a == 48 && b == 48 && c == 16:
		return []string{"netntlmv1", "netlm"}
	case a == 48 && b == -1 && c == 16:
		return []string{"netlm"}
	case (a == -1 || a == 0) && b == 48 && c == 16:
		return []string{"netntlmv1"}
	}
	// A shape none of those describe, but still the six-field line the family
	// is written as, keeps the reading it had before this function existed.
	if isNetNTLMLine(s) {
		return []string{"netntlmv2", "netntlmv1"}
	}
	return nil
}
