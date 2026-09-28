package smith

// Digest authentication, captured from a network.
//
//	$response$<response>$<user>$<realm>$<method>$<uri>$<nonce>$<nc>$<cnonce>$<qop>
//	$DIGEST-MD5$<user>$<realm>$<nonce>$<uri>$<cnonce>$<nc>$<qop>$<response>
//
// The first is HTTP Digest as RFC 2617 defines it, the second is SASL's
// DIGEST-MD5 from RFC 2831. Both compute a response the same way — hash the
// credentials, hash the request, then hash those together with the nonces —
// and both are recoverable because everything except the password travels in
// the clear, so a single observed authentication is the whole record.
//
// They differ in one place, and it is the place that matters. HTTP Digest
// hashes the credentials to hex and uses that; SASL's mixes the raw sixteen
// bytes with the nonces and hashes again, so its first stage is a hash of
// binary rather than of text. Reading either as the other produces a
// plausible-looking chain that never matches.

import (
	"crypto/md5"
	"encoding/hex"
	"errors"
	"strings"
)

// md5HexOf returns the lower-case hex MD5 of the parts joined by colons.
func md5HexOf(parts ...string) string {
	sum := md5.Sum([]byte(strings.Join(parts, ":")))
	return hex.EncodeToString(sum[:])
}

// ── HTTP Digest ───────────────────────────────────────────────────────────────

const httpDigestPrefix = "$response$"

type httpDigest struct {
	response, user, realm, method, uri, nonce, nc, cnonce, qop string
}

func parseHTTPDigest(target string) (*httpDigest, error) {
	t := strings.TrimSpace(target)
	if !strings.HasPrefix(t, httpDigestPrefix) {
		return nil, errors.New("not an HTTP Digest record")
	}
	f := strings.Split(t[len(httpDigestPrefix):], "$")
	if len(f) != 9 {
		return nil, errors.New("an HTTP Digest record has nine fields after the response")
	}
	d := &httpDigest{f[0], f[1], f[2], f[3], f[4], f[5], f[6], f[7], f[8]}
	if len(d.response) != 32 || !isHex(d.response) {
		return nil, errors.New("invalid HTTP Digest response")
	}
	if d.user == "" || d.realm == "" || d.method == "" || d.nonce == "" {
		return nil, errors.New("an HTTP Digest record must name the user, realm, method and nonce")
	}
	return d, nil
}

// verifyHTTPDigest checks a captured HTTP Digest authentication.
func verifyHTTPDigest(target, candidate string) (bool, error) {
	d, err := parseHTTPDigest(target)
	if err != nil {
		return false, err
	}
	ha1 := md5HexOf(d.user, d.realm, candidate)
	ha2 := md5HexOf(d.method, d.uri)
	got := md5HexOf(ha1, d.nonce, d.nc, d.cnonce, d.qop, ha2)
	return strings.EqualFold(got, d.response), nil
}

func isHTTPDigest(target string) bool {
	_, err := parseHTTPDigest(target)
	return err == nil
}

// ── SASL DIGEST-MD5 ───────────────────────────────────────────────────────────

const saslDigestPrefix = "$DIGEST-MD5$"

type saslDigest struct {
	user, realm, nonce, uri, cnonce, nc, qop, response string
}

func parseSASLDigest(target string) (*saslDigest, error) {
	t := strings.TrimSpace(target)
	if len(t) < len(saslDigestPrefix) || !strings.EqualFold(t[:len(saslDigestPrefix)], saslDigestPrefix) {
		return nil, errors.New("not a SASL DIGEST-MD5 record")
	}
	f := strings.Split(t[len(saslDigestPrefix):], "$")
	if len(f) != 8 {
		return nil, errors.New("a SASL DIGEST-MD5 record has eight fields")
	}
	d := &saslDigest{f[0], f[1], f[2], f[3], f[4], f[5], f[6], f[7]}
	if len(d.response) != 32 || !isHex(d.response) {
		return nil, errors.New("invalid SASL DIGEST-MD5 response")
	}
	if d.user == "" || d.nonce == "" || d.uri == "" {
		return nil, errors.New("a SASL DIGEST-MD5 record must name the user, nonce and digest-uri")
	}
	return d, nil
}

// verifySASLDigest checks a captured SASL DIGEST-MD5 authentication.
func verifySASLDigest(target, candidate string) (bool, error) {
	d, err := parseSASLDigest(target)
	if err != nil {
		return false, err
	}
	// The first stage mixes the RAW digest of the credentials with the
	// nonces, not its hex — which is the one thing that separates this from
	// HTTP Digest.
	inner := md5.Sum([]byte(strings.Join([]string{d.user, d.realm, candidate}, ":")))
	a1 := md5.Sum(append(append([]byte(nil), inner[:]...), ":"+d.nonce+":"+d.cnonce...))
	ha1 := hex.EncodeToString(a1[:])
	ha2 := md5HexOf("AUTHENTICATE", d.uri)
	got := md5HexOf(ha1, d.nonce, d.nc, d.cnonce, d.qop, ha2)
	return strings.EqualFold(got, d.response), nil
}

func isSASLDigest(target string) bool {
	_, err := parseSASLDigest(target)
	return err == nil
}
