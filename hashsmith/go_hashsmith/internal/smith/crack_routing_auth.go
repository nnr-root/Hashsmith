package smith

// Keyed authentication on routing and IPsec traffic.
//
// crack_john_envelopes.go covers the members of this family whose digest is a
// plain hash over the packet and the key (RIPv2, OSPF's original MD5, TCP-MD5,
// EIGRP). These three are the keyed-MAC members:
//
//	net-ah  IPsec AH, HMAC-MD5-96: the MAC truncated to its first twelve
//	        bytes, which is what the authentication header carries
//	rsvp    RSVP INTEGRITY, HMAC-MD5 or HMAC-SHA1 over the message
//	ospf    OSPFv2 cryptographic authentication as RFC 5709 defines it, where
//	        the authentication field is filled with Apad — 0x878FE1F3 repeated
//	        — before the MAC is taken over the packet
//
// The salt in all three is a captured packet, so the record is evidence
// anyone on the path could collect, and the key it protects is typically
// configured identically on every device in the routing domain.
//
// Two members of the family are not here but in crack_cisco_hsrp_vtp.go.
// John's $hsrp$ and $vtp$ records were first put through the same search that
// settled these three — every hash of the packet and the key in either order,
// the key NUL-padded and repeated to nine different lengths, HMAC under each
// of those keys, and for HSRP the key written over the packet at every
// two-byte offset — and nothing reproduced either vector. The conclusion drawn
// then was that a search cannot find a construction outside the space
// searched, and that turned out to be exactly right: HSRP prefixes the packet
// with the key MD-PADDED, length field and all, and VTP does not hash the
// password at all but a secret stretched from it over nearly a megabyte. Both
// are now read, from their sources rather than by search.

import (
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"hash"
	"strconv"
	"strings"
)

// routingRecord reads "$name$<type>$<packet hex>$<digest hex>".
func routingRecord(target, prefix string) (kind int, packet, digest []byte, err error) {
	t := strings.TrimSpace(target)
	if !strings.HasPrefix(t, prefix) {
		return 0, nil, nil, errors.New("not a " + strings.Trim(prefix, "$") + " record")
	}
	f := strings.Split(t[len(prefix):], "$")
	if len(f) != 3 {
		return 0, nil, nil, errors.New("a " + strings.Trim(prefix, "$") + " record needs a type, a packet and a digest")
	}
	// The type field starts at zero, so it is read directly rather than
	// through the positive-integer helper.
	kind, err = strconv.Atoi(f[0])
	if err != nil || kind < 0 || kind > 16 {
		return 0, nil, nil, errors.New("invalid authentication type")
	}
	if packet, err = hex.DecodeString(f[1]); err != nil || len(packet) == 0 || len(packet) > maxKDFFieldSize*16 {
		return 0, nil, nil, errors.New("invalid captured packet")
	}
	if digest, err = hex.DecodeString(f[2]); err != nil || len(digest) < 12 || len(digest) > 64 {
		return 0, nil, nil, errors.New("invalid authentication digest")
	}
	return kind, packet, digest, nil
}

// verifyNetAH checks an IPsec AH authenticator. The header carries only the
// first twelve bytes of the MAC, so twelve bytes is what agrees — still far
// more than enough to identify a key, and the reason the record is short.
func verifyNetAH(target, candidate string) (bool, error) {
	kind, packet, digest, err := routingRecord(target, "$net-ah$")
	if err != nil {
		return false, err
	}
	newHash := map[int]func() hash.Hash{0: md5.New, 1: sha1.New}[kind]
	if newHash == nil {
		return false, errors.New("this AH record names an authentication algorithm Hashsmith does not run")
	}
	mac := hmac.New(newHash, []byte(candidate))
	_, _ = mac.Write(packet)
	got := mac.Sum(nil)
	if len(got) < len(digest) {
		return false, errors.New("AH digest is longer than the algorithm produces")
	}
	return hmac.Equal(got[:len(digest)], digest), nil
}

// verifyRSVP checks an RSVP INTEGRITY object: the MAC over the message, whole
// rather than truncated. The type field says which MAC, and the digest length
// says the same thing, so the two are required to agree.
func verifyRSVP(target, candidate string) (bool, error) {
	_, packet, digest, err := routingRecord(target, "$rsvp$")
	if err != nil {
		return false, err
	}
	var newHash func() hash.Hash
	switch len(digest) {
	case md5.Size:
		newHash = md5.New
	case sha1.Size:
		newHash = sha1.New
	default:
		return false, errors.New("an RSVP digest is an HMAC-MD5 or HMAC-SHA1")
	}
	mac := hmac.New(newHash, []byte(candidate))
	_, _ = mac.Write(packet)
	return hmac.Equal(mac.Sum(nil), digest), nil
}

// ospfApad fills the authentication field the way RFC 5709 requires before
// the MAC is taken: 0x878FE1F3 repeated to the length of the digest.
func ospfApad(n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = [4]byte{0x87, 0x8F, 0xE1, 0xF3}[i%4]
	}
	return out
}

// verifyOSPF checks OSPFv2 cryptographic authentication.
//
// The digest length picks the hash, which is how RFC 5709 distinguishes its
// four variants. Only the SHA-1 one is covered by a test vector here; the
// others follow the same construction with the hash the length names, which
// is what the RFC says and all that differs between them.
func verifyOSPF(target, candidate string) (bool, error) {
	_, packet, digest, err := routingRecord(target, "$ospf$")
	if err != nil {
		return false, err
	}
	var newHash func() hash.Hash
	switch len(digest) {
	case sha1.Size:
		newHash = sha1.New
	case sha256.Size:
		newHash = sha256.New
	case sha512.Size384:
		newHash = sha512.New384
	case sha512.Size:
		newHash = sha512.New
	default:
		return false, errors.New("an OSPF digest is one of RFC 5709's four SHA sizes")
	}
	mac := hmac.New(newHash, []byte(candidate))
	_, _ = mac.Write(packet)
	_, _ = mac.Write(ospfApad(len(digest)))
	return hmac.Equal(mac.Sum(nil), digest), nil
}

func isNetAH(target string) bool {
	_, _, _, err := routingRecord(target, "$net-ah$")
	return err == nil
}
func isRSVP(target string) bool { _, _, _, err := routingRecord(target, "$rsvp$"); return err == nil }
func isOSPF(target string) bool { _, _, _, err := routingRecord(target, "$ospf$"); return err == nil }
