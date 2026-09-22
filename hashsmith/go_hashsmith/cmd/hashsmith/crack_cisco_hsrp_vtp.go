package main

// Cisco's HSRP and VTP authentication, and the two constructions an earlier
// search could not reach.
//
// Both of these were put through a bounded sweep once before — every hash of
// the packet and the key in either order, the key NUL-padded and repeated to
// nine lengths, HMAC under each of those keys, and for HSRP the key written
// over the packet at every two-byte offset — and neither vector was
// reproduced. That note is still where it was written, in
// crack_routing_auth.go, and it was accurate: a search says nothing about the
// space outside the one searched. This is what was outside it.
//
// HSRP prefixes the packet with the key MD-PADDED: the key, then 0x80, then
// zeros, then the key's bit length at byte 56, sixty-four bytes in all — the
// exact block MD5 would have produced had the key been the whole message.
// Then the packet, then the key again. No sweep of orderings and paddings
// reaches a construction with a length field inside it.
//
// VTP stretches first. The password is repeated cyclically into 1,563
// sixty-four-byte blocks — very nearly a megabyte — and MD5'd down to a
// sixteen-byte secret, and it is that secret, not the password, that brackets
// the packet. A sweep over the password itself was searching the wrong string
// entirely.

import (
	"crypto/hmac"
	"crypto/md5"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"strconv"
	"strings"
)

// ── HSRP ──────────────────────────────────────────────────────────────────────

const hsrpPrefix = "$hsrp$"

func hsrpFields(target string) (packet, digest []byte, err error) {
	t := strings.TrimSpace(target)
	if !strings.HasPrefix(t, hsrpPrefix) {
		return nil, nil, errors.New("not an HSRP record")
	}
	p, d, ok := strings.Cut(t[len(hsrpPrefix):], "$")
	if !ok || strings.Contains(d, "$") {
		return nil, nil, errors.New("an HSRP record is $hsrp$<packet>$<digest>")
	}
	if packet, err = hex.DecodeString(p); err != nil || len(packet) == 0 || len(packet) > maxKDFFieldSize*16 {
		return nil, nil, errors.New("invalid HSRP packet")
	}
	if digest, err = decodeExactHex(d, md5.Size, "HSRP digest"); err != nil {
		return nil, nil, err
	}
	return packet, digest, nil
}

// mdPadBlock builds the sixty-four-byte block MD5 would feed its compression
// function if the given bytes were the entire message: the bytes, a 0x80, then
// zeros, with the length in bits as a little-endian 32-bit value at offset 56.
//
// A key longer than fifty-five bytes does not fit alongside its own padding,
// which is why HSRP keys are bounded there rather than by anything Cisco
// documents.
func mdPadBlock(key []byte) ([]byte, bool) {
	if len(key) > 55 {
		return nil, false
	}
	block := make([]byte, 64)
	copy(block, key)
	block[len(key)] = 0x80
	binary.LittleEndian.PutUint32(block[56:], uint32(len(key))*8)
	return block, true
}

func verifyHSRP(target, candidate string) (bool, error) {
	packet, digest, err := hsrpFields(target)
	if err != nil {
		return false, err
	}
	block, ok := mdPadBlock([]byte(candidate))
	if !ok {
		return false, nil
	}
	h := md5.New()
	_, _ = h.Write(block)
	_, _ = h.Write(packet)
	_, _ = h.Write([]byte(candidate))
	return hmac.Equal(h.Sum(nil), digest), nil
}

func isHSRP(target string) bool {
	_, _, err := hsrpFields(target)
	return err == nil
}

// ── VTP ───────────────────────────────────────────────────────────────────────

// "$vtp$<version>$<vlans length>$<vlans>$<salt length>$<salt>$<digest>"
//
// The salt is the summary advertisement packet as captured. Three of its
// fields are zeroed before the MAC is taken, because a switch computes the MAC
// over the packet it is about to send and cannot include the checksum it has
// not written yet: the follower count, the twelve-byte update timestamp and
// the sixteen-byte checksum itself.
const vtpPrefix = "$vtp$"

// vtpStretchBlocks is the number of sixty-four-byte blocks of repeated
// password that VTP hashes down to its secret. It is the format's entire work
// factor — just under a megabyte of MD5 per candidate.
const vtpStretchBlocks = 1563

type vtpRecord struct {
	version int
	vlans   []byte
	salt    []byte
	digest  []byte
}

func vtpFields(target string) (vtpRecord, error) {
	var r vtpRecord
	t := strings.TrimSpace(target)
	if !strings.HasPrefix(t, vtpPrefix) {
		return r, errors.New("not a VTP record")
	}
	f := strings.Split(t[len(vtpPrefix):], "$")
	if len(f) != 6 {
		return r, errors.New("a VTP record is <version>$<vlans length>$<vlans>$<salt length>$<salt>$<digest>")
	}
	var err error
	if r.version, err = strconv.Atoi(f[0]); err != nil || r.version < 1 || r.version > 3 {
		return r, errors.New("a VTP version is 1, 2 or 3")
	}
	vlansLen, err := strconv.Atoi(f[1])
	if err != nil {
		return r, errors.New("invalid VTP vlans length")
	}
	if r.vlans, err = hex.DecodeString(f[2]); err != nil || len(r.vlans) != vlansLen {
		return r, errors.New("the VTP vlans field does not match its stated length")
	}
	saltLen, err := strconv.Atoi(f[3])
	if err != nil {
		return r, errors.New("invalid VTP salt length")
	}
	if r.salt, err = hex.DecodeString(f[4]); err != nil || len(r.salt) != saltLen || saltLen < 72 {
		return r, errors.New("a VTP salt is at least the 72-byte summary advertisement")
	}
	if r.digest, err = decodeExactHex(f[5], md5.Size, "VTP digest"); err != nil {
		return r, err
	}
	return r, nil
}

// vtpSecret is the stretch: the password repeated cyclically across 1,563
// blocks of sixty-four bytes, hashed once. An empty password is defined as
// sixteen zero bytes rather than as the hash of nothing.
func vtpSecret(password string) []byte {
	if password == "" {
		return make([]byte, md5.Size)
	}
	h := md5.New()
	var block [64]byte
	idx := 0
	for i := 0; i < vtpStretchBlocks; i++ {
		for j := range block {
			block[j] = password[idx%len(password)]
			idx++
		}
		_, _ = h.Write(block[:])
	}
	return h.Sum(nil)
}

// vtpSummary rebuilds the 72-byte packet with the three fields a switch cannot
// know when it signs: the follower count, the update timestamp and the
// checksum.
func vtpSummary(salt []byte) []byte {
	out := make([]byte, 72)
	out[0], out[1] = salt[0], salt[1]
	out[3] = salt[3]
	nameLen := int(salt[3])
	if nameLen > 32 {
		nameLen = 32
	}
	copy(out[4:4+nameLen], salt[4:4+nameLen])
	copy(out[36:40], salt[36:40]) // revision
	copy(out[40:44], salt[40:44]) // updater
	return out
}

func verifyVTP(target, candidate string) (bool, error) {
	r, err := vtpFields(target)
	if err != nil {
		return false, err
	}
	secret := vtpSecret(candidate)
	h := md5.New()
	_, _ = h.Write(secret)
	_, _ = h.Write(vtpSummary(r.salt))
	if r.version != 1 && len(r.salt) > 72 {
		_, _ = h.Write(r.salt[72:])
	}
	_, _ = h.Write(r.vlans)
	_, _ = h.Write(secret)
	return hmac.Equal(h.Sum(nil), r.digest), nil
}

func isVTP(target string) bool {
	_, err := vtpFields(target)
	return err == nil
}
