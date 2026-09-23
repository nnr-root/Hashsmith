package main

import (
	"bytes"
	"crypto/md5"
	"encoding/binary"
	"encoding/hex"
	"strings"
	"testing"
)

// ── RADIUS ───────────────────────────────────────────────────────────────────

// udpFrame wraps a payload in UDP, IPv4 and Ethernet, which is what a capture
// of a RADIUS exchange holds.
func udpFrame(src, dst [4]byte, sport, dport uint16, payload []byte) string {
	udp := make([]byte, 8+len(payload))
	binary.BigEndian.PutUint16(udp[0:], sport)
	binary.BigEndian.PutUint16(udp[2:], dport)
	binary.BigEndian.PutUint16(udp[4:], uint16(len(udp)))
	copy(udp[8:], payload)

	ip := make([]byte, 20+len(udp))
	ip[0] = 0x45
	binary.BigEndian.PutUint16(ip[2:], uint16(len(ip)))
	ip[8] = 64
	ip[9] = 17 // UDP
	copy(ip[12:16], src[:])
	copy(ip[16:20], dst[:])
	copy(ip[20:], udp)

	eth := make([]byte, 14+len(ip))
	binary.BigEndian.PutUint16(eth[12:], 0x0800)
	copy(eth[14:], ip)
	return hex.EncodeToString(eth)
}

// radiusPacket builds one packet. The Response Authenticator is what RFC 2865
// says it is — MD5 over the reply with the REQUEST's authenticator in place of
// its own, followed by the shared secret — so the test states the construction
// in the specification's own terms and the extractor has to agree.
func radiusPacket(code, id byte, authenticator, attributes []byte) []byte {
	p := make([]byte, 20+len(attributes))
	p[0] = code
	p[1] = id
	binary.BigEndian.PutUint16(p[2:], uint16(len(p)))
	copy(p[4:20], authenticator)
	copy(p[20:], attributes)
	return p
}

func TestExtractRADIUSRoundTrip(t *testing.T) {
	const secret = "sharedsecret"
	nas := [4]byte{10, 0, 0, 5}
	server := [4]byte{10, 0, 0, 1}

	requestAuth := bytes.Repeat([]byte{0xa7}, 16)
	attributes := []byte{1, 6, 'b', 'o', 'b', 0} // User-Name
	request := radiusPacket(radiusAccessRequest, 0x2a, requestAuth, attributes)

	// Build the reply, then fill in its authenticator the way a server does.
	reply := radiusPacket(radiusAccessAccept, 0x2a, requestAuth, []byte{8, 6, 192, 168, 1, 2})
	sum := md5.Sum(append(append([]byte(nil), reply...), []byte(secret)...))
	copy(reply[4:20], sum[:])

	file := pcapOf(t, linkTypeEthernet, false,
		udpFrame(nas, server, 40000, radiusAuthPort, request),
		udpFrame(server, nas, radiusAuthPort, 40000, reply))

	got, err := extractRADIUSRecords(writeFixture(t, "radius.pcap", file))
	if err != nil {
		t.Fatalf("extractRADIUSRecords: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("got %d records, want 1: %v", len(got), got)
	}
	// The salt must carry the REQUEST's authenticator, not the reply's.
	if !strings.Contains(got[0], "$HEX$") ||
		!strings.Contains(strings.SplitN(got[0], "$HEX$", 2)[1], hex.EncodeToString(requestAuth)) {
		t.Fatalf("the request's authenticator did not reach the salt: %s", got[0])
	}
	mustCrack(t, "dynamic", got[0], secret)
}

// A reply with no request in the capture cannot be turned into a record: the
// request's authenticator is half the digest's input.
func TestExtractRADIUSNeedsBothHalves(t *testing.T) {
	server := [4]byte{10, 0, 0, 1}
	nas := [4]byte{10, 0, 0, 5}
	reply := radiusPacket(radiusAccessAccept, 7, bytes.Repeat([]byte{1}, 16), nil)
	file := pcapOf(t, linkTypeEthernet, false,
		udpFrame(server, nas, radiusAuthPort, 40000, reply))

	_, err := extractRADIUSRecords(writeFixture(t, "half.pcap", file))
	if err == nil || !strings.Contains(err.Error(), "both halves") {
		t.Fatalf("a reply with no request should say what is missing, got %v", err)
	}
}

// RADIUS has no magic and its header is four bytes of counters, so traffic on
// other ports must not be read as RADIUS.
func TestExtractRADIUSIgnoresOtherPorts(t *testing.T) {
	a := [4]byte{10, 0, 0, 5}
	b := [4]byte{10, 0, 0, 1}
	packet := radiusPacket(radiusAccessRequest, 1, bytes.Repeat([]byte{2}, 16), nil)
	file := pcapOf(t, linkTypeEthernet, false, udpFrame(a, b, 53, 53, packet))

	_, err := extractRADIUSRecords(writeFixture(t, "dns.pcap", file))
	if err == nil || !strings.Contains(err.Error(), "ports 1812 or 1813") {
		t.Fatalf("non-RADIUS ports should be ignored, got %v", err)
	}
}

// ── hccap ────────────────────────────────────────────────────────────────────

// TestExtractHCCAPRoundTrip builds an hccap out of the REAL Coherer handshake
// and checks that the record it produces cracks.
//
// The point of the test is the nonce order. hccap stores the station's nonce
// first and the AP's second, the opposite of the hccapx structure that
// replaced it. Swapped, the record parses, looks right, and never cracks — so
// a test that only checked the record's shape would pass on a broken reader.
func TestExtractHCCAPRoundTrip(t *testing.T) {
	m1Raw := mustHex(t, cohererM1)
	m2Raw := mustHex(t, cohererM2)
	m1, ok := parseDot11(m1Raw, linkTypeIEEE80211)
	if !ok {
		t.Fatal("the message 1 fixture does not parse")
	}
	m2, ok := parseDot11(m2Raw, linkTypeIEEE80211)
	if !ok {
		t.Fatal("the message 2 fixture does not parse")
	}
	k1, ok1 := parseEAPOLKey(m1.body)
	k2, ok2 := parseEAPOLKey(m2.body)
	if !ok1 || !ok2 {
		t.Fatal("the fixtures do not carry EAPOL-Key frames")
	}

	h := make([]byte, hccapSize)
	copy(h[0:36], "Coherer")
	copy(h[36:42], m1.addr2[:]) // mac1 is the AP
	copy(h[42:48], m1.addr1[:]) // mac2 is the station
	copy(h[48:80], k2.nonce)    // nonce1 is the STATION's
	copy(h[80:112], k1.nonce)   // nonce2 is the AP's
	copy(h[112:], k2.raw)
	binary.LittleEndian.PutUint32(h[368:372], uint32(len(k2.raw)))
	binary.LittleEndian.PutUint32(h[372:376], 2) // HMAC-SHA1
	copy(h[376:392], k2.mic)

	got, err := extractHCCAPRecords(writeFixture(t, "handshake.hccap", h))
	if err != nil {
		t.Fatalf("extractHCCAPRecords: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("got %d records, want 1", len(got))
	}
	if !strings.Contains(got[0], "*"+hex.EncodeToString([]byte("Coherer"))+"*") {
		t.Errorf("the ESSID did not reach the record: %s", got[0])
	}
	mustCrack(t, "wpa", got[0], "Induction")
}

// A file that is not a whole number of structures is refused by name rather
// than read up to the last complete one.
func TestExtractHCCAPRefusesAPartialFile(t *testing.T) {
	_, err := extractHCCAPRecords(writeFixture(t, "short.hccap", make([]byte, hccapSize-1)))
	if err == nil || !strings.Contains(err.Error(), "whole number") {
		t.Fatalf("a partial hccap should be refused by name, got %v", err)
	}
}
