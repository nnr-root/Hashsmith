package main

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"
)

// ── SNMPv3 ───────────────────────────────────────────────────────────────────

// TestExtractPCAPSNMPv3RoundTrip rebuilds the UDP payload from the record John
// ships — putting the authentication digest back into the hole the record
// carries zeroed — and checks the extractor produces that record again.
//
// The engine id in John's own vector is THIRTEEN bytes. John's converter
// scans for the two bytes \x04\x0b, an eleven-byte engine id, so it would not
// find this one; this parses the message instead, which is why it does.
func TestExtractPCAPSNMPv3RoundTrip(t *testing.T) {
	record, password := johnVector(t, "SNMP $snmpv3$")
	f := strings.Split(strings.TrimPrefix(record, "$SNMPv3$"), "$")
	message := mustHex(t, f[2])
	engineID := mustHex(t, f[3])
	digest := mustHex(t, f[4])
	if len(engineID) != 13 {
		t.Fatalf("John's vector no longer has a 13-byte engine id (%d)", len(engineID))
	}

	// Put the digest back where the sender wrote it: the only run of as
	// many zero bytes preceded by its own OCTET STRING header.
	hole := strings.Index(string(message), string(make([]byte, len(digest))))
	if hole < 0 {
		t.Fatal("the record's message carries no zeroed authentication field")
	}
	copy(message[hole:], digest)

	file := pcapOf(t, linkTypeEthernet, false,
		udpFrame([4]byte{10, 0, 0, 2}, [4]byte{10, 0, 0, 1}, 50000, snmpPort, message))

	got, err := extractPCAPRecords(writeFixture(t, "snmp.pcap", file))
	if err != nil {
		t.Fatalf("extractPCAPRecords: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("got %d records, want 1: %v", len(got), got)
	}
	// Two fields differ from John's vector and neither is read by anything.
	// The authentication protocol is zero — "try both" — because the
	// message does not state it. The second field is a debug counter, and
	// pcap2john's value for it is 4 when the message carried privacy
	// parameters, which this one did.
	want := "$SNMPv3$0$4$" + strings.Join(f[2:], "$")
	if got[0] != want {
		t.Fatalf("\n got: %.80s...\nwant: %.80s...", got[0], want)
	}
	mustCrack(t, "snmpv3", got[0], password)
}

// ── HTTP Digest ──────────────────────────────────────────────────────────────

func TestExtractPCAPHTTPDigest(t *testing.T) {
	record, password := johnVector(t, "hdaa $response$")
	// user:$response$<response>$<user>$<realm>$<method>$<uri>$<nonce>$<nc>$<cnonce>$<qop>
	f := strings.Split(record, "$")
	response, user, realm, method := f[2], f[3], f[4], f[5]
	uri, nonce, nc, cnonce, qop := f[6], f[7], f[8], f[9], f[10]

	request := fmt.Sprintf("%s %s HTTP/1.1\r\nHost: example.org\r\n"+
		"Authorization: Digest username=\"%s\", realm=\"%s\", nonce=\"%s\", uri=\"%s\", "+
		"qop=%s, nc=%s, cnonce=\"%s\", response=\"%s\", algorithm=MD5\r\n"+
		"User-Agent: curl/8\r\n\r\n",
		method, uri, user, realm, nonce, uri, qop, nc, cnonce, response)

	file := pcapOf(t, linkTypeEthernet, false,
		tcpFrame([4]byte{10, 0, 0, 2}, [4]byte{10, 0, 0, 1}, 40000, 80, []byte(request)))

	got, err := extractPCAPRecords(writeFixture(t, "http.pcap", file))
	if err != nil {
		t.Fatalf("extractPCAPRecords: %v", err)
	}
	want := user + ":" + record
	if len(got) != 1 || got[0] != want {
		t.Fatalf("\n got: %v\nwant: %s", got, want)
	}
	// The method comes from the REQUEST LINE, not the header, and the
	// digest covers it — so this is what catches a reader that built the
	// record from the header alone.
	_, bare, _ := strings.Cut(got[0], ":")
	mustCrack(t, "http-digest", bare, password)
}

// Basic authentication carries the password itself, so it is counted and
// reported rather than turned into a record whose answer is already in the
// capture.
func TestExtractPCAPNamesBasicAuth(t *testing.T) {
	request := "GET / HTTP/1.1\r\nHost: example.org\r\n" +
		"Authorization: Basic YWxpY2U6aHVudGVyMg==\r\n\r\n"
	file := pcapOf(t, linkTypeEthernet, false,
		tcpFrame([4]byte{10, 0, 0, 2}, [4]byte{10, 0, 0, 1}, 40000, 80, []byte(request)))

	_, err := extractPCAPRecords(writeFixture(t, "basic.pcap", file))
	if err == nil || !strings.Contains(err.Error(), "Basic auth carries the password itself") {
		t.Fatalf("expected Basic auth to be named, got %v", err)
	}
}

// The header's parameters are a comma-separated list where a quoted value may
// itself contain a comma, so splitting on commas alone loses fields.
func TestParseHTTPAuthParams(t *testing.T) {
	got := parseHTTPAuthParams(`username="bob", realm="Some, Realm", qop=auth, nc=00000001`)
	for k, want := range map[string]string{
		"username": "bob", "realm": "Some, Realm", "qop": "auth", "nc": "00000001",
	} {
		if got[k] != want {
			t.Errorf("%s read as %q, want %q", k, got[k], want)
		}
	}
}

// John's pcap2john appends the privacy parameters as a sixth field whenever a
// message carried any. John's own format reads five and ignores the rest;
// requiring exactly five meant refusing every authPriv record John's converter
// writes, so a trailing field is now accepted and dropped.
func TestSNMPv3AcceptsJohnsPrivacyField(t *testing.T) {
	record, password := johnVector(t, "SNMP $snmpv3$")
	f := strings.Split(record, "$")
	message := f[4]
	i := strings.Index(message, "0408")
	if i < 0 {
		t.Skip("this vector carries no privacy parameters")
	}
	withPriv := record + "$" + message[i+4:i+4+16]

	ok, err := verifySNMPv3(withPriv, password)
	if err != nil || !ok {
		t.Fatalf("a record with John's privacy field was refused: ok=%v err=%v", ok, err)
	}
	if bad, _ := verifySNMPv3(withPriv, password+"x"); bad {
		t.Error("it also accepted a wrong password")
	}
	// Seven fields is still the shape this writes, and a longer one is
	// still refused.
	if _, err := verifySNMPv3(record+"$aa$bb", password); err == nil {
		t.Error("two trailing fields should still be refused")
	}
}

// ── TACACS+ ──────────────────────────────────────────────────────────────────

func TestExtractPCAPTacacsPlus(t *testing.T) {
	record, password := johnVector(t, "tacacs-plus $tacacs-plus$")
	f := strings.Split(strings.TrimPrefix(record, "$tacacs-plus$"), "$")
	sessionID := mustHex(t, f[1])
	body := mustHex(t, f[2])
	tail := mustHex(t, f[3]) // the version byte and the sequence number

	header := make([]byte, tacacsHeaderBytes)
	header[0] = tail[0] // version
	header[1] = tacacsTypeAuthen
	header[2] = tail[1] // sequence number
	header[3] = 0       // flags: encrypted
	copy(header[4:8], sessionID)
	header[8] = byte(len(body) >> 24)
	header[9] = byte(len(body) >> 16)
	header[10] = byte(len(body) >> 8)
	header[11] = byte(len(body))

	// The port has to be the SOURCE for this to be a reply.
	file := pcapOf(t, linkTypeEthernet, false,
		tcpFrame([4]byte{10, 0, 0, 1}, [4]byte{10, 0, 0, 2}, tacacsPort, 40000,
			append(header, body...)))

	got, err := extractPCAPRecords(writeFixture(t, "tacacs.pcap", file))
	if err != nil {
		t.Fatalf("extractPCAPRecords: %v", err)
	}
	if len(got) != 1 || got[0] != record {
		t.Fatalf("\n got: %v\nwant: %s", got, record)
	}
	mustCrack(t, "tacacs-plus", got[0], password)
}

// The client's request is encrypted the same way, but its decrypted body has
// no shape to check against, so only the server's reply becomes a record.
func TestExtractPCAPTacacsIgnoresTheRequest(t *testing.T) {
	record, _ := johnVector(t, "tacacs-plus $tacacs-plus$")
	f := strings.Split(strings.TrimPrefix(record, "$tacacs-plus$"), "$")
	tail := mustHex(t, f[3])

	header := make([]byte, tacacsHeaderBytes)
	header[0], header[1], header[2] = tail[0], tacacsTypeAuthen, tail[1]
	copy(header[4:8], mustHex(t, f[1]))
	body := mustHex(t, f[2])
	header[11] = byte(len(body))

	// Port 49 as the DESTINATION is a request.
	file := pcapOf(t, linkTypeEthernet, false,
		tcpFrame([4]byte{10, 0, 0, 2}, [4]byte{10, 0, 0, 1}, 40000, tacacsPort,
			append(header, body...)))

	if _, err := extractPCAPRecords(writeFixture(t, "req.pcap", file)); err == nil {
		t.Error("a request should not become a record")
	}
}

// ── TCP-MD5 ──────────────────────────────────────────────────────────────────

// TestExtractPCAPTcpMD5 rebuilds the segment from the salt John's record
// carries. The salt is three layers glued together — a pseudo-header that is
// never on the wire, the TCP header with its checksum zeroed, and the payload
// — so putting it back is the strongest check that the reader assembles them
// in the right order.
func TestExtractPCAPTcpMD5(t *testing.T) {
	record, password := johnVector(t, "tcp-md5 $tcpmd5$")
	f := strings.Split(strings.TrimPrefix(record, "$tcpmd5$"), "$")
	salt := mustHex(t, f[0])
	signature := mustHex(t, f[1])
	if len(salt) < 32 {
		t.Fatalf("John's salt is %d bytes, too short to rebuild", len(salt))
	}

	src, dst := salt[0:4], salt[4:8]
	segmentLen := int(salt[10])<<8 | int(salt[11])
	tcpHead := salt[12:32] // header to the checksum, then the zeroed four
	payload := salt[32:]

	// Rebuild the segment: the header, an MD5 option padded to a whole
	// number of four-byte words, then the payload.
	const optionBytes = 20 // 18 for the option, 2 of padding
	segment := make([]byte, 20+optionBytes+len(payload))
	copy(segment, tcpHead)
	segment[12] = byte((20 + optionBytes) / 4 << 4) // data offset
	segment[16], segment[17] = 0xab, 0xcd           // a real checksum, which the salt zeroes
	segment[20] = tcpOptMD5
	segment[21] = 18
	copy(segment[22:38], signature)
	segment[38], segment[39] = 1, 1 // two no-operation bytes of padding
	copy(segment[20+optionBytes:], payload)
	if len(segment) != segmentLen {
		t.Fatalf("rebuilt segment is %d bytes, the salt says %d", len(segment), segmentLen)
	}

	ip := make([]byte, 20+len(segment))
	ip[0] = 0x45
	ip[2], ip[3] = byte(len(ip)>>8), byte(len(ip))
	ip[8], ip[9] = 64, 6
	copy(ip[12:16], src)
	copy(ip[16:20], dst)
	copy(ip[20:], segment)

	eth := make([]byte, 14+len(ip))
	eth[12], eth[13] = 0x08, 0x00
	copy(eth[14:], ip)

	file := pcapOf(t, linkTypeEthernet, false, hex.EncodeToString(eth))
	got, err := extractPCAPRecords(writeFixture(t, "bgp.pcap", file))
	if err != nil {
		t.Fatalf("extractPCAPRecords: %v", err)
	}
	if len(got) != 1 || got[0] != record {
		t.Fatalf("\n got: %.70s...\nwant: %.70s...", got[0], record)
	}
	mustCrack(t, "tcp-md5", got[0], password)
}

// The option list has two one-byte entries with no length field, which is
// where a naive walk runs off the end.
func TestTCPOptionWalk(t *testing.T) {
	// no-op, no-op, MD5(19) with sixteen bytes, end of list
	opts := append([]byte{1, 1, tcpOptMD5, 18}, bytes.Repeat([]byte{0x7f}, 16)...)
	opts = append(opts, 0)
	got, ok := tcpOption(opts, tcpOptMD5)
	if !ok || len(got) != 16 || got[0] != 0x7f {
		t.Fatalf("got %x, %v", got, ok)
	}
	if _, ok := tcpOption([]byte{2, 4, 0, 0, 0}, tcpOptMD5); ok {
		t.Error("a list without the option should report absence")
	}
	if _, ok := tcpOption([]byte{tcpOptMD5, 40}, tcpOptMD5); ok {
		t.Error("an option longer than the list should be refused")
	}
}
