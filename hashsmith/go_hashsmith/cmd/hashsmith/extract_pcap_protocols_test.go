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

// ipv4Frame wraps a payload in IPv4 and Ethernet for a given protocol number.
func ipv4Frame(t *testing.T, proto byte, src, dst [4]byte, payload []byte) string {
	t.Helper()
	ip := make([]byte, 20+len(payload))
	ip[0] = 0x45
	ip[1] = 0x10 // a non-zero type of service, which the AH record must clear
	ip[2], ip[3] = byte(len(ip)>>8), byte(len(ip))
	ip[4], ip[5] = 0x00, 0x15
	ip[6] = 0x40 // the "don't fragment" flag, which the AH record must clear
	ip[8], ip[9] = 0xff, proto
	ip[10], ip[11] = 0xbe, 0xef // a real checksum, which the AH record must clear
	copy(ip[12:16], src[:])
	copy(ip[16:20], dst[:])
	copy(ip[20:], payload)

	eth := make([]byte, 14+len(ip))
	eth[12], eth[13] = 0x08, 0x00
	copy(eth[14:], ip)
	return hex.EncodeToString(eth)
}

func TestExtractPCAPHSRP(t *testing.T) {
	record, password := johnVector(t, "hsrp $hsrp$")
	f := strings.Split(strings.TrimPrefix(record, "$hsrp$"), "$")
	salt := mustHex(t, f[0])
	digest := mustHex(t, f[1])

	// The packet is the real part of the salt with the digest put back
	// where the router wrote it.
	payload := append(append([]byte(nil), salt[:hsrpSaltBytes]...), digest...)

	file := pcapOf(t, linkTypeEthernet, false,
		udpFrame([4]byte{10, 0, 0, 1}, [4]byte{224, 0, 0, 2}, hsrpPort, hsrpPort, payload))

	got, err := extractPCAPRecords(writeFixture(t, "hsrp.pcap", file))
	if err != nil {
		t.Fatalf("extractPCAPRecords: %v", err)
	}
	if len(got) != 1 || got[0] != record {
		t.Fatalf("\n got: %v\nwant: %s", got, record)
	}
	mustCrack(t, "hsrp", got[0], password)
}

// TestExtractPCAPNetAH rebuilds the packet from the record, putting back the
// three fields the record zeroes and the ICV, and requires the extractor to
// zero them again. The fixture sets all three to non-zero values, so a reader
// that copied the packet across unchanged fails here.
func TestExtractPCAPNetAH(t *testing.T) {
	record, password := johnVector(t, "net-ah $net-ah$")
	f := strings.Split(strings.TrimPrefix(record, "$net-ah$"), "$")
	packet := append([]byte(nil), mustHex(t, f[1])...)
	icv := mustHex(t, f[2])

	ipLen := int(packet[0]&0x0f) * 4
	icvAt := ipLen + ahFixedLen
	copy(packet[icvAt:], icv)
	// Put back what a router would have changed on the way.
	packet[1] = 0x10
	packet[6] |= 0x40
	packet[10], packet[11] = 0xbe, 0xef

	eth := make([]byte, 14+len(packet))
	eth[12], eth[13] = 0x08, 0x00
	copy(eth[14:], packet)

	file := pcapOf(t, linkTypeEthernet, false, hex.EncodeToString(eth))
	got, err := extractPCAPRecords(writeFixture(t, "ah.pcap", file))
	if err != nil {
		t.Fatalf("extractPCAPRecords: %v", err)
	}
	if len(got) != 1 || got[0] != record {
		t.Fatalf("\n got: %.70s...\nwant: %.70s...", got[0], record)
	}
	mustCrack(t, "net-ah", got[0], password)
}

func TestExtractPCAPRSVP(t *testing.T) {
	record, password := johnVector(t, "rsvp $rsvp$")
	f := strings.Split(strings.TrimPrefix(record, "$rsvp$"), "$")
	message := append([]byte(nil), mustHex(t, f[1])...)
	digest := mustHex(t, f[2])
	if f[0] != "1" || len(digest) != 16 {
		t.Fatalf("this vector is no longer the MD5 shape (%s, %d)", f[0], len(digest))
	}
	// The digest sits twenty bytes into the INTEGRITY object, which follows
	// the eight-byte RSVP header.
	copy(message[8+20:], digest)

	file := pcapOf(t, linkTypeEthernet, false,
		ipv4Frame(t, ipProtoRSVP, [4]byte{192, 168, 1, 20}, [4]byte{192, 168, 1, 10}, message))

	got, err := extractPCAPRecords(writeFixture(t, "rsvp.pcap", file))
	if err != nil {
		t.Fatalf("extractPCAPRecords: %v", err)
	}
	if len(got) != 1 || got[0] != record {
		t.Fatalf("\n got: %.70s...\nwant: %.70s...", got[0], record)
	}
	mustCrack(t, "rsvp", got[0], password)
}

// ── Kerberos TGS-REP ─────────────────────────────────────────────────────────

// tgsRepMessage builds a TGS-REP carrying one ticket, to RFC 4120's
// definition. The reply's OWN encrypted part is filled with junk on purpose:
// it is encrypted under the requesting user's key, which the attacker already
// has, and taking it instead of the ticket's would give a record that cracks
// with a password nobody wanted.
func tgsRepMessage(t *testing.T, ticketCipher []byte) []byte {
	t.Helper()
	sname := der(0xa2, der(0x30,
		der(0xa0, derInteger(2)),
		der(0xa1, der(0x30,
			der(0x1b, []byte("HTTP")),
			der(0x1b, []byte("web.example.com")))),
	))
	ticket := der(0x61, der(0x30,
		der(0xa0, derInteger(5)),
		der(0xa1, der(0x1b, []byte("EXAMPLE.COM"))),
		sname,
		der(0xa3, der(0x30,
			der(0xa0, derInteger(23)),
			der(0xa2, derOctets(ticketCipher)))),
	))
	return der(0x6d, der(0x30,
		der(0xa0, derInteger(5)),  // pvno
		der(0xa1, derInteger(13)), // msg-type: TGS-REP
		der(0xa3, der(0x1b, []byte("EXAMPLE.COM"))),
		der(0xa4, der(0x30, der(0xa0, derInteger(1)),
			der(0xa1, der(0x30, der(0x1b, []byte("alice")))))),
		der(0xa5, ticket),
		// The reply's own enc-part, under the USER's key.
		der(0xa6, der(0x30,
			der(0xa0, derInteger(23)),
			der(0xa2, derOctets(bytes.Repeat([]byte{0xee}, 64))))),
	))
}

func TestExtractPCAPTGSRep(t *testing.T) {
	record, password := johnVector(t, "krb5tgs $krb5tgs$")
	f := strings.Split(strings.TrimPrefix(record, "$krb5tgs$"), "$")
	cipher := append(mustHex(t, f[1]), mustHex(t, f[2])...)
	message := tgsRepMessage(t, cipher)

	for _, tc := range []struct {
		name  string
		frame string
	}{
		{"over UDP", udpFrame([4]byte{10, 0, 0, 1}, [4]byte{10, 0, 0, 2},
			kerberosPort, 40000, message)},
		// TCP prefixes the reply with a four-byte length.
		{"over TCP", tcpFrame([4]byte{10, 0, 0, 1}, [4]byte{10, 0, 0, 2},
			kerberosPort, 40000, append([]byte{
				byte(len(message) >> 24), byte(len(message) >> 16),
				byte(len(message) >> 8), byte(len(message)),
			}, message...))},
	} {
		t.Run(tc.name, func(t *testing.T) {
			file := pcapOf(t, linkTypeEthernet, false, tc.frame)
			got, err := extractPCAPRecords(writeFixture(t, "krb.pcap", file))
			if err != nil {
				t.Fatalf("extractPCAPRecords: %v", err)
			}
			if len(got) != 1 {
				t.Fatalf("got %d records, want 1: %v", len(got), got)
			}
			// The record names the service, which is what tells a user
			// which account a ticket belongs to.
			want := "$krb5tgs$23$*HTTP/web.example.com@EXAMPLE.COM*$" + f[1] + "$" + f[2]
			if got[0] != want {
				t.Fatalf("\n got: %.70s...\nwant: %.70s...", got[0], want)
			}
			mustCrack(t, "krb5tgs", got[0], password)
		})
	}
}

// A reply split across TCP segments is left alone: half a reply is not a
// record, and emitting one would be emitting something that cannot parse.
func TestExtractPCAPTGSRepIgnoresATruncatedReply(t *testing.T) {
	message := tgsRepMessage(t, bytes.Repeat([]byte{0x11}, 64))
	// Claim a length larger than what the segment carries.
	prefixed := append([]byte{0, 0, 0xff, 0xff}, message...)
	file := pcapOf(t, linkTypeEthernet, false,
		tcpFrame([4]byte{10, 0, 0, 1}, [4]byte{10, 0, 0, 2}, kerberosPort, 40000, prefixed))

	if _, err := extractPCAPRecords(writeFixture(t, "part.pcap", file)); err == nil {
		t.Error("a truncated reply should not become a record")
	}
}

// KDC-REP's padata field is OPTIONAL, so the ticket is the sixth element of a
// reply that carries it and the fifth of one that does not. Both shapes must
// give the same record — a reader that counts elements gets the reply's own
// encrypted part for one of them, which cracks with the password of the
// account that ASKED for the ticket rather than the one that owns it.
func TestExtractPCAPTGSRepBothPadataShapes(t *testing.T) {
	record, password := johnVector(t, "krb5tgs $krb5tgs$")
	f := strings.Split(strings.TrimPrefix(record, "$krb5tgs$"), "$")
	cipher := append(mustHex(t, f[1]), mustHex(t, f[2])...)

	without := tgsRepMessage(t, cipher)
	// Splice a padata element in as field [2], where a KDC that sends one
	// puts it.
	padata := der(0xa2, der(0x30, der(0x30,
		der(0xa1, derInteger(19)),
		der(0xa2, derOctets([]byte("padata"))))))
	inner, _, err := derParse(without)
	if err != nil {
		t.Fatal(err)
	}
	body := inner.body // the SEQUENCE, as encoded
	seq, _, err := derParse(body)
	if err != nil {
		t.Fatal(err)
	}
	children, err := derChildren(seq)
	if err != nil {
		t.Fatal(err)
	}
	var rebuilt []byte
	for i, c := range children {
		rebuilt = append(rebuilt, reencode(c)...)
		if i == 1 { // after msg-type, where padata belongs
			rebuilt = append(rebuilt, padata...)
		}
	}
	with := der(0x6d, der(0x30, rebuilt))

	for name, message := range map[string][]byte{"without padata": without, "with padata": with} {
		t.Run(name, func(t *testing.T) {
			file := pcapOf(t, linkTypeEthernet, false,
				udpFrame([4]byte{10, 0, 0, 1}, [4]byte{10, 0, 0, 2},
					kerberosPort, 40000, message))
			got, err := extractPCAPRecords(writeFixture(t, "krb.pcap", file))
			if err != nil {
				t.Fatalf("extractPCAPRecords: %v", err)
			}
			want := "$krb5tgs$23$*HTTP/web.example.com@EXAMPLE.COM*$" + f[1] + "$" + f[2]
			if len(got) != 1 || got[0] != want {
				t.Fatalf("\n got: %.70s...\nwant: %.70s...", got[0], want)
			}
			mustCrack(t, "krb5tgs", got[0], password)
		})
	}
}
