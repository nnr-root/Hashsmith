package main

import (
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
