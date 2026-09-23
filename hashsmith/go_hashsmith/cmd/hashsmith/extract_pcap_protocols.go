package main

// Credentials carried by protocols, out of a packet capture.
//
// John's pcap2john handles twenty-one protocols in one script. This covers the
// two with the widest reach — HTTP Digest authentication and SNMPv3 — and
// names the rest as absent rather than pretending to a coverage it does not
// have. Both reuse the container reader in pcap.go, which WPA and RADIUS
// already share.

import (
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

func runExtractPCAP(args []string) error {
	return runFileRecordExtractor("pcap2smith", args, extractPCAPRecords)
}

func extractPCAPRecords(path string) ([]string, error) {
	b, err := readExtractorFile(path)
	if err != nil {
		return nil, err
	}
	frames, err := pcapFrames(b)
	if err != nil {
		return nil, err
	}

	var records []string
	seen := map[string]bool{}
	add := func(r string) {
		if r != "" && !seen[r] {
			seen[r] = true
			records = append(records, r)
		}
	}
	basicAuth := 0

	for _, f := range frames {
		if payload, ok := tcpPayload(f.data, f.linkType); ok {
			digest, basic := httpAuthorizationRecords(payload)
			for _, r := range digest {
				add(r)
			}
			basicAuth += basic
		}
		if payload, ok := udpPayloadToPort(f.data, f.linkType, snmpPort); ok {
			if r, ok := snmpv3Record(payload); ok {
				add(r)
			}
		}
	}

	if len(records) == 0 {
		if basicAuth > 0 {
			return nil, fmt.Errorf("this capture holds %d HTTP Basic Authorization header(s) and no crackable record: Basic auth carries the password itself, base64-encoded, so there is nothing to crack — decode the header", basicAuth)
		}
		return nil, errors.New("no HTTP Digest or SNMPv3 credentials in this capture (the other protocols pcap2john reads are not covered here)")
	}
	if basicAuth > 0 {
		fmt.Printf("note: %d HTTP Basic Authorization header(s) are also present; those carry the password itself and need no cracking\n", basicAuth)
	}
	return records, nil
}

// ── HTTP Digest ───────────────────────────────────────────────────────────────

// httpAuthorizationRecords reads the Authorization headers out of one TCP
// payload, returning Digest records and a count of Basic ones.
//
// Basic is counted rather than converted on purpose: it carries the PASSWORD
// ITSELF, base64-encoded, so a record for it would be a record whose answer is
// already in the capture. Reporting the count tells the user to go and read it.
func httpAuthorizationRecords(payload []byte) (records []string, basic int) {
	text := string(payload)
	if !strings.Contains(text, "Authorization:") {
		return nil, 0
	}
	method := httpRequestMethod(text)

	for _, line := range strings.Split(text, "\r\n") {
		value, ok := headerValue(line, "Authorization:")
		if !ok {
			continue
		}
		switch {
		case strings.HasPrefix(value, "Basic "):
			basic++
		case strings.HasPrefix(value, "Digest "):
			if r, ok := httpDigestRecord(method, value[len("Digest "):]); ok {
				records = append(records, r)
			}
		}
	}
	return records, basic
}

func headerValue(line, name string) (string, bool) {
	if len(line) < len(name) || !strings.EqualFold(line[:len(name)], name) {
		return "", false
	}
	return strings.TrimSpace(line[len(name):]), true
}

// httpRequestMethod reads the method off the request line, which is where it
// lives — the Authorization header does not carry it, and the digest covers
// it, so a record built without the request line cannot be right.
func httpRequestMethod(text string) string {
	line, _, _ := strings.Cut(text, "\r\n")
	method, rest, ok := strings.Cut(line, " ")
	if !ok || !strings.Contains(rest, "HTTP/") {
		return ""
	}
	for _, m := range []string{"GET", "POST", "HEAD", "PUT", "DELETE", "OPTIONS", "PATCH", "TRACE", "CONNECT"} {
		if method == m {
			return m
		}
	}
	return ""
}

// httpDigestRecord builds the record from one Digest challenge response.
func httpDigestRecord(method, params string) (string, bool) {
	opts := parseHTTPAuthParams(params)
	for _, need := range []string{"username", "realm", "uri", "nonce", "response"} {
		if opts[need] == "" {
			return "", false
		}
	}
	if method == "" {
		return "", false
	}
	// RFC 2617 has two shapes. With qop the digest covers the nonce count
	// and the client nonce as well; without it, it does not — and the
	// record has to say which, because the same fields hashed the two ways
	// give different answers.
	return fmt.Sprintf("%s:$response$%s$%s$%s$%s$%s$%s$%s$%s$%s",
		opts["username"], opts["response"], opts["username"], opts["realm"],
		method, opts["uri"], opts["nonce"], opts["nc"], opts["cnonce"], opts["qop"]), true
}

// parseHTTPAuthParams splits a comma-separated list of key=value pairs, where
// a value may be quoted and a quoted value may contain a comma.
func parseHTTPAuthParams(s string) map[string]string {
	out := map[string]string{}
	for i := 0; i < len(s); {
		for i < len(s) && (s[i] == ' ' || s[i] == ',') {
			i++
		}
		eq := strings.IndexByte(s[i:], '=')
		if eq < 0 {
			break
		}
		key := strings.TrimSpace(s[i : i+eq])
		i += eq + 1
		var value string
		if i < len(s) && s[i] == '"' {
			i++
			end := strings.IndexByte(s[i:], '"')
			if end < 0 {
				break
			}
			value, i = s[i:i+end], i+end+1
		} else {
			end := strings.IndexByte(s[i:], ',')
			if end < 0 {
				value, i = s[i:], len(s)
			} else {
				value, i = s[i:i+end], i+end+1
			}
		}
		out[strings.ToLower(key)] = strings.TrimSpace(value)
	}
	return out
}

// ── SNMPv3 ────────────────────────────────────────────────────────────────────

const snmpPort = 161

// snmpv3Record builds the record for one SNMPv3 message.
//
// John's converter finds the fields by SCANNING for their tag and length bytes
// — \x04\x0b for the engine id, \x04\x0c for the authentication parameters —
// which works for an eleven-byte engine id and silently misses every other
// length. Engine ids are commonly thirteen bytes and may be up to
// thirty-two, so this parses the message instead.
//
//	SNMPv3Message ::= SEQUENCE {
//	    msgVersion INTEGER, msgGlobalData SEQUENCE,
//	    msgSecurityParameters OCTET STRING (which holds another SEQUENCE),
//	    msgData ... }
//
// The security parameters are a DER SEQUENCE wrapped in an OCTET STRING, which
// is why they need parsing twice.
//
// The authentication parameters are ZEROED in the copy the record carries,
// because that is the state the digest was computed over: the sender fills the
// field with zeros, computes the MAC over the whole message, and then writes
// the MAC into the hole.
func snmpv3Record(payload []byte) (string, bool) {
	top, _, err := derParse(payload)
	if err != nil || !top.constructed {
		return "", false
	}
	fields, err := derChildren(top)
	if err != nil || len(fields) < 3 {
		return "", false
	}
	if version, err := derInt(fields[0]); err != nil || version != 3 {
		return "", false
	}
	// The security parameters are an OCTET STRING holding a SEQUENCE.
	params := fields[2]
	if params.class != 0 || params.tag != 4 {
		return "", false
	}
	inner, _, err := derParseAt(params.body, params.off)
	if err != nil || !inner.constructed {
		return "", false
	}
	usm, err := derChildren(inner)
	if err != nil || len(usm) < 6 {
		return "", false
	}
	engineID, authParams, privParams := usm[0], usm[4], usm[5]
	for _, f := range []derValue{engineID, authParams, privParams} {
		if f.class != 0 || f.tag != 4 {
			return "", false
		}
	}
	if len(engineID.body) == 0 || len(authParams.body) == 0 {
		return "", false
	}

	// Zero the authentication parameters where they sit.
	message := append([]byte(nil), payload...)
	if authParams.off+len(authParams.body) > len(message) {
		return "", false
	}
	for i := 0; i < len(authParams.body); i++ {
		message[authParams.off+i] = 0
	}

	// Zero for the authentication protocol means "try both MD5 and SHA-1",
	// which is the honest value: the message does not say which was used.
	//
	// The second field is a counter John's format reads and discards — its
	// source calls it "packet number, for debugging". pcap2john puts 3 or
	// 4 there depending on whether the message carried privacy parameters,
	// so the same is written here and means nothing more.
	//
	// pcap2john also appends the privacy parameters as a sixth field when
	// there are any. That field is not written here: nothing reads it, and
	// the bytes are already inside the message, which is what the MAC
	// covers. A record carrying it is still accepted (see verifySNMPv3).
	const authUnknown, privNone, privPresent = 0, 3, 4
	marker := privNone
	if len(privParams.body) > 0 {
		marker = privPresent
	}
	return fmt.Sprintf("$SNMPv3$%d$%d$%s$%s$%s", authUnknown, marker,
		hex.EncodeToString(message), hex.EncodeToString(engineID.body),
		hex.EncodeToString(authParams.body)), true
}

// ── Transport ─────────────────────────────────────────────────────────────────

// tcpPayload returns a frame's TCP payload.
func tcpPayload(frame []byte, linkType uint32) ([]byte, bool) {
	ipAt, ok := ipv4Offset(frame, linkType)
	if !ok || len(frame) < ipAt+20 || frame[ipAt]>>4 != 4 || frame[ipAt+9] != 6 {
		return nil, false
	}
	ipLen := int(frame[ipAt]&0x0f) * 4
	if ipLen < 20 || len(frame) < ipAt+ipLen+20 {
		return nil, false
	}
	total := int(bigEndianUint16(frame[ipAt+2:]))
	if total < ipLen+20 || ipAt+total > len(frame) {
		total = len(frame) - ipAt
	}
	tcpAt := ipAt + ipLen
	tcpLen := int(frame[tcpAt+12]>>4) * 4
	if tcpLen < 20 || tcpAt+tcpLen > ipAt+total {
		return nil, false
	}
	payload := frame[tcpAt+tcpLen : ipAt+total]
	if len(payload) == 0 {
		return nil, false
	}
	return payload, true
}

// udpPayloadToPort returns a frame's UDP payload when either endpoint is the
// given port.
func udpPayloadToPort(frame []byte, linkType uint32, port uint16) ([]byte, bool) {
	ipAt, ok := ipv4Offset(frame, linkType)
	if !ok || len(frame) < ipAt+20 || frame[ipAt]>>4 != 4 || frame[ipAt+9] != 17 {
		return nil, false
	}
	ipLen := int(frame[ipAt]&0x0f) * 4
	if ipLen < 20 || len(frame) < ipAt+ipLen+8 {
		return nil, false
	}
	udpAt := ipAt + ipLen
	if bigEndianUint16(frame[udpAt:]) != port && bigEndianUint16(frame[udpAt+2:]) != port {
		return nil, false
	}
	total := int(bigEndianUint16(frame[ipAt+2:]))
	if total < ipLen+8 || ipAt+total > len(frame) {
		total = len(frame) - ipAt
	}
	udpLen := int(bigEndianUint16(frame[udpAt+4:]))
	end := udpAt + udpLen
	if udpLen < 8 || end > ipAt+total {
		end = ipAt + total
	}
	if udpAt+8 >= end {
		return nil, false
	}
	return frame[udpAt+8 : end], true
}

func bigEndianUint16(b []byte) uint16 { return uint16(b[0])<<8 | uint16(b[1]) }
