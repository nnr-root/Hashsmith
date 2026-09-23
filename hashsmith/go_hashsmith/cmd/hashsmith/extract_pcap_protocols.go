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
		if payload, fromServer, ok := tcpPayloadFromPort(f.data, f.linkType, tacacsPort); ok {
			if r, ok := tacacsRecord(payload, fromServer); ok {
				add(r)
			}
		}
		if r, ok := tcpMD5Record(f.data, f.linkType); ok {
			add(r)
		}
		if payload, ok := udpPayloadToPort(f.data, f.linkType, hsrpPort); ok {
			if r, ok := hsrpRecord(payload); ok {
				add(r)
			}
		}
		if r, ok := netAHRecord(f.data, f.linkType); ok {
			add(r)
		}
		if r, ok := rsvpRecord(f.data, f.linkType); ok {
			add(r)
		}
	}

	if len(records) == 0 {
		if basicAuth > 0 {
			return nil, fmt.Errorf("this capture holds %d HTTP Basic Authorization header(s) and no crackable record: Basic auth carries the password itself, base64-encoded, so there is nothing to crack — decode the header", basicAuth)
		}
		return nil, errors.New("no HTTP Digest, SNMPv3, TACACS+, TCP-MD5, HSRP, IPsec AH or RSVP credentials in this capture (the other protocols pcap2john reads are not covered here)")
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

// ── TACACS+ ───────────────────────────────────────────────────────────────────

const (
	tacacsPort        = 49
	tacacsTypeAuthen  = 0x01
	tacacsUnencrypted = 0x01
	tacacsVersionHigh = 0x0c
	tacacsHeaderBytes = 12
)

// tacacsRecord builds a record from one TACACS+ packet.
//
// TACACS+ does not encrypt with a cipher. It XORs the body with a keystream of
// chained MD5s over the session id, the shared secret, the version byte and
// the sequence number — so the record carries those three plaintext fields and
// the body, and cracking is recomputing the keystream.
//
// Only the SERVER's reply is taken. The client's request is encrypted the same
// way, but a reply's decrypted body has a known shape — a status byte followed
// by two lengths that must agree with what is left — and the request's does
// not, so a record built from a request has nothing to check against.
//
// A packet with the unencrypted flag set carries no secret at all.
func tacacsRecord(payload []byte, fromServer bool) (string, bool) {
	if !fromServer || len(payload) <= tacacsHeaderBytes {
		return "", false
	}
	version, kind, seq, flags := payload[0], payload[1], payload[2], payload[3]
	if flags&tacacsUnencrypted != 0 || kind != tacacsTypeAuthen {
		return "", false
	}
	if version>>4 != tacacsVersionHigh {
		return "", false
	}
	sessionID := payload[4:8]
	body := payload[tacacsHeaderBytes:]

	// John's converter rebuilds this byte as
	// TACACS_PLUS_VERSION_MAJOR << 4 + version_minor, which Python reads as
	// a shift by (4 + minor). For minor 0 that is the right answer by
	// accident and for minor 1 it overflows a byte and raises. The version
	// byte is already in the packet, so it is simply copied.
	return fmt.Sprintf("$tacacs-plus$0$%s$%s$%s",
		hex.EncodeToString(sessionID), hex.EncodeToString(body),
		hex.EncodeToString([]byte{version, seq})), true
}

// ── TCP-MD5 (RFC 2385) ────────────────────────────────────────────────────────

const tcpOptMD5 = 19

// tcpMD5Record builds a record from a TCP segment carrying an MD5 signature.
//
// The digest covers a PSEUDO-HEADER that is not on the wire — the two
// addresses, the protocol number and the segment length — followed by the TCP
// header with its checksum zeroed, then the payload, then the secret. So the
// record's salt has to be assembled from three layers, and the addresses come
// from the IP header while everything else comes from the TCP one.
//
// The TCP OPTIONS are not covered, which is what makes the signature stable
// across a path that rewrites them.
func tcpMD5Record(frame []byte, linkType uint32) (string, bool) {
	ipAt, ok := ipv4Offset(frame, linkType)
	if !ok || len(frame) < ipAt+20 || frame[ipAt]>>4 != 4 || frame[ipAt+9] != 6 {
		return "", false
	}
	ipLen := int(frame[ipAt]&0x0f) * 4
	total := int(bigEndianUint16(frame[ipAt+2:]))
	if ipLen < 20 || total < ipLen+20 || ipAt+total > len(frame) {
		return "", false
	}
	segment := frame[ipAt+ipLen : ipAt+total]
	if len(segment) < 20 {
		return "", false
	}
	headerLen := int(segment[12]>>4) * 4
	// A segment with no room for options cannot carry a signature.
	if headerLen < 40 || headerLen > len(segment) {
		return "", false
	}
	signature, ok := tcpOption(segment[20:headerLen], tcpOptMD5)
	if !ok || len(signature) != 16 {
		return "", false
	}

	salt := make([]byte, 0, 12+20+len(segment)-headerLen)
	salt = append(salt, frame[ipAt+12:ipAt+20]...) // source and destination
	salt = append(salt, 0, frame[ipAt+9])          // padding, protocol
	salt = append(salt, byte(len(segment)>>8), byte(len(segment)))
	salt = append(salt, segment[:16]...) // the header up to the checksum
	salt = append(salt, 0, 0, 0, 0)      // checksum and urgent pointer, zeroed
	salt = append(salt, segment[headerLen:]...)

	return fmt.Sprintf("$tcpmd5$%s$%s",
		hex.EncodeToString(salt), hex.EncodeToString(signature)), true
}

// tcpOption walks the options for one kind. The list is a sequence of
// kind/length/value triples with two one-byte exceptions — end of list and
// no-operation — which is where a naive walk runs off the end.
func tcpOption(opts []byte, want byte) ([]byte, bool) {
	for i := 0; i < len(opts); {
		kind := opts[i]
		if kind == 0 { // end of option list
			return nil, false
		}
		if kind == 1 { // no-operation, one byte and no length
			i++
			continue
		}
		if i+1 >= len(opts) {
			return nil, false
		}
		length := int(opts[i+1])
		if length < 2 || i+length > len(opts) {
			return nil, false
		}
		if kind == want {
			return opts[i+2 : i+length], true
		}
		i += length
	}
	return nil, false
}

// tcpPayloadFromPort returns a TCP payload when either endpoint is the given
// port, and says whether the port was the SOURCE — which for a
// client/server protocol is what distinguishes a reply from a request.
func tcpPayloadFromPort(frame []byte, linkType uint32, port uint16) (payload []byte, fromPort bool, ok bool) {
	ipAt, good := ipv4Offset(frame, linkType)
	if !good || len(frame) < ipAt+20 || frame[ipAt]>>4 != 4 || frame[ipAt+9] != 6 {
		return nil, false, false
	}
	ipLen := int(frame[ipAt]&0x0f) * 4
	if ipLen < 20 || len(frame) < ipAt+ipLen+20 {
		return nil, false, false
	}
	tcpAt := ipAt + ipLen
	sport, dport := bigEndianUint16(frame[tcpAt:]), bigEndianUint16(frame[tcpAt+2:])
	if sport != port && dport != port {
		return nil, false, false
	}
	body, good := tcpPayload(frame, linkType)
	if !good {
		return nil, false, false
	}
	return body, sport == port, true
}

// ── HSRP version 1 ────────────────────────────────────────────────────────────

const (
	hsrpPort = 1985
	// hsrpAuthTLV is the MD5 authentication TLV's type byte, and
	// hsrpSaltBytes is how much of the packet the digest covers before the
	// digest field itself.
	hsrpAuthTLV    = 4
	hsrpHeaderLen  = 20
	hsrpSaltBytes  = 34
	hsrpDigestLen  = 16
	hsrpRecordSalt = hsrpSaltBytes + hsrpDigestLen
)

// hsrpRecord builds a record from an HSRP version 1 hello.
//
// The digest covers the first thirty-four bytes of the packet — the twenty
// byte header and the fourteen that open the authentication TLV — followed by
// SIXTEEN ZEROS where the digest itself will go. So the salt is longer than
// the part of the packet that is real, and a reader that stopped at
// thirty-four bytes would produce a salt the router never hashed.
func hsrpRecord(payload []byte) (string, bool) {
	if len(payload) < hsrpRecordSalt {
		return "", false
	}
	// The authentication TLV follows the fixed header; without it there is
	// no digest and nothing to crack.
	if payload[hsrpHeaderLen] != hsrpAuthTLV {
		return "", false
	}
	tlvLen := int(payload[hsrpHeaderLen+1])
	if hsrpHeaderLen+2+tlvLen > len(payload) || tlvLen < hsrpDigestLen+12 {
		return "", false
	}
	salt := make([]byte, hsrpRecordSalt)
	copy(salt, payload[:hsrpSaltBytes])
	digest := payload[hsrpSaltBytes : hsrpSaltBytes+hsrpDigestLen]

	return fmt.Sprintf("$hsrp$%s$%s",
		hex.EncodeToString(salt), hex.EncodeToString(digest)), true
}

// ── IPsec Authentication Header ───────────────────────────────────────────────

const (
	ipProtoAH   = 51
	ipProtoRSVP = 46
	ahFixedLen  = 12 // next header, payload length, reserved, SPI, sequence
)

// netAHRecord builds a record from a packet carrying an Authentication Header.
//
// The digest covers the WHOLE IP PACKET, which means the fields a router is
// allowed to change in flight have to be put back to what the sender hashed:
// the type-of-service byte, the three flag bits, and the header checksum are
// all zeroed. Leave any of them as captured and the record is the packet as it
// ARRIVED rather than as it was signed, which is a record that cannot crack
// on a path with more than one hop.
func netAHRecord(frame []byte, linkType uint32) (string, bool) {
	ipAt, ok := ipv4Offset(frame, linkType)
	if !ok || len(frame) < ipAt+20 || frame[ipAt]>>4 != 4 || frame[ipAt+9] != ipProtoAH {
		return "", false
	}
	ipLen := int(frame[ipAt]&0x0f) * 4
	total := int(bigEndianUint16(frame[ipAt+2:]))
	if ipLen < 20 || total < ipLen+ahFixedLen || ipAt+total > len(frame) {
		return "", false
	}
	packet := append([]byte(nil), frame[ipAt:ipAt+total]...)

	// The AH's own length field counts 32-bit words and is two less than
	// the header's real size, which is the one place this format's
	// arithmetic is not what it looks like.
	payloadLen := int(packet[ipLen+1])
	ahLen := (payloadLen + 2) * 4
	icvLen := ahLen - ahFixedLen
	if icvLen <= 0 || ipLen+ahLen > len(packet) {
		return "", false
	}
	icvAt := ipLen + ahFixedLen
	icv := append([]byte(nil), packet[icvAt:icvAt+icvLen]...)

	packet[1] = 0                 // type of service
	packet[6] &^= 0xe0            // the three flag bits, keeping the fragment offset
	packet[10], packet[11] = 0, 0 // header checksum
	for i := 0; i < icvLen; i++ {
		packet[icvAt+i] = 0
	}
	return fmt.Sprintf("$net-ah$0$%s$%s",
		hex.EncodeToString(packet), hex.EncodeToString(icv)), true
}

// ── RSVP ──────────────────────────────────────────────────────────────────────

const rsvpIntegrityClass = 4

// rsvpRecord builds a record from an RSVP message carrying an INTEGRITY
// object.
//
// The digest sits twenty bytes into that object and runs to its end, so its
// LENGTH is not stated anywhere — it is whatever is left. Sixteen bytes means
// MD5 and anything else means SHA-1, which is how the record's first field is
// decided: the message does not name the algorithm either.
func rsvpRecord(frame []byte, linkType uint32) (string, bool) {
	ipAt, ok := ipv4Offset(frame, linkType)
	if !ok || len(frame) < ipAt+20 || frame[ipAt]>>4 != 4 || frame[ipAt+9] != ipProtoRSVP {
		return "", false
	}
	ipLen := int(frame[ipAt]&0x0f) * 4
	total := int(bigEndianUint16(frame[ipAt+2:]))
	if ipLen < 20 || total <= ipLen || ipAt+total > len(frame) {
		return "", false
	}
	message := append([]byte(nil), frame[ipAt+ipLen:ipAt+total]...)

	// The RSVP header is eight bytes and the INTEGRITY object, when there
	// is one, follows it directly.
	const headerLen, digestAt = 8, 20
	if len(message) < headerLen+digestAt {
		return "", false
	}
	objectLen := int(bigEndianUint16(message[headerLen:]))
	if message[headerLen+2] != rsvpIntegrityClass {
		return "", false
	}
	if objectLen <= digestAt || headerLen+objectLen > len(message) {
		return "", false
	}
	digestLen := objectLen - digestAt
	at := headerLen + digestAt
	digest := append([]byte(nil), message[at:at+digestLen]...)
	for i := 0; i < digestLen; i++ {
		message[at+i] = 0
	}

	algorithm := 2 // SHA-1
	if digestLen == 16 {
		algorithm = 1 // MD5
	}
	return fmt.Sprintf("$rsvp$%d$%s$%s", algorithm,
		hex.EncodeToString(message), hex.EncodeToString(digest)), true
}
