package smith

// RADIUS shared secrets out of a packet capture, and the legacy hccap
// handshake container.
//
// The RADIUS attack is not on a password at all. It is on the SHARED SECRET
// between a network access server and the RADIUS server, and it works because
// of a 1997 design decision: the Response Authenticator in every reply is
// MD5(code || id || length || RequestAuthenticator || attributes || secret).
// Everything in that digest except the secret travels in the clear, in the
// same capture, so a reply plus the request it answers is an offline
// dictionary attack on the secret with one MD5 per candidate.
//
// That is Joshua Hill's attack 3.1 from his 2001 analysis, and RADIUS still
// works this way. The secret is usually typed by a network engineer into two
// devices once and never changed.

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

func runExtractRADIUS(args []string) error {
	return runFileRecordExtractor("radius2smith", args, extractRADIUSRecords)
}

const (
	radiusAuthPort = 1812
	radiusAcctPort = 1813
	// radiusHeader is code(1) + id(1) + length(2) + authenticator(16).
	radiusHeader = 20
)

// RADIUS packet codes worth reading.
const (
	radiusAccessRequest      = 1
	radiusAccessAccept       = 2
	radiusAccessReject       = 3
	radiusAccountingRequest  = 4
	radiusAccountingResponse = 5
	radiusAccessChallenge    = 11
)

// radiusExchange keys a request by who sent it and its identifier, which is
// all a reply carries to say which request it answers.
type radiusExchange struct {
	peer [4]byte
	id   byte
}

func extractRADIUSRecords(path string) ([]string, error) {
	b, err := readExtractorFile(path)
	if err != nil {
		return nil, err
	}
	frames, err := pcapFrames(b)
	if err != nil {
		return nil, err
	}

	requests := map[radiusExchange][]byte{}
	var records []string
	seen := map[string]bool{}
	sawRADIUS := false

	for _, f := range frames {
		src, dst, payload, ok := decodeIPv4UDP(f.data, f.linkType)
		if !ok || len(payload) < radiusHeader {
			continue
		}
		code := payload[0]
		id := payload[1]
		// The stated length is what the authenticator covers; anything
		// past it is padding the sender added and the digest does not
		// include.
		stated := int(binary.BigEndian.Uint16(payload[2:4]))
		if stated < radiusHeader || stated > len(payload) {
			continue
		}
		packet := payload[:stated]
		sawRADIUS = true

		switch code {
		case radiusAccessRequest, radiusAccountingRequest:
			// Remember the request's authenticator against the
			// address the reply will come back to.
			requests[radiusExchange{peer: src, id: id}] = append([]byte(nil), packet[4:20]...)

		case radiusAccessAccept, radiusAccessReject, radiusAccessChallenge, radiusAccountingResponse:
			requestAuth, found := requests[radiusExchange{peer: dst, id: id}]
			if !found {
				continue
			}
			// The digest is over the reply with the REQUEST's
			// authenticator in place of the reply's own. Leaving
			// the reply's there hashes the answer into its own
			// input and nothing ever matches.
			salt := append([]byte(nil), packet...)
			copy(salt[4:20], requestAuth)

			// John's converter chooses between two expressions by
			// the salt's length. A RADIUS packet is at least
			// twenty bytes, so in practice only the second is ever
			// written; the first is kept because a record carrying
			// it is still a record this should read.
			expression := "dynamic_1017"
			if len(salt) <= 16 {
				expression = "dynamic_1009"
			}
			record := fmt.Sprintf("$%s$%s$HEX$%s", expression,
				hex.EncodeToString(packet[4:20]), hex.EncodeToString(salt))
			if !seen[record] {
				seen[record] = true
				records = append(records, record)
			}
		}
	}

	if len(records) == 0 {
		if sawRADIUS {
			return nil, errors.New("this capture holds RADIUS packets but no reply that could be matched to the request it answers; both halves of one exchange are needed")
		}
		return nil, errors.New("no RADIUS traffic on ports 1812 or 1813 in this capture")
	}
	return records, nil
}

// decodeIPv4UDP pulls the UDP payload out of a frame, and reports the RADIUS
// endpoints. Only ports 1812 and 1813 are accepted: RADIUS has no magic and
// its header is four bytes of counters, so a port-blind reader would find
// "RADIUS packets" in any UDP traffic.
func decodeIPv4UDP(frame []byte, linkType uint32) (src, dst [4]byte, payload []byte, ok bool) {
	ipAt, ok := ipv4Offset(frame, linkType)
	if !ok {
		return src, dst, nil, false
	}
	if len(frame) < ipAt+20 || frame[ipAt]>>4 != 4 || frame[ipAt+9] != 17 {
		return src, dst, nil, false
	}
	ipLen := int(frame[ipAt]&0x0f) * 4
	if ipLen < 20 || len(frame) < ipAt+ipLen+8 {
		return src, dst, nil, false
	}
	// A fragmented datagram carries only part of the packet, and
	// reassembling is a different job; the offset field says so.
	if binary.BigEndian.Uint16(frame[ipAt+6:ipAt+8])&0x1fff != 0 {
		return src, dst, nil, false
	}
	total := int(binary.BigEndian.Uint16(frame[ipAt+2 : ipAt+4]))
	if total < ipLen+8 || ipAt+total > len(frame) {
		total = len(frame) - ipAt
	}
	udpAt := ipAt + ipLen
	sport := binary.BigEndian.Uint16(frame[udpAt : udpAt+2])
	dport := binary.BigEndian.Uint16(frame[udpAt+2 : udpAt+4])
	if !isRADIUSPort(sport) && !isRADIUSPort(dport) {
		return src, dst, nil, false
	}
	udpLen := int(binary.BigEndian.Uint16(frame[udpAt+4 : udpAt+6]))
	end := udpAt + udpLen
	if udpLen < 8 || end > ipAt+total {
		end = ipAt + total
	}
	if udpAt+8 > end {
		return src, dst, nil, false
	}
	copy(src[:], frame[ipAt+12:ipAt+16])
	copy(dst[:], frame[ipAt+16:ipAt+20])
	return src, dst, frame[udpAt+8 : end], true
}

func isRADIUSPort(p uint16) bool { return p == radiusAuthPort || p == radiusAcctPort }

// ipv4Offset reports where the IPv4 header starts for a link type that carries
// one at a fixed place.
func ipv4Offset(frame []byte, linkType uint32) (int, bool) {
	switch linkType {
	case linkTypeEthernet:
		if len(frame) < 14 {
			return 0, false
		}
		etherType, at := binary.BigEndian.Uint16(frame[12:14]), 14
		// One VLAN tag is common enough to be worth stepping over.
		if etherType == 0x8100 || etherType == 0x88a8 {
			if len(frame) < 18 {
				return 0, false
			}
			etherType, at = binary.BigEndian.Uint16(frame[16:18]), 18
		}
		if etherType != 0x0800 {
			return 0, false
		}
		return at, true
	case linkTypeLinuxCooked:
		if len(frame) < 16 || binary.BigEndian.Uint16(frame[14:16]) != 0x0800 {
			return 0, false
		}
		return 16, true
	case linkTypeRawIP, linkTypeIPv4:
		return 0, true
	}
	return 0, false
}

// ── The legacy hccap container ───────────────────────────────────────────────

func runExtractHCCAP(args []string) error {
	return runFileRecordExtractor("hccap2smith", args, extractHCCAPRecords)
}

// hccapSize is aircrack-ng's 392-byte handshake structure, the one hccapx
// replaced. A file holds one or more of them back to back.
const hccapSize = 392

// extractHCCAPRecords converts the legacy hccap container.
//
// The field that must not be guessed is which nonce is whose. hccap stores the
// STATION's nonce first and the AP's second, which is the opposite order from
// the hccapx structure that replaced it — John's own hccap2john swaps them
// when it converts between the two. Emitting them the wrong way round gives a
// record that parses, looks right, and never cracks.
func extractHCCAPRecords(path string) ([]string, error) {
	b, err := readExtractorFile(path)
	if err != nil {
		return nil, err
	}
	if len(b) == 0 || len(b)%hccapSize != 0 {
		return nil, fmt.Errorf("an hccap file is a whole number of %d-byte structures; this one is %d bytes",
			hccapSize, len(b))
	}
	var records []string
	for off := 0; off+hccapSize <= len(b); off += hccapSize {
		h := b[off : off+hccapSize]
		essid := strings.TrimRight(string(h[0:36]), "\x00")
		if essid == "" {
			return nil, fmt.Errorf("hccap record %d names no ESSID, and the ESSID is the salt", off/hccapSize+1)
		}
		eapolLen := int(int32(binary.LittleEndian.Uint32(h[368:372])))
		if eapolLen < eapolMinLen || eapolLen > 256 {
			return nil, fmt.Errorf("hccap record %d states an EAPOL length of %d", off/hccapSize+1, eapolLen)
		}
		keyVer := int(int32(binary.LittleEndian.Uint32(h[372:376])))
		if keyVer < 1 || keyVer > 3 {
			return nil, fmt.Errorf("hccap record %d states key version %d", off/hccapSize+1, keyVer)
		}
		records = append(records, fmt.Sprintf("WPA*02*%s*%s*%s*%s*%s*%s*00",
			hex.EncodeToString(h[376:392]), // keymic
			hex.EncodeToString(h[36:42]),   // mac1, the AP
			hex.EncodeToString(h[42:48]),   // mac2, the station
			hex.EncodeToString([]byte(essid)),
			hex.EncodeToString(h[80:112]), // nonce2, the AP's
			hex.EncodeToString(wpaZeroMIC(h[112:112+eapolLen]))))
	}
	return records, nil
}
