package main

// WPA and WPA2 personal, out of a packet capture.
//
// This is the extractor an engagement reaches for most often and the one with
// the most ways to be quietly wrong, so what it does and does not do is worth
// stating up front.
//
// TWO things in a capture are crackable and they are found in different
// places. The PMKID is a single frame from the AP: it appears in the RSN
// information element of message 1 of the four-way handshake and needs no
// client cooperation at all. The EAPOL MIC needs a PAIR of messages — one
// carrying the AP's nonce, one carrying the client's MIC over a frame that
// includes the client's nonce — and the two must belong to the same exchange.
//
// Neither is usable without the ESSID, which is NOT in either of them. It
// comes from a beacon or a probe response, which is a different frame type
// entirely, and it is the PBKDF2 salt — so a capture with a perfect handshake
// and no beacon yields nothing, and saying so is more useful than emitting a
// record with an empty salt that will never crack.
//
// One caveat about the PMKID is worth stating because it looks like a failure
// and is not. The PMKID an AP offers is derived from whatever PMK that AP is
// holding, which with a pre-shared key is the one the passphrase gives — but
// an AP that cached a PMK from an earlier association, or that ran 802.1X,
// offers a PMKID over a DIFFERENT key. Such a record will not crack even
// though the handshake from the same capture will. It is still emitted,
// because nothing in the frame says which case it is and a cracker should try
// it; what is not done is suppressing the handshake record in its favour.
//
// The records are hashcat's 22000 spelling, which Hashsmith and hashcat both
// read directly. John's own converter writes its $WPAPSK$ blob instead; that
// spelling is read here too (crack_wpa_john.go) but not written, because the
// 22000 form carries the same material in a form a human can check.

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

func runExtractWPAPCAP(args []string) error {
	return runFileRecordExtractor("wpapcap2smith", args, extractWPAPCAPRecords)
}

// ── 802.11 framing ────────────────────────────────────────────────────────────

// dot11Frame is the part of a captured 802.11 frame this needs.
type dot11Frame struct {
	frameType, subtype byte
	toDS, fromDS       bool
	addr1, addr2       [6]byte
	addr3              [6]byte
	body               []byte
}

// parseDot11 strips the radio header the capture driver prepended and reads
// the 802.11 header.
//
// FOUR different radio headers exist and a capture uses whichever the driver
// felt like. Radiotap states its own length in a field, PPI likewise; Prism
// and AVS use a fixed-size header whose length field is at a different offset
// in each. Getting the length wrong does not produce an error — it produces an
// 802.11 header read from the middle of the radio header, which parses into
// plausible nonsense.
func parseDot11(frame []byte, linkType uint32) (dot11Frame, bool) {
	var f dot11Frame
	switch linkType {
	case linkTypeIEEE80211:
	case linkTypeRadiotap:
		if len(frame) < 4 {
			return f, false
		}
		n := int(binary.LittleEndian.Uint16(frame[2:4]))
		if n < 8 || n > len(frame) {
			return f, false
		}
		frame = frame[n:]
	case linkTypePPI:
		if len(frame) < 8 {
			return f, false
		}
		n := int(binary.LittleEndian.Uint16(frame[2:4]))
		if n < 8 || n > len(frame) {
			return f, false
		}
		frame = frame[n:]
	case linkTypePrismHeader:
		// The Prism header states its own length at offset 4, but the
		// header is 144 bytes in every capture anyone has, and a
		// nonsensical length field is commoner than a different size.
		if len(frame) < 144 {
			return f, false
		}
		n := int(binary.LittleEndian.Uint32(frame[4:8]))
		if n < 8 || n > len(frame) {
			n = 144
		}
		frame = frame[n:]
	case linkTypeIEEE80211Avs:
		if len(frame) < 8 {
			return f, false
		}
		n := int(binary.BigEndian.Uint32(frame[4:8]))
		if n < 8 || n > len(frame) {
			return f, false
		}
		frame = frame[n:]
	default:
		return f, false
	}

	if len(frame) < 24 {
		return f, false
	}
	f.frameType = (frame[0] >> 2) & 0x03
	f.subtype = (frame[0] >> 4) & 0x0f
	f.toDS = frame[1]&0x01 != 0
	f.fromDS = frame[1]&0x02 != 0
	copy(f.addr1[:], frame[4:10])
	copy(f.addr2[:], frame[10:16])
	copy(f.addr3[:], frame[16:22])

	at := 24
	if f.toDS && f.fromDS { // a four-address frame carries one more
		at += 6
	}
	if f.frameType == 2 && f.subtype&0x08 != 0 { // QoS data
		at += 2
	}
	if at > len(frame) {
		return f, false
	}
	f.body = frame[at:]
	return f, true
}

// dot11SSID reads the SSID out of a beacon or probe response.
//
// The body opens with twelve bytes of fixed parameters — a timestamp, a beacon
// interval, a capability field — and then a list of tagged elements, of which
// tag 0 is the SSID. A hidden network broadcasts a zero-length or all-zero
// SSID, which is not an ESSID and must not be recorded as one.
func dot11SSID(body []byte) (string, bool) {
	if len(body) < 12 {
		return "", false
	}
	for at := 12; at+2 <= len(body); {
		tag, length := body[at], int(body[at+1])
		at += 2
		if at+length > len(body) {
			return "", false
		}
		if tag == 0 {
			ssid := body[at : at+length]
			if len(ssid) == 0 {
				return "", false
			}
			for _, c := range ssid {
				if c != 0 {
					return string(ssid), true
				}
			}
			return "", false
		}
		at += length
	}
	return "", false
}

// ── EAPOL-Key ─────────────────────────────────────────────────────────────────

// The LLC/SNAP header that introduces an EAPOL frame inside an 802.11 data
// frame: SNAP with a null OUI and EtherType 0x888E.
var eapolSNAP = []byte{0xaa, 0xaa, 0x03, 0x00, 0x00, 0x00, 0x88, 0x8e}

// Offsets inside an EAPOL-Key frame, counted from the 802.1X version byte,
// which is where hashcat's 22000 record starts its EAPOL field.
const (
	eapolKeyInfoAt    = 5
	eapolNonceAt      = 17
	eapolMICAt        = 81
	eapolKeyDataLenAt = 97
	eapolKeyDataAt    = 99
	eapolMinLen       = 99
)

// eapolKey is one parsed EAPOL-Key frame.
type eapolKey struct {
	raw     []byte // from the 802.1X version byte
	keyInfo uint16
	nonce   []byte
	mic     []byte
	keyData []byte
	replay  uint64
}

// parseEAPOLKey reads an EAPOL-Key frame out of an 802.11 data frame's body.
func parseEAPOLKey(body []byte) (eapolKey, bool) {
	var k eapolKey
	if len(body) < len(eapolSNAP) || string(body[:len(eapolSNAP)]) != string(eapolSNAP) {
		return k, false
	}
	b := body[len(eapolSNAP):]
	if len(b) < eapolMinLen || b[1] != 3 { // EAPOL type 3 is Key
		return k, false
	}
	// The 802.1X length field covers everything after it. Trusting the
	// captured length instead would fold the frame's FCS and any padding
	// into the MIC computation.
	stated := int(binary.BigEndian.Uint16(b[2:4])) + 4
	if stated < eapolMinLen || stated > len(b) {
		stated = len(b)
	}
	b = b[:stated]

	k.raw = b
	k.keyInfo = binary.BigEndian.Uint16(b[eapolKeyInfoAt : eapolKeyInfoAt+2])
	k.replay = binary.BigEndian.Uint64(b[9:17])
	k.nonce = b[eapolNonceAt : eapolNonceAt+32]
	k.mic = b[eapolMICAt : eapolMICAt+16]
	dataLen := int(binary.BigEndian.Uint16(b[eapolKeyDataLenAt : eapolKeyDataLenAt+2]))
	if eapolKeyDataAt+dataLen <= len(b) {
		k.keyData = b[eapolKeyDataAt : eapolKeyDataAt+dataLen]
	}
	return k, true
}

// Key Information bits, from IEEE 802.11-2016 table 12-8.
const (
	keyInfoInstall   = 0x0040
	keyInfoACK       = 0x0080
	keyInfoMIC       = 0x0100
	keyInfoSecure    = 0x0200
	keyInfoEncrypted = 0x1000
)

// eapolMessageNumber says which of the four handshake messages a frame is.
//
// Nothing in the frame states it. The number follows from three flags and one
// length, and the pairs that matter are told apart by only one bit each:
// message 2 and message 4 both carry a MIC and no ACK, and differ in Secure
// and in whether any key data follows. Reading message 4 as message 2 gives a
// record whose nonce is the client's second one and which never cracks.
func eapolMessageNumber(k eapolKey) int {
	info := k.keyInfo
	switch {
	case info&keyInfoACK != 0 && info&keyInfoMIC == 0:
		return 1
	case info&keyInfoACK != 0 && info&keyInfoMIC != 0 && info&keyInfoInstall != 0:
		return 3
	case info&keyInfoACK == 0 && info&keyInfoMIC != 0:
		if info&keyInfoSecure != 0 && len(k.keyData) == 0 {
			return 4
		}
		if len(k.keyData) == 0 {
			return 4
		}
		return 2
	}
	return 0
}

// rsnPMKID digs the PMKID out of message 1's key data.
//
// The key data is a list of tagged elements; tag 0xdd is a vendor-specific
// element, and the one that matters carries OUI 00-0F-AC with type 4. An
// all-zero PMKID means the AP offered the field and had nothing to put in it,
// which is not a PMKID and must not be emitted as one.
func rsnPMKID(keyData []byte) ([]byte, bool) {
	for at := 0; at+2 <= len(keyData); {
		tag, length := keyData[at], int(keyData[at+1])
		at += 2
		if at+length > len(keyData) {
			return nil, false
		}
		body := keyData[at : at+length]
		at += length
		if tag != 0xdd || len(body) < 4+16 {
			continue
		}
		if body[0] != 0x00 || body[1] != 0x0f || body[2] != 0xac || body[3] != 0x04 {
			continue
		}
		pmkid := body[4 : 4+16]
		for _, c := range pmkid {
			if c != 0 {
				return pmkid, true
			}
		}
		return nil, false
	}
	return nil, false
}

// ── Putting a capture together ────────────────────────────────────────────────

// wpaExchange collects what has been seen for one AP and client pair.
type wpaExchange struct {
	ap, sta [6]byte
	// m1 and m3 carry the AP's nonce; m2 and m4 carry the client's MIC.
	m1, m2, m3, m4 *eapolKey
}

// Message-pair codes, as hashcat's 22000 format defines them. The code says
// which two messages the record was built from, which is what tells a reader
// whether the nonce and the MIC could have belonged to the same exchange.
const (
	wpaPairM1M2 = "00"
	wpaPairM1M4 = "01"
	wpaPairM2M3 = "02"
	wpaPairM3M4 = "03"
)

func extractWPAPCAPRecords(path string) ([]string, error) {
	b, err := readExtractorFile(path)
	if err != nil {
		return nil, err
	}
	frames, err := pcapFrames(b)
	if err != nil {
		return nil, err
	}

	essids := map[[6]byte]string{}
	exchanges := map[[12]byte]*wpaExchange{}
	var order [][12]byte
	sawDot11 := false

	for _, raw := range frames {
		f, ok := parseDot11(raw.data, raw.linkType)
		if !ok {
			continue
		}
		sawDot11 = true

		// Beacons and probe responses name the network. addr3 is the
		// BSSID in both.
		if f.frameType == 0 && (f.subtype == 8 || f.subtype == 5) {
			if ssid, ok := dot11SSID(f.body); ok {
				if _, seen := essids[f.addr3]; !seen {
					essids[f.addr3] = ssid
				}
			}
			continue
		}
		if f.frameType != 2 {
			continue
		}
		key, ok := parseEAPOLKey(f.body)
		if !ok {
			continue
		}
		// Which address is the AP depends on the direction, and the
		// two cases are mirror images. A frame going TO the
		// distribution system carries the BSSID in address 1 and the
		// sender in address 2; a frame coming FROM it carries the
		// destination in address 1 and the BSSID in address 2. Get
		// this backwards and every record names the client as the
		// access point, the ESSID lookup misses, and the capture looks
		// like one with a handshake and no beacon.
		ap, sta := f.addr2, f.addr1
		if f.toDS {
			ap, sta = f.addr1, f.addr2
		}
		var id [12]byte
		copy(id[0:6], ap[:])
		copy(id[6:12], sta[:])
		ex, seen := exchanges[id]
		if !seen {
			ex = &wpaExchange{ap: ap, sta: sta}
			exchanges[id] = ex
			order = append(order, id)
		}
		stored := key
		switch eapolMessageNumber(key) {
		case 1:
			ex.m1 = &stored
		case 2:
			ex.m2 = &stored
		case 3:
			ex.m3 = &stored
		case 4:
			ex.m4 = &stored
		}
	}

	if !sawDot11 {
		return nil, errors.New("this capture holds no 802.11 frames; a WPA handshake is only visible in a wireless capture, not in one taken on a wired interface")
	}

	var (
		records []string
		noESSID []string
		seen    = map[string]bool{}
	)
	for _, id := range order {
		ex := exchanges[id]
		essid, haveESSID := essids[ex.ap]
		if !haveESSID {
			noESSID = append(noESSID, macString(ex.ap))
			continue
		}
		for _, r := range wpaRecordsFor(ex, essid) {
			if !seen[r] {
				seen[r] = true
				records = append(records, r)
			}
		}
	}

	if len(records) == 0 {
		if len(noESSID) > 0 {
			return nil, fmt.Errorf("handshakes were found for %s but the capture holds no beacon or probe response naming the network, and the ESSID is the salt — without it there is nothing to crack",
				strings.Join(uniqueNonEmpty(noESSID), ", "))
		}
		return nil, errors.New("this capture holds 802.11 frames but no usable PMKID or four-way handshake")
	}
	return records, nil
}

// wpaRecordsFor turns one exchange into whatever records it supports.
func wpaRecordsFor(ex *wpaExchange, essid string) []string {
	var out []string
	essidHex := hex.EncodeToString([]byte(essid))

	if ex.m1 != nil {
		if pmkid, ok := rsnPMKID(ex.m1.keyData); ok {
			out = append(out, fmt.Sprintf("WPA*01*%s*%s*%s*%s***",
				hex.EncodeToString(pmkid), macHex(ex.ap), macHex(ex.sta), essidHex))
		}
	}

	// The MIC comes from a client message and the AP's nonce from an AP
	// message. M1+M2 and M3+M4 are the natural pairs; the crossed pairs are
	// used only when the natural partner was not captured, because when
	// both are present they carry the same nonce and the same MIC and a
	// second record would double the work for nothing.
	for _, pair := range []struct {
		apMsg, staMsg *eapolKey
		code          string
		onlyIf        bool
	}{
		{ex.m1, ex.m2, wpaPairM1M2, true},
		{ex.m3, ex.m4, wpaPairM3M4, true},
		{ex.m3, ex.m2, wpaPairM2M3, ex.m1 == nil},
		{ex.m1, ex.m4, wpaPairM1M4, ex.m3 == nil},
	} {
		if !pair.onlyIf || pair.apMsg == nil || pair.staMsg == nil {
			continue
		}
		if !wpaReplayMatches(pair.code, pair.apMsg.replay, pair.staMsg.replay) {
			continue
		}
		// The client's nonce is read back out of the frame the MIC
		// covers, so a frame whose nonce field is zero cannot produce a
		// working record. Message 4 is ALLOWED to leave it zero — the
		// standard does not require the SNonce there — and most clients
		// do, so most message-4 pairs are unusable and emitting them
		// would hand back records that cannot crack.
		if allZero(pair.staMsg.nonce) {
			continue
		}
		out = append(out, fmt.Sprintf("WPA*02*%s*%s*%s*%s*%s*%s*%s",
			hex.EncodeToString(pair.staMsg.mic), macHex(ex.ap), macHex(ex.sta),
			essidHex, hex.EncodeToString(pair.apMsg.nonce),
			hex.EncodeToString(wpaZeroMIC(pair.staMsg.raw)), pair.code))
	}
	return out
}

func allZero(b []byte) bool {
	for _, c := range b {
		if c != 0 {
			return false
		}
	}
	return true
}

// wpaReplayMatches checks the replay counters of a candidate pair.
//
// Within one exchange the AP sends message 1 and the client answers message 2
// with the SAME counter; the AP then sends message 3 with the counter raised
// by one and the client answers message 4 with that one. So M1+M2 and M3+M4
// want equal counters, and the cross pairs want a difference of one.
func wpaReplayMatches(code string, ap, sta uint64) bool {
	switch code {
	case wpaPairM1M2, wpaPairM3M4:
		return ap == sta
	case wpaPairM1M4:
		return sta == ap+1
	case wpaPairM2M3:
		return ap == sta+1
	}
	return false
}

// wpaZeroMIC returns the frame with its MIC field cleared, which is the state
// the MIC was computed over and the state the 22000 format records.
func wpaZeroMIC(frame []byte) []byte {
	out := append([]byte(nil), frame...)
	for i := eapolMICAt; i < eapolMICAt+16 && i < len(out); i++ {
		out[i] = 0
	}
	return out
}

func macHex(m [6]byte) string { return hex.EncodeToString(m[:]) }

func macString(m [6]byte) string {
	parts := make([]string, 6)
	for i, c := range m {
		parts[i] = fmt.Sprintf("%02x", c)
	}
	return strings.Join(parts, ":")
}
