package smith

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"strings"
	"testing"
)

// The three frames below are REAL, taken byte for byte from the Wireshark
// project's wpa-Induction.pcap sample: a beacon naming "Coherer" and the first
// two messages of a four-way handshake whose passphrase is "Induction".
//
// They are embedded rather than the capture being shipped, because what has to
// be tested is the framing and the handshake pairing, not the container — and
// the container is built here in three shapes so the test covers all of them.
// The MIC is genuine, so a record that cracks here is a record that would have
// cracked from the original file.

const cohererBeacon = "80000000ffffffffffff000c4182b255000c4182b25550f889f1d41b0100000064001104" +
	"0007436f6865726572010882848b962430486c0301010504000100002a01022f01023018" +
	"0100000fac020200000fac04000fac020100000fac02000032040c121860dd0600101802" +
	"0004dd1c0050f20101000050f20202000050f2040050f20201000050f20200009f61c95c"

const cohererM1 = "08022c00000d9382363a000c4182b255000c4182b255b0fcaaaa03000000888e02030075" +
	"02008a001000000000000000003e8e967dacd960324cac5b6aa721235bf57b949771c867" +
	"989f49d04ed47c6933000000000000000000000000000000000000000000000000000000" +
	"0000000000000000000000000000000000000000000016dd14000fac04592da88096c461" +
	"da246c69001e877f3db7084b70"

const cohererM2 = "08012c00000c4182b255000d9382363a000c4182b2559001aaaa03000000888e02030075" +
	"02010a00100000000000000000cdf405ceb9d889ef3dec42609828fae546b7add7baecbb" +
	"1a394eac5214b1d386000000000000000000000000000000000000000000000000000000" +
	"0000000000a462a7029ad5ba30b6af0df391988e45001630140100000fac020100000fac" +
	"040100000fac0200008a0b2ef7"

// pcapOf wraps 802.11 frames in a classic libpcap file with a radiotap header
// in front of each, which is what a wireless capture actually looks like.
func pcapOf(t *testing.T, linkType uint32, radiotap bool, frames ...string) []byte {
	t.Helper()
	var out bytes.Buffer
	header := make([]byte, 24)
	copy(header, []byte{0xd4, 0xc3, 0xb2, 0xa1})
	binary.LittleEndian.PutUint16(header[4:], 2)
	binary.LittleEndian.PutUint16(header[6:], 4)
	binary.LittleEndian.PutUint32(header[16:], 65535)
	binary.LittleEndian.PutUint32(header[20:], linkType)
	out.Write(header)

	for _, f := range frames {
		body, err := hex.DecodeString(f)
		if err != nil {
			t.Fatalf("bad frame hex: %v", err)
		}
		if radiotap {
			rt := make([]byte, 18)
			binary.LittleEndian.PutUint16(rt[2:], uint16(len(rt)))
			body = append(rt, body...)
		}
		rec := make([]byte, 16)
		binary.LittleEndian.PutUint32(rec[8:], uint32(len(body)))
		binary.LittleEndian.PutUint32(rec[12:], uint32(len(body)))
		out.Write(rec)
		out.Write(body)
	}
	return out.Bytes()
}

func TestExtractWPAPCAPRoundTrip(t *testing.T) {
	file := pcapOf(t, linkTypeRadiotap, true, cohererBeacon, cohererM1, cohererM2)
	got, err := extractWPAPCAPRecords(writeFixture(t, "capture.pcap", file))
	if err != nil {
		t.Fatalf("extractWPAPCAPRecords: %v", err)
	}

	var eapol, pmkid string
	for _, r := range got {
		switch {
		case strings.HasPrefix(r, "WPA*02*"):
			eapol = r
		case strings.HasPrefix(r, "WPA*01*"):
			pmkid = r
		}
	}
	if eapol == "" {
		t.Fatalf("no EAPOL record came out: %v", got)
	}
	// "Coherer" is the ESSID, and it is the PBKDF2 salt, so a record that
	// carries the wrong one cannot crack no matter what else is right.
	if !strings.Contains(eapol, "*"+hex.EncodeToString([]byte("Coherer"))+"*") {
		t.Errorf("the ESSID did not reach the record: %s", eapol)
	}
	// The AP is the BSSID from the beacon, not the client.
	if !strings.Contains(eapol, "*000c4182b255*000d9382363a*") {
		t.Errorf("the AP and client are not the ones the beacon names: %s", eapol)
	}
	mustCrack(t, "wpa", eapol, "Induction")

	// The capture also carries a PMKID element. It is emitted because a
	// cracker should try it; it does not crack with this passphrase,
	// because the PMKID an AP offers may come from a cached PMK rather
	// than from the pre-shared key. See the note in extract_wpapcap.go.
	if pmkid == "" {
		t.Error("the PMKID element in message 1 was not emitted")
	}
}

// Message 4 carries a zeroed nonce in almost every capture, and the client's
// nonce is read back out of the frame the MIC covers — so a record built from
// message 4 could never crack and must not be offered.
func TestExtractWPAPCAPSkipsMessageFourWithNoNonce(t *testing.T) {
	file := pcapOf(t, linkTypeRadiotap, true, cohererBeacon, cohererM1, cohererM2)
	got, err := extractWPAPCAPRecords(writeFixture(t, "capture.pcap", file))
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range got {
		if strings.HasSuffix(r, "*01") || strings.HasSuffix(r, "*03") {
			t.Errorf("a message-4 pair was emitted: %s", r)
		}
	}
}

// Without a beacon there is no ESSID, and the ESSID is the salt. Saying so
// beats emitting a record with an empty salt that can never crack.
func TestExtractWPAPCAPNeedsTheESSID(t *testing.T) {
	file := pcapOf(t, linkTypeRadiotap, true, cohererM1, cohererM2)
	_, err := extractWPAPCAPRecords(writeFixture(t, "nobeacon.pcap", file))
	if err == nil || !strings.Contains(err.Error(), "ESSID is the salt") {
		t.Fatalf("a capture with no beacon should say what is missing, got %v", err)
	}
}

// A capture taken on a wired interface cannot hold a handshake, and the reason
// is worth naming rather than reporting as "nothing found".
func TestExtractWPAPCAPNamesAWiredCapture(t *testing.T) {
	file := pcapOf(t, linkTypeEthernet, false, strings.Repeat("00", 60))
	_, err := extractWPAPCAPRecords(writeFixture(t, "wired.pcap", file))
	if err == nil || !strings.Contains(err.Error(), "wired interface") {
		t.Fatalf("a wired capture should be named as such, got %v", err)
	}
}

// The same frames in a bare 802.11 capture, with no radio header at all, must
// give the same records: the radio header is the capture driver's, not the
// protocol's.
func TestExtractWPAPCAPWithoutARadioHeader(t *testing.T) {
	withRT := pcapOf(t, linkTypeRadiotap, true, cohererBeacon, cohererM1, cohererM2)
	bare := pcapOf(t, linkTypeIEEE80211, false, cohererBeacon, cohererM1, cohererM2)

	a, err := extractWPAPCAPRecords(writeFixture(t, "rt.pcap", withRT))
	if err != nil {
		t.Fatal(err)
	}
	b, err := extractWPAPCAPRecords(writeFixture(t, "bare.pcap", bare))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(a, "\n") != strings.Join(b, "\n") {
		t.Errorf("the radio header changed the records:\n%v\nvs\n%v", a, b)
	}
}
