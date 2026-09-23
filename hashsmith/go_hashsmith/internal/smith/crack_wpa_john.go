package smith

// John's WPA capture record, which is a struct rather than a list of fields.
//
//	$WPAPSK$<essid>#<356 bytes, base64>
//
// Where hashcat writes the handshake as named fields joined by stars, John
// encodes the hccap structure the older conversion tools produced — the two
// MAC addresses, the two nonces, the EAPOL frame and its length, the key
// version, and the MIC — and base64s it whole. The network name is outside
// the blob because the struct's first member is a 36-byte name field the
// encoding skips.
//
// Two things about that encoding are worth stating, because both were wrong
// on the first reading and neither announces itself:
//
//   - The alphabet is crypt(3)'s "./0-9A-Za-z", but the bits are packed the
//     ordinary way round — most significant character first — not crypt's
//     little end first. The little-endian reading also decodes to 356 bytes
//     and even yields plausible-looking MAC addresses, so the thing that
//     settles it is that only one of them puts a valid 802.1X header where
//     the structure says the EAPOL frame begins.
//   - The nonces are stored in the order the client and the access point
//     sent them, so the ANONCE hashcat's record names is the SECOND one. The
//     first is the station's, which also appears inside the EAPOL frame.

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"strconv"
	"strings"
)

const (
	wpapskPrefix = "$WPAPSK$"
	// The encoded part of the structure: everything after its name field.
	wpapskBlobSize  = 356
	wpapskEapolSize = 256
)

// johnWPAPSKRecord reads that record as the hc22000 line hashcat writes.
func johnWPAPSKRecord(target string) (string, bool) {
	t := strings.TrimSpace(target)
	if len(t) < len(wpapskPrefix) || !strings.EqualFold(t[:len(wpapskPrefix)], wpapskPrefix) {
		return "", false
	}
	essid, blob, ok := strings.Cut(t[len(wpapskPrefix):], "#")
	if !ok || essid == "" || len(essid) > 32 {
		return "", false
	}
	// John may append its own metadata after the blob; the structure ends
	// where the base64 does.
	if i := strings.IndexByte(blob, ':'); i >= 0 {
		blob = blob[:i]
	}
	d := decodeCrypt64BE(blob)
	if len(d) != wpapskBlobSize {
		return "", false
	}
	var (
		ap     = d[0:6]
		sta    = d[6:12]
		anonce = d[44:76]
		eapol  = d[76 : 76+wpapskEapolSize]
		size   = binary.LittleEndian.Uint32(d[332:336])
		keyver = binary.LittleEndian.Uint32(d[336:340])
		mic    = d[340:356]
	)
	if size < 1 || int(size) > wpapskEapolSize || keyver < 1 || keyver > 3 {
		return "", false
	}
	return "WPA*02*" + hex.EncodeToString(mic) +
		"*" + hex.EncodeToString(ap) +
		"*" + hex.EncodeToString(sta) +
		"*" + hex.EncodeToString([]byte(essid)) +
		"*" + hex.EncodeToString(anonce) +
		"*" + hex.EncodeToString(eapol[:size]) +
		"*" + strconv.Itoa(int(keyver)), true
}

// decodeCrypt64BE decodes crypt(3)'s alphabet with the bits packed most
// significant character first. A trailing group shorter than four characters
// carries the bytes it has room for.
func decodeCrypt64BE(s string) []byte {
	out := make([]byte, 0, len(s)*3/4)
	for i := 0; i < len(s); i += 4 {
		n := len(s) - i
		if n > 4 {
			n = 4
		}
		var v uint32
		for j := 0; j < n; j++ {
			k := strings.IndexByte(itoa64, s[i+j])
			if k < 0 {
				return nil
			}
			v = v<<6 | uint32(k)
		}
		v <<= uint(6 * (4 - n))
		for b := 0; b < n*6/8; b++ {
			out = append(out, byte(v>>(8*(2-b))))
		}
	}
	return out
}

func isJohnWPAPSK(target string) bool {
	_, ok := johnWPAPSKRecord(target)
	return ok
}

// johnWPAPSKError explains a record whose prefix matches but whose body does
// not, so that a truncated paste is not silently ignored.
func johnWPAPSKError(target string) error {
	if strings.HasPrefix(strings.TrimSpace(target), wpapskPrefix) && !isJohnWPAPSK(target) {
		return errors.New("this $WPAPSK$ record's encoded handshake did not decode to " +
			strconv.Itoa(wpapskBlobSize) + " bytes")
	}
	return nil
}
