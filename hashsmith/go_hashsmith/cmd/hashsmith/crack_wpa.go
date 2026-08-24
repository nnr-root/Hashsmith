package main

// WPA/WPA2 personal (PSK) cracking — both capture types:
//
//   PMKID : a single frame from the AP is enough. The AP leaks
//           PMKID = HMAC-SHA1(PMK, "PMK Name" || AP_MAC || STA_MAC)[:16].
//   EAPOL : the 4-way-handshake MIC. PMK feeds a PRF to derive the KCK, which
//           keys the MIC over the EAPOL-Key frame (HMAC-MD5 / HMAC-SHA1 /
//           AES-CMAC depending on the key-descriptor version).
//
// In both cases PMK = PBKDF2-HMAC-SHA1(passphrase, ESSID, 4096, 32).
//
// Accepted formats:
//
//	WPA*01*<pmkid>*<ap_mac>*<sta_mac>*<essid_hex>*...            (22000 PMKID)
//	WPA*02*<mic>*<ap_mac>*<sta_mac>*<essid_hex>*<anonce>*<eapol>*<mp>  (22000 EAPOL)
//	<pmkid>*<ap_mac>*<sta_mac>*<essid_hex>                        (legacy 16800 PMKID)

import (
	"crypto/aes"
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha1"
	"encoding/hex"
	"errors"
	"hash"
	"strings"

	"golang.org/x/crypto/pbkdf2"
)

// wpaHash holds the parsed material for one WPA target.
type wpaHash struct {
	isPMKID bool
	digest  []byte // PMKID (16) or MIC (16)
	apMAC   []byte // 6 bytes
	staMAC  []byte // 6 bytes
	essid   []byte // raw SSID bytes (PBKDF2 salt)
	anonce  []byte // 32 bytes (EAPOL only)
	snonce  []byte // 32 bytes (EAPOL only)
	eapol   []byte // EAPOL-Key frame with MIC zeroed (EAPOL only)
	keyVer  int    // 1=HMAC-MD5, 2=HMAC-SHA1, 3=AES-CMAC
}

// parseWPAHash decodes a 22000 or legacy-16800 WPA line.
func parseWPAHash(target string) (*wpaHash, error) {
	t := strings.TrimSpace(target)
	f := strings.Split(t, "*")

	// Legacy 16800 PMKID: pmkid*ap*sta*essid
	if !strings.HasPrefix(t, "WPA*") && len(f) == 4 {
		return buildPMKID(f[0], f[1], f[2], f[3])
	}

	if len(f) < 6 || f[0] != "WPA" {
		return nil, errors.New("invalid WPA hash (want WPA*01*… or WPA*02*…)")
	}
	switch f[1] {
	case "01":
		return buildPMKID(f[2], f[3], f[4], f[5])
	case "02":
		if len(f) < 9 {
			return nil, errors.New("invalid WPA EAPOL hash (need mic*ap*sta*essid*anonce*eapol*mp)")
		}
		return buildEAPOL(f[2], f[3], f[4], f[5], f[6], f[7])
	}
	return nil, errors.New("unknown WPA hash type " + f[1] + " (want 01 or 02)")
}

func buildPMKID(pmkid, ap, sta, essid string) (*wpaHash, error) {
	d, err := hex.DecodeString(pmkid)
	if err != nil || len(d) != 16 {
		return nil, errors.New("invalid PMKID (need 32 hex chars)")
	}
	apb, err := hex.DecodeString(ap)
	if err != nil || len(apb) != 6 {
		return nil, errors.New("invalid AP MAC")
	}
	stab, err := hex.DecodeString(sta)
	if err != nil || len(stab) != 6 {
		return nil, errors.New("invalid STA MAC")
	}
	essidb, err := hex.DecodeString(essid)
	if err != nil {
		return nil, errors.New("invalid ESSID (must be hex-encoded)")
	}
	return &wpaHash{isPMKID: true, digest: d, apMAC: apb, staMAC: stab, essid: essidb}, nil
}

func buildEAPOL(mic, ap, sta, essid, anonce, eapol string) (*wpaHash, error) {
	d, err := hex.DecodeString(mic)
	if err != nil || len(d) != 16 {
		return nil, errors.New("invalid MIC (need 32 hex chars)")
	}
	apb, err := hex.DecodeString(ap)
	if err != nil || len(apb) != 6 {
		return nil, errors.New("invalid AP MAC")
	}
	stab, err := hex.DecodeString(sta)
	if err != nil || len(stab) != 6 {
		return nil, errors.New("invalid STA MAC")
	}
	essidb, err := hex.DecodeString(essid)
	if err != nil {
		return nil, errors.New("invalid ESSID (must be hex-encoded)")
	}
	anonceb, err := hex.DecodeString(anonce)
	if err != nil || len(anonceb) != 32 {
		return nil, errors.New("invalid ANONCE (need 64 hex chars)")
	}
	eapolb, err := hex.DecodeString(eapol)
	if err != nil || len(eapolb) < 99 {
		return nil, errors.New("invalid EAPOL frame")
	}
	// Key-descriptor version = low 3 bits of the 2-byte key-info field.
	keyInfo := int(eapolb[5])<<8 | int(eapolb[6])
	keyVer := keyInfo & 0x07
	// The MIC (offset 81, 16 bytes) must be zeroed before it is recomputed.
	frame := make([]byte, len(eapolb))
	copy(frame, eapolb)
	for i := 81; i < 97 && i < len(frame); i++ {
		frame[i] = 0
	}
	return &wpaHash{
		isPMKID: false, digest: d, apMAC: apb, staMAC: stab,
		essid: essidb, anonce: anonceb, snonce: frame[17:49], eapol: frame, keyVer: keyVer,
	}, nil
}

// isLegacyPMKID reports whether s is a bare "pmkid*ap*sta*essid" PMKID line.
func isLegacyPMKID(s string) bool {
	f := strings.Split(strings.TrimSpace(s), "*")
	if len(f) != 4 {
		return false
	}
	if len(f[0]) != 32 || len(f[1]) != 12 || len(f[2]) != 12 || len(f[3]) == 0 {
		return false
	}
	for _, part := range f {
		if _, err := hex.DecodeString(part); err != nil {
			return false
		}
	}
	return true
}

// wpaPMK derives the pairwise master key for a passphrase and ESSID.
func wpaPMK(passphrase string, essid []byte) []byte {
	return pbkdf2.Key([]byte(passphrase), essid, 4096, 32, sha1.New)
}

// verifyWPA checks a passphrase against a parsed WPA target.
func verifyWPA(targetHash, candidate string) (bool, error) {
	w, err := parseWPAHash(targetHash)
	if err != nil {
		return false, err
	}
	return verifyWPAWithPMK(w, wpaPMK(candidate, w.essid))
}

// verifyWPAWithPMK checks a parsed WPA record using an already-derived PMK.
// Hashcat's raw-PMK modes use this path directly; password modes first derive
// the PMK with PBKDF2-HMAC-SHA1 in verifyWPA.
func verifyWPAWithPMK(w *wpaHash, pmk []byte) (bool, error) {
	if len(pmk) != 32 {
		return false, errors.New("invalid WPA PMK (need 32 bytes)")
	}
	if w.isPMKID {
		mac := hmac.New(sha1.New, pmk)
		mac.Write([]byte("PMK Name"))
		mac.Write(w.apMAC)
		mac.Write(w.staMAC)
		return hmac.Equal(mac.Sum(nil)[:16], w.digest), nil
	}

	// EAPOL: derive the KCK via the pairwise-key-expansion PRF, then MIC it.
	data := make([]byte, 0, 76)
	data = append(data, minMax(w.apMAC, w.staMAC)...)
	data = append(data, minMax(w.anonce, w.snonce)...)
	kck := wpaPRF(pmk, []byte("Pairwise key expansion"), data)[:16]

	var mic []byte
	switch w.keyVer {
	case 1:
		mic = wpaHMAC(md5.New, kck, w.eapol)
	case 2:
		mic = wpaHMAC(sha1.New, kck, w.eapol)
	case 3:
		m, err := aesCMAC(kck, w.eapol)
		if err != nil {
			return false, err
		}
		mic = m[:16]
	default:
		return false, errors.New("unsupported EAPOL key-descriptor version")
	}
	return hmac.Equal(mic, w.digest), nil
}

// wpaHMAC returns the first 16 bytes of HMAC(newHash, key, msg).
func wpaHMAC(newHash func() hash.Hash, key, msg []byte) []byte {
	m := hmac.New(newHash, key)
	m.Write(msg)
	return m.Sum(nil)[:16]
}

// minMax returns min(a,b) concatenated with max(a,b) (byte-wise comparison),
// as used when ordering the MAC and nonce pairs for the PRF input.
func minMax(a, b []byte) []byte {
	out := make([]byte, 0, len(a)+len(b))
	if bytesLess(a, b) {
		out = append(out, a...)
		out = append(out, b...)
	} else {
		out = append(out, b...)
		out = append(out, a...)
	}
	return out
}

func bytesLess(a, b []byte) bool {
	for i := 0; i < len(a) && i < len(b); i++ {
		if a[i] != b[i] {
			return a[i] < b[i]
		}
	}
	return len(a) < len(b)
}

// wpaPRF is the IEEE 802.11 PRF-n used to expand the PMK into the PTK. For each
// counter i it appends HMAC-SHA1(key, label || 0x00 || data || i).
func wpaPRF(key, label, data []byte) []byte {
	var out []byte
	for i := byte(0); len(out) < 64; i++ {
		mac := hmac.New(sha1.New, key)
		mac.Write(label)
		mac.Write([]byte{0x00})
		mac.Write(data)
		mac.Write([]byte{i})
		out = append(out, mac.Sum(nil)...)
	}
	return out[:64]
}

// ── AES-CMAC (RFC 4493), used by EAPOL key-descriptor version 3 (802.11w) ──

func aesCMAC(key, msg []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	const bs = aes.BlockSize
	// Subkey generation.
	l := make([]byte, bs)
	block.Encrypt(l, l)
	k1 := cmacShift(l)
	k2 := cmacShift(k1)

	n := (len(msg) + bs - 1) / bs
	lastComplete := false
	if n == 0 {
		n = 1
	} else if len(msg)%bs == 0 {
		lastComplete = true
	}

	last := make([]byte, bs)
	if lastComplete {
		xor(last, msg[(n-1)*bs:], k1)
	} else {
		rem := msg[(n-1)*bs:]
		padded := make([]byte, bs)
		copy(padded, rem)
		padded[len(rem)] = 0x80
		xor(last, padded, k2)
	}

	x := make([]byte, bs)
	for i := 0; i < n-1; i++ {
		y := make([]byte, bs)
		xor(y, x, msg[i*bs:(i+1)*bs])
		block.Encrypt(x, y)
	}
	y := make([]byte, bs)
	xor(y, x, last)
	out := make([]byte, bs)
	block.Encrypt(out, y)
	return out, nil
}

// cmacShift left-shifts a block by one bit and conditionally XORs the Rb
// constant, per the CMAC subkey schedule.
func cmacShift(in []byte) []byte {
	out := make([]byte, len(in))
	var carry byte
	for i := len(in) - 1; i >= 0; i-- {
		out[i] = in[i]<<1 | carry
		carry = in[i] >> 7
	}
	if in[0]&0x80 != 0 {
		out[len(out)-1] ^= 0x87
	}
	return out
}

func xor(dst, a, b []byte) {
	for i := range dst {
		dst[i] = a[i] ^ b[i]
	}
}
