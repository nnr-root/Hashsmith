package main

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"strings"
)

// hccapx is Hashcat's retired 393-byte WPA handshake container. Hashcat modes
// 2500 and 2501 still expose it for compatibility and encode their module
// self-test records as the hexadecimal bytes of one hccapx structure.
const hccapxSize = 393

func parseHCCAPX(target string) (*wpaHash, error) {
	raw, err := hex.DecodeString(strings.TrimSpace(target))
	if err != nil || len(raw) != hccapxSize {
		return nil, errors.New("invalid hccapx record (need 393 bytes as hex)")
	}
	if string(raw[:4]) != "HCPX" || binary.LittleEndian.Uint32(raw[4:8]) != 4 {
		return nil, errors.New("invalid hccapx signature or version")
	}
	essidLen := int(raw[9])
	if essidLen > 32 {
		return nil, errors.New("invalid hccapx ESSID length")
	}
	keyVer := int(raw[42])
	if keyVer < 1 || keyVer > 3 {
		return nil, errors.New("unsupported hccapx key version")
	}
	eapolLen := int(binary.LittleEndian.Uint16(raw[135:137]))
	if eapolLen < 1 || eapolLen > 255 {
		return nil, errors.New("invalid hccapx EAPOL length")
	}
	eapol := append([]byte(nil), raw[137:137+eapolLen]...)
	return &wpaHash{
		digest: append([]byte(nil), raw[43:59]...),
		apMAC:  append([]byte(nil), raw[59:65]...),
		anonce: append([]byte(nil), raw[65:97]...),
		staMAC: append([]byte(nil), raw[97:103]...),
		snonce: append([]byte(nil), raw[103:135]...),
		essid:  append([]byte(nil), raw[10:10+essidLen]...),
		eapol:  eapol,
		keyVer: keyVer,
	}, nil
}

func verifyHCCAPX(target, candidate string, candidateIsPMK bool) (bool, error) {
	w, err := parseHCCAPX(target)
	if err != nil {
		return false, err
	}
	var pmk []byte
	if candidateIsPMK {
		pmk, err = hex.DecodeString(candidate)
		if err != nil || len(pmk) != 32 {
			return false, nil
		}
	} else {
		if len(candidate) < 8 || len(candidate) > 63 {
			return false, nil
		}
		pmk = wpaPMK(candidate, w.essid)
	}
	return verifyWPAWithPMK(w, pmk)
}

func isHCCAPXHex(target string) bool {
	t := strings.TrimSpace(target)
	return len(t) == hccapxSize*2 && strings.HasPrefix(strings.ToUpper(t), "4843505804000000") && isHex(t)
}
