package main

// Juniper NetScreen / SSG (ScreenOS):
//
//	<username>$<30-char scrambled>
//
// The stored value is MD5(username . ":Administration Tools:" . password),
// base64-packed (6 chars per 4 bytes) with six obfuscation characters "nrcstn"
// inserted at positions 0,6,12,17,23,29. Verification decodes the stored value
// back to the target MD5 and compares.

import (
	"crypto/md5"
	"errors"
	"strings"
)

const juniperB64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
const juniperAdm = ":Administration Tools:"

// juniperDecode turns the 30-char scrambled string into the 16-byte MD5 target.
func juniperDecode(h string) ([]byte, bool) {
	if len(h) != 30 {
		return nil, false
	}
	var u [24]byte
	copy(u[0:6], h[1:7])
	copy(u[5:11], h[7:13])
	copy(u[10:15], h[13:18])
	copy(u[14:20], h[18:24])
	copy(u[19:24], h[24:29])

	val := func(c byte) (uint32, bool) {
		i := strings.IndexByte(juniperB64, c)
		if i < 0 {
			return 0, false
		}
		return uint32(i), true
	}
	out := make([]byte, 16)
	for i := 0; i < 4; i++ {
		var v [6]uint32
		for k := 0; k < 6; k++ {
			x, ok := val(u[6*i+k])
			if !ok {
				return nil, false
			}
			v[k] = x
		}
		x := ((v[0] << 12) | (v[1] << 6) | v[2]) & 0xffff
		y := ((v[3] << 12) | (v[4] << 6) | v[5]) & 0xffff
		w := (x << 16) | y
		out[4*i] = byte(w >> 24)
		out[4*i+1] = byte(w >> 16)
		out[4*i+2] = byte(w >> 8)
		out[4*i+3] = byte(w)
	}
	return out, true
}

func verifyJuniper(targetHash, candidate string) (bool, error) {
	i := strings.IndexByte(targetHash, '$')
	if i < 0 {
		return false, errors.New("invalid Juniper hash (need user$hash)")
	}
	user := targetHash[:i]
	target, ok := juniperDecode(targetHash[i+1:])
	if !ok {
		return false, errors.New("invalid Juniper hash body")
	}
	got := md5.Sum([]byte(user + juniperAdm + candidate))
	return bytesEqualCT(got[:], target), nil
}

// isJuniper: <user>$<30 base64 chars> with "nrcstn" at positions 0,6,12,17,23,29.
func isJuniper(s string) bool {
	i := strings.IndexByte(s, '$')
	if i < 0 {
		return false
	}
	h := s[i+1:]
	if len(h) != 30 {
		return false
	}
	const obf = "nrcstn"
	pos := []int{0, 6, 12, 17, 23, 29}
	for k, p := range pos {
		if h[p] != obf[k] {
			return false
		}
	}
	for j := 0; j < 30; j++ {
		if strings.IndexByte(juniperB64, h[j]) < 0 {
			return false
		}
	}
	return true
}
