package main

// iSCSI CHAP authentication (MD5):
//
//	<hash>:<challenge>:<id>
//	hash = md5( byte(id) . password . challenge )

import (
	"crypto/md5"
	"encoding/hex"
	"errors"
	"strconv"
	"strings"
)

func verifyChap(targetHash, candidate string) (bool, error) {
	f := strings.Split(targetHash, ":")
	if len(f) != 3 || len(f[0]) != 32 {
		return false, errors.New("invalid iSCSI CHAP hash (need md5:challenge:id)")
	}
	challenge, err := hex.DecodeString(f[1])
	if err != nil {
		return false, errors.New("invalid CHAP challenge")
	}
	id, err := strconv.ParseUint(f[2], 16, 16)
	if err != nil {
		return false, errors.New("invalid CHAP id")
	}
	h := md5.New()
	h.Write([]byte{byte(id)})
	h.Write([]byte(candidate))
	h.Write(challenge)
	return strings.EqualFold(hex.EncodeToString(h.Sum(nil)), f[0]), nil
}

// isChap: <32-hex md5>:<hex challenge>:<hex id>.
func isChap(s string) bool {
	f := strings.Split(s, ":")
	if len(f) != 3 || len(f[0]) != 32 || !isHex(f[0]) {
		return false
	}
	return isHex(f[1]) && f[1] != "" && isHex(f[2]) && f[2] != ""
}
