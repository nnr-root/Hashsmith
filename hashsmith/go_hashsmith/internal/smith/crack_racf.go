package smith

// RACF (IBM z/OS security manager) — Hashcat 8500.
//
//	$racf$*<userid>*<16 hex digits>
//
// The same construction as AS/400 DES, and the reason hashcat runs both on one
// kernel: the userid becomes the DES block and the password becomes the DES
// key, both by way of EBCDIC, then sixteen rounds with the permutations moved
// onto the host. RACF caps the userid at eight characters, so it has none of
// the folding AS/400 needs for nine- and ten-character profile names.
//
// Real RACF folds the password to uppercase before hashing. This does not,
// because hashcat does not: its own published vector uses a lowercase
// password, and lowercasing here would make Hashsmith disagree with it. The
// practical consequence is only that a wordlist should be case-folded by a
// rule, which is how both tools already expect this to be handled.

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"strings"
)

const (
	racfPrefix       = "$racf$*"
	racfMaxUserID    = 8
	racfDigestHexLen = 16
)

// racfBlock turns a userid into the eight-byte EBCDIC DES block.
func racfBlock(userID string) ([8]byte, error) {
	if len(userID) == 0 || len(userID) > racfMaxUserID {
		return [8]byte{}, errors.New("RACF userid must be 1 to 8 characters")
	}
	var b [8]byte
	for i := range b {
		b[i] = as400ASCIIToEBCDIC[' ']
	}
	for i := 0; i < len(userID); i++ {
		b[i] = as400ASCIIToEBCDIC[userID[i]]
	}
	return b, nil
}

func verifyRACF(target, candidate string) (bool, error) {
	t := strings.TrimSpace(target)
	if !strings.HasPrefix(t, racfPrefix) {
		return false, errors.New("not a RACF record")
	}
	rest := strings.TrimPrefix(t, racfPrefix)
	i := strings.LastIndex(rest, "*")
	if i < 0 {
		return false, errors.New("RACF record must be $racf$*<userid>*<digest>")
	}
	userID, digestHex := rest[:i], rest[i+1:]
	if len(digestHex) != racfDigestHexLen {
		return false, errors.New("RACF digest must be 16 hex digits")
	}
	raw, err := hex.DecodeString(digestHex)
	if err != nil {
		return false, errors.New("RACF digest must be hex")
	}
	block, err := racfBlock(userID)
	if err != nil {
		return false, err
	}
	bl, br := as400HostPermute(
		binary.LittleEndian.Uint32(block[0:4]),
		binary.LittleEndian.Uint32(block[4:8]),
	)
	want0, want1 := as400HostPermute(
		binary.LittleEndian.Uint32(raw[0:4]),
		binary.LittleEndian.Uint32(raw[4:8]),
	)
	got := racfDigestWords(bl, br, candidate)
	return got[0] == want0 && got[1] == want1, nil
}
