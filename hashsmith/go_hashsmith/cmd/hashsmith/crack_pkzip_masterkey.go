package main

// PKZIP master key — Hashcat 20500.
//
//	<12 bytes of key state, hex>
//
// ZipCrypto's whole secret is three 32-bit words, and its key schedule folds
// the password into them one byte at a time with no salt and no iteration
// count. So a "master key" record is just that final state, and checking a
// candidate means running the schedule and comparing — the cheapest verifier
// in the tool, and the reason this cipher has been indefensible since 1994.
//
// The state is written key0, key1, key2, each big-endian.
//
// Hashcat's companion mode 20510, "6 byte optimization", is NOT implemented
// and cannot be: it is a solver rather than a verifier. Given the candidate
// "t" against this same record, hashcat reports the plaintext "hashcat" —
// it treats the candidate as a prefix and recovers the remaining six bytes
// itself by inverting the key schedule. A verifier answers yes or no about
// the candidate it was given; that mode answers with a different string.

import (
	"crypto/subtle"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"strings"
)

const pkzipMasterKeyLen = 12

func parsePKZIPMasterKey(target string) ([]byte, error) {
	t := strings.TrimSpace(target)
	if len(t) != pkzipMasterKeyLen*2 || !isHex(t) {
		return nil, errors.New("PKZIP master key must be 24 hex characters")
	}
	return hex.DecodeString(t)
}

func verifyPKZIPMasterKey(target, candidate string) (bool, error) {
	want, err := parsePKZIPMasterKey(target)
	if err != nil {
		return false, err
	}
	s := newZipCryptoState(candidate)
	got := make([]byte, pkzipMasterKeyLen)
	binary.BigEndian.PutUint32(got[0:], s.k0)
	binary.BigEndian.PutUint32(got[4:], s.k1)
	binary.BigEndian.PutUint32(got[8:], s.k2)
	return subtle.ConstantTimeCompare(got, want) == 1, nil
}
