package main

// mega.nz password-protected links — Hashcat 33400.
//
// A protected link is "P!" followed by a base64url blob that MEGA hands out in
// place of the usual key. Offsets, taken from the module's own parser:
//
//	[0]      algorithm, which must be 2 (PBKDF2-HMAC-SHA512, 100,000 rounds)
//	[1]      link type: 0 for a file, 1 for a folder
//	[8:40]   the PBKDF2 salt
//	[0:n]    the bytes covered by the MAC, n = 56 for a file, 72 for a folder
//	[n:n+32] the stored MAC
//
// The derived key is 64 bytes and is used in halves: the first decrypts the
// link's own key, the second is the HMAC-SHA256 key that authenticates it.
// Cracking only needs the second, so nothing is decrypted here — which is also
// why the bytes between the salt and the MAC can be, and in Hashcat's own
// example record are, filler.
//
// The MAC comparison is 16 bytes rather than all 32, matching the kernel. That
// is 2^-128 against a wrong password, and taking the whole tag would reject
// nothing a sane attack would ever produce.

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"errors"
	"strings"

	"golang.org/x/crypto/pbkdf2"
)

const (
	megaPrefix     = "P!"
	megaIterations = 100000
	megaSaltOffset = 8
	megaSaltLen    = 32
	// A file link authenticates 56 bytes and is 88 long; a folder link
	// authenticates 72 and is 104. Both carry a 32-byte MAC.
	megaFileMACOffset   = 56
	megaFolderMACOffset = 72
	megaMACLen          = 32
)

type megaLink struct {
	salt []byte
	data []byte
	mac  []byte
}

func parseMegaLink(target string) (*megaLink, error) {
	t := strings.TrimSpace(target)
	// Accept the full URL as well as the bare blob: what a user copies is a
	// link, and the fragment is the only part that carries anything.
	if i := strings.Index(t, "#"); i >= 0 {
		t = t[i+1:]
	}
	if !strings.HasPrefix(t, megaPrefix) {
		return nil, errors.New("not a mega.nz protected link (no \"P!\" prefix)")
	}
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(t[len(megaPrefix):], "="))
	if err != nil {
		return nil, errors.New("mega.nz link body is not valid base64url")
	}
	if len(raw) < 2 {
		return nil, errors.New("mega.nz link is too short")
	}
	if raw[0] != 2 {
		return nil, errors.New("unsupported mega.nz key-derivation algorithm")
	}
	macOffset := megaFileMACOffset
	switch raw[1] {
	case 0:
		macOffset = megaFileMACOffset
	case 1:
		macOffset = megaFolderMACOffset
	default:
		return nil, errors.New("unsupported mega.nz link type")
	}
	// The length is fixed by the type, so a blob of any other size is a
	// different thing wearing this prefix, not a link to guess at.
	if len(raw) != macOffset+megaMACLen {
		return nil, errors.New("mega.nz link has the wrong length for its type")
	}
	return &megaLink{
		salt: raw[megaSaltOffset : megaSaltOffset+megaSaltLen],
		data: raw[:macOffset],
		mac:  raw[macOffset:],
	}, nil
}

func verifyMegaLink(target, candidate string) (bool, error) {
	link, err := parseMegaLink(target)
	if err != nil {
		return false, err
	}
	derived := pbkdf2.Key([]byte(candidate), link.salt, megaIterations, 64, sha512.New)
	mac := hmac.New(sha256.New, derived[32:])
	_, _ = mac.Write(link.data)
	return bytes.Equal(mac.Sum(nil)[:16], link.mac[:16]), nil
}

// looksLikeMegaLink reports whether a string is a mega.nz protected link.
//
// "P!" alone is two characters and would match plenty of things that are not
// links, so the check goes as far as the structure allows: the body must be
// base64url, the algorithm byte must be the one Hashcat supports, and the
// length must be exactly what the link type implies. That is a full parse, so
// the detection claim is as strong as the format permits.
func looksLikeMegaLink(s string) bool {
	_, err := parseMegaLink(s)
	return err == nil
}
