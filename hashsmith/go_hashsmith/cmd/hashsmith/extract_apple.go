package main

// Apple artifacts: a macOS account's password material, and the STRIP
// password manager's store.

import (
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
)

// ── macOS local accounts ──────────────────────────────────────────────────────

func runExtractMacOS(args []string) error {
	return runFileRecordExtractor("mac2smith", args, extractMacOSRecords)
}

const (
	// macShadowKey is where 10.8 and later keep the password material, as a
	// plist inside a plist. Before that it was a flat file in /var/db/shadow
	// and the whole thing was easier to find and easier to steal.
	macShadowKey  = "ShadowHashData"
	macPBKDF2Key  = "SALTED-SHA512-PBKDF2"
	macEntropyHex = 128 // the first 64 bytes, which is what the check reads
)

// extractMacOSRecords reads a macOS account plist.
//
// The password material is a binary plist stored as a DATA VALUE inside the
// account's plist, under ShadowHashData — so the file has to be decoded, a
// value pulled out of it, and that value decoded as a plist in its own right.
// A scan for a magic string finds the inner plist's header and nothing that
// says where it ends.
//
// Both wrappings are accepted, because both are what a user actually has: the
// account plist as it sits on disk, and the inner plist alone, which is what
// `defaults read … ShadowHashData | xxd -r -p | plutil -convert xml1 -` gives
// on a machine where the outer file could not be read as root.
func extractMacOSRecords(path string) ([]string, error) {
	b, err := readExtractorFile(path)
	if err != nil {
		return nil, err
	}
	outer, err := plistParse(b)
	if err != nil {
		return nil, err
	}

	inner := outer
	if shadow, ok := outer.at(macShadowKey); ok {
		blob, ok := macShadowBlob(shadow)
		if !ok {
			return nil, errors.New("this account's ShadowHashData is not a data value")
		}
		if inner, err = plistParse(blob); err != nil {
			return nil, fmt.Errorf("reading the plist inside ShadowHashData: %w", err)
		}
	}

	entry, ok := inner.at(macPBKDF2Key)
	if !ok {
		return nil, errors.New("this plist carries no SALTED-SHA512-PBKDF2 entry; an account with only a legacy hash, or one with no password set, has none")
	}
	salt, okSalt := entry.at("salt")
	entropy, okEntropy := entry.at("entropy")
	iterations, okIter := entry.at("iterations")
	if !okSalt || !okEntropy || !okIter ||
		salt.kind != plistData || entropy.kind != plistData || iterations.kind != plistInt {
		return nil, errors.New("this account's SALTED-SHA512-PBKDF2 entry is missing its salt, entropy or iteration count")
	}
	if iterations.num < 1 || iterations.num > 1<<28 {
		return nil, fmt.Errorf("this account states %d iterations", iterations.num)
	}
	if len(salt.data) == 0 || len(entropy.data) < 64 {
		return nil, errors.New("this account's salt or entropy is too short to be real")
	}

	// macOS stores 128 bytes of entropy and the check reads the first 64.
	// Carrying all of it would make the record twice as long and no more
	// answerable.
	entropyHex := hex.EncodeToString(entropy.data)
	if len(entropyHex) > macEntropyHex {
		entropyHex = entropyHex[:macEntropyHex]
	}
	return []string{fmt.Sprintf("$pbkdf2-hmac-sha512$%d.%s.%s",
		iterations.num, hex.EncodeToString(salt.data), entropyHex)}, nil
}

// macShadowBlob reaches the data value. An account plist wraps it in a
// one-element array, which is how `dscl` writes a multi-valued attribute even
// when it holds one thing.
func macShadowBlob(v plistValue) ([]byte, bool) {
	switch v.kind {
	case plistData:
		return v.data, true
	case plistArray:
		for _, e := range v.arr {
			if e.kind == plistData {
				return e.data, true
			}
		}
	}
	return nil, false
}

// ── STRIP ─────────────────────────────────────────────────────────────────────

func runExtractSTRIP(args []string) error {
	return runFileRecordExtractor("strip2smith", args, extractSTRIPRecords)
}

// stripPageBytes is how much of the database the record carries: SQLCipher's
// first page, whose first sixteen bytes are the salt and whose remainder is
// enough structure to say whether a key was right.
const stripPageBytes = 1024

// extractSTRIPRecords reads an iPhone STRIP password manager database.
//
// There is no parsing to do: the record is the first page and nothing else.
// What makes the extractor worth having is that nothing about the file says it
// is one — a SQLCipher database has no header, by design, because a header
// would announce that the file is encrypted. The one thing that CAN be said is
// the opposite: a file starting with SQLite's own format string is not
// encrypted at all, and that is worth saying rather than handing back a record
// over a plaintext database.
func extractSTRIPRecords(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	page := make([]byte, stripPageBytes)
	if n, err := io.ReadFull(f, page); err != nil && n < stripPageBytes {
		return nil, errors.New("this file is shorter than one SQLCipher page")
	}
	if strings.HasPrefix(string(page), "SQLite format 3\x00") {
		return nil, errors.New("this is an unencrypted SQLite database, so there is no key to find")
	}
	return []string{"$strip$*" + hex.EncodeToString(page)}, nil
}
