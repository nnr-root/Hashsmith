package main

import (
	"bytes"
	"compress/zlib"
	"crypto/sha1"
	"encoding/base64"
	"encoding/hex"
	"strings"
	"testing"
)

// ── Microsoft Money ──────────────────────────────────────────────────────────

// The Money fixture is built BACKWARDS from the record John ships: the record
// says what the unmasked header must contain, the mask says what the file must
// hold to produce it. So the extractor has to undo exactly the transformation
// the fixture applied, and a wrong mask offset or a wrong check position shows
// up immediately.
func TestExtractMoneyRoundTrip(t *testing.T) {
	record, password := johnVector(t, "money $money$")
	f := strings.Split(strings.TrimPrefix(record, "$money$"), "*")
	salt := mustHex(t, f[1])
	check := mustHex(t, f[2])

	header := make([]byte, moneyHeaderBytes)
	copy(header[moneySaltAt:], salt)
	// The check value's position depends on the first salt byte.
	copy(header[moneyCheckStart+int(salt[0]):], check)
	header[moneyFlagsAt] = moneyFlagNew | moneyFlagSHA1 // f[0] is "1"

	// Apply the mask, so the file is what Money would have written.
	mask := mustHex(t, moneyHeaderMask)
	for i, m := range mask {
		header[moneyMaskAt+i] ^= m
	}

	got, err := extractMoneyRecords(writeFixture(t, "money.mny", header))
	if err != nil {
		t.Fatalf("extractMoneyRecords: %v", err)
	}
	if len(got) != 1 || got[0] != record {
		t.Fatalf("\n got: %v\nwant: %s", got, record)
	}
	mustCrack(t, "money", got[0], password)
}

// A file whose flags say it is not encrypted has no password to find.
func TestExtractMoneyNamesAnUnencryptedFile(t *testing.T) {
	header := make([]byte, moneyHeaderBytes)
	mask := mustHex(t, moneyHeaderMask)
	for i, m := range mask {
		header[moneyMaskAt+i] ^= m
	}
	_, err := extractMoneyRecords(writeFixture(t, "plain.mny", header))
	if err == nil || !strings.Contains(err.Error(), "not encrypted") {
		t.Fatalf("expected a named refusal, got %v", err)
	}
}

// ── BitShares ────────────────────────────────────────────────────────────────

func TestExtractBitSharesLevelDB(t *testing.T) {
	// The field is 64 bytes of hex following the word and three bytes of
	// LevelDB's own framing.
	payload := strings.Repeat("ab", 64)
	blob := append([]byte("\x00\x01junkchecksum\x11\x22\x33"), []byte(payload)...)

	got, err := extractBitSharesRecords(writeFixture(t, "000003.ldb", blob))
	if err != nil {
		t.Fatalf("extractBitSharesRecords: %v", err)
	}
	if len(got) != 1 || got[0] != "$dynamic_84$"+payload {
		t.Fatalf("got %v", got)
	}
}

// A backup file's record wraps a secp256k1 key and nothing in it can say
// whether a password was right, so no record is written for it.
func TestExtractBitSharesRefusesTheBackupFile(t *testing.T) {
	_, err := extractBitSharesRecords(writeFixture(t, "wallet.bin", bytes.Repeat([]byte{0x42}, 512)))
	if err == nil || !strings.Contains(err.Error(), "secp256k1") {
		t.Fatalf("expected the backup shape to be named, got %v", err)
	}
	// And the verifier agrees: it declines a type 1 record by name rather
	// than answering it.
	if _, err := verifyBitShares("$BitShares$1*"+strings.Repeat("ab", 64), "x"); err == nil {
		t.Error("the verifier should decline a type 1 record")
	}
}

// ── PS_TOKEN ─────────────────────────────────────────────────────────────────

// psToken builds a cookie the way PeopleSoft does: a header, the SHA-1 of the
// compressed-out data at offset 44, and the DEFLATE stream from offset 76.
func psToken(t *testing.T, data []byte, mac []byte) string {
	t.Helper()
	var compressed bytes.Buffer
	zw := zlib.NewWriter(&compressed)
	if _, err := zw.Write(data); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	raw := make([]byte, psTokenDataAt+compressed.Len())
	copy(raw[psTokenMACAt:], mac)
	copy(raw[psTokenDataAt:], compressed.Bytes())
	return base64.StdEncoding.EncodeToString(raw)
}

func TestExtractPSToken(t *testing.T) {
	const password = "nodepass"
	data := []byte("\x71\x00\x00\x00\x04\x03\x02\x01PS_TOKEN payload for one node")
	// dynamic_1600 is sha1($s.utf16le($p)).
	sum := sha1.Sum(append(append([]byte(nil), data...), utf16le(password)...))

	file := "# tokens\n" + psToken(t, data, sum[:]) + "\n"
	got, err := extractPSTokenRecords(writeFixture(t, "tokens.txt", []byte(file)))
	if err != nil {
		t.Fatalf("extractPSTokenRecords: %v", err)
	}
	want := "$dynamic_1600$" + hex.EncodeToString(sum[:]) + "$HEX$" + hex.EncodeToString(data)
	if len(got) != 1 || got[0] != want {
		t.Fatalf("\n got: %v\nwant: %s", got, want)
	}
	// The salt is only reachable by DECOMPRESSING the cookie, so a reader
	// that carried the raw bytes across would fail here.
	mustCrack(t, "dynamic", got[0], password)
}

// A token whose MAC is the SHA-1 of its own data is signed with an empty key:
// that node has no password, and saying so beats emitting a record for it.
func TestExtractPSTokenNamesAnUnsignedNode(t *testing.T) {
	data := []byte("no password on this node")
	sum := sha1.Sum(data)
	file := psToken(t, data, sum[:]) + "\n"

	_, err := extractPSTokenRecords(writeFixture(t, "tokens.txt", []byte(file)))
	if err == nil || !strings.Contains(err.Error(), "empty key") {
		t.Fatalf("expected the unsigned case to be named, got %v", err)
	}
}
