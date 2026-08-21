package main

import (
	"encoding/hex"
	"strings"
	"testing"
)

func TestExtendedCodecRoundTrips(t *testing.T) {
	const input = "Hashsmith 2026 — codecs"
	for _, typ := range []string{
		"base32crockford", "base58check", "base64-mime", "pem",
		"gzip", "zlib", "hex-escape", "rot5", "rot18",
	} {
		encoded, err := encodeText(input, typ, 3, "", 2)
		if err != nil {
			t.Errorf("encode %s: %v", typ, err)
			continue
		}
		decoded, err := decodeText(encoded, typ, 3, "", 2)
		if err != nil {
			t.Errorf("decode %s: %v", typ, err)
			continue
		}
		if decoded != input {
			t.Errorf("%s round trip: got %q, want %q", typ, decoded, input)
		}
	}
}

func TestCrockfordBase32Vectors(t *testing.T) {
	if got := encodeCrockford([]byte("foobar")); got != "CSQPYRK1E8" {
		t.Fatalf("Crockford foobar = %q", got)
	}
	got, err := decodeCrockford("csqp-yrkLe8") // L is accepted as 1.
	if err != nil || string(got) != "foobar" {
		t.Fatalf("Crockford tolerant decode = %q, %v", got, err)
	}
	got, err = decodeCrockford("OO") // O is accepted as 0.
	if err != nil || len(got) != 1 || got[0] != 0 {
		t.Fatalf("Crockford O alias = %x, %v", got, err)
	}
	if _, err := decodeCrockford("1"); err == nil {
		t.Fatal("Crockford decoder accepted non-zero trailing bits")
	}
}

func TestBase58CheckBitcoinVector(t *testing.T) {
	payload, err := hex.DecodeString("00010966776006953D5567439E5E39F86A0D273BEE")
	if err != nil {
		t.Fatal(err)
	}
	const want = "16UwLL9Risc3QfPqBUvKofHmBQ7wMtjvM"
	if got := encodeBase58Check(payload); got != want {
		t.Fatalf("Base58Check vector = %q, want %q", got, want)
	}
	got, err := decodeBase58Check(want)
	if err != nil || !bytesEqualCT(got, payload) {
		t.Fatalf("Base58Check decode = %x, %v", got, err)
	}
	if _, err := decodeBase58Check(want[:len(want)-1] + "N"); err == nil {
		t.Fatal("Base58Check decoder accepted a bad checksum")
	}
}

func TestMIMEBase64Wrapping(t *testing.T) {
	input := strings.Repeat("Hashsmith", 40)
	encoded := encodeMIMEBase64([]byte(input))
	for _, line := range strings.Split(encoded, "\r\n") {
		if len(line) > 76 {
			t.Fatalf("MIME Base64 line has %d columns", len(line))
		}
	}
	decoded, err := decodeText(encoded, "base64-mime", 0, "", 0)
	if err != nil || decoded != input {
		t.Fatalf("MIME Base64 round trip failed: %v", err)
	}
}

func TestExtendedCodecRejectsMalformedInput(t *testing.T) {
	for _, tc := range []struct {
		typ, value string
	}{
		{"gzip", "bm90LWd6aXA="},
		{"zlib", "bm90LXpsaWI="},
		{"hex-escape", `\x4g`},
		{"pem", "-----BEGIN DATA-----\n%%%%\n-----END DATA-----"},
	} {
		if _, err := decodeText(tc.value, tc.typ, 0, "", 0); err == nil {
			t.Errorf("%s accepted malformed input", tc.typ)
		}
	}
}

func TestExtendedCodecIdentification(t *testing.T) {
	gzipText, err := encodeText("compressed payload", "gzip", 0, "", 0)
	if err != nil {
		t.Fatal(err)
	}
	zlibText, err := encodeText("compressed payload", "zlib", 0, "", 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		value, marker string
	}{
		{encodePEM([]byte("payload")), "PEM"},
		{encodeBase58Check([]byte("payload")), "Base58Check"},
		{encodeCrockford([]byte("foobar")), "Crockford Base32"},
		{gzipText, "Gzip + Base64"},
		{zlibText, "Zlib + Base64"},
		{encodeHexEscape([]byte("bytes")), "C-style Hex Escapes"},
	} {
		if got := identifyText(tc.value); !strings.Contains(got, tc.marker) {
			t.Errorf("identifyText(%q) = %q; missing %q", tc.value, got, tc.marker)
		}
	}
}

func TestBase58CheckHashNormalization(t *testing.T) {
	raw, err := hex.DecodeString("ed1a4cb602d450909991fa0ee6bad099")
	if err != nil {
		t.Fatal(err)
	}
	encoded := encodeBase58Check(raw)
	got, format := normalizeHashInput(encoded)
	if got != hex.EncodeToString(raw) || format != "Base58Check" {
		t.Fatalf("normalizeHashInput(%q) = %q, %q", encoded, got, format)
	}
}
