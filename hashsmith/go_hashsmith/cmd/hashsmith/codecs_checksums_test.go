package main

import (
	"encoding/hex"
	"strings"
	"testing"
)

func TestZBase32Vectors(t *testing.T) {
	for _, tc := range []struct {
		plain, encoded string
	}{
		{"f", "ca"},
		{"fo", "c3zo"},
		{"foo", "c3zs6"},
		{"foob", "c3zs6ao"},
		{"fooba", "c3zs6aub"},
		{"foobar", "c3zs6aubqe"},
		{"hello", "pb1sa5dx"},
	} {
		if got := encodeZBase32([]byte(tc.plain)); got != tc.encoded {
			t.Errorf("z-base-32(%q) = %q, want %q", tc.plain, got, tc.encoded)
		}
		got, err := decodeZBase32(strings.ToUpper(tc.encoded))
		if err != nil || string(got) != tc.plain {
			t.Errorf("z-base-32 decode %q = %q, %v", tc.encoded, got, err)
		}
	}
	if _, err := decodeZBase32("c"); err == nil {
		t.Fatal("z-base-32 accepted non-zero trailing bits")
	}
}

func TestBech32PublishedChecksumVectors(t *testing.T) {
	data, hrp, err := decodeBech32("A12UEL5L", "", "bech32")
	if err != nil || hrp != "a" || len(data) != 0 {
		t.Fatalf("BIP-173 vector failed: data=%x hrp=%q err=%v", data, hrp, err)
	}
	if got, err := encodeBech32(nil, "a", "bech32"); err != nil || got != "a12uel5l" {
		t.Fatalf("BIP-173 encode = %q, %v", got, err)
	}
	data, hrp, err = decodeBech32("A1LQFN3A", "", "bech32m")
	if err != nil || hrp != "a" || len(data) != 0 {
		t.Fatalf("BIP-350 vector failed: data=%x hrp=%q err=%v", data, hrp, err)
	}
	if got, err := encodeBech32(nil, "a", "bech32m"); err != nil || got != "a1lqfn3a" {
		t.Fatalf("BIP-350 encode = %q, %v", got, err)
	}
}

func TestBech32CodecRoundTrips(t *testing.T) {
	const input = "Hashsmith checksums"
	for _, typ := range []string{"bech32", "bech32m"} {
		encoded, err := encodeText(input, typ, 0, "hs", 0)
		if err != nil {
			t.Fatalf("encode %s: %v", typ, err)
		}
		decoded, err := decodeText(encoded, typ, 0, "hs", 0)
		if err != nil || decoded != input {
			t.Errorf("%s round trip = %q, %v", typ, decoded, err)
		}
		if _, err := decodeText(encoded, typ, 0, "wrong", 0); err == nil {
			t.Errorf("%s accepted a mismatched HRP", typ)
		}
		last := encoded[len(encoded)-1]
		replacement := byte('q')
		if last == replacement {
			replacement = 'p'
		}
		if _, _, err := decodeBech32(encoded[:len(encoded)-1]+string(replacement), "", typ); err == nil {
			t.Errorf("%s accepted a bad checksum", typ)
		}
	}
	if _, _, err := decodeBech32("a12UEL5L", "", "bech32"); err == nil {
		t.Fatal("Bech32 accepted mixed case")
	}
}

func TestChecksummedCodecIdentification(t *testing.T) {
	for _, tc := range []struct {
		value, want string
	}{
		{"A12UEL5L", "Bech32"},
		{"A1LQFN3A", "Bech32m"},
		{encodeZBase32([]byte("foobar")), "z-base-32"},
	} {
		if got := identifyText(tc.value); !strings.Contains(got, tc.want) {
			t.Errorf("identifyText(%q) = %q; missing %q", tc.value, got, tc.want)
		}
	}
}

func TestChecksummedHashNormalization(t *testing.T) {
	raw, err := hex.DecodeString("ed1a4cb602d450909991fa0ee6bad099")
	if err != nil {
		t.Fatal(err)
	}
	bech, err := encodeBech32(raw, "hash", "bech32m")
	if err != nil {
		t.Fatal(err)
	}
	if got, format := normalizeHashInput(bech); got != hex.EncodeToString(raw) || format != "Bech32m" {
		t.Errorf("Bech32m normalization = %q, %q", got, format)
	}
	zbase := encodeZBase32(raw)
	if got, format := normalizeHashInput(zbase); got != hex.EncodeToString(raw) || format != "z-base-32" {
		t.Errorf("z-base-32 normalization = %q, %q", got, format)
	}
}
