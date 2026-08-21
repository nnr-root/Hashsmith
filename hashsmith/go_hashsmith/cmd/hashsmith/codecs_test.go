package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestCodecRoundTrips(t *testing.T) {
	cases := []struct {
		typ  string
		text string
	}{
		{"base64", "Hashsmith: hello, 世界"},
		{"base64raw", "Hashsmith: hello, 世界"},
		{"base64url", "Hashsmith: hello, 世界"},
		{"base64url-padded", "Hashsmith: hello, 世界"},
		{"base32", "Hashsmith: hello, 世界"},
		{"base32-nopad", "Hashsmith: hello, 世界"},
		{"base32hex", "Hashsmith: hello, 世界"},
		{"base36", "Hashsmith: hello, 世界"},
		{"base45", "Hashsmith: hello, 世界"},
		{"base58", "Hashsmith: hello, 世界"},
		{"base62", "Hashsmith: hello, 世界"},
		{"base85", "Hashsmith: hello, 世界"},
		{"adobe85", "Hashsmith: hello, 世界"},
		{"base91", "Hashsmith: hello, 世界"},
		{"quoted-printable", "Hashsmith: hello, 世界"},
		{"html-entities", "<tag attr=\"x\">Tom & Jerry</tag>"},
		{"json", "line 1\n\"quoted\"\\slash\t世界"},
		{"uu", "Hashsmith: hello, 世界"},
		{"hex", "Hashsmith: hello, 世界"},
		{"binary", "Hashsmith"},
		{"decimal", "Hashsmith"},
		{"octal", "Hashsmith"},
		{"url", "a value/with?reserved&chars=1"},
		{"url-form", "a value/with?reserved&chars=1"},
		{"rot47", "Hashsmith 2026!"},
		{"reverse", "Hashsmith 世界"},
		{"unicode", "Hashsmith 世界 😀"},
		{"utf16le", "Hashsmith 世界 😀"},
		{"utf16be", "Hashsmith 世界 😀"},
		{"utf32le", "Hashsmith 世界 😀"},
		{"utf32be", "Hashsmith 世界 😀"},
	}

	for _, tc := range cases {
		t.Run(tc.typ, func(t *testing.T) {
			encoded, err := encodeText(tc.text, tc.typ, 3, "key", 3)
			if err != nil {
				t.Fatalf("encodeText: %v", err)
			}
			decoded, err := decodeText(encoded, tc.typ, 3, "key", 3)
			if err != nil {
				t.Fatalf("decodeText(%q): %v", encoded, err)
			}
			if decoded != tc.text {
				t.Fatalf("round trip mismatch: got %q, want %q", decoded, tc.text)
			}
		})
	}
}

func TestCodecReferenceVectors(t *testing.T) {
	if got := encodeBase45([]byte("AB")); got != "BB8" {
		t.Errorf("Base45 RFC vector: got %q, want BB8", got)
	}
	if got := encodeBase45([]byte("Hello!!")); got != "%69 VD92EX0" {
		t.Errorf("Base45 RFC vector: got %q, want %%69 VD92EX0", got)
	}

	z85Input := []byte{0x86, 0x4f, 0xd2, 0x6f, 0xb5, 0x59, 0xf7, 0x5b}
	z85, err := encodeZ85(z85Input)
	if err != nil {
		t.Fatal(err)
	}
	if z85 != "HelloWorld" {
		t.Errorf("Z85 reference vector: got %q, want HelloWorld", z85)
	}
	z85Decoded, err := decodeZ85("HelloWorld")
	if err != nil || !bytes.Equal(z85Decoded, z85Input) {
		t.Errorf("Z85 decode vector: got %x, err=%v", z85Decoded, err)
	}

	if got := encodeBase91([]byte("Hello World!")); got != ">OwJh>Io0Tv!8PE" {
		t.Errorf("basE91 reference vector: got %q", got)
	}

	if got, _ := encodeText("AB", "utf16le", 0, "", 2); got != "41004200" {
		t.Errorf("UTF-16LE: got %q", got)
	}
	if got, _ := encodeText("😀", "unicode", 0, "", 2); got != "\\ud83d\\ude00" {
		t.Errorf("Unicode surrogate pair: got %q", got)
	}
}

func TestFlexibleBaseAndHexDecoding(t *testing.T) {
	cases := []struct {
		typ, encoded, want string
	}{
		{"base64", "aGFzaHNtaXRo", "hashsmith"},
		{"base64", "aGFz\naHNtaXRo", "hashsmith"},
		{"base32", "NBQXG2DTNVUXI2A", "hashsmith"},
		{"hex", "0x68:61:73:68-73 6d 69 74 68", "hashsmith"},
		{"base16", "68617368736d697468", "hashsmith"},
		{"ascii85", "BOu!rD]j7BEbo7", "hello world"},
	}
	for _, tc := range cases {
		got, err := decodeText(tc.encoded, tc.typ, 0, "", 2)
		if err != nil || got != tc.want {
			t.Errorf("decode %s: got %q, err=%v; want %q", tc.typ, got, err, tc.want)
		}
	}
}

func TestHumanReadableCodecVectors(t *testing.T) {
	for _, tc := range []struct {
		typ, plain, encoded, decoded string
	}{
		{"a1z26", "HELLO WORLD", "8-5-12-12-15 / 23-15-18-12-4", "HELLO WORLD"},
		{"rot47", "Hello!", "w6==@P", "Hello!"},
	} {
		got, err := encodeText(tc.plain, tc.typ, 3, "", 2)
		if err != nil || got != tc.encoded {
			t.Errorf("encode %s: got %q, err=%v", tc.typ, got, err)
		}
		back, err := decodeText(tc.encoded, tc.typ, 3, "", 2)
		if err != nil || back != tc.decoded {
			t.Errorf("decode %s: got %q, err=%v", tc.typ, back, err)
		}
	}
}

func TestNewCodecValidation(t *testing.T) {
	invalid := []struct{ typ, value string }{
		{"base45", "A"},
		{"z85", "abcd"},
		{"base91", "\x00"},
		{"utf16le", "00"},
		{"utf32be", "00110000"},
		{"unicode", "\\ud83d"},
		{"a1z26", "27"},
	}
	for _, tc := range invalid {
		if _, err := decodeText(tc.value, tc.typ, 0, "", 2); err == nil {
			t.Errorf("decode %s accepted invalid value %q", tc.typ, tc.value)
		}
	}
	if _, err := encodeText("short", "z85", 0, "", 2); err == nil || !strings.Contains(err.Error(), "multiple of 4") {
		t.Errorf("Z85 should reject a non-block-aligned input, got %v", err)
	}
}

func TestExpandedEncodingIdentification(t *testing.T) {
	for _, tc := range []struct {
		value, want string
	}{
		{"%69 VD92EX0", "Base45"},
		{"HelloWorld", "Z85"},
		{">OwJh>Io0Tv!8PE", "basE91"},
		{`line 1\n\"quoted\"`, "JSON String Escapes"},
	} {
		found := false
		for _, candidate := range scoreCandidates(tc.value) {
			if candidate.name == tc.want {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("identify %q omitted %s: %v", tc.value, tc.want, scoreCandidates(tc.value))
		}
	}
}

func TestExpandedHashEncodingNormalization(t *testing.T) {
	const md5Hex = "ed1a4cb602d450909991fa0ee6bad099"
	for _, tc := range []struct {
		encoded, format string
	}{
		{"7RpMtgLUUJCZkfoO5rrQmQ", "Base64"},
		{"5UNEZNQC2RIJBGMR7IHONOWQTE======", "Base32"},
		{"TKD4PDG2QH8916CHV87EDEMGJ4======", "Base32hex"},
	} {
		got, format := normalizeHashInput(tc.encoded)
		if got != md5Hex || format != tc.format {
			t.Errorf("normalizeHashInput(%q) = %q, %q; want %q, %q", tc.encoded, got, format, md5Hex, tc.format)
		}
	}
}
