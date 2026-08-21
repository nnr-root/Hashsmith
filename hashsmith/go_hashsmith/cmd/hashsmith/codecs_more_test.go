package main

import (
	"strings"
	"testing"
)

func TestBubbleBabbleVectors(t *testing.T) {
	vectors := []struct {
		plain, encoded string
	}{
		{"", "xexax"},
		{"Pineapple", "xigak-nyryk-humil-bosek-sonax"},
		{"1234567890", "xesef-disof-gytuf-katof-movif-baxux"},
	}
	for _, tc := range vectors {
		if got := encodeBubbleBabble([]byte(tc.plain)); got != tc.encoded {
			t.Errorf("Bubble Babble encode %q = %q, want %q", tc.plain, got, tc.encoded)
		}
		got, err := decodeBubbleBabble(tc.encoded)
		if err != nil || string(got) != tc.plain {
			t.Errorf("Bubble Babble decode %q = %q, %v", tc.encoded, got, err)
		}
		if identified := identifyText(tc.encoded); identified == "" || !strings.Contains(identified, "Bubble Babble") {
			t.Errorf("Bubble Babble identify %q = %q", tc.encoded, identified)
		}
	}
	if _, err := decodeBubbleBabble("xesef-disof-gytuf-katof-movif-baxix"); err == nil {
		t.Fatal("Bubble Babble accepted a damaged checksum")
	}
}

func TestBase58AlphabetVariants(t *testing.T) {
	vectors := []struct {
		name, alphabet, encoded string
	}{
		{"Flickr", flickrBase58Alphabet, "iXf12sRWto45bmC"},
		{"Ripple", rippleBase58Alphabet, "JxErpTiA7PhnBMd"},
	}
	for _, tc := range vectors {
		if got := encodeBase58WithAlphabet([]byte("Hello World"), tc.alphabet); got != tc.encoded {
			t.Errorf("%s Base58 = %q, want %q", tc.name, got, tc.encoded)
		}
		got, err := decodeBase58WithAlphabet(tc.encoded, tc.alphabet)
		if err != nil || string(got) != "Hello World" {
			t.Errorf("%s Base58 decode = %q, %v", tc.name, got, err)
		}
	}
}

func TestMoreCodecDispatchRoundTrips(t *testing.T) {
	for _, typ := range []string{"bubblebabble", "base58flickr", "base58ripple"} {
		encoded, err := encodeText("hashsmith", typ, 0, "", 2)
		if err != nil {
			t.Fatalf("encode %s: %v", typ, err)
		}
		decoded, err := decodeText(encoded, typ, 0, "", 2)
		if err != nil || decoded != "hashsmith" {
			t.Errorf("%s round trip = %q, %v", typ, decoded, err)
		}
	}
}
