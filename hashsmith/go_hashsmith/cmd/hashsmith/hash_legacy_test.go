package main

import (
	"strings"
	"testing"
)

func TestLegacyAndRegionalHashVectors(t *testing.T) {
	cases := []struct {
		text, typ, want string
	}{
		{"", "md2", "8350e5a3e24c153df2275c9f80692773"},
		{"abc", "md2", "da853b0d3f88d99b30283a69e6ded6bb"},
		{"message digest", "md2", "ab4f496bfb2a530b219ff33031fe06b0"},
		{"abc", "sha0", "0164b8a914cd2a5e74c4f7ff082c4d97f1edf880"},
		{"abc", "sm3", "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0"},
		{strings.Repeat("abcd", 16), "sm3", "debe9ff92275b8a138604889c18e5a4d6fdb70e5387e5765293dcba39c0c5732"},
		{"", "xxhash32", "02cc5d05"},
		{"abc", "xxhash32", "32d153ff"},
		{"", "xxhash64", "ef46db3751d8e999"},
		{"abc", "xxhash64", "44bc2cf5ad770999"},
		{"abc", "murmur3-32", "b3dd93fa"},
	}
	for _, tc := range cases {
		got, err := hashText(tc.text, tc.typ, "", "prefix")
		if err != nil || got != tc.want {
			t.Errorf("%s(%q): got %q, err=%v; want %q", tc.typ, tc.text, got, err, tc.want)
		}
		ok, err := verifyCandidate(tc.text, tc.want, tc.typ, "", "prefix")
		if err != nil || !ok {
			t.Errorf("verify %s(%q): ok=%v err=%v", tc.typ, tc.text, ok, err)
		}
	}
}
