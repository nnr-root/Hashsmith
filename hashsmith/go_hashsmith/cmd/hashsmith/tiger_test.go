package main

import (
	"encoding/hex"
	"strings"
	"testing"
)

// The empty-message digest is John's own vector for its `tiger` format, and
// "abc" and "Tiger" are the specification's. The three long messages were
// cross-checked the other way round: Hashsmith computed them, John was asked
// to crack them as its Tiger format, and John recovered all three plaintexts.
//
// That cross-check is worth more here than a transcribed constant, because it
// is the S-boxes these vectors are really testing. They are generated rather
// than written down, and a single wrong byte among the four thousand would
// change every digest below — including, quietly, only the long ones, since a
// short message touches only part of the table.
func TestTiger(t *testing.T) {
	for _, tc := range []struct{ msg, want string }{
		{"", "3293ac630c13f0245f92bbb1766e16167a4e58492dde73f3"},
		{"abc", "2aab1484e8c158f2bfb8c5ff41b57a525129131c957b5f93"},
		{"Tiger", "dd00230799f5009fec6debc838bb6a27df2b9d6f110c7937"},
		{"abcdefghijklmnopqrstuvwxyz",
			"1714a472eee57d30040412bfcc55032a0b11602ff37beee9"},
		{"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+-",
			"f71c8583902afb879edfe610f82c0d4786a3a534504486b5"},
		{"Tiger - A Fast New Hash Function, by Ross Anderson and Eli Biham",
			"8a866829040a410c729ad23f5ada711603b3cdd357e4c15e"},
	} {
		h := newTiger()
		_, _ = h.Write([]byte(tc.msg))
		if got := hex.EncodeToString(h.Sum(nil)); got != tc.want {
			t.Errorf("Tiger(%.30q) = %s, want %s", tc.msg, got, tc.want)
		}
	}
}

// A message long enough to need several blocks, written one byte at a time,
// must agree with the same message written at once — the buffering is the
// only part of this that is not covered by the vectors above.
func TestTigerStreaming(t *testing.T) {
	msg := strings.Repeat("The quick brown fox jumps over the lazy dog. ", 40)
	whole := newTiger()
	_, _ = whole.Write([]byte(msg))
	piecemeal := newTiger()
	for i := 0; i < len(msg); i++ {
		_, _ = piecemeal.Write([]byte(msg[i : i+1]))
	}
	if a, b := hex.EncodeToString(whole.Sum(nil)), hex.EncodeToString(piecemeal.Sum(nil)); a != b {
		t.Errorf("byte-at-a-time = %s, all at once = %s", b, a)
	}
}
