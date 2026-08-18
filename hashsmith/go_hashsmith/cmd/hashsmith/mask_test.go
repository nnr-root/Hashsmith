package main

import (
	"context"
	"crypto/md5"
	"encoding/hex"
	"testing"
)

func md5hex(s string) string { d := md5.Sum([]byte(s)); return hex.EncodeToString(d[:]) }

func TestMaskParse(t *testing.T) {
	sets, err := parseMask(&maskConfig{mask: "?u?l?d?s\\?A"})
	if err != nil {
		t.Fatal(err)
	}
	// ?u ?l ?d ?s then literal '?' then literal 'A' = 6 positions.
	if len(sets) != 6 {
		t.Fatalf("want 6 positions, got %d", len(sets))
	}
	if len(sets[0]) != 26 || len(sets[2]) != 10 {
		t.Errorf("charset sizes wrong: %d %d", len(sets[0]), len(sets[2]))
	}
	if string(sets[4]) != "?" || string(sets[5]) != "A" {
		t.Errorf("literals wrong: %q %q", sets[4], sets[5])
	}
	if maskKeyspace(sets) != int64(26*26*10*len(maskSymbol)*1*1) {
		t.Errorf("keyspace wrong: %d", maskKeyspace(sets))
	}
}

func TestMaskAttack(t *testing.T) {
	var n int64
	// basic mask
	pw, err := maskAttack(context.Background(), md5hex("ab12"), "md5",
		&maskConfig{mask: "?l?l?d?d"}, 4, "", "prefix", &n)
	if err != nil || pw != "ab12" {
		t.Errorf("basic mask: got %q err %v", pw, err)
	}
	// custom set + increment
	pw, _ = maskAttack(context.Background(), md5hex("x9"), "md5",
		&maskConfig{mask: "?1?1?1", custom: [4]string{expandCustomSet("?d?l"), "", "", ""}, increment: true, incMin: 1}, 4, "", "prefix", &n)
	if pw != "x9" {
		t.Errorf("custom+increment: got %q", pw)
	}
	// literal
	pw, _ = maskAttack(context.Background(), md5hex("A007"), "md5",
		&maskConfig{mask: "A?d?d?d"}, 4, "", "prefix", &n)
	if pw != "A007" {
		t.Errorf("literal: got %q", pw)
	}
}
