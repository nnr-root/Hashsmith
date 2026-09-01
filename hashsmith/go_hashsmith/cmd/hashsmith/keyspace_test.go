package main

import (
	"context"
	"crypto/md5"
	"encoding/hex"
	"sync/atomic"
	"testing"
)

func md5x(s string) string { d := md5.Sum([]byte(s)); return hex.EncodeToString(d[:]) }

func TestBruteLayoutOrder(t *testing.T) {
	l := bruteLayout("ab", 1, 2)
	// length 1: a,b  then length 2: aa,ab,ba,bb  → total 6
	if l.total != 6 {
		t.Fatalf("total: want 6 got %d", l.total)
	}
	want := []string{"a", "b", "aa", "ab", "ba", "bb"}
	for i, w := range want {
		if got := l.candidate(int64(i)); got != w {
			t.Errorf("candidate(%d): want %q got %q", i, w, got)
		}
	}
}

func TestRunLayoutResumeFindsAndSkips(t *testing.T) {
	// Answer "zy" is at global index 700 of a-z length-2 (total 702).
	l := bruteLayout("abcdefghijklmnopqrstuvwxyz", 1, 2)
	target := md5x("zy")
	verify := func(c string) bool { return md5x(c) == target }

	// Full run from 0 finds it.
	var n1 int64
	pw, err := runLayout(context.Background(), l, 0, 0, 4, &n1, nil, verify)
	if err != nil || pw != "zy" {
		t.Fatalf("full run: got %q err %v", pw, err)
	}

	// Resuming past the answer (index 701 > 700) must MISS it, proving resumeFrom
	// genuinely skips the earlier keyspace.
	var n2 int64
	pw, _ = runLayout(context.Background(), l, 701, 0, 4, &n2, nil, verify)
	if pw == "zy" {
		t.Fatal("resume past the answer should not find it")
	}

	// Resuming just before the answer still finds it, with far fewer tries.
	var n3 int64
	pw, _ = runLayout(context.Background(), l, 699, 0, 4, &n3, nil, verify)
	if pw != "zy" {
		t.Fatalf("resume before answer: want zy got %q", pw)
	}
	if atomic.LoadInt64(&n3) > 100 {
		t.Errorf("resume should skip most of the keyspace, tried %d", n3)
	}
}

func TestSessionMatch(t *testing.T) {
	s := &sessionState{Mode: "brute", Type: "md5", Target: "x", Charset: "ab",
		MinLen: 1, MaxLen: 3, SaltMode: "prefix"}
	if !s.matches("brute", "md5", "x", "ab", 1, 3, "", [4]string{}, false, "", "prefix", "", "") {
		t.Error("identical params should match")
	}
	if s.matches("brute", "md5", "x", "ab", 1, 4, "", [4]string{}, false, "", "prefix", "", "") {
		t.Error("different maxLen must not match")
	}
	if s.matches("brute", "md5", "x", "ab", 1, 3, "", [4]string{}, false, "", "prefix", "other.txt", "") {
		t.Error("different wordlist must not match")
	}
}
