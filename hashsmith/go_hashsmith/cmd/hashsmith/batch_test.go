package main

import (
	"context"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
)

func TestRawDigestAndBatchable(t *testing.T) {
	if got := rawDigest("md5")("password"); got != "5f4dcc3b5aa765d61d8327deb882cf99" {
		t.Errorf("md5(password) = %q", got)
	}
	if got := rawDigest("ntlm")("password"); got != "8846f7eaee8fb117ad06bdd830b7586c" {
		t.Errorf("ntlm(password) = %q", got)
	}
	// explicit batchable / non-batchable
	if _, ok := allBatchable("md5", "5f4dcc3b5aa765d61d8327deb882cf99"); !ok {
		t.Error("md5 should be batchable")
	}
	if _, ok := allBatchable("bcrypt", "$2b$08$abc"); ok {
		t.Error("bcrypt must not be batchable")
	}
	// auto-detect on a 32-hex value: all candidates must be raw digests
	if cands, ok := allBatchable("", "5f4dcc3b5aa765d61d8327deb882cf99"); !ok || len(cands) == 0 {
		t.Errorf("auto 32-hex should be batchable, got %v ok=%v", cands, ok)
	}
}

func TestBatchDictAttackFindsAll(t *testing.T) {
	dir := t.TempDir()
	wl := filepath.Join(dir, "wl.txt")
	if err := os.WriteFile(wl, []byte("nope\npassword\nadmin\nletmein\nother\n"), 0644); err != nil {
		t.Fatal(err)
	}
	// three md5 targets: password, admin, letmein
	batch := []*batchTarget{
		{norm: "5f4dcc3b5aa765d61d8327deb882cf99", key: "5f4dcc3b5aa765d61d8327deb882cf99"},
		{norm: "21232f297a57a5a743894a0e4a801fc3", key: "21232f297a57a5a743894a0e4a801fc3"},
		{norm: "0d107d09f5bbe40cade3de5c71e9e9b7", key: "0d107d09f5bbe40cade3de5c71e9e9b7"},
	}
	digestToIdx := map[string][]int{}
	for i, e := range batch {
		digestToIdx[e.key] = []int{i}
	}
	remaining := int64(len(batch))
	digestFn := rawDigest("md5")
	verify := func(c string) bool {
		d := digestFn(c)
		idxs, ok := digestToIdx[d]
		if !ok {
			return false
		}
		for _, idx := range idxs {
			if atomic.CompareAndSwapInt32(&batch[idx].flag, 0, 1) {
				batch[idx].password = c
				if atomic.AddInt64(&remaining, -1) == 0 {
					return true
				}
			}
		}
		return false
	}
	var n int64
	batchDictAttack(context.Background(), wl, 0, 0, verify, 4, nil, &n)

	if atomic.LoadInt64(&remaining) != 0 {
		t.Fatalf("not all found, remaining=%d", remaining)
	}
	want := map[string]string{
		"5f4dcc3b5aa765d61d8327deb882cf99": "password",
		"21232f297a57a5a743894a0e4a801fc3": "admin",
		"0d107d09f5bbe40cade3de5c71e9e9b7": "letmein",
	}
	for _, e := range batch {
		if e.password != want[e.key] {
			t.Errorf("%s: got %q want %q", e.key, e.password, want[e.key])
		}
	}
}
