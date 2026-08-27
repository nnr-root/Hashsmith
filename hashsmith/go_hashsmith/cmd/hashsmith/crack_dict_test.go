package main

import (
	"context"
	"crypto/md5"
	"encoding/hex"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
)

type fakeMD5Batcher struct {
	batches int
	seen    int
}

func (f *fakeMD5Batcher) md5(candidates []string, out [][16]byte) error {
	f.batches++
	f.seen += len(candidates)
	for i, candidate := range candidates {
		out[i] = md5.Sum([]byte(candidate))
	}
	return nil
}

func TestDictAttackUsesInjectedVerifier(t *testing.T) {
	wordlist := filepath.Join(t.TempDir(), "words.txt")
	if err := os.WriteFile(wordlist, []byte("first\nsecond\nneedle\n"), 0600); err != nil {
		t.Fatal(err)
	}
	var attempts int64
	var verifierCalls atomic.Int64
	result, err := dictAttack(context.Background(), wordlist, 2, &attempts, nil, func(candidate string) bool {
		verifierCalls.Add(1)
		return candidate == "needle"
	})
	if err != nil || result.password != "needle" {
		t.Fatalf("result=%#v err=%v", result, err)
	}
	if verifierCalls.Load() == 0 || attempts == 0 {
		t.Fatalf("verifier calls=%d attempts=%d", verifierCalls.Load(), attempts)
	}
}

func TestGPUDictAttackStreamsAndFindsTarget(t *testing.T) {
	wordlist := filepath.Join(t.TempDir(), "words.txt")
	if err := os.WriteFile(wordlist, []byte("first\nsecond\nneedle\n"), 0600); err != nil {
		t.Fatal(err)
	}
	target := md5.Sum([]byte("needle"))
	var attempts int64
	backend := &fakeMD5Batcher{}
	result, err := gpuDictAttackWithBackend(context.Background(), backend, wordlist,
		hex.EncodeToString(target[:]), nil, &attempts)
	if err != nil || result.password != "needle" {
		t.Fatalf("result=%#v err=%v", result, err)
	}
	if backend.batches != 1 || backend.seen != 3 || attempts != 3 {
		t.Fatalf("batches=%d seen=%d attempts=%d", backend.batches, backend.seen, attempts)
	}
}

func TestGPUDictAttackExpandsRulesAndPreservesLabel(t *testing.T) {
	wordlist := filepath.Join(t.TempDir(), "words.txt")
	if err := os.WriteFile(wordlist, []byte("password\n"), 0600); err != nil {
		t.Fatal(err)
	}
	rules := builtinRuleEngine()
	expanded := rules.expand("password")
	if len(expanded) == 0 {
		t.Fatal("built-in rules produced no candidates")
	}
	targetCandidate := expanded[0]
	target := md5.Sum([]byte(targetCandidate.password))
	var attempts int64
	result, err := gpuDictAttackWithBackend(context.Background(), &fakeMD5Batcher{}, wordlist,
		hex.EncodeToString(target[:]), rules, &attempts)
	if err != nil || result.password != targetCandidate.password || result.ruleLabel != targetCandidate.ruleLabel {
		t.Fatalf("result=%#v want=%#v err=%v", result, targetCandidate, err)
	}
}

func TestGPUDictAttackHandlesOverlengthCandidateOnCPU(t *testing.T) {
	long := "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234"
	if len(long) <= maxGPUWordLen("md5") {
		t.Fatal("test candidate must exceed the GPU one-block limit")
	}
	wordlist := filepath.Join(t.TempDir(), "words.txt")
	if err := os.WriteFile(wordlist, []byte("first\n"+long+"\nlast\n"), 0600); err != nil {
		t.Fatal(err)
	}
	target := md5.Sum([]byte(long))
	var attempts int64
	backend := &fakeMD5Batcher{}
	result, err := gpuDictAttackWithBackend(context.Background(), backend, wordlist,
		hex.EncodeToString(target[:]), nil, &attempts)
	if err != nil || result.password != long {
		t.Fatalf("result=%#v err=%v", result, err)
	}
	if backend.seen != 1 || attempts != 2 {
		t.Fatalf("GPU seen=%d attempts=%d", backend.seen, attempts)
	}
}
