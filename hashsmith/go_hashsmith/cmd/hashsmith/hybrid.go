package main

// Hybrid attack — a dictionary attack whose every word is extended by a mask.
// For each wordlist word, all expansions of the mask are appended (word+mask)
// or prepended (mask+word), so `password` + `?d?d?d?d` tries password0000 …
// password9999. It combines the coverage of a wordlist with the structured
// brute-force of a mask, which is how most real passwords are built: a base word
// plus a trailing year / digits / symbol.
//
// Words stream through the same producer/consumer pipeline as the dictionary
// attack; each word's mask keyspace is enumerated by the worker that owns it.
// The verify closure is supplied by the caller, so hybrid runs benefit from the
// zero-allocation fast verifier (single target) or the multi-hash set check
// (a whole dump) exactly like the other modes.

import (
	"bufio"
	"context"
	"os"
	"strings"
	"sync"
	"sync/atomic"
)

func hybridAttack(ctx context.Context, wordlistPath string, sets [][]byte, maskFirst bool,
	workers int, verify func(string) bool, atomicAttempts *int64) (string, error) {

	f, label, err := openWordlist(wordlistPath)
	if err != nil {
		return "", err
	}
	defer f.Close()
	if label == defaultWordlistLabel {
		clrYellow.Fprintf(os.Stderr, "No wordlist supplied — using %s\n", label)
	}

	total := maskKeyspace(sets)
	if total == 0 {
		return "", nil
	}
	maskLen := len(sets)

	innerCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	batchCh := make(chan []string, workers*4)
	resultCh := make(chan string, 1)

	// reader
	go func() {
		defer close(batchCh)
		scanner := bufio.NewScanner(f)
		scanner.Buffer(make([]byte, 1<<20), 1<<20)
		cur := make([]string, 0, dictBatchSize)
		for scanner.Scan() {
			word := strings.TrimSpace(scanner.Text())
			if word == "" {
				continue
			}
			cur = append(cur, word)
			if len(cur) >= dictBatchSize {
				select {
				case batchCh <- cur:
					cur = make([]string, 0, dictBatchSize)
				case <-innerCtx.Done():
					return
				}
			}
		}
		if len(cur) > 0 {
			select {
			case batchCh <- cur:
			case <-innerCtx.Done():
			}
		}
	}()

	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-innerCtx.Done():
					return
				case words, ok := <-batchCh:
					if !ok {
						return
					}
					for _, word := range words {
						// buf holds word+mask (or mask+word); only the mask
						// region is rewritten per candidate.
						buf := make([]byte, len(word)+maskLen)
						var moff int
						if maskFirst {
							copy(buf[maskLen:], word)
							moff = 0
						} else {
							copy(buf[:len(word)], word)
							moff = len(word)
						}
						var local int64
						iter := 0
						for idx := int64(0); idx < total; idx++ {
							if iter++; iter >= ctxCheckEvery {
								iter = 0
								select {
								case <-innerCtx.Done():
									atomic.AddInt64(atomicAttempts, local)
									return
								default:
								}
							}
							maskIdxInto(buf[moff:moff+maskLen], idx, sets)
							local++
							if verify(string(buf)) {
								atomic.AddInt64(atomicAttempts, local)
								select {
								case resultCh <- string(buf):
								default:
								}
								cancel()
								return
							}
						}
						atomic.AddInt64(atomicAttempts, local)
					}
				}
			}
		}()
	}
	wg.Wait()
	select {
	case r := <-resultCh:
		return r, nil
	default:
		return "", nil
	}
}
