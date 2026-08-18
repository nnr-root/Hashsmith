package main

// Combinator attack — concatenate every word of a left list with every word of a
// right list: `super` + `man` → `superman`. It cracks passphrase-style passwords
// built from two real words (two names, adjective+noun, word+word) that neither a
// plain wordlist nor a mask would reach. Keyspace is |left| × |right|.
//
// The right list is held in memory (it is scanned in full for every left word);
// the left list streams through the same producer/consumer pipeline as the other
// modes, so combinator inherits the fast verifier and multi-hash set check via
// the caller-supplied verify closure.

import (
	"bufio"
	"context"
	"os"
	"strings"
	"sync"
	"sync/atomic"
)

// loadWordlistSlice reads an entire wordlist into memory (trimmed, blanks
// dropped). Used for the combinator right-hand list.
func loadWordlistSlice(path string) ([]string, string, error) {
	f, label, err := openWordlist(path)
	if err != nil {
		return nil, "", err
	}
	defer f.Close()
	var out []string
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		if w := strings.TrimSpace(sc.Text()); w != "" {
			out = append(out, w)
		}
	}
	return out, label, sc.Err()
}

func combinatorAttack(ctx context.Context, leftPath, rightPath string,
	workers int, verify func(string) bool, atomicAttempts *int64) (string, error) {

	right, _, err := loadWordlistSlice(rightPath)
	if err != nil {
		return "", err
	}
	if len(right) == 0 {
		return "", nil
	}

	f, label, err := openWordlist(leftPath)
	if err != nil {
		return "", err
	}
	defer f.Close()
	if label == defaultWordlistLabel {
		clrYellow.Fprintf(os.Stderr, "No left wordlist supplied — using %s\n", label)
	}

	innerCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	batchCh := make(chan []string, workers*4)
	resultCh := make(chan string, 1)

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
					for _, left := range words {
						var local int64
						iter := 0
						for _, r := range right {
							if iter++; iter >= ctxCheckEvery {
								iter = 0
								select {
								case <-innerCtx.Done():
									atomic.AddInt64(atomicAttempts, local)
									return
								default:
								}
							}
							cand := left + r
							local++
							if verify(cand) {
								atomic.AddInt64(atomicAttempts, local)
								select {
								case resultCh <- cand:
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
