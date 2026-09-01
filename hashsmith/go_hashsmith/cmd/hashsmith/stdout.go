package main

// --stdout turns any attack mode into a candidate generator: instead of hashing
// and comparing, every candidate the attack would try is written to stdout, in
// the exact order it would be attempted. This lets Hashsmith preview a mask or
// ruleset, estimate a keyspace, or feed its candidate stream into another tool.
//
// Generation runs single-threaded so the output is ordered and unbuffered
// interleaving cannot occur; candidate generation is rarely the bottleneck when
// piping (the consumer usually is).

import (
	"bufio"
	"context"
	"errors"
	"os"
	"strings"
)

func streamCandidates(mode, wordlist, wordlist2, charset string,
	minLen, maxLen int, mc *maskConfig, rules *ruleEngine) error {

	w := bufio.NewWriterSize(os.Stdout, 1<<20)
	defer w.Flush()

	var dummy int64
	emit := func(c string) bool {
		w.WriteString(c)
		w.WriteByte('\n')
		return false // never stop — enumerate the whole keyspace
	}

	switch strings.ToLower(mode) {
	case "brute":
		if minLen < 1 || maxLen < minLen {
			return errors.New("invalid -n/-x range")
		}
		_, err := runLayout(context.Background(), bruteLayout(charset, minLen, maxLen),
			0, 0, 1, &dummy, nil, emit)
		return err
	case "mask":
		if mc == nil {
			return errors.New("mask mode requires --mask <mask>")
		}
		layout, err := maskLayout(mc)
		if err != nil {
			return err
		}
		_, err = runLayout(context.Background(), layout, 0, 0, 1, &dummy, nil, emit)
		return err
	case "markov":
		if minLen < 1 || maxLen < minLen {
			return errors.New("invalid -n/-x range")
		}
		model, err := trainMarkov(charset, wordlist)
		if err != nil {
			return err
		}
		_, err = runLayout(context.Background(), markovLayout(model, minLen, maxLen), 0, 0, 1, &dummy, nil, emit)
		return err
	case "hybrid":
		if mc == nil {
			return errors.New("hybrid mode requires --mask <mask> and -w <wordlist>")
		}
		sets, err := parseMask(mc)
		if err != nil {
			return err
		}
		words, _, err := loadWordlistSlice(wordlist)
		if err != nil {
			return err
		}
		_, err = runLayout(context.Background(), hybridLayout(words, sets, mc.maskFirst), 0, 0, 1, &dummy, nil, emit)
		return err
	case "combinator":
		if wordlist2 == "" {
			return errors.New("combinator mode requires -w <left list> and --wordlist2 <right list>")
		}
		left, _, err := loadWordlistSlice(wordlist)
		if err != nil {
			return err
		}
		right, _, err := loadWordlistSlice(wordlist2)
		if err != nil {
			return err
		}
		_, err = runLayout(context.Background(), combinatorLayout(left, right), 0, 0, 1, &dummy, nil, emit)
		return err
	default: // dict
		f, _, err := openWordlist(wordlist)
		if err != nil {
			return err
		}
		defer f.Close()
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 1<<20), 1<<20)
		for sc.Scan() {
			word := strings.TrimSpace(sc.Text())
			if word == "" {
				continue
			}
			emit(word)
			if rules != nil {
				for _, mw := range rules.expand(word) {
					emit(mw.password)
				}
			}
		}
		return sc.Err()
	}
}
