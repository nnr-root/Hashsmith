package main

import (
	"fmt"
	"strings"
)

// ── Codec chains ──────────────────────────────────────────────────────────────
//
// `-t hex+base64` applies hex, then base64. `decode -t base64+hex` undoes it.
//
// Before this, a multi-step recipe meant N separate invocations piped into one
// another, and every hop back through argv re-exposed the input to whatever
// the argument layer does to it. It is also the other half of `magic`: magic
// reports a chain as "base64 -> hex", and this is how you replay one.
//
// The steps read left to right in BOTH directions, so a chain and its inverse
// are mirror images and can be read off a magic result directly:
//
//	encode -t hex+base64   "text"   ->  encoded
//	decode -t base64+hex   encoded  ->  "text"

const codecChainSep = "+"

// parseCodecChain splits a -t value into its steps. A name with no separator
// is a one-step chain, so every caller can use this unconditionally.
func parseCodecChain(typ string) ([]string, error) {
	raw := strings.Split(typ, codecChainSep)
	steps := make([]string, 0, len(raw))
	for _, s := range raw {
		s = strings.TrimSpace(s)
		if s == "" {
			return nil, fmt.Errorf("empty step in codec chain %q", typ)
		}
		steps = append(steps, s)
	}
	if len(steps) == 0 {
		return nil, fmt.Errorf("no codec named")
	}
	return steps, nil
}

// encodeChain applies every step in order.
func encodeChain(text, typ string, shift int, key string, rails int) (string, error) {
	steps, err := parseCodecChain(typ)
	if err != nil {
		return "", err
	}
	cur := text
	for i, step := range steps {
		out, err := encodeText(cur, step, shift, key, rails)
		if err != nil {
			if len(steps) == 1 {
				return "", err
			}
			// Name the step that failed: "unsupported encode type" is not
			// useful when the user gave four of them.
			return "", fmt.Errorf("chain step %d (%s): %w", i+1, step, err)
		}
		cur = out
	}
	return cur, nil
}

// decodeChain applies every step in order. To undo `encode -t a+b`, pass
// `decode -t b+a`.
func decodeChain(text, typ string, shift int, key string, rails int) (string, error) {
	steps, err := parseCodecChain(typ)
	if err != nil {
		return "", err
	}
	cur := text
	for i, step := range steps {
		out, err := decodeText(cur, step, shift, key, rails)
		if err != nil {
			if len(steps) == 1 {
				return "", err
			}
			return "", fmt.Errorf("chain step %d (%s): %w", i+1, step, err)
		}
		cur = out
	}
	return cur, nil
}
