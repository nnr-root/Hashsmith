package main

// Mask attack — a brute-force where each position has its own character set,
// specified with placeholders:
//
//	?l a-z   ?u A-Z   ?d 0-9   ?s <symbols>   ?a ?l?u?d?s
//	?h 0-9a-f   ?H 0-9A-F   ?b 0x00-0xff
//	?1 ?2 ?3 ?4  user-defined sets (via -1 -2 -3 -4)
//	\?  a literal '?'   ;  any other character is a literal
//
// Example: -M mask --mask '?u?l?l?l?l?d?d'  cracks Word12-style passwords.

import (
	"context"
	"errors"
	"strings"
)

const (
	maskLower  = "abcdefghijklmnopqrstuvwxyz"
	maskUpper  = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	maskDigit  = "0123456789"
	maskSymbol = " !\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~"
	maskHexLow = "0123456789abcdef"
	maskHexUp  = "0123456789ABCDEF"
)

// maskConfig carries the mask string, the four custom sets, and increment mode.
type maskConfig struct {
	mask      string
	custom    [4]string
	increment bool
	incMin    int
	maskFirst bool // hybrid mode: place the mask before the word (mask+word)
}

// parseMask expands a mask into a per-position list of candidate byte sets.
func parseMask(cfg *maskConfig) ([][]byte, error) {
	m := cfg.mask
	var sets [][]byte
	byName := func(c byte) (string, bool) {
		switch c {
		case 'l':
			return maskLower, true
		case 'u':
			return maskUpper, true
		case 'd':
			return maskDigit, true
		case 's':
			return maskSymbol, true
		case 'a':
			return maskLower + maskUpper + maskDigit + maskSymbol, true
		case 'h':
			return maskHexLow, true
		case 'H':
			return maskHexUp, true
		case 'b':
			all := make([]byte, 256)
			for i := range all {
				all[i] = byte(i)
			}
			return string(all), true
		case '1', '2', '3', '4':
			s := cfg.custom[c-'1']
			if s == "" {
				return "", false
			}
			return s, true
		}
		return "", false
	}
	for i := 0; i < len(m); i++ {
		switch m[i] {
		case '?':
			if i+1 >= len(m) {
				return nil, errors.New("mask ends with a dangling '?'")
			}
			i++
			set, ok := byName(m[i])
			if !ok {
				return nil, errors.New("unknown mask placeholder ?" + string(m[i]) +
					" (or empty custom set)")
			}
			sets = append(sets, []byte(set))
		case '\\':
			if i+1 >= len(m) {
				return nil, errors.New("mask ends with a dangling '\\'")
			}
			i++
			sets = append(sets, []byte{m[i]})
		default:
			sets = append(sets, []byte{m[i]})
		}
	}
	if len(sets) == 0 {
		return nil, errors.New("empty mask")
	}
	return sets, nil
}

// expandCustomSets resolves nested placeholders inside a custom set definition
// (e.g. -1 ?d?l = digits+lowercase).
func expandCustomSet(def string) string {
	var b strings.Builder
	for i := 0; i < len(def); i++ {
		if def[i] == '?' && i+1 < len(def) {
			i++
			switch def[i] {
			case 'l':
				b.WriteString(maskLower)
			case 'u':
				b.WriteString(maskUpper)
			case 'd':
				b.WriteString(maskDigit)
			case 's':
				b.WriteString(maskSymbol)
			case 'a':
				b.WriteString(maskLower + maskUpper + maskDigit + maskSymbol)
			case 'h':
				b.WriteString(maskHexLow)
			case 'H':
				b.WriteString(maskHexUp)
			default:
				b.WriteByte(def[i])
			}
		} else {
			b.WriteByte(def[i])
		}
	}
	return b.String()
}

// maskKeyspace returns the total number of candidates for a set list.
func maskKeyspace(sets [][]byte) int64 {
	total := int64(1)
	for _, s := range sets {
		if len(s) == 0 {
			return 0
		}
		total *= int64(len(s))
	}
	return total
}

// calcMaskTotal is the progress-bar total for a mask (sum over increment lengths).
func calcMaskTotal(cfg *maskConfig) int64 {
	sets, err := parseMask(cfg)
	if err != nil {
		return -1
	}
	if !cfg.increment {
		return maskKeyspace(sets)
	}
	var total int64
	lo := cfg.incMin
	if lo < 1 {
		lo = 1
	}
	for l := lo; l <= len(sets); l++ {
		total += maskKeyspace(sets[:l])
	}
	return total
}

// maskIdxToStr maps a linear index to the candidate for a mixed-radix set list.
func maskIdxToStr(index int64, sets [][]byte) string {
	out := make([]byte, len(sets))
	maskIdxInto(out, index, sets)
	return string(out)
}

// maskIdxInto writes the mixed-radix expansion of index into dst (len == len(sets)).
func maskIdxInto(dst []byte, index int64, sets [][]byte) {
	for i := len(sets) - 1; i >= 0; i-- {
		base := int64(len(sets[i]))
		dst[i] = sets[i][index%base]
		index /= base
	}
}

// maskAttack runs a mask across `workers` goroutines, honouring increment mode
// (try shorter prefixes first). It is a thin wrapper over the shared keyspace
// runner; doCrack drives the resumable/session-aware path directly.
func maskAttack(ctx context.Context, targetHash, typ string, cfg *maskConfig,
	workers int, salt, saltMode string, atomicAttempts *int64) (string, error) {

	layout, err := maskLayout(cfg)
	if err != nil {
		return "", err
	}
	return runLayout(ctx, layout, 0, workers, atomicAttempts, nil,
		func(c string) bool {
			ok, _ := verifyCandidate(c, targetHash, typ, salt, saltMode)
			return ok
		})
}

// buildMaskConfig assembles a maskConfig from CLI flags (custom sets are
// expanded so -1 ?d?l works). Returns nil when no mask was supplied.
func buildMaskConfig(mask, c1, c2, c3, c4 string, increment bool, incMin int, maskFirst bool) *maskConfig {
	if mask == "" {
		return nil
	}
	return &maskConfig{
		mask: mask,
		custom: [4]string{
			expandCustomSet(c1), expandCustomSet(c2),
			expandCustomSet(c3), expandCustomSet(c4),
		},
		increment: increment,
		incMin:    incMin,
		maskFirst: maskFirst,
	}
}
