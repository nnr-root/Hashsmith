package main

import (
	"errors"
	"fmt"
	"strings"
)

const (
	flickrBase58Alphabet = "123456789abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ"
	rippleBase58Alphabet = "rpshnaf39wBUDNEGHJKLM4PQRST7VWXYZ2bcdeCg65jkm8oFqi1tuvAxyz"
	bubbleVowels         = "aeiouy"
	bubbleConsonants     = "bcdfghklmnprstvzx"
)

func encodeBase58WithAlphabet(data []byte, alphabet string) string {
	if len(data) == 0 {
		return ""
	}
	return encodeBigRadix(data, alphabet, alphabet[0])
}

func decodeBase58WithAlphabet(text, alphabet string) ([]byte, error) {
	return decodeBigRadix(text, alphabet, alphabet[0])
}

// encodeBubbleBabble implements Antti Huima's pronounceable binary encoding.
// The rolling seed makes transpositions and truncated syllables conspicuous.
func encodeBubbleBabble(data []byte) string {
	var out strings.Builder
	out.Grow(5 + 3*len(data))
	out.WriteByte('x')
	seed := 1
	for i := 0; i < len(data); i += 2 {
		first := int(data[i])
		out.WriteByte(bubbleVowels[(((first>>6)&3)+seed)%6])
		out.WriteByte(bubbleConsonants[(first>>2)&15])
		out.WriteByte(bubbleVowels[((first&3)+(seed/6))%6])
		if i+1 == len(data) {
			break
		}
		second := int(data[i+1])
		out.WriteByte(bubbleConsonants[(second>>4)&15])
		out.WriteByte('-')
		out.WriteByte(bubbleConsonants[second&15])
		seed = (seed*5 + first*7 + second) % 36
	}
	if len(data)%2 == 0 {
		out.WriteByte(bubbleVowels[seed%6])
		out.WriteByte(bubbleConsonants[16])
		out.WriteByte(bubbleVowels[seed/6])
	}
	out.WriteByte('x')
	return out.String()
}

func decodeBubbleBabble(text string) ([]byte, error) {
	if len(text) < 5 || text[0] != 'x' || text[len(text)-1] != 'x' {
		return nil, errors.New("invalid Bubble Babble boundary")
	}
	body := text[1 : len(text)-1]
	seed := 1
	out := make([]byte, 0, len(body)/3)
	for pos := 0; ; {
		if len(body)-pos == 3 && body[pos] == bubbleVowels[seed%6] &&
			body[pos+1] == bubbleConsonants[16] && body[pos+2] == bubbleVowels[seed/6] {
			if encodeBubbleBabble(out) != text {
				return nil, errors.New("invalid Bubble Babble checksum")
			}
			return out, nil
		}
		if len(body)-pos < 3 {
			return nil, errors.New("truncated Bubble Babble syllable")
		}
		v0 := strings.IndexByte(bubbleVowels, body[pos])
		c1 := strings.IndexByte(bubbleConsonants[:16], body[pos+1])
		v2 := strings.IndexByte(bubbleVowels, body[pos+2])
		if v0 < 0 || c1 < 0 || v2 < 0 {
			return nil, fmt.Errorf("invalid Bubble Babble syllable at byte %d", pos+1)
		}
		top := (v0 - seed%6 + 6) % 6
		low := (v2 - seed/6 + 6) % 6
		if top > 3 || low > 3 {
			return nil, errors.New("invalid Bubble Babble seed checksum")
		}
		first := byte(top<<6 | c1<<2 | low)
		out = append(out, first)
		pos += 3
		if pos == len(body) { // odd-length input ends after one syllable
			if encodeBubbleBabble(out) != text {
				return nil, errors.New("invalid Bubble Babble checksum")
			}
			return out, nil
		}
		if len(body)-pos < 3 || body[pos+1] != '-' {
			return nil, errors.New("invalid Bubble Babble pair separator")
		}
		hi := strings.IndexByte(bubbleConsonants[:16], body[pos])
		lo := strings.IndexByte(bubbleConsonants[:16], body[pos+2])
		if hi < 0 || lo < 0 {
			return nil, errors.New("invalid Bubble Babble consonant")
		}
		second := byte(hi<<4 | lo)
		out = append(out, second)
		seed = (seed*5 + int(first)*7 + int(second)) % 36
		pos += 3
	}
}

func isBubbleBabble(text string) bool {
	_, err := decodeBubbleBabble(text)
	return err == nil
}
