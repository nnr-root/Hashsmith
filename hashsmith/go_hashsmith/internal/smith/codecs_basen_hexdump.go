package smith

// Two codecs that exist to handle what a tool in front of Hashsmith produced:
// an arbitrary base-N alphabet, and a canonical hex dump.

import (
	"errors"
	"fmt"
	"strings"
)

// ── base-N with a supplied alphabet ───────────────────────────────────────────

// The alphabet comes from -k, which is already this CLI's channel for "this
// codec needs a string": vigenere and xor take their key there, bech32 its
// human-readable part.
//
// This exists because the named base-N codecs are a list of alphabets somebody
// standardised, and the data an analyst is handed frequently uses one nobody
// did. A product that shuffled Base58's alphabet, a CTF that rotated Base62,
// an application that dropped the vowels to avoid accidental words — all of
// them are this codec with a different string, and none of them is worth its
// own entry in a catalogue.
//
// The radix is the alphabet's LENGTH, so the same code covers base 2 through
// base 256 without knowing which it is doing.

const (
	baseNMinRadix = 2
	baseNMaxRadix = 256
)

// validateBaseNAlphabet checks the alphabet before it is used, because every
// way of getting it wrong produces silent nonsense rather than an error.
func validateBaseNAlphabet(alphabet string) ([]rune, error) {
	if alphabet == "" {
		return nil, errors.New("basen needs an alphabet: pass it with -k, for example -k 0123456789abcdef")
	}
	runes := []rune(alphabet)
	if len(runes) < baseNMinRadix {
		return nil, fmt.Errorf("an alphabet of %d character(s) is not a base to count in; at least %d are needed",
			len(runes), baseNMinRadix)
	}
	if len(runes) > baseNMaxRadix {
		return nil, fmt.Errorf("an alphabet of %d characters exceeds the %d this handles", len(runes), baseNMaxRadix)
	}
	seen := make(map[rune]int, len(runes))
	for i, r := range runes {
		if first, dup := seen[r]; dup {
			return nil, fmt.Errorf("the alphabet repeats %q at positions %d and %d, so a digit would have two meanings",
				string(r), first, i)
		}
		seen[r] = i
	}
	return runes, nil
}

// encodeBaseN writes data in the supplied alphabet.
//
// Leading zero BYTES become leading zero DIGITS rather than being folded into
// the number, which is the convention Base58 established and the only way a
// value with a leading zero survives a round trip: the arithmetic alone cannot
// tell 0x00 0x01 from 0x01.
func encodeBaseN(data []byte, alphabet string) (string, error) {
	runes, err := validateBaseNAlphabet(alphabet)
	if err != nil {
		return "", err
	}
	if len(data) == 0 {
		return "", nil
	}
	return encodeBigRadixRunes(data, runes), nil
}

func decodeBaseN(text, alphabet string) ([]byte, error) {
	runes, err := validateBaseNAlphabet(alphabet)
	if err != nil {
		return nil, err
	}
	return decodeBigRadixRunes(text, runes)
}

// ── Hex dumps ─────────────────────────────────────────────────────────────────

const hexDumpBytesPerLine = 16

// encodeHexDump writes the canonical dump `hexdump -C` produces: an offset,
// two groups of eight bytes, and the printable characters between pipes.
//
// The pipes are not decoration. They are what makes the format decodable:
// without them the ASCII column and the hex column cannot be told apart when
// the data happens to look like hex, which is exactly what happens to a dump
// of hexadecimal text.
func encodeHexDump(data []byte) string {
	// An empty input gets an empty dump, which is what the system tool
	// writes: there is no closing offset line because there is nothing for
	// it to close.
	if len(data) == 0 {
		return ""
	}
	var out strings.Builder
	for off := 0; off < len(data); off += hexDumpBytesPerLine {
		end := off + hexDumpBytesPerLine
		if end > len(data) {
			end = len(data)
		}
		line := data[off:end]

		fmt.Fprintf(&out, "%08x  ", off)
		for i := 0; i < hexDumpBytesPerLine; i++ {
			if i == hexDumpBytesPerLine/2 {
				out.WriteByte(' ')
			}
			if i < len(line) {
				fmt.Fprintf(&out, "%02x ", line[i])
			} else {
				out.WriteString("   ")
			}
		}
		out.WriteString(" |")
		for _, b := range line {
			if b >= 0x20 && b < 0x7f {
				out.WriteByte(b)
			} else {
				out.WriteByte('.')
			}
		}
		out.WriteString("|\n")
	}
	// The canonical format closes with the total length on its own line,
	// which is how a reader knows a truncated dump from a complete one.
	fmt.Fprintf(&out, "%08x\n", len(data))
	return out.String()
}

// decodeHexDump reads a dump back.
//
// Three things on a line are not data, and each needs its own rule: the offset
// at the start, the printable column at the end, and the closing length line,
// which is an offset with nothing after it.
//
// The printable column is the hard one. When it is delimited by pipes, as
// `hexdump -C` writes it, there is no ambiguity. When it is not — `xxd`
// without -C — the column is separated from the hex by a RUN OF TWO OR MORE
// SPACES, where the hex bytes are separated by one, and that spacing is the
// only signal there is: the text itself may be indistinguishable from more
// hex. "beef" is a word and four bytes.
//
// So the spacing rule is applied only to a line that began with an offset,
// because that is a line from a tool that lays out columns. A bare run of hex
// with no offset is taken whole, since there is no column to mistake.
func decodeHexDump(text string) ([]byte, error) {
	if strings.TrimSpace(text) == "" {
		return []byte{}, nil
	}
	var out []byte
	sawBytes := false

	for _, raw := range strings.Split(text, "\n") {
		line := strings.TrimRight(raw, " \t\r")
		if strings.TrimSpace(line) == "" {
			continue
		}
		delimited := false
		if i := strings.IndexByte(line, '|'); i >= 0 {
			line, delimited = line[:i], true
		}

		hadOffset := false
		if i := strings.IndexByte(line, ':'); i > 0 && isHex(strings.TrimSpace(line[:i])) {
			line, hadOffset = line[i+1:], true
		} else if fields := strings.Fields(line); len(fields) == 1 &&
			len(fields[0]) >= 4 && isHex(fields[0]) && !delimited {
			// A lone offset is the closing length line.
			continue
		} else if len(fields) > 1 && len(fields[0]) >= 8 && isHex(fields[0]) {
			line, hadOffset = strings.TrimSpace(line[len(fields[0]):]), true
		}

		// An undelimited column, on a line that came from a tool.
		if !delimited && hadOffset {
			if i := lastRunOfSpaces(line, 2); i >= 0 {
				line = line[:i]
			}
		}

		line = strings.TrimRight(line, " \t")
		for _, token := range strings.Fields(line) {
			if len(token)%2 != 0 || !isHex(token) {
				return nil, fmt.Errorf("%q is not a pair of hex digits; if this dump's printable column is not delimited by pipes, re-dump it with `hexdump -C`, or use `xxd -p` and the hex codec", token)
			}
			for i := 0; i < len(token); i += 2 {
				out = append(out, hexPairValue(token[i], token[i+1]))
			}
			sawBytes = true
		}
	}
	if !sawBytes {
		return nil, errors.New("this text holds no hex dump lines")
	}
	return out, nil
}

// lastRunOfSpaces returns where the last run of at least n spaces begins, or
// -1. It is how a laid-out column is told from a separator.
func lastRunOfSpaces(s string, n int) int {
	run, end := 0, -1
	for i := len(s) - 1; i >= 0; i-- {
		if s[i] == ' ' {
			run++
			if run >= n {
				end = i
			}
			continue
		}
		if end >= 0 {
			return end
		}
		run = 0
	}
	return end
}

// hexPairValue turns two hex digits into a byte. fmt.Sscanf would do it and
// costs a parse of the format string for every byte of the dump.
func hexPairValue(hi, lo byte) byte {
	value := func(c byte) byte {
		switch {
		case c >= '0' && c <= '9':
			return c - '0'
		case c >= 'a' && c <= 'f':
			return c - 'a' + 10
		default:
			return c - 'A' + 10
		}
	}
	return value(hi)<<4 | value(lo)
}
