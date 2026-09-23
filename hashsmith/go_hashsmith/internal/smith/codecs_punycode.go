package smith

// Punycode (RFC 3492) and the IDNA domain wrapper around it (RFC 3490).
//
// This is here because of what it is USED FOR rather than what it is. Punycode
// is how a domain name containing non-ASCII characters is carried by a system
// that only speaks ASCII: "bücher.de" travels as "xn--bcher-kva.de". A reader
// looking at traffic, a certificate or a phishing report sees only the second
// form, and the two look nothing alike.
//
// That gap is the homograph attack. "аpple.com" with a Cyrillic а is a
// different domain from "apple.com" and renders identically; on the wire it is
// "xn--pple-43d.com", which is the only form that shows the substitution at
// all. Decoding is how you see what a name really says; encoding is how you
// check what a suspicious string would become.
//
// The algorithm is a bootstring parameterisation: an adaptive base-36 encoding
// that writes the non-ASCII characters as deltas from the ones already placed.
// The parameters below are RFC 3492's and are not adjustable — a different set
// is a different encoding, not a variant of this one.

import (
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"
)

const (
	punyBase        = 36
	punyTMin        = 1
	punyTMax        = 26
	punySkew        = 38
	punyDamp        = 700
	punyInitialBias = 72
	punyInitialN    = 128
	punyDelimiter   = '-'
	// punyMaxDelta bounds the arithmetic so that a crafted string cannot
	// spin the decoder for an unbounded time before failing.
	punyMaxDelta = 0x7fffffff
)

// punyDigit maps a base-36 digit to its character, and back.
func punyDigitToRune(d int) byte {
	if d < 26 {
		return byte('a' + d)
	}
	return byte('0' + d - 26)
}

func punyRuneToDigit(c byte) (int, bool) {
	switch {
	case c >= 'a' && c <= 'z':
		return int(c - 'a'), true
	case c >= 'A' && c <= 'Z':
		return int(c - 'A'), true
	case c >= '0' && c <= '9':
		return int(c-'0') + 26, true
	}
	return 0, false
}

// punyAdapt is the bias adaptation from RFC 3492 section 6.1. Its job is to
// keep the common case — a name whose non-ASCII characters are near each other
// in the code space — down to one digit per character.
func punyAdapt(delta, numPoints int, firstTime bool) int {
	if firstTime {
		delta /= punyDamp
	} else {
		delta /= 2
	}
	delta += delta / numPoints
	k := 0
	for delta > ((punyBase-punyTMin)*punyTMax)/2 {
		delta /= punyBase - punyTMin
		k += punyBase
	}
	return k + (punyBase-punyTMin+1)*delta/(delta+punySkew)
}

// encodePunycode converts a string to the Punycode of RFC 3492.
//
// The output is the BARE encoding, without the "xn--" prefix an IDNA label
// carries: this is the codec, and idna is the wrapper that knows about domain
// names.
func encodePunycode(s string) (string, error) {
	if !utf8.ValidString(s) {
		return "", errors.New("punycode input is not valid UTF-8")
	}
	var out strings.Builder
	input := []rune(s)

	// The basic code points are copied out first, in order, followed by a
	// delimiter when there were any.
	basic := 0
	for _, r := range input {
		if r < punyInitialN {
			out.WriteRune(r)
			basic++
		}
	}
	handled := basic
	if basic > 0 {
		out.WriteByte(punyDelimiter)
	}

	n, delta, bias := punyInitialN, 0, punyInitialBias
	for handled < len(input) {
		// The next code point to encode is the smallest one still above
		// what has been handled.
		m := 0x7fffffff
		for _, r := range input {
			if int(r) >= n && int(r) < m {
				m = int(r)
			}
		}
		if m-n > (punyMaxDelta-delta)/(handled+1) {
			return "", errors.New("punycode input overflows the encoding's arithmetic")
		}
		delta += (m - n) * (handled + 1)
		n = m

		for _, r := range input {
			switch {
			case int(r) < n:
				delta++
				if delta > punyMaxDelta {
					return "", errors.New("punycode input overflows the encoding's arithmetic")
				}
			case int(r) == n:
				q := delta
				for k := punyBase; ; k += punyBase {
					t := k - bias
					switch {
					case t < punyTMin:
						t = punyTMin
					case t > punyTMax:
						t = punyTMax
					}
					if q < t {
						break
					}
					out.WriteByte(punyDigitToRune(t + (q-t)%(punyBase-t)))
					q = (q - t) / (punyBase - t)
				}
				out.WriteByte(punyDigitToRune(q))
				bias = punyAdapt(delta, handled+1, handled == basic)
				delta, handled = 0, handled+1
			}
		}
		delta++
		n++
	}
	return out.String(), nil
}

// decodePunycode converts Punycode back to the string it stands for.
func decodePunycode(s string) (string, error) {
	// Everything before the LAST delimiter is literal. A name with no
	// delimiter is all-encoded, which is why the search is for the last one
	// and its absence is not an error.
	var output []rune
	encoded := s
	if i := strings.LastIndexByte(s, punyDelimiter); i >= 0 {
		for _, c := range s[:i] {
			if c >= punyInitialN {
				return "", errors.New("punycode literal part holds a non-ASCII character")
			}
			output = append(output, c)
		}
		encoded = s[i+1:]
	}

	n, i, bias := punyInitialN, 0, punyInitialBias
	for at := 0; at < len(encoded); {
		oldi, w := i, 1
		for k := punyBase; ; k += punyBase {
			if at >= len(encoded) {
				return "", errors.New("punycode ends in the middle of a digit sequence")
			}
			digit, ok := punyRuneToDigit(encoded[at])
			if !ok {
				return "", fmt.Errorf("punycode holds %q, which is not a base-36 digit", encoded[at])
			}
			at++
			if digit > (punyMaxDelta-i)/w {
				return "", errors.New("punycode overflows the encoding's arithmetic")
			}
			i += digit * w
			t := k - bias
			switch {
			case t < punyTMin:
				t = punyTMin
			case t > punyTMax:
				t = punyTMax
			}
			if digit < t {
				break
			}
			if w > punyMaxDelta/(punyBase-t) {
				return "", errors.New("punycode overflows the encoding's arithmetic")
			}
			w *= punyBase - t
		}
		bias = punyAdapt(i-oldi, len(output)+1, oldi == 0)
		if i/(len(output)+1) > punyMaxDelta-n {
			return "", errors.New("punycode overflows the encoding's arithmetic")
		}
		n += i / (len(output) + 1)
		i %= len(output) + 1
		if n > utf8.MaxRune || (n >= 0xd800 && n <= 0xdfff) {
			return "", errors.New("punycode decodes to a code point that does not exist")
		}
		output = append(output, 0)
		copy(output[i+1:], output[i:])
		output[i] = rune(n)
		i++
	}
	return string(output), nil
}

// ── IDNA ──────────────────────────────────────────────────────────────────────

// idnaPrefix is the ACE prefix RFC 3490 puts in front of an encoded label. It
// is case-insensitive on the wire.
const idnaPrefix = "xn--"

// encodeIDNA converts a domain name to its ASCII form, label by label.
//
// A label that is already all-ASCII is left EXACTLY as it is, including its
// case: encoding it would change a name that needed no changing. Only a label
// carrying something outside ASCII gets the prefix.
func encodeIDNA(name string) (string, error) {
	labels := strings.Split(name, ".")
	for i, label := range labels {
		if label == "" {
			continue
		}
		ascii := true
		for _, r := range label {
			if r >= punyInitialN {
				ascii = false
				break
			}
		}
		if ascii {
			continue
		}
		encoded, err := encodePunycode(label)
		if err != nil {
			return "", fmt.Errorf("label %q: %w", label, err)
		}
		labels[i] = idnaPrefix + encoded
	}
	return strings.Join(labels, "."), nil
}

// decodeIDNA converts a domain name from its ASCII form back to Unicode.
//
// A label without the prefix is passed through unchanged rather than decoded:
// "test" is a perfectly good label and is not Punycode for anything.
func decodeIDNA(name string) (string, error) {
	labels := strings.Split(name, ".")
	for i, label := range labels {
		if len(label) < len(idnaPrefix) ||
			!strings.EqualFold(label[:len(idnaPrefix)], idnaPrefix) {
			continue
		}
		decoded, err := decodePunycode(label[len(idnaPrefix):])
		if err != nil {
			return "", fmt.Errorf("label %q: %w", label, err)
		}
		labels[i] = decoded
	}
	return strings.Join(labels, "."), nil
}
