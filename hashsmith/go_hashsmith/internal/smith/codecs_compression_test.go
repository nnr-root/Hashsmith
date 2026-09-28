package smith

import (
	"bytes"
	"strings"
	"testing"
)

// ── Compression codecs ────────────────────────────────────────────────────────
//
// Every fixture below was produced by the format's own reference tool on this
// machine — brotli(1), zstd(1), xz(1), lzma(1), bzip2(1), gzip(1) and Python's
// zlib for the two the CLI tools do not emit directly — and then Base64'd for
// transport. None of them came from this code.
//
// That distinction is the whole point of the file. A decoder tested against
// its own encoder proves the two agree with each other; these prove the
// decoder agrees with the rest of the world, which is what a forensics tool is
// actually asked to do: read the bytes someone else produced.

const compressionPlaintext = "The quick brown fox jumps over the lazy dog.\n"

func TestCompressionDecodesRealProducerOutput(t *testing.T) {
	for _, tc := range []struct{ typ, producer, b64 string }{
		{"brotli", "brotli -q 11", "IbAABFRoZSBxdWljayBicm93biBmb3gganVtcHMgb3ZlciB0aGUgbGF6eSBkb2cuCgM="},
		{"zstd", "zstd -19", "KLUv/SQtaQEAVGhlIHF1aWNrIGJyb3duIGZveCBqdW1wcyBvdmVyIHRoZSBsYXp5IGRvZy4KzdVXww=="},
		{"xz", "xz -9", "/Td6WFoAAATm1rRGBMAxLSEBHAAAAAAAAAAAAGwr9QEBACxUaGUgcXVpY2sgYnJvd24gZm94IGp1bXBzIG92ZXIgdGhlIGxhenkgZG9nLgoAAAAA4yYLUgRZ0igAAU0tFtiOIB+2830BAAAAAARZWg=="},
		{"lzma", "lzma -9", "XQAAAAT//////////wAqGgiiAyVm8Ut4xaIF/y7m2dIgGq00+OId6EE2+twGabs85BA0Jwnrs2bj7JfqriP//o6gAA=="},
		{"bzip2", "bzip2 -9", "QlpoOTFBWSZTWbM1tvIAAAVTgAAQQAEEAD////AgACMeJBoNGIbRtSFAAAAADgJDhSXt/m8yngx0tFnekYokFskasgHWN7/i7kinChIWZrbeQA=="},
		{"gzip", "gzip -9", "H4sICGfps2oCA3BsYWluLnR4dAALyUhVKCzNTM5WSCrKL89TSMuvUMgqzS0oVsgvSy1SKAFK5yRWVSqk5KfrcQEAasxQ6y0AAAA="},
		{"zlib", "Python zlib.compress level 9", "eNoLyUhVKCzNTM5WSCrKL89TSMuvUMgqzS0oVsgvSy1SKAFK5yRWVSqk5KfrcQEAe/YQEg=="},
		{"deflate", "Python zlib raw deflate, wbits -15", "C8lIVSgszUzOVkgqyi/PU0jLr1DIKs0tKFbIL0stUigBSuckVlUqpOSn63EBAA=="},
	} {
		tc := tc
		t.Run(tc.typ, func(t *testing.T) {
			got, err := decodeText(tc.b64, tc.typ, 0, "", 0)
			if err != nil {
				t.Fatalf("decoding %s from %s: %v", tc.typ, tc.producer, err)
			}
			if got != compressionPlaintext {
				t.Fatalf("%s from %s gave %q, want %q", tc.typ, tc.producer, got, compressionPlaintext)
			}
		})
	}
}

// TestCompressionRoundTripsBinaryBytes covers what the catalogue-wide
// round-trip test cannot: those probes are text, and a compressor that
// mangles a byte above 0x7f or a NUL would still pass them.
func TestCompressionRoundTripsBinaryBytes(t *testing.T) {
	var payload bytes.Buffer
	for i := 0; i < 4096; i++ {
		payload.WriteByte(byte(i * 7))
	}
	payload.WriteString(strings.Repeat("\x00", 512))
	in := payload.String()

	for typ := range compressionCodecs {
		typ := typ
		t.Run(typ, func(t *testing.T) {
			enc, err := encodeText(in, typ, 0, "", 0)
			if err != nil {
				t.Fatalf("encode: %v", err)
			}
			dec, err := decodeText(enc, typ, 0, "", 0)
			if err != nil {
				t.Fatalf("decode: %v", err)
			}
			if dec != in {
				t.Fatalf("%s round trip lost bytes: %d in, %d out", typ, len(in), len(dec))
			}
		})
	}
}

// TestCompressionTrailerIsWritten is the bug this shape invites: several of
// these formats hold their checksum and end-of-stream marker until Close, so
// an encoder that forgets to close produces a stream that looks right and
// truncates. It does not show up on a short input, where everything lands in
// the trailer anyway, so the test uses a payload big enough to have real
// content before it.
func TestCompressionTrailerIsWritten(t *testing.T) {
	in := strings.Repeat("compressible. ", 8192)
	for typ := range compressionCodecs {
		typ := typ
		t.Run(typ, func(t *testing.T) {
			enc, err := encodeText(in, typ, 0, "", 0)
			if err != nil {
				t.Fatalf("encode: %v", err)
			}
			dec, err := decodeText(enc, typ, 0, "", 0)
			if err != nil {
				t.Fatalf("decode: %v", err)
			}
			if len(dec) != len(in) {
				t.Fatalf("%s: wrote %d bytes and read back %d", typ, len(in), len(dec))
			}
		})
	}
}

// TestCompressionRefusesToInflatePastTheLimit is the defence against a
// decompression bomb. Thirty-two megabytes of zeros is a few hundred bytes in
// every one of these formats, and a decoder that reads to EOF hands an
// attacker the allocation.
func TestCompressionRefusesToInflatePastTheLimit(t *testing.T) {
	bomb := strings.Repeat("\x00", 32<<20)
	for typ := range compressionCodecs {
		typ := typ
		t.Run(typ, func(t *testing.T) {
			enc, err := encodeText(bomb, typ, 0, "", 0)
			if err != nil {
				t.Fatalf("encode: %v", err)
			}
			if len(enc) > 1<<20 {
				t.Fatalf("%s did not compress the zeros: %d bytes of transport", typ, len(enc))
			}
			if _, err := decodeTextLimited(enc, typ, 0, "", 0, 1<<20); err == nil {
				t.Fatalf("%s inflated 32 MiB under a 1 MiB limit", typ)
			}
			// The same stream is fine when the caller asks for the room.
			got, err := decodeText(enc, typ, 0, "", 0)
			if err != nil {
				t.Fatalf("%s: %v", typ, err)
			}
			if len(got) != len(bomb) {
				t.Fatalf("%s: got %d bytes, want %d", typ, len(got), len(bomb))
			}
		})
	}
}

// TestMagicDoesNotGuessHeaderlessCompression pins the reason deflate, LZMA and
// Brotli are held out of magic's search while gzip, zlib, zstd, xz and bzip2
// are not: the first three have no signature, so their decoders accept
// arbitrary bytes and magic would report the noise as a finding.
func TestMagicDoesNotGuessHeaderlessCompression(t *testing.T) {
	tried := map[string]bool{}
	for _, name := range magicCodecs() {
		tried[name] = true
	}
	for _, name := range []string{"deflate", "lzma", "brotli"} {
		if tried[name] {
			t.Errorf("magic tries %q, which has no signature to check", name)
		}
	}
	for _, name := range []string{"gzip", "zlib", "zstd", "xz", "bzip2"} {
		if !tried[name] {
			t.Errorf("magic skips %q, which has a signature its decoder checks", name)
		}
	}
}
