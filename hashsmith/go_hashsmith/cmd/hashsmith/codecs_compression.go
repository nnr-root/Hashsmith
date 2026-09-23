package main

import (
	"compress/bzip2"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"errors"
	"io"

	"github.com/andybalholm/brotli"
	dsnetbzip2 "github.com/dsnet/compress/bzip2"
	"github.com/klauspost/compress/zstd"
	"github.com/ulikunitz/xz"
	"github.com/ulikunitz/xz/lzma"
)

// ── Compression codecs ────────────────────────────────────────────────────────
//
// Everything the encode/decode commands treat as a compression format goes
// through these two constructors, so a format is added in one place and gets
// the Base64 transport, the expansion ceiling and the round-trip test for
// free.
//
// The ceiling matters more here than anywhere else in the catalogue. A
// compressed stream is an instruction to allocate, and the ratios these
// formats reach are the reason `decodeCompressed` refuses to inflate past a
// caller-supplied limit rather than reading to EOF: 64 MiB of zeros is about
// 250 bytes of zstd, and a few hundred bytes of xz will happily ask for a
// gigabyte.

// compressWriter returns the writer for a compression codec. Closing it
// flushes the format's trailer, so every caller must Close before reading the
// buffer — a truncated stream is the classic bug here and it does not show up
// on small inputs, where the whole thing lands in the trailer anyway.
func compressWriter(typ string, w io.Writer) (io.WriteCloser, error) {
	switch typ {
	case "gzip":
		return gzip.NewWriter(w), nil
	case "zlib":
		return zlib.NewWriter(w), nil
	case "deflate":
		return flate.NewWriter(w, flate.DefaultCompression)
	case "brotli":
		return brotli.NewWriter(w), nil
	case "zstd":
		return zstd.NewWriter(w)
	case "xz":
		return xz.NewWriter(w)
	case "lzma":
		return lzma.NewWriter(w)
	case "bzip2":
		// The standard library's bzip2 is a decompressor only, which is why
		// this one format needs an outside package to go both ways.
		return dsnetbzip2.NewWriter(w, nil)
	default:
		return nil, errors.New("unsupported compression type " + typ)
	}
}

// decompressReader returns the reader for a compression codec.
//
// The formats disagree about whether their reader is a Closer, so the ones
// that are not get wrapped: the caller closes exactly one thing and does not
// have to know which format it is holding.
func decompressReader(typ string, r io.Reader) (io.ReadCloser, error) {
	switch typ {
	case "gzip":
		return gzip.NewReader(r)
	case "zlib":
		return zlib.NewReader(r)
	case "deflate":
		return flate.NewReader(r), nil
	case "brotli":
		return io.NopCloser(brotli.NewReader(r)), nil
	case "zstd":
		d, err := zstd.NewReader(r)
		if err != nil {
			return nil, err
		}
		return d.IOReadCloser(), nil
	case "xz":
		zr, err := xz.NewReader(r)
		if err != nil {
			return nil, err
		}
		return io.NopCloser(zr), nil
	case "lzma":
		lr, err := lzma.NewReader(r)
		if err != nil {
			return nil, err
		}
		return io.NopCloser(lr), nil
	case "bzip2":
		// Decompression is the standard library's, even though compression is
		// not: there is no reason to carry an outside decoder for a format Go
		// already reads.
		return io.NopCloser(bzip2.NewReader(r)), nil
	default:
		return nil, errors.New("unsupported compression type " + typ)
	}
}

// compressionCodecs is the set encode/decode route through the two
// constructors above. It is the single list the CLI switches consult, so a
// format added to the constructors is wired by adding its name here.
var compressionCodecs = map[string]bool{
	"gzip": true, "zlib": true, "deflate": true, "brotli": true,
	"zstd": true, "xz": true, "lzma": true, "bzip2": true,
}
