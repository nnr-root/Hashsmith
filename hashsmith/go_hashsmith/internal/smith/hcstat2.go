package smith

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/ulikunitz/xz/lzma"
)

// hcstat2 is hashcat's positional Markov statistics file format. See
// docs/superpowers/specs/2026-09-25-hcstat2-markov-design.md §2 for the full
// derivation of every constant and the byte layout below — it was validated
// against a real file produced by hashcat-utils' own hcstat2gen.c, not
// assumed from documentation.
const (
	hcstat2CharSize = 256
	hcstat2PWMax    = 256
	hcstat2RootCnt  = hcstat2PWMax * hcstat2CharSize
	hcstat2MarkovCnt = hcstat2PWMax * hcstat2CharSize * hcstat2CharSize
	// hcstat2FileSize is the exact decompressed size: two 8-byte header
	// words (magic + zero padding) plus the root and markov tables, each
	// entry a big-endian uint64.
	hcstat2FileSize = 8 + 8 + hcstat2RootCnt*8 + hcstat2MarkovCnt*8
	// hcstat2Magic is "hcstat" followed by 0x00 0x02 (version 2), read as
	// one big-endian uint64.
	hcstat2Magic = 0x6863737461740002
	// hcstat2LZMAProps is the raw-LZMA1 properties byte (lc=1, lp=3, pb=0)
	// hashcat hardcodes for every .hcstat2 file it reads — any file it can
	// open was necessarily compressed with these exact parameters.
	hcstat2LZMAProps = 0x1c
	// hcstat2LZMADictCap matches the dictionary size xz's -9e preset uses;
	// it only needs to be at least as large as what encoding actually used.
	hcstat2LZMADictCap = 1 << 26
)

// hcstat2Tables holds the decoded root and markov count tables — see the
// design doc's table in §2 for what each index means.
type hcstat2Tables struct {
	root   [hcstat2PWMax][hcstat2CharSize]uint64
	markov [hcstat2PWMax][hcstat2CharSize][hcstat2CharSize]uint64
}

// decodeHCStat2 decompresses and parses a .hcstat2 file's raw on-disk bytes.
// The file is a headerless raw LZMA1 stream, so a synthetic 13-byte
// LZMA_ALONE-style header (properties + dict size + the exact known output
// size) is prepended in memory before handing it to lzma.Reader, which
// expects that header and has no other way to learn these parameters.
func decodeHCStat2(compressed []byte) (*hcstat2Tables, error) {
	header := make([]byte, 13)
	header[0] = hcstat2LZMAProps
	binary.LittleEndian.PutUint32(header[1:5], hcstat2LZMADictCap)
	binary.LittleEndian.PutUint64(header[5:13], uint64(hcstat2FileSize))

	r, err := lzma.NewReader(io.MultiReader(bytes.NewReader(header), bytes.NewReader(compressed)))
	if err != nil {
		return nil, fmt.Errorf("hcstat2: %w", err)
	}
	raw := make([]byte, hcstat2FileSize)
	if _, err := io.ReadFull(r, raw); err != nil {
		return nil, fmt.Errorf("hcstat2: decompression failed (not a valid .hcstat2 file?): %w", err)
	}

	if magic := binary.BigEndian.Uint64(raw[0:8]); magic != hcstat2Magic {
		return nil, errors.New("hcstat2: bad magic — not a version-2 hcstat file")
	}
	if binary.BigEndian.Uint64(raw[8:16]) != 0 {
		return nil, errors.New("hcstat2: bad header padding")
	}

	t := &hcstat2Tables{}
	off := 16
	for pos := 0; pos < hcstat2PWMax; pos++ {
		for b := 0; b < hcstat2CharSize; b++ {
			t.root[pos][b] = binary.BigEndian.Uint64(raw[off : off+8])
			off += 8
		}
	}
	for pos := 0; pos < hcstat2PWMax; pos++ {
		for prev := 0; prev < hcstat2CharSize; prev++ {
			for next := 0; next < hcstat2CharSize; next++ {
				t.markov[pos][prev][next] = binary.BigEndian.Uint64(raw[off : off+8])
				off += 8
			}
		}
	}
	return t, nil
}

// loadHCStat2Tables reads and decodes the .hcstat2 file at path.
func loadHCStat2Tables(path string) (*hcstat2Tables, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return decodeHCStat2(data)
}
