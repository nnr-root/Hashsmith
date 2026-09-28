package smith

// Deep sniffers: the escape hatch for a container whose signature is not in
// the leading sniffHeadBytes that sniffContainer's fast path reads. Each one
// does its own bounded I/O and is tried only after every ordinary sniff in
// the registry has already come up empty — see sniffContainer in sniff.go.
//
// Every check below reuses the exact fields and constants the extractor
// itself validates (geliMagic, pgpSDAMagic/pgpSDAHeaderSize,
// pgpWDEUserInfoSize/pgpWDEMagic/pgpWDEUserWithSym), just windowed to a
// bounded read instead of the extractor's own read of the whole file or a
// full megabyte — the same rule sniff.go's existing sniffers already follow.
// A real container outside that window is a false NEGATIVE for sniffing
// (never a false positive) and is still reachable by naming the extractor
// directly, same as any other unsniffed extractor.

import (
	"bytes"
	"encoding/binary"
	"io"
	"os"

	"hashsmith-go/internal/hashid"
)

// sniffTailBytes covers GELI's metadata block with headroom: extractGELIRecords
// itself only reads the provider's last 1024 bytes.
const sniffTailBytes = 4096

// sniffPGPSDATailBytes bounds the trailer scan for PGP SDA's appended
// archive. extractPGPSDARecords scans the whole host file; this scans only
// the last megabyte so a plain `identify` on a large image stays fast.
const sniffPGPSDATailBytes = 1 << 20

func readTail(path string, n int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	size := info.Size()
	if n > size {
		n = size
	}
	if n <= 0 {
		return nil, nil
	}
	buf := make([]byte, n)
	if _, err := f.ReadAt(buf, size-n); err != nil && err != io.EOF {
		return nil, err
	}
	return buf, nil
}

func readHeadUpTo(path string, n int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	buf := make([]byte, n)
	read, err := io.ReadFull(f, buf)
	if err != nil && err != io.ErrUnexpectedEOF && err != io.EOF {
		return nil, err
	}
	return buf[:read], nil
}

// sniffGELIDeep looks for "GEOM::ELI" in the provider's last sniffTailBytes.
// A bare magic match is Likely; one whose following version field is also in
// GELI's valid 0-7 range is Certain — the same first check
// extractGELIRecords itself performs before trusting a candidate block.
func sniffGELIDeep(path string) (hashid.Evidence, hashid.Confidence, bool) {
	tail, err := readTail(path, sniffTailBytes)
	if err != nil || tail == nil {
		return "", 0, false
	}
	i := bytes.LastIndex(tail, []byte(geliMagic))
	if i < 0 {
		return "", 0, false
	}
	if len(tail)-i >= 20 {
		version := binary.LittleEndian.Uint32(tail[i+16 : i+20])
		if version <= 7 {
			return "GELI metadata magic \"GEOM::ELI\" near the end of the file, with a valid version field",
				hashid.Certain, true
		}
	}
	return "GELI metadata magic \"GEOM::ELI\" near the end of the file", hashid.Likely, true
}

// sniffPGPSDADeep replicates extractPGPSDARecords' own two checks — the
// magic and the in-file offset sanity check — over the file's last
// sniffPGPSDATailBytes instead of the whole file.
func sniffPGPSDADeep(path string) (hashid.Evidence, hashid.Confidence, bool) {
	info, err := os.Stat(path)
	if err != nil {
		return "", 0, false
	}
	tail, err := readTail(path, sniffPGPSDATailBytes)
	if err != nil || tail == nil {
		return "", 0, false
	}
	for i := 0; i+pgpSDAHeaderSize <= len(tail); i++ {
		h := tail[i : i+pgpSDAHeaderSize]
		if string(h[:6]) != pgpSDAMagic {
			continue
		}
		if int64(binary.LittleEndian.Uint32(h[6:10])) >= info.Size() {
			continue
		}
		return "SDAHEADER magic \"PGPSDA\" near the end of the file, with a valid in-file offset field",
			hashid.Certain, true
	}
	return "", 0, false
}

// sniffPGPWDEDeep replicates extractPGPWDERecords' own five-field compound
// check (record size 512, version 0, magic, user kind, record index 0) over
// the file's first pgpWDEScan bytes — the same budget the extractor itself
// uses, so this never scans less than the extractor would find a record in.
func sniffPGPWDEDeep(path string) (hashid.Evidence, hashid.Confidence, bool) {
	head, err := readHeadUpTo(path, pgpWDEScan)
	if err != nil {
		return "", 0, false
	}
	for i := 0; i+pgpWDEUserInfoSize <= len(head); i++ {
		u := head[i : i+pgpWDEUserInfoSize]
		if binary.LittleEndian.Uint16(u[0:2]) != 512 || u[2] != 0 ||
			binary.LittleEndian.Uint32(u[4:8]) != pgpWDEMagic || u[9] != 0 {
			continue
		}
		if u[3] != pgpWDEUserWithSym {
			continue
		}
		return "PGP WDE user record (size 512, version 0, magic, symmetric-key kind, index 0) " +
			"found within the first megabyte", hashid.Certain, true
	}
	return "", 0, false
}
