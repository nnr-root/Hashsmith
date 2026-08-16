package main

import (
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"regexp"
	"unicode/utf16"
)

// ── MS Office document extraction (office2smith) ───────────────────────────────
//
// Parses an encrypted OOXML file (.docx/.xlsx/.pptx), which is an OLE Compound
// File (CFB) holding an "EncryptionInfo" stream and an "EncryptedPackage"
// stream. For agile encryption (Office 2013+) the EncryptionInfo is XML; the
// verifier fields are extracted into the $office$ hash the crack module reads.

var cfbSignature = []byte{0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1}

func extractOffice(path string) (*zipHashResult, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("cannot read %q: %w", path, err)
	}
	if len(data) < 512 || !bytesEqual(data[:8], cfbSignature) {
		return nil, errors.New("not an encrypted Office document (missing OLE/CFB signature)")
	}

	info, err := cfbReadStream(data, "EncryptionInfo")
	if err != nil {
		return nil, err
	}
	if len(info) < 8 {
		return nil, errors.New("EncryptionInfo stream too short")
	}
	verMajor := binary.LittleEndian.Uint16(info[0:2])
	verMinor := binary.LittleEndian.Uint16(info[2:4])

	switch {
	case verMajor == 4 && verMinor == 4:
		// Agile encryption (Office 2013+): XML descriptor after the 8-byte header.
		return officeAgileFromXML(info[8:], path)
	case verMinor == 2 && (verMajor == 3 || verMajor == 4):
		// Standard encryption: 3.2 = Office 2007, 4.2 = Office 2010.
		return officeStandardFromBinary(info, verMajor, path)
	}
	return nil, fmt.Errorf("unsupported Office EncryptionInfo version %d.%d", verMajor, verMinor)
}

// officeAgileFromXML parses the agile EncryptionInfo XML and builds the hash.
func officeAgileFromXML(xml []byte, path string) (*zipHashResult, error) {
	s := string(xml)
	// The <encryptedKey> element (in the <keyEncryptor>) holds the password verifier.
	keyElem := sliceElement(s, "encryptedKey")
	if keyElem == "" {
		return nil, errors.New("no <encryptedKey> element found (not password-encrypted?)")
	}

	spinCount := attrInt(keyElem, "spinCount")
	keyBits := attrInt(keyElem, "keyBits")
	saltB64 := attrStr(keyElem, "saltValue")
	verifierB64 := attrStr(keyElem, "encryptedVerifierHashInput")
	verifierHashB64 := attrStr(keyElem, "encryptedVerifierHashValue")
	if saltB64 == "" || verifierB64 == "" || verifierHashB64 == "" {
		return nil, errors.New("agile EncryptionInfo missing verifier fields")
	}

	salt, err := base64.StdEncoding.DecodeString(saltB64)
	if err != nil {
		return nil, fmt.Errorf("invalid saltValue: %w", err)
	}
	verifier, err := base64.StdEncoding.DecodeString(verifierB64)
	if err != nil {
		return nil, fmt.Errorf("invalid encryptedVerifierHashInput: %w", err)
	}
	verifierHash, err := base64.StdEncoding.DecodeString(verifierHashB64)
	if err != nil {
		return nil, fmt.Errorf("invalid encryptedVerifierHashValue: %w", err)
	}

	hash := fmt.Sprintf("$office$*2013*%d*%d*%d*%s*%s*%s",
		spinCount, keyBits, len(salt),
		hex.EncodeToString(salt),
		hex.EncodeToString(verifier),
		hex.EncodeToString(verifierHash))
	return &zipHashResult{
		hashType: "office",
		hash:     hash,
		filename: path,
		encLabel: fmt.Sprintf("MS Office 2013+ agile (SHA-512, AES-%d, %d spins)", keyBits, spinCount),
	}, nil
}

// officeStandardFromBinary parses the binary EncryptionInfo of a standard-
// encryption (2007/2010) document: an EncryptionHeader followed by an
// EncryptionVerifier (MS-OFFCRYPTO §2.3.4.5/§2.3.3).
func officeStandardFromBinary(info []byte, verMajor uint16, path string) (*zipHashResult, error) {
	if len(info) < 12 {
		return nil, errors.New("standard EncryptionInfo too short")
	}
	headerSize := int(binary.LittleEndian.Uint32(info[8:12]))
	hdrStart := 12
	if hdrStart+headerSize > len(info) {
		return nil, errors.New("standard EncryptionInfo header exceeds stream")
	}
	hdr := info[hdrStart : hdrStart+headerSize]
	// EncryptionHeader: flags(4) sizeExtra(4) algID(4) algIDHash(4) keySize(4) ...
	if len(hdr) < 20 {
		return nil, errors.New("standard EncryptionHeader too short")
	}
	keyBits := int(binary.LittleEndian.Uint32(hdr[16:20]))
	if keyBits == 0 {
		keyBits = 128
	}

	// EncryptionVerifier follows the header.
	v := info[hdrStart+headerSize:]
	if len(v) < 4 {
		return nil, errors.New("standard EncryptionVerifier missing")
	}
	saltSize := int(binary.LittleEndian.Uint32(v[0:4]))
	p := 4
	if p+saltSize+16+4 > len(v) {
		return nil, errors.New("standard EncryptionVerifier truncated")
	}
	salt := v[p : p+saltSize]
	p += saltSize
	encVerifier := v[p : p+16]
	p += 16
	verifierHashSize := int(binary.LittleEndian.Uint32(v[p : p+4]))
	p += 4
	// The stored encrypted verifier hash is padded up to a cipher-block multiple.
	encHashLen := ((verifierHashSize + 15) / 16) * 16
	if p+encHashLen > len(v) {
		encHashLen = len(v) - p
	}
	encVerifierHash := v[p : p+encHashLen]

	version := 2007
	if verMajor == 4 {
		version = 2010
	}
	// office2john/hashcat store the verifier-hash size for 2007 and the spin
	// count for 2010 in field 2.
	field2 := verifierHashSize
	if version == 2010 {
		field2 = 100000
	}

	hash := fmt.Sprintf("$office$*%d*%d*%d*%d*%s*%s*%s",
		version, field2, keyBits, saltSize,
		hex.EncodeToString(salt),
		hex.EncodeToString(encVerifier),
		hex.EncodeToString(encVerifierHash))
	return &zipHashResult{
		hashType: "office",
		hash:     hash,
		filename: path,
		encLabel: fmt.Sprintf("MS Office %d standard (SHA-1, AES-%d)", version, keyBits),
	}, nil
}

// ── Tiny XML attribute helpers (the descriptor is simple, flat XML) ─────────────

// sliceElement returns the text of the first "<name ...>" start tag.
func sliceElement(s, name string) string {
	re := regexp.MustCompile(`<(?:\w+:)?` + name + `\b[^>]*>`)
	return re.FindString(s)
}

func attrStr(elem, attr string) string {
	re := regexp.MustCompile(attr + `="([^"]*)"`)
	m := re.FindStringSubmatch(elem)
	if m == nil {
		return ""
	}
	return m[1]
}

func attrInt(elem, attr string) int {
	return atoiDefault(attrStr(elem, attr), 0)
}

// ── Minimal OLE Compound File (CFB) reader ──────────────────────────────────────

type cfbReader struct {
	data         []byte
	sectorSize   int
	miniSize     int
	miniCutoff   uint32
	fat          []uint32
	dir          []byte
	miniFAT      []uint32
	miniStream   []byte
}

const (
	cfbFreeSector    = 0xFFFFFFFF
	cfbEndOfChain    = 0xFFFFFFFE
	cfbEntryStream   = 2
	cfbEntryRoot     = 5
	cfbDirEntrySize  = 128
)

// cfbReadStream returns the bytes of the named stream from a CFB container.
func cfbReadStream(data []byte, name string) ([]byte, error) {
	r, err := newCFBReader(data)
	if err != nil {
		return nil, err
	}
	return r.readNamedStream(name)
}

func newCFBReader(data []byte) (*cfbReader, error) {
	r := &cfbReader{data: data}
	r.sectorSize = 1 << binary.LittleEndian.Uint16(data[30:32])
	r.miniSize = 1 << binary.LittleEndian.Uint16(data[32:34])
	r.miniCutoff = binary.LittleEndian.Uint32(data[56:60])
	if r.sectorSize != 512 && r.sectorSize != 4096 {
		return nil, fmt.Errorf("unsupported CFB sector size %d", r.sectorSize)
	}

	// Assemble the FAT from the DIFAT (first 109 entries live in the header;
	// encrypted Office files are small enough to stay within them).
	numDIFAT := int(binary.LittleEndian.Uint32(data[72:76]))
	if numDIFAT > 0 {
		return nil, errors.New("CFB DIFAT extension sectors not supported (file unusually large)")
	}
	for i := 0; i < 109; i++ {
		off := 76 + i*4
		sect := binary.LittleEndian.Uint32(data[off : off+4])
		if sect == cfbFreeSector || sect == cfbEndOfChain {
			continue
		}
		fatSector, err := r.sector(sect)
		if err != nil {
			return nil, err
		}
		for j := 0; j+4 <= len(fatSector); j += 4 {
			r.fat = append(r.fat, binary.LittleEndian.Uint32(fatSector[j:j+4]))
		}
	}

	// Directory stream.
	firstDir := binary.LittleEndian.Uint32(data[48:52])
	dir, err := r.readChain(firstDir)
	if err != nil {
		return nil, err
	}
	r.dir = dir

	// Mini-FAT.
	firstMiniFAT := binary.LittleEndian.Uint32(data[60:64])
	if firstMiniFAT != cfbEndOfChain && firstMiniFAT != cfbFreeSector {
		mf, err := r.readChain(firstMiniFAT)
		if err != nil {
			return nil, err
		}
		for j := 0; j+4 <= len(mf); j += 4 {
			r.miniFAT = append(r.miniFAT, binary.LittleEndian.Uint32(mf[j:j+4]))
		}
	}

	// Mini-stream container = the Root Entry's stream (directory entry 0).
	if len(r.dir) >= cfbDirEntrySize {
		rootStart := binary.LittleEndian.Uint32(r.dir[116:120])
		if rootStart != cfbEndOfChain && rootStart != cfbFreeSector {
			ms, err := r.readChain(rootStart)
			if err != nil {
				return nil, err
			}
			r.miniStream = ms
		}
	}
	return r, nil
}

// sector returns the raw bytes of regular sector n.
func (r *cfbReader) sector(n uint32) ([]byte, error) {
	start := 512 + int(n)*r.sectorSize
	if start < 0 || start+r.sectorSize > len(r.data) {
		return nil, fmt.Errorf("CFB sector %d out of range", n)
	}
	return r.data[start : start+r.sectorSize], nil
}

// readChain follows a FAT sector chain and returns the concatenated bytes.
func (r *cfbReader) readChain(start uint32) ([]byte, error) {
	var out []byte
	cur := start
	for cur != cfbEndOfChain && cur != cfbFreeSector {
		if int(cur) >= len(r.fat) {
			return nil, errors.New("CFB FAT chain out of range")
		}
		sec, err := r.sector(cur)
		if err != nil {
			return nil, err
		}
		out = append(out, sec...)
		cur = r.fat[cur]
		if len(out) > 64<<20 {
			return nil, errors.New("CFB chain too large")
		}
	}
	return out, nil
}

// readMiniChain follows a mini-FAT chain inside the mini-stream.
func (r *cfbReader) readMiniChain(start uint32, size int) ([]byte, error) {
	var out []byte
	cur := start
	for cur != cfbEndOfChain && cur != cfbFreeSector && len(out) < size {
		off := int(cur) * r.miniSize
		if off+r.miniSize > len(r.miniStream) {
			return nil, errors.New("CFB mini-sector out of range")
		}
		out = append(out, r.miniStream[off:off+r.miniSize]...)
		if int(cur) >= len(r.miniFAT) {
			break
		}
		cur = r.miniFAT[cur]
	}
	if size <= len(out) {
		return out[:size], nil
	}
	return out, nil
}

// readNamedStream finds a directory entry by name and returns its stream bytes.
func (r *cfbReader) readNamedStream(name string) ([]byte, error) {
	for off := 0; off+cfbDirEntrySize <= len(r.dir); off += cfbDirEntrySize {
		entry := r.dir[off : off+cfbDirEntrySize]
		nameLen := int(binary.LittleEndian.Uint16(entry[64:66]))
		if nameLen < 2 {
			continue
		}
		entryType := entry[66]
		if entryType != cfbEntryStream && entryType != cfbEntryRoot {
			continue
		}
		u16 := make([]uint16, (nameLen-2)/2)
		for i := range u16 {
			u16[i] = binary.LittleEndian.Uint16(entry[i*2 : i*2+2])
		}
		if string(utf16.Decode(u16)) != name {
			continue
		}
		start := binary.LittleEndian.Uint32(entry[116:120])
		size := int(binary.LittleEndian.Uint64(entry[120:128]))
		if uint32(size) < r.miniCutoff {
			return r.readMiniChain(start, size)
		}
		full, err := r.readChain(start)
		if err != nil {
			return nil, err
		}
		if size <= len(full) {
			return full[:size], nil
		}
		return full, nil
	}
	return nil, fmt.Errorf("stream %q not found in Office document", name)
}
