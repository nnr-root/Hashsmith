package main

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

// ── 7-Zip constants ───────────────────────────────────────────────────────────

var sevenZMagic = [6]byte{0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C}
var aesCodecID = []byte{0x06, 0xF1, 0x07, 0x01}

// ── RAR constants ─────────────────────────────────────────────────────────────

var rar4Magic = []byte{0x52, 0x61, 0x72, 0x21, 0x1A, 0x07, 0x00}
var rar5Magic = []byte{0x52, 0x61, 0x72, 0x21, 0x1A, 0x07, 0x01, 0x00}

// ── CLI entries ───────────────────────────────────────────────────────────────

func runExtract7z(args []string) error {
	fs := flag.NewFlagSet("7z2smith", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	filePath := fs.String("f", "", "7z file path")
	outFile := fs.String("o", "", "write hash to file")
	copyRes := fs.Bool("c", false, "copy hash to clipboard")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *filePath == "" {
		return errors.New("7z2smith requires -f <7z-file>")
	}
	res, err := extract7z(*filePath)
	if err != nil {
		return err
	}
	printExtractResult(res)
	return outputResult(res.hash, *outFile, *copyRes)
}

func runExtractRAR(args []string) error {
	fs := flag.NewFlagSet("rar2smith", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	filePath := fs.String("f", "", "RAR file path")
	outFile := fs.String("o", "", "write hash to file")
	copyRes := fs.Bool("c", false, "copy hash to clipboard")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *filePath == "" {
		return errors.New("rar2smith requires -f <rar-file>")
	}
	res, err := extractRAR(*filePath)
	if err != nil {
		return err
	}
	printExtractResult(res)
	return outputResult(res.hash, *outFile, *copyRes)
}

func runExtractPDF(args []string) error {
	fs := flag.NewFlagSet("pdf2smith", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	filePath := fs.String("f", "", "PDF file path")
	outFile := fs.String("o", "", "write hash to file")
	copyRes := fs.Bool("c", false, "copy hash to clipboard")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *filePath == "" {
		return errors.New("pdf2smith requires -f <pdf-file>")
	}
	res, err := extractPDF(*filePath)
	if err != nil {
		return err
	}
	printExtractResult(res)
	return outputResult(res.hash, *outFile, *copyRes)
}

// ── Auto-detect dispatcher ────────────────────────────────────────────────────

// extractArchiveHash auto-detects the archive format by extension and delegates.
func extractArchiveHash(path string) (*zipHashResult, error) {
	switch strings.ToLower(filepath.Ext(path)) {
	case ".zip":
		return extractZipHash(path)
	case ".7z":
		return extract7z(path)
	case ".rar":
		return extractRAR(path)
	case ".pdf":
		return extractPDF(path)
	default:
		// Sniff the magic bytes to handle misnamed files.
		f, err := os.Open(path)
		if err != nil {
			return nil, err
		}
		magic := make([]byte, 8)
		n, _ := f.Read(magic)
		f.Close()
		magic = magic[:n]
		switch {
		case len(magic) >= 4 && binary.LittleEndian.Uint32(magic) == 0x04034b50:
			return extractZipHash(path)
		case bytes.HasPrefix(magic, sevenZMagic[:]):
			return extract7z(path)
		case bytes.HasPrefix(magic, rar5Magic):
			return extractRAR(path)
		case bytes.HasPrefix(magic, rar4Magic[:7]):
			return extractRAR(path)
		case len(magic) >= 4 && string(magic[:4]) == "%PDF":
			return extractPDF(path)
		default:
			return nil, errors.New("unsupported archive format (use .zip, .7z, .rar, or .pdf)")
		}
	}
}

// ── 7-Zip extraction ──────────────────────────────────────────────────────────

// extract7z parses a 7-Zip file and returns a crackable hash for AES-256 archives.
//
// Hash format: $7z$<numCyclesPower>$<salt_hex>$<iv_hex>$<crc_hex>$<dataLen>$<data_hex>
//
// The encrypted data blob and CRC come from the encoded/packed header region.
// The KDF uses a rolling SHA-256 accumulation (2^numCyclesPower rounds).
func extract7z(path string) (*zipHashResult, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("cannot open %q: %w", path, err)
	}
	defer f.Close()

	// ── SignatureHeader (32 bytes) ────────────────────────────────────────────
	var sig [6]byte
	if _, err := io.ReadFull(f, sig[:]); err != nil {
		return nil, errors.New("cannot read 7z signature")
	}
	if sig != sevenZMagic {
		return nil, errors.New("not a 7-zip file")
	}

	// skip version (2 bytes) + startHeaderCRC (4 bytes)
	if _, err := f.Seek(6, io.SeekCurrent); err != nil {
		return nil, err
	}

	var nextHeaderOffset, nextHeaderSize uint64
	var nextHeaderCRC uint32
	if err := binary.Read(f, binary.LittleEndian, &nextHeaderOffset); err != nil {
		return nil, err
	}
	if err := binary.Read(f, binary.LittleEndian, &nextHeaderSize); err != nil {
		return nil, err
	}
	if err := binary.Read(f, binary.LittleEndian, &nextHeaderCRC); err != nil {
		return nil, err
	}

	// ── Encrypted data snapshot (at byte 32, before the header) ──────────────
	// For archives with encrypted file content: the packed stream starts at 32.
	// For archives with encrypted headers: the encoded header starts at 32.
	const snapLen = 32
	encSnap := make([]byte, snapLen)
	nSnap, _ := f.Read(encSnap)
	encSnap = encSnap[:nSnap]

	// ── Read the header blob ─────────────────────────────────────────────────
	headerOff := int64(32) + int64(nextHeaderOffset)
	if _, err := f.Seek(headerOff, io.SeekStart); err != nil {
		return nil, fmt.Errorf("cannot seek to 7z header: %w", err)
	}
	if nextHeaderSize > 64<<20 {
		return nil, errors.New("7z header too large (> 64 MiB)")
	}
	headerBuf := make([]byte, nextHeaderSize)
	if _, err := io.ReadFull(f, headerBuf); err != nil {
		return nil, fmt.Errorf("cannot read 7z header: %w", err)
	}

	// ── Find AES codec and parse properties ───────────────────────────────────
	aesIdx := bytes.Index(headerBuf, aesCodecID)
	if aesIdx < 0 {
		return nil, errors.New("no AES codec found — archive may not be password-protected")
	}

	// After the 4-byte codec ID: properties-size byte (VINT, single byte for <128)
	propOff := aesIdx + 4
	if propOff >= len(headerBuf) {
		return nil, errors.New("truncated 7z AES codec properties")
	}
	propsSize := int(headerBuf[propOff])
	propOff++
	if propOff+propsSize > len(headerBuf) || propsSize < 2 {
		return nil, errors.New("invalid 7z AES properties length")
	}
	props := headerBuf[propOff : propOff+propsSize]

	// Properties byte 0: bits 0-5 = numCyclesPower; bits 6-7 reserved
	// Properties byte 1: bits 4-7 = saltLen; bits 0-3 = (ivLen - 1)
	numCyclesPower := props[0] & 0x3F
	saltLen := int((props[1] >> 4) & 0x0F)
	ivLen := int(props[1]&0x0F) + 1

	if 2+saltLen+ivLen > len(props) {
		return nil, errors.New("7z AES properties: salt/iv exceed property block")
	}
	salt := props[2 : 2+saltLen]
	iv := props[2+saltLen : 2+saltLen+ivLen]

	// Pad IV to 16 bytes (AES block size).
	ivPadded := make([]byte, 16)
	copy(ivPadded, iv)

	// CRC of the next-header: used for verification after decryption.
	crcBuf := make([]byte, 4)
	binary.BigEndian.PutUint32(crcBuf, nextHeaderCRC)

	hash := fmt.Sprintf("$7z$%d$%s$%s$%s$%d$%s",
		numCyclesPower,
		hex.EncodeToString(salt),
		hex.EncodeToString(ivPadded),
		hex.EncodeToString(crcBuf),
		nextHeaderOffset,
		hex.EncodeToString(encSnap))

	return &zipHashResult{
		hashType: "7z",
		hash:     hash,
		filename: path,
		encLabel: fmt.Sprintf("7-Zip AES-256 (2^%d KDF rounds)", numCyclesPower),
	}, nil
}

// ── RAR extraction ────────────────────────────────────────────────────────────

// extractRAR detects RAR4 vs RAR5 by magic bytes and dispatches accordingly.
func extractRAR(path string) (*zipHashResult, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("cannot open %q: %w", path, err)
	}
	defer f.Close()

	magic := make([]byte, 8)
	n, err := io.ReadFull(f, magic)
	if err != nil && n < 7 {
		return nil, errors.New("file too small to be a RAR archive")
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return nil, err
	}

	switch {
	case bytes.HasPrefix(magic, rar5Magic):
		return extractRAR5(f)
	case bytes.HasPrefix(magic, rar4Magic):
		return extractRAR4(f)
	default:
		return nil, errors.New("not a RAR archive (invalid magic)")
	}
}

// extractRAR4 extracts a crackable hash from an AES-encrypted RAR4 archive.
//
// RAR4 with header encryption (-hp) stores 8 bytes of salt immediately after
// the 7-byte signature, followed by the encrypted archive header.
//
// Hash format: $rar3$0$<salt_hex>$<data_hex>
// Where data is the first 16 bytes of the encrypted stream.
func extractRAR4(r io.Reader) (*zipHashResult, error) {
	sig := make([]byte, 7)
	if _, err := io.ReadFull(r, sig); err != nil || !bytes.Equal(sig, rar4Magic) {
		return nil, errors.New("invalid RAR4 signature")
	}

	// 8-byte encryption salt follows the signature (in -hp mode).
	salt := make([]byte, 8)
	if _, err := io.ReadFull(r, salt); err != nil {
		return nil, errors.New("cannot read RAR4 encryption salt — archive may not have header encryption (-hp)")
	}

	// First 16 bytes of the encrypted archive header (first AES block).
	encData := make([]byte, 16)
	if _, err := io.ReadFull(r, encData); err != nil {
		return nil, errors.New("cannot read RAR4 encrypted header block")
	}

	hash := fmt.Sprintf("$rar3$0$%s$%s",
		hex.EncodeToString(salt),
		hex.EncodeToString(encData))

	return &zipHashResult{
		hashType: "rar4",
		hash:     hash,
		filename: "",
		encLabel: "RAR4 AES-128 (header encryption)",
	}, nil
}

// extractRAR5 parses a RAR5 archive to extract PBKDF2 parameters.
//
// RAR5 uses VINT-encoded block records. The CRYPT_HEAD block (type 4) contains
// the password KDF parameters: lgCount (iterations = 2^lgCount), salt (16B),
// and a check value (8B) for fast verification.
//
// Hash format: $rar5$<salt_hex>$<lgcount>$<checkval_hex>
func extractRAR5(r io.Reader) (*zipHashResult, error) {
	sig := make([]byte, 8)
	if _, err := io.ReadFull(r, sig); err != nil || !bytes.Equal(sig, rar5Magic) {
		return nil, errors.New("invalid RAR5 signature")
	}

	// Read up to 4 KiB of blocks looking for CRYPT_HEAD (type 4).
	buf := make([]byte, 4096)
	n, _ := r.Read(buf)
	buf = buf[:n]

	pos := 0
	for pos+4 < len(buf) {
		// Each RAR5 block: header_crc32 (4B) + vint(header_size) + header_type + flags + ...
		// We skip the CRC and read the header.
		pos += 4 // skip CRC

		sz, szBytes := readVINT(buf[pos:])
		if szBytes == 0 || pos+int(sz)+szBytes > len(buf) {
			break
		}
		pos += szBytes

		blockStart := pos
		typ, typBytes := readVINT(buf[pos:])
		if typBytes == 0 {
			break
		}

		if typ == 4 { // CRYPT_HEAD
			p := blockStart + typBytes
			// flags (vint), enc_version (vint), lg_count (vint), salt (16B), check_value (8B)
			_, n1 := readVINT(buf[p:]) // flags
			p += n1
			_, n2 := readVINT(buf[p:]) // enc_version
			p += n2
			lgCount, n3 := readVINT(buf[p:])
			p += n3

			if p+16 > len(buf) {
				return nil, errors.New("RAR5 CRYPT_HEAD: truncated salt")
			}
			salt := make([]byte, 16)
			copy(salt, buf[p:p+16])
			p += 16

			checkVal := make([]byte, 8)
			if p+8 <= len(buf) {
				copy(checkVal, buf[p:p+8])
			}

			hash := fmt.Sprintf("$rar5$%s$%d$%s",
				hex.EncodeToString(salt),
				lgCount,
				hex.EncodeToString(checkVal))

			return &zipHashResult{
				hashType: "rar5",
				hash:     hash,
				filename: "",
				encLabel: fmt.Sprintf("RAR5 AES-256 PBKDF2 (2^%d iterations)", lgCount),
			}, nil
		}

		pos = blockStart + int(sz)
	}

	return nil, errors.New("no CRYPT_HEAD found — RAR5 archive may not be password-protected or uses file-level encryption")
}

// readVINT reads a RAR5 variable-length integer from b.
// Returns (value, bytesConsumed). bytesConsumed=0 on error.
func readVINT(b []byte) (uint64, int) {
	var val uint64
	for i, byt := range b {
		val |= uint64(byt&0x7F) << (7 * uint(i))
		if byt&0x80 == 0 {
			return val, i + 1
		}
		if i >= 9 {
			return 0, 0
		}
	}
	return 0, 0
}

// ── PDF extraction ────────────────────────────────────────────────────────────

// extractPDF parses a PDF file to extract Standard security handler parameters.
//
// It reads the /Encrypt dictionary from the trailer/xref and extracts the
// owner key (/O), user key (/U), revision (/R), permissions (/P), and doc ID.
//
// Hash format: $pdf$<R>$<keylen>$<P>$<id_hex>$<U_hex>$<O_hex>
func extractPDF(path string) (*zipHashResult, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("cannot read %q: %w", path, err)
	}
	if len(data) < 5 || string(data[:4]) != "%PDF" {
		return nil, errors.New("not a PDF file")
	}

	// Find the /Encrypt dictionary by scanning for the marker.
	encDict, err := findPDFEncryptDict(data)
	if err != nil {
		return nil, err
	}

	R := pdfDictInt(encDict, "/R")
	V := pdfDictInt(encDict, "/V")
	P := pdfDictInt(encDict, "/P")

	// Key length in bits: /Length field (default 40 for V=1, 128 for V>=2).
	keyLenBits := pdfDictInt(encDict, "/Length")
	if keyLenBits == 0 {
		if V >= 2 {
			keyLenBits = 128
		} else {
			keyLenBits = 40
		}
	}

	O, err := pdfDictBinary(encDict, "/O")
	if err != nil {
		return nil, fmt.Errorf("PDF /O: %w", err)
	}
	U, err := pdfDictBinary(encDict, "/U")
	if err != nil {
		return nil, fmt.Errorf("PDF /U: %w", err)
	}

	// Document ID: from the /ID array in the trailer.
	docID, _ := pdfExtractDocID(data)

	hash := fmt.Sprintf("$pdf$%d$%d$%d$%s$%s$%s",
		R, keyLenBits, P,
		hex.EncodeToString(docID),
		hex.EncodeToString(U),
		hex.EncodeToString(O))

	revLabel := map[int]string{2: "RC4-40", 3: "RC4-128", 4: "AES-128", 5: "AES-256"}
	label, ok := revLabel[R]
	if !ok {
		label = fmt.Sprintf("revision %d", R)
	}

	return &zipHashResult{
		hashType: "pdf",
		hash:     hash,
		filename: path,
		encLabel: "PDF Standard Encryption " + label,
	}, nil
}

// findPDFEncryptDict locates the /Encrypt dictionary bytes within PDF data.
// It walks from the end of the file, finds the trailer, resolves the /Encrypt
// object reference, and returns the raw dictionary bytes.
func findPDFEncryptDict(data []byte) (string, error) {
	// Find "trailer" near end of file.
	trailerIdx := bytes.LastIndex(data, []byte("trailer"))
	if trailerIdx < 0 {
		// Try cross-reference stream (PDF 1.5+) — look for /Encrypt directly.
		return pdfScanEncryptDirect(data)
	}

	trailerSection := data[trailerIdx:]
	dictStart := bytes.Index(trailerSection, []byte("<<"))
	dictEnd := bytes.Index(trailerSection, []byte(">>"))
	if dictStart < 0 || dictEnd < 0 {
		return "", errors.New("cannot parse PDF trailer dictionary")
	}
	trailerDict := string(trailerSection[dictStart : dictEnd+2])

	// Get /Encrypt object reference (e.g. "5 0 R").
	encRef := pdfDictValue(trailerDict, "/Encrypt")
	if encRef == "" {
		return "", errors.New("PDF is not encrypted (no /Encrypt in trailer)")
	}

	// Resolve the object reference and return the dictionary.
	return pdfResolveObj(data, strings.TrimSpace(encRef))
}

// pdfScanEncryptDirect searches the file for an inline /Encrypt dictionary.
func pdfScanEncryptDirect(data []byte) (string, error) {
	idx := bytes.Index(data, []byte("/Encrypt"))
	if idx < 0 {
		return "", errors.New("PDF is not encrypted (no /Encrypt found)")
	}
	// Find the surrounding << ... >>
	start := bytes.LastIndex(data[:idx], []byte("<<"))
	if start < 0 {
		start = idx
	}
	end := bytes.Index(data[start:], []byte(">>"))
	if end < 0 {
		return "", errors.New("cannot locate PDF /Encrypt dictionary bounds")
	}
	return string(data[start : start+end+2]), nil
}

// pdfResolveObj finds "N G obj ... endobj" in data for the given reference "N G R".
func pdfResolveObj(data []byte, ref string) (string, error) {
	// ref = "5 0 R" → look for "5 0 obj"
	parts := strings.Fields(ref)
	if len(parts) < 2 {
		// Might be an inline dict already.
		if strings.HasPrefix(ref, "<<") {
			return ref, nil
		}
		return "", fmt.Errorf("cannot parse PDF object reference %q", ref)
	}
	objMarker := []byte(parts[0] + " " + parts[1] + " obj")
	idx := bytes.Index(data, objMarker)
	if idx < 0 {
		return "", fmt.Errorf("PDF object %q not found", ref)
	}
	objData := data[idx:]
	start := bytes.Index(objData, []byte("<<"))
	end := bytes.Index(objData, []byte(">>"))
	if start < 0 || end < 0 {
		return "", fmt.Errorf("PDF object %q has no dictionary", ref)
	}
	return string(objData[start : end+2]), nil
}

// pdfDictValue returns the raw value string for a key in a PDF dictionary snippet.
func pdfDictValue(dict, key string) string {
	idx := strings.Index(dict, key)
	if idx < 0 {
		return ""
	}
	rest := strings.TrimSpace(dict[idx+len(key):])
	// Value ends at whitespace or / or >
	for i, ch := range rest {
		if ch == '/' || ch == '>' || ch == '\n' || ch == '\r' {
			return strings.TrimSpace(rest[:i])
		}
	}
	return strings.TrimSpace(rest)
}

// pdfDictInt returns an integer value from a PDF dictionary snippet.
func pdfDictInt(dict, key string) int {
	v := pdfDictValue(dict, key)
	n, _ := strconv.Atoi(v)
	return n
}

// pdfDictBinary extracts a binary string value (literal or hex) for key in dict.
// PDF literal strings: (...), hex strings: <...>
func pdfDictBinary(dict, key string) ([]byte, error) {
	idx := strings.Index(dict, key)
	if idx < 0 {
		return nil, fmt.Errorf("key %q not found", key)
	}
	rest := strings.TrimSpace(dict[idx+len(key):])

	if strings.HasPrefix(rest, "<") {
		// Hex string <AABBCC...>
		end := strings.Index(rest, ">")
		if end < 0 {
			return nil, fmt.Errorf("unterminated hex string for %q", key)
		}
		return hex.DecodeString(strings.ReplaceAll(rest[1:end], " ", ""))
	}
	if strings.HasPrefix(rest, "(") {
		// Literal string (...) — decode escapes and return bytes.
		return pdfDecodeLiteralString(rest)
	}
	return nil, fmt.Errorf("unsupported value encoding for %q", key)
}

// pdfDecodeLiteralString decodes a PDF literal string starting with '('.
func pdfDecodeLiteralString(s string) ([]byte, error) {
	depth := 0
	out := make([]byte, 0, 32)
	i := 0
	for i < len(s) {
		ch := s[i]
		if ch == '(' {
			if depth > 0 {
				out = append(out, ch)
			}
			depth++
			i++
			continue
		}
		if depth == 0 {
			i++
			continue
		}
		if ch == ')' {
			depth--
			if depth == 0 {
				break
			}
			out = append(out, ch)
			i++
			continue
		}
		if ch == '\\' && i+1 < len(s) {
			i++
			switch s[i] {
			case 'n':
				out = append(out, '\n')
			case 'r':
				out = append(out, '\r')
			case 't':
				out = append(out, '\t')
			case 'b':
				out = append(out, '\b')
			case 'f':
				out = append(out, '\f')
			case '(':
				out = append(out, '(')
			case ')':
				out = append(out, ')')
			case '\\':
				out = append(out, '\\')
			default:
				if s[i] >= '0' && s[i] <= '7' {
					octal := string(s[i])
					for j := 1; j < 3 && i+j < len(s) && s[i+j] >= '0' && s[i+j] <= '7'; j++ {
						octal += string(s[i+j])
					}
					v, _ := strconv.ParseInt(octal, 8, 16)
					out = append(out, byte(v))
					i += len(octal) - 1
				}
			}
			i++
			continue
		}
		out = append(out, ch)
		i++
	}
	return out, nil
}

// pdfExtractDocID extracts the first element of the /ID array from the trailer.
var pdfIDRegex = regexp.MustCompile(`/ID\s*\[\s*(<[0-9a-fA-F]*>|\([^)]*\))`)

func pdfExtractDocID(data []byte) ([]byte, error) {
	m := pdfIDRegex.Find(data)
	if m == nil {
		return make([]byte, 16), nil // zero ID if not found
	}
	s := string(m)
	ltIdx := strings.LastIndex(s, "<")
	gtIdx := strings.LastIndex(s, ">")
	if ltIdx < 0 || gtIdx <= ltIdx {
		return make([]byte, 16), nil
	}
	b, err := hex.DecodeString(s[ltIdx+1 : gtIdx])
	if err != nil {
		return make([]byte, 16), nil
	}
	return b, nil
}
