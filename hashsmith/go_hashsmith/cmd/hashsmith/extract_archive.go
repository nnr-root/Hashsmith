package main

import (
	"bytes"
	"crypto/aes"
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
	if err := parseArgsFlexible(fs, args); err != nil {
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
	if err := parseArgsFlexible(fs, args); err != nil {
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
	if err := parseArgsFlexible(fs, args); err != nil {
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

func runExtractSSH(args []string) error {
	fs := flag.NewFlagSet("ssh2smith", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	filePath := fs.String("f", "", "SSH private key path")
	outFile := fs.String("o", "", "write hash to file")
	copyRes := fs.Bool("c", false, "copy hash to clipboard")
	if err := parseArgsFlexible(fs, args); err != nil {
		return err
	}
	// Allow the key path as a positional argument too (ssh2smith id_rsa).
	if *filePath == "" && fs.NArg() > 0 {
		*filePath = fs.Arg(0)
	}
	if *filePath == "" {
		return errors.New("ssh2smith requires -f <private-key> (or a path argument)")
	}
	res, err := extractSSHKey(*filePath)
	if err != nil {
		return err
	}
	printExtractResult(res)
	return outputResult(res.hash, *outFile, *copyRes)
}

func runExtractOffice(args []string) error {
	fs := flag.NewFlagSet("office2smith", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	filePath := fs.String("f", "", "encrypted Office document path")
	outFile := fs.String("o", "", "write hash to file")
	copyRes := fs.Bool("c", false, "copy hash to clipboard")
	if err := parseArgsFlexible(fs, args); err != nil {
		return err
	}
	if *filePath == "" && fs.NArg() > 0 {
		*filePath = fs.Arg(0)
	}
	if *filePath == "" {
		return errors.New("office2smith requires -f <docx/xlsx/pptx> (or a path argument)")
	}
	res, err := extractOffice(*filePath)
	if err != nil {
		return err
	}
	printExtractResult(res)
	return outputResult(res.hash, *outFile, *copyRes)
}

func runExtractKeePass(args []string) error {
	fs := flag.NewFlagSet("keepass2smith", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	filePath := fs.String("f", "", "KDBX database path")
	outFile := fs.String("o", "", "write hash to file")
	copyRes := fs.Bool("c", false, "copy hash to clipboard")
	if err := parseArgsFlexible(fs, args); err != nil {
		return err
	}
	if *filePath == "" && fs.NArg() > 0 {
		*filePath = fs.Arg(0)
	}
	if *filePath == "" {
		return errors.New("keepass2smith requires -f <kdbx-file> (or a path argument)")
	}
	res, err := extractKeePass(*filePath)
	if err != nil {
		return err
	}
	printExtractResult(res)
	return outputResult(res.hash, *outFile, *copyRes)
}

func runExtractGPG(args []string) error {
	fs := flag.NewFlagSet("gpg2smith", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	filePath := fs.String("f", "", "gpg-encrypted file path")
	outFile := fs.String("o", "", "write hash to file")
	copyRes := fs.Bool("c", false, "copy hash to clipboard")
	if err := parseArgsFlexible(fs, args); err != nil {
		return err
	}
	if *filePath == "" && fs.NArg() > 0 {
		*filePath = fs.Arg(0)
	}
	if *filePath == "" {
		return errors.New("gpg2smith requires -f <gpg-file> (or a path argument)")
	}
	res, err := extractGPG(*filePath)
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
	case ".pem", ".key":
		return extractSSHKey(path)
	case ".gpg", ".pgp", ".asc":
		return extractGPG(path)
	case ".kdbx", ".kdb":
		return extractKeePass(path)
	case ".docx", ".xlsx", ".pptx", ".doc", ".xls", ".ppt":
		return extractOffice(path)
	default:
		// Sniff the magic bytes to handle misnamed files.
		f, err := os.Open(path)
		if err != nil {
			return nil, err
		}
		magic := make([]byte, 32)
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
		case bytes.Contains(magic, []byte("-----BEGIN")) && bytes.Contains(magic, []byte("PRIVATE KEY")):
			return extractSSHKey(path)
		case len(magic) >= 8 && binary.LittleEndian.Uint32(magic) == kdbxSig1 &&
			binary.LittleEndian.Uint32(magic[4:]) == kdbxSig2:
			return extractKeePass(path)
		case bytes.HasPrefix(magic, cfbSignature):
			return extractOffice(path)
		default:
			return nil, errors.New("unsupported file format (use .zip, .7z, .rar, .pdf, or an SSH private key)")
		}
	}
}

// ── 7-Zip extraction ──────────────────────────────────────────────────────────

// extract7z builds a crackable record from a password-protected 7-Zip archive.
//
// It parses the archive's next-header properly rather than searching it for
// the AES codec ID. The search finds the salt and IV, but not which bytes are
// the ciphertext, how long the plaintext is, or what it should checksum to —
// and without those the old implementation emitted a record that could never
// crack, for any archive 7-Zip actually writes.
//
// Which of two checks a record carries is a property of the archive, not a
// choice:
//
//   - The AES output IS the final data — the coder chain is AES alone, or AES
//     followed only by Copy — and a CRC is recorded for it. Decrypting and
//     checksumming is then a complete test, and the record is written in
//     hashcat's own `$7z$0$…` form, which hashcat -m 11600 reads and cracks.
//     `7z a -mhe=on` and `7z a -m0=Copy` both land here.
//
//   - Anything else. The chain compresses, so the recorded CRC belongs to the
//     DECOMPRESSED bytes and checking it would mean running LZMA per
//     candidate. 7-Zip zero-pads the AES stream to a 16-byte boundary, and
//     those padding bytes are a complete test on their own: the right key
//     leaves zeros, a wrong key leaves noise. This record carries the padding
//     length where hashcat keeps its data-type, so hashcat refuses it outright
//     rather than misreading it — see verify7z for why that field, and note
//     that hashcat's own compressed-7z form was tried here and did not verify.
//
// An archive that offers neither — no usable CRC and too little padding — is
// refused rather than given a record that cannot tell a right password from a
// wrong one.
func extract7z(path string) (*zipHashResult, error) {
	raw, err := readExtractorFile(path)
	if err != nil {
		return nil, err
	}
	if len(raw) < 32 || !bytes.HasPrefix(raw, sevenZMagic[:]) {
		return nil, errors.New("not a 7-zip file")
	}
	nextHeaderOffset := binary.LittleEndian.Uint64(raw[12:20])
	nextHeaderSize := binary.LittleEndian.Uint64(raw[20:28])

	hdrStart := uint64(32) + nextHeaderOffset
	if nextHeaderSize > 64<<20 || hdrStart > uint64(len(raw)) ||
		hdrStart+nextHeaderSize > uint64(len(raw)) {
		return nil, errors.New("7z next-header lies outside the file")
	}
	info, err := parseSevenZipNextHeader(raw[hdrStart : hdrStart+nextHeaderSize])
	if err != nil {
		return nil, err
	}

	folderIdx, coderIdx := findSevenZipAESFolder(info)
	if folderIdx < 0 {
		return nil, errors.New("no AES-encrypted folder found — the archive may not be password-protected")
	}
	folder := info.folders[folderIdx]
	params, err := parseSevenZipAESProps(folder.coders[coderIdx].props)
	if err != nil {
		return nil, err
	}

	// The packed stream this folder reads from. Folders consume the packed
	// streams in order, and a folder may consume more than one, so the offset
	// is the sum of every stream the earlier folders took — not the sum of
	// the first folderIdx sizes, which is the same number only while every
	// folder happens to take exactly one.
	packIdx := 0
	for i := 0; i < folderIdx; i++ {
		packIdx += info.folders[i].numPackedStreams
	}
	if folder.numPackedStreams != 1 {
		return nil, fmt.Errorf("this 7z archive's encrypted folder draws on %d packed streams; "+
			"Hashsmith reads single-stream folders, which is what 7-Zip writes for an "+
			"encrypted archive. Use hashcat -m 11600 with a 7z2john record",
			folder.numPackedStreams)
	}
	if packIdx >= len(info.packSizes) {
		return nil, errors.New("7z folder has no packed stream")
	}
	packStart := uint64(32) + info.packPos
	for i := 0; i < packIdx; i++ {
		packStart += info.packSizes[i]
	}
	packSize := info.packSizes[packIdx]
	if packStart+packSize > uint64(len(raw)) {
		return nil, errors.New("7z packed stream lies outside the file")
	}
	if packSize < aes.BlockSize || packSize%aes.BlockSize != 0 {
		return nil, fmt.Errorf("7z packed stream is %d bytes, not a whole number of AES blocks", packSize)
	}
	if packSize > maxSevenZipRecordBytes {
		return nil, fmt.Errorf("7z packed stream is %d bytes, past the %d-byte limit for a record",
			packSize, maxSevenZipRecordBytes)
	}
	encData := raw[packStart : packStart+packSize]

	// The AES coder's own output size, which is what the padding is measured
	// against. Coder outputs are listed in chain order.
	outIdx := 0
	for i := 0; i < coderIdx; i++ {
		outIdx += folder.coders[i].numOutStreams
	}
	if outIdx >= len(folder.unpackSizes) {
		return nil, errors.New("7z folder is missing the AES coder's output size")
	}
	aesOutSize := folder.unpackSizes[outIdx]
	if aesOutSize > packSize {
		return nil, errors.New("7z AES output is larger than its packed stream")
	}

	// Copy is the identity coder, so a chain of AES followed only by Copy
	// leaves the AES output as the archive's final data — and that is exactly
	// the case where the recorded CRC checks the bytes we can produce.
	plainIsFinal := true
	for i, c := range folder.coders {
		if i != coderIdx && !bytes.Equal(c.id, sevenZipCopyCoderID) {
			plainIsFinal = false
			break
		}
	}
	padding := packSize - aesOutSize

	var p int
	var crc uint32
	switch {
	case plainIsFinal && folder.crcDefined:
		p, crc = 0, folder.crc
	case padding >= minSevenZipPaddingBytes:
		p = int(padding)
	default:
		return nil, fmt.Errorf("this 7z archive offers no way to check a password: "+
			"its AES stream feeds a %d-coder chain, so the recorded CRC covers the "+
			"decompressed bytes, and only %d padding byte(s) remain — too few to tell "+
			"a right password from a wrong one. Use hashcat -m 11600 with a 7z2john record",
			len(folder.coders), padding)
	}

	hash := fmt.Sprintf("$7z$%d$%d$%d$%s$%d$%s$%d$%d$%d$%s",
		p,
		params.numCyclesPower,
		len(params.salt), hex.EncodeToString(params.salt),
		len(params.iv), hex.EncodeToString(params.iv),
		crc,
		packSize,
		aesOutSize,
		hex.EncodeToString(encData))

	label := fmt.Sprintf("7-Zip AES-256 (2^%d KDF rounds, CRC-verified, hashcat -m 11600 compatible)",
		params.numCyclesPower)
	if p != 0 {
		label = fmt.Sprintf("7-Zip AES-256 (2^%d KDF rounds, %d-byte padding check, Hashsmith only)",
			params.numCyclesPower, p)
	}
	return &zipHashResult{
		hashType: "7z",
		hash:     hash,
		filename: path,
		encLabel: label,
	}, nil
}

const (
	// maxSevenZipRecordBytes bounds what goes into a record: the whole
	// encrypted stream is embedded, and a record is a line in a hash file.
	maxSevenZipRecordBytes = 1 << 20
	// minSevenZipPaddingBytes is the least padding that makes the padding
	// check meaningful. Each byte a wrong key has to get right is a factor of
	// 256, so four bytes is about one false positive in four billion — and
	// anything less is refused rather than shipped as a check.
	minSevenZipPaddingBytes = 4
)

// sevenZipCopyCoderID is 7-Zip's Copy coder: it passes its input through
// unchanged, so it does not stand between the AES output and the archive's
// data the way a compressor does.
var sevenZipCopyCoderID = []byte{0x00}

// parseSevenZipNextHeader reads either a plain Header or an EncodedHeader and
// returns the StreamsInfo inside it.
func parseSevenZipNextHeader(hdr []byte) (*sevenZipStreamsInfo, error) {
	if len(hdr) == 0 {
		return nil, errors.New("7z next-header is empty")
	}
	r := &sevenZipReader{b: hdr}
	id, err := r.byteAt()
	if err != nil {
		return nil, err
	}
	switch id {
	case kEncodedHeaderMarker:
		// -mhe=on: the real header is itself a packed, encrypted stream, and
		// this StreamsInfo says where.
		return r.readStreamsInfo()
	case kHeader:
		next, err := r.byteAt()
		if err != nil {
			return nil, err
		}
		for next == kArchiveProperties {
			if next, err = r.byteAt(); err != nil {
				return nil, err
			}
		}
		if next != kMainStreamsInfo {
			return nil, errors.New("7z header has no streams — the archive may hold no encrypted data")
		}
		return r.readStreamsInfo()
	default:
		return nil, fmt.Errorf("7z next-header starts with 0x%02x, which is neither a Header nor an EncodedHeader", id)
	}
}

// findSevenZipAESFolder returns the first folder with an AES coder, and that
// coder's index within the folder, or (-1, -1).
func findSevenZipAESFolder(info *sevenZipStreamsInfo) (int, int) {
	for fi, f := range info.folders {
		for ci, c := range f.coders {
			if bytes.Equal(c.id, sevenZipAESCoderID) {
				return fi, ci
			}
		}
	}
	return -1, -1
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
