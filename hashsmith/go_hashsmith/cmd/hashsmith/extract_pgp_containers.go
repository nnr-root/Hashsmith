package main

// PGP's three encrypted containers: the self-decrypting archive, the virtual
// disk, and whole-disk encryption.
//
// None of the three has a file header that says what it is. Each keeps its
// structure somewhere inside a file whose beginning belongs to something else
// — an executable stub, a partition table, a disk image — so all three are
// found by SCANNING for a structure that validates rather than by reading an
// offset. That is why each extractor below tests several fields at once
// before believing it has found anything: at one candidate offset per byte
// over a megabyte, a one-field test finds false structures constantly.

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
)

// ── PGP self-decrypting archive (SDA) ─────────────────────────────────────────

func runExtractPGPSDA(args []string) error {
	return runFileRecordExtractor("pgpsda2smith", args, extractPGPSDARecords)
}

const (
	pgpSDAMagic      = "PGPSDA"
	pgpSDAHeaderSize = 44
)

// extractPGPSDARecords finds the SDAHEADER appended to a self-decrypting
// archive.
//
// An SDA is an executable with the archive bolted on, so the header is near
// the END of the file and the beginning is a PE or Mach-O stub. The structure
// is packed, little-endian, and laid out as:
//
//	magic[6] offset:u32 compressedLength:u64 fileCount:u64
//	salt[8] iterations:u16 checkBytes[8]
//
// The offset field is used as a sanity check rather than for navigation: it
// must point inside the file, which together with the magic is enough to
// reject the stub's own data.
func extractPGPSDARecords(path string) ([]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if len(data) < pgpSDAHeaderSize {
		return nil, errors.New("this file is too short to hold an SDA header")
	}
	var records []string
	seen := map[string]bool{}
	for i := 0; i+pgpSDAHeaderSize <= len(data); i++ {
		h := data[i : i+pgpSDAHeaderSize]
		if string(h[:6]) != pgpSDAMagic {
			continue
		}
		if int(binary.LittleEndian.Uint32(h[6:10])) >= len(data) {
			continue
		}
		iterations := binary.LittleEndian.Uint16(h[34:36])
		record := fmt.Sprintf("$pgpsda$0*%d*%s*%s", iterations,
			hex.EncodeToString(h[26:34]), hex.EncodeToString(h[36:44]))
		if !seen[record] {
			seen[record] = true
			records = append(records, record)
		}
	}
	if len(records) == 0 {
		return nil, errors.New("no PGPSDA header found in this file")
	}
	return records, nil
}

// ── PGP Virtual Disk (.pgd) ───────────────────────────────────────────────────

func runExtractPGPDisk(args []string) error {
	return runFileRecordExtractor("pgpdisk2smith", args, extractPGPDiskRecords)
}

const (
	pgpDiskMainSize = 356
	pgpDiskUserSize = 312
	pgpDiskScanHead = 4096
	pgpDiskScanUser = 1 << 20
)

// extractPGPDiskRecords reads a PGP Virtual Disk.
//
// This is the two-stage one. The MAIN header carries the salt and the cipher
// but not the iteration count or the check bytes; those live in a USER record
// that the main header points at, and the pointer can reach almost the end of
// the file. So the salt comes from one place and everything it is used with
// comes from another, and a reader that finds only one of the two has nothing.
//
// A disk may carry several users, each with its own iteration count and check
// bytes over the SAME salt. All of them are emitted: they are different
// passwords to the same volume, and any one of them opens it.
func extractPGPDiskRecords(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	head := make([]byte, pgpDiskScanHead)
	n, _ := io.ReadFull(f, head)
	head = head[:n]

	var (
		algorithm  uint32
		salt       []byte
		nextHeader uint64
		found      bool
	)
	for i := 0; i+pgpDiskMainSize <= len(head); i++ {
		h := head[i : i+pgpDiskMainSize]
		if string(h[0:4]) != "PGPd" || string(h[4:8]) != "MAIN" {
			continue
		}
		major := h[32]
		if major != 6 && major != 7 {
			return nil, fmt.Errorf("PGP Virtual Disk major version %d has not been tested; no record is written for it", major)
		}
		algorithm = binary.LittleEndian.Uint32(h[60:64])
		switch algorithm {
		case 3, 4, 5, 6, 7: // CAST5, EME-AES, AES-256, Twofish, EME2-AES
		default:
			return nil, fmt.Errorf("PGP Virtual Disk cipher %d is not one this reads", algorithm)
		}
		salt = h[64:80]
		nextHeader = binary.LittleEndian.Uint64(h[16:24])
		found = true
		break
	}
	if !found {
		return nil, errors.New("no PGPd MAIN header in the first four kilobytes of this file")
	}

	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if nextHeader >= uint64(info.Size()) {
		return nil, errors.New("this disk's MAIN header points past the end of the file")
	}
	users := make([]byte, pgpDiskScanUser)
	n, _ = f.ReadAt(users, int64(nextHeader))
	users = users[:n]

	var records []string
	for i := 0; i+pgpDiskUserSize <= len(users); i++ {
		u := users[i : i+pgpDiskUserSize]
		if string(u[0:4]) != "USER" || string(u[4:8]) != "SYMM" {
			continue
		}
		check := u[288:304]
		// CAST5 uses a 128-bit key and leaves the second half of the
		// check field zero. A record that carried the junk there would
		// still crack, but a non-zero tail means this is not the
		// structure it looks like.
		if algorithm == 3 {
			for _, c := range check[8:] {
				if c != 0 {
					check = nil
					break
				}
			}
			if check == nil {
				continue
			}
		}
		iterations := binary.LittleEndian.Uint16(u[304:306])
		records = append(records, fmt.Sprintf("$pgpdisk$0*%d*%d*%s*%s",
			algorithm, iterations, hex.EncodeToString(salt),
			hex.EncodeToString(u[288:304])))
	}
	if len(records) == 0 {
		return nil, errors.New("this disk's MAIN header was found but no USER/SYMM record followed it")
	}
	return records, nil
}

// ── PGP Whole Disk Encryption ─────────────────────────────────────────────────

func runExtractPGPWDE(args []string) error {
	return runFileRecordExtractor("pgpwde2smith", args, extractPGPWDERecords)
}

const (
	pgpWDEUserInfoSize = 330
	pgpWDEScan         = 1 << 20
	// pgpWDEMagic is 0x57446900, which the on-disk structure carries at a
	// fixed offset and which is the only constant in the record.
	pgpWDEMagic = 0x57446900
	// pgpWDEUserWithSym is the only user-record kind with a passphrase
	// behind it; the others hold a token, a public key or a TPM blob.
	pgpWDEUserWithSym = 0x08
	// pgpWDEESKHexChars is how much of the encrypted session key the record
	// carries. The field on disk is longer; the check needs this much.
	pgpWDEESKHexChars = 256
)

// extractPGPWDERecords reads a PGP WDE (Symantec Encryption Desktop) disk.
//
// There is no offset to follow here and no magic at the start of the file: the
// user records are somewhere in the first megabyte of a whole-disk image, and
// the only way to find one is to test four fields at once — a record size of
// exactly 512, a version of 0, the magic, and a record index of 0. Any one of
// those alone would match constantly over a megabyte of disk.
//
// The iteration field is a LOGARITHM. A value of 17 means 131,072, not
// seventeen, which is worth stating because a record carrying 17 looks like a
// format with almost no work factor and is in fact doing a hundred thousand
// rounds.
func extractPGPWDERecords(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data := make([]byte, pgpWDEScan)
	n, _ := io.ReadFull(f, data)
	data = data[:n]

	var records []string
	seen := map[string]bool{}
	for i := 0; i+pgpWDEUserInfoSize <= len(data); i++ {
		u := data[i : i+pgpWDEUserInfoSize]
		if binary.LittleEndian.Uint16(u[0:2]) != 512 || u[2] != 0 ||
			binary.LittleEndian.Uint32(u[4:8]) != pgpWDEMagic || u[9] != 0 {
			continue
		}
		if u[3] != pgpWDEUserWithSym {
			continue
		}
		symmAlg := u[28]
		s2kType := u[162]
		iterations := binary.LittleEndian.Uint32(u[163:167])
		salt := u[170:186]
		esk := hex.EncodeToString(u[186:])
		if len(esk) > pgpWDEESKHexChars {
			esk = esk[:pgpWDEESKHexChars]
		}
		record := fmt.Sprintf("$pgpwde$0*%d*%d*%d*%s*%s",
			symmAlg, s2kType, iterations, hex.EncodeToString(salt), esk)
		if !seen[record] {
			seen[record] = true
			records = append(records, record)
		}
	}
	if len(records) == 0 {
		return nil, errors.New("no PGP WDE user record found in the first megabyte of this image")
	}
	return records, nil
}
