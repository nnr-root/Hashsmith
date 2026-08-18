package main

// luks2smith — turn a LUKS v1 volume (or its first ~2 MB) into a crackable
// $luks$ line by parsing the on-disk header and one active keyslot.

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
)

const luksActiveMagic = 0x00AC71F3

// runExtractLUKS implements `luks2smith -f <volume.luks>`.
func runExtractLUKS(args []string) error {
	fs := flag.NewFlagSet("luks2smith", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	filePath := fs.String("f", "", "LUKS volume path")
	outFile := fs.String("o", "", "write hash to file")
	copyRes := fs.Bool("c", false, "copy hash to clipboard")
	if err := parseArgsFlexible(fs, args); err != nil {
		return err
	}
	if *filePath == "" && len(fs.Args()) > 0 {
		*filePath = fs.Args()[0]
	}
	if *filePath == "" {
		return errors.New("luks2smith requires -f <luks-volume>")
	}

	hash, info, err := extractLUKSHash(*filePath)
	if err != nil {
		return err
	}
	preview := hash
	if len(preview) > 60 {
		preview = preview[:60] + "…"
	}
	fmt.Fprintf(os.Stderr, "\n%s %s\n", accentSprint("LUKS:  "), info)
	fmt.Fprintf(os.Stderr, "%s %s\n\n", accentSprint("Hash:  "), preview)
	return outputResult(hash, *outFile, *copyRes)
}

// extractLUKSHash reads a LUKS v1 header and its first active keyslot and
// returns a $luks$ hash string plus a human-readable summary.
func extractLUKSHash(path string) (string, string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", "", fmt.Errorf("cannot open %q: %w", path, err)
	}
	defer f.Close()

	head := make([]byte, 592)
	if _, err := io.ReadFull(f, head); err != nil {
		return "", "", errors.New("cannot read LUKS header")
	}
	if !bytes.Equal(head[0:6], []byte{'L', 'U', 'K', 'S', 0xba, 0xbe}) {
		return "", "", errors.New("not a LUKS volume (bad magic)")
	}
	if binary.BigEndian.Uint16(head[6:8]) != 1 {
		return "", "", errors.New("only LUKS version 1 is supported")
	}

	cstr := func(b []byte) string { return strings.SplitN(string(b), "\x00", 2)[0] }
	cipherName := cstr(head[8:40])
	cipherMode := cstr(head[40:72])
	hashSpec := cstr(head[72:104])
	keyBytes := int(binary.BigEndian.Uint32(head[108:112]))
	mkDigest := head[112:132]
	mkSalt := head[132:164]
	mkIter := binary.BigEndian.Uint32(head[164:168])

	// Find the first active keyslot (8 slots of 48 bytes from offset 208).
	for i := 0; i < 8; i++ {
		ks := head[208+i*48 : 208+i*48+48]
		if binary.BigEndian.Uint32(ks[0:4]) != luksActiveMagic {
			continue
		}
		slotIter := binary.BigEndian.Uint32(ks[4:8])
		slotSalt := ks[8:40]
		kmo := int(binary.BigEndian.Uint32(ks[40:44]))
		stripes := int(binary.BigEndian.Uint32(ks[44:48]))

		material := make([]byte, keyBytes*stripes)
		if _, err := f.ReadAt(material, int64(kmo)*512); err != nil {
			return "", "", fmt.Errorf("cannot read keyslot %d material: %w", i, err)
		}

		hashStr := strings.Join([]string{
			"$luks$1",
			hashSpec, cipherName, cipherMode,
			fmt.Sprint(keyBytes),
			hex.EncodeToString(mkDigest),
			hex.EncodeToString(mkSalt),
			fmt.Sprint(mkIter),
			fmt.Sprint(slotIter),
			hex.EncodeToString(slotSalt),
			fmt.Sprint(stripes),
			hex.EncodeToString(material),
		}, "$")
		info := fmt.Sprintf("%s / %s / %s, key %d bytes, slot %d", cipherName, cipherMode, hashSpec, keyBytes, i)
		return hashStr, info, nil
	}
	return "", "", errors.New("no active LUKS keyslot found")
}
