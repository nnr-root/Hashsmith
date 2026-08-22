package main

// Password Safe v3 (.psafe3) — John's "pwsafe" format, Hashcat mode 5200.
//
// The v3 header stores a stretched key rather than the password:
//
//	P' = SHA-256 applied ITER times to SHA-256($pass . $salt)
//	stored = SHA-256(P')
//
// Verification therefore costs ITER+2 SHA-256 compressions and touches none of
// the encrypted database, which is why the header alone is enough to crack.
//
// Record: $pwsafe$*3*<salt hex>*<iterations>*<stored hash hex>

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
)

type pwsafeHash struct {
	salt       []byte
	iterations int
	digest     []byte
}

func parsePwsafeHash(target string) (*pwsafeHash, error) {
	if !strings.HasPrefix(target, "$pwsafe$*") {
		return nil, errors.New("invalid Password Safe hash (missing $pwsafe$ prefix)")
	}
	f := strings.Split(target[len("$pwsafe$*"):], "*")
	if len(f) != 4 {
		return nil, errors.New("invalid Password Safe hash (need version*salt*iterations*digest)")
	}
	if f[0] != "3" {
		return nil, errors.New("unsupported Password Safe version: " + f[0])
	}
	out := &pwsafeHash{}
	var err error
	if out.salt, err = hex.DecodeString(f[1]); err != nil || len(out.salt) != 32 {
		return nil, errors.New("invalid Password Safe salt (need 32 bytes)")
	}
	if out.iterations, err = strconv.Atoi(f[2]); err != nil || out.iterations < 1 || out.iterations > maxKDFIterations {
		return nil, errors.New("invalid Password Safe iteration count")
	}
	if out.digest, err = hex.DecodeString(f[3]); err != nil || len(out.digest) != sha256.Size {
		return nil, errors.New("invalid Password Safe digest (need 32 bytes)")
	}
	return out, nil
}

// pwsafeStretch derives P' — the stretched key the header commits to.
func pwsafeStretch(password string, salt []byte, iterations int) []byte {
	h := sha256.New()
	_, _ = h.Write([]byte(password))
	_, _ = h.Write(salt)
	key := h.Sum(nil)
	for i := 0; i < iterations; i++ {
		sum := sha256.Sum256(key)
		key = sum[:]
	}
	return key
}

func verifyPwsafe(targetHash, candidate string) (bool, error) {
	p, err := parsePwsafeHash(targetHash)
	if err != nil {
		return false, err
	}
	stretched := pwsafeStretch(candidate, p.salt, p.iterations)
	got := sha256.Sum256(stretched)
	return subtle.ConstantTimeCompare(got[:], p.digest) == 1, nil
}

func isPwsafe(s string) bool {
	_, err := parsePwsafeHash(s)
	return err == nil
}

// ── pwsafe2smith ──────────────────────────────────────────────────────────────

// The v3 header is fixed-layout and unencrypted: a 4-byte tag, a 32-byte salt,
// a 4-byte little-endian iteration count, then the 32-byte stretched-key hash.
const (
	pwsafeTag        = "PWS3"
	pwsafeHeaderSize = 4 + 32 + 4 + 32
)

func extractPwsafeHash(path string) (string, string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", "", err
	}
	defer f.Close()

	header := make([]byte, pwsafeHeaderSize)
	if _, err := io.ReadFull(f, header); err != nil {
		return "", "", errors.New("not a Password Safe v3 database (file is too short)")
	}
	if string(header[:4]) != pwsafeTag {
		return "", "", errors.New("not a Password Safe v3 database (missing PWS3 tag)")
	}
	salt := header[4:36]
	iterations := binary.LittleEndian.Uint32(header[36:40])
	if iterations == 0 || iterations > maxKDFIterations {
		return "", "", fmt.Errorf("implausible Password Safe iteration count: %d", iterations)
	}
	digest := header[40:72]

	hash := fmt.Sprintf("$pwsafe$*3*%s*%d*%s",
		hex.EncodeToString(salt), iterations, hex.EncodeToString(digest))
	info := fmt.Sprintf("Password Safe v3, %d stretch iterations", iterations)
	return hash, info, nil
}

func runExtractPwsafe(args []string) error {
	fs := flag.NewFlagSet("pwsafe2smith", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	filePath := fs.String("f", "", "Password Safe database path")
	outFile := fs.String("o", "", "write hash to file")
	copyRes := fs.Bool("c", false, "copy hash to clipboard")
	if err := parseArgsFlexible(fs, args); err != nil {
		return err
	}
	if *filePath == "" && len(fs.Args()) > 0 {
		*filePath = fs.Args()[0]
	}
	if *filePath == "" {
		return errors.New("pwsafe2smith requires -f <database.psafe3>")
	}

	hash, info, err := extractPwsafeHash(*filePath)
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "\n%s %s\n", accentSprint("PwSafe:"), info)
	fmt.Fprintf(os.Stderr, "%s %s\n\n", accentSprint("Hash:  "), hash)
	return outputResult(hash, *outFile, *copyRes)
}
