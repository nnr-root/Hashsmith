package main

// pfx2smith — turn a PKCS#12 keystore (.p12 / .pfx) into a crackable record.
//
// Only the MAC envelope is needed: the digest algorithm, the MAC salt, the
// iteration count, the stored MAC, and the authenticated-safe bytes the MAC
// covers.  The encrypted key material is copied verbatim into the record but is
// never decrypted here.

import (
	"encoding/asn1"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"crypto/x509/pkix"
)

type pfxPDU struct {
	Version  int
	AuthSafe pfxContentInfo
	MacData  pfxMacData `asn1:"optional"`
}

type pfxContentInfo struct {
	ContentType asn1.ObjectIdentifier
	Content     asn1.RawValue `asn1:"tag:0,explicit,optional"`
}

type pfxMacData struct {
	Mac        pfxDigestInfo
	MacSalt    []byte
	Iterations int `asn1:"optional,default:1"`
}

type pfxDigestInfo struct {
	Algorithm pkix.AlgorithmIdentifier
	Digest    []byte
}

// Digest OIDs a PKCS#12 MAC may name.
var pkcs12DigestOIDs = map[string]string{
	"1.3.14.3.2.26":           "sha1",
	"2.16.840.1.101.3.4.2.1":  "sha256",
	"2.16.840.1.101.3.4.2.2":  "sha384",
	"2.16.840.1.101.3.4.2.3":  "sha512",
	"2.16.840.1.101.3.4.2.10": "sha3-512",
}

func extractPKCS12Hash(path string) (string, string, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", "", err
	}
	var pfx pfxPDU
	if _, err := asn1.Unmarshal(raw, &pfx); err != nil {
		return "", "", fmt.Errorf("not a PKCS#12 file: %w", err)
	}
	if pfx.MacData.Iterations == 0 {
		// A PFX with no MacData is unauthenticated; there is no password to
		// recover from the MAC envelope.
		return "", "", errors.New("this PKCS#12 file carries no MAC — nothing to crack")
	}
	algorithm, ok := pkcs12DigestOIDs[pfx.MacData.Mac.Algorithm.Algorithm.String()]
	if !ok {
		return "", "", errors.New("unsupported PKCS#12 MAC digest: " + pfx.MacData.Mac.Algorithm.Algorithm.String())
	}
	if _, supported := pkcs12MACAlgorithms[algorithm]; !supported {
		return "", "", errors.New("unsupported PKCS#12 MAC digest: " + algorithm)
	}

	// The MAC covers the contents of the authenticated safe's OCTET STRING,
	// not its DER header.
	var content []byte
	if _, err := asn1.Unmarshal(pfx.AuthSafe.Content.Bytes, &content); err != nil {
		return "", "", fmt.Errorf("malformed PKCS#12 authenticated safe: %w", err)
	}

	hash := fmt.Sprintf("$pfx$*%s*%d*%s*%s*%s",
		algorithm, pfx.MacData.Iterations,
		hex.EncodeToString(pfx.MacData.MacSalt),
		hex.EncodeToString(pfx.MacData.Mac.Digest),
		hex.EncodeToString(content))
	info := fmt.Sprintf("PKCS#12, MAC %s, %d iterations, %d bytes protected",
		algorithm, pfx.MacData.Iterations, len(content))
	return hash, info, nil
}

func runExtractPKCS12(args []string) error {
	fs := flag.NewFlagSet("pfx2smith", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	filePath := fs.String("f", "", "PKCS#12 keystore path")
	outFile := fs.String("o", "", "write hash to file")
	copyRes := fs.Bool("c", false, "copy hash to clipboard")
	if err := parseArgsFlexible(fs, args); err != nil {
		return err
	}
	if *filePath == "" && len(fs.Args()) > 0 {
		*filePath = fs.Args()[0]
	}
	if *filePath == "" {
		return errors.New("pfx2smith requires -f <keystore.pfx>")
	}

	hash, info, err := extractPKCS12Hash(*filePath)
	if err != nil {
		return err
	}
	preview := hash
	if len(preview) > 60 {
		preview = preview[:60] + "…"
	}
	fmt.Fprintf(os.Stderr, "\n%s %s\n", accentSprint("PKCS#12:"), info)
	fmt.Fprintf(os.Stderr, "%s %s\n\n", accentSprint("Hash:   "), preview)
	return outputResult(hash, *outFile, *copyRes)
}
