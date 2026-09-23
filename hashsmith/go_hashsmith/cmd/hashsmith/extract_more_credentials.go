package main

// Three more converters: IBM i scanner output, Mosquitto's password file, and
// an encrypted PKCS#8 key in the spelling John and hashcat use.

import (
	"bufio"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
)

// ── IBM i (AS/400) scanner output ─────────────────────────────────────────────

func runExtractIBMiScanner(args []string) error {
	return runFileRecordExtractor("ibmiscanner2smith", args, extractIBMiScannerRecords)
}

// extractIBMiScannerRecords converts a line of `user:hash` into an AS/400
// record.
//
// The user name is the SALT as well as the label, so it appears twice in the
// record: once before the colon, where it names the account, and once at the
// end, where it is hashed. Dropping either copy gives a file that looks right
// and either loses the account name or cannot crack.
func extractIBMiScannerRecords(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var records []string
	s := bufio.NewScanner(f)
	for s.Scan() {
		line := strings.TrimSpace(s.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		user, digest, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		user, digest = strings.TrimSpace(user), strings.TrimSpace(digest)
		if user == "" || len(digest) != 40 || !isHex(digest) {
			continue
		}
		records = append(records, user+":$as400ssha1$"+strings.ToUpper(digest)+"$"+user)
	}
	if err := s.Err(); err != nil {
		return nil, err
	}
	if len(records) == 0 {
		return nil, errors.New("no IBM i rows found; each line should be user:40-hex-digit-hash")
	}
	return records, nil
}

// ── Mosquitto ─────────────────────────────────────────────────────────────────

func runExtractMosquitto(args []string) error {
	return runFileRecordExtractor("mosquitto2smith", args, extractMosquittoRecords)
}

// extractMosquittoRecords reads an MQTT broker's password file.
//
// Mosquitto has used two schemes and the file says which by a single digit: a
// leading $6$ is a plain salted SHA-512, a leading $7$ is PBKDF2-HMAC-SHA512
// with an iteration count. They become DIFFERENT records — a dynamic
// expression and a PBKDF2 one — so the digit cannot be skipped over.
//
// Both store their salt and digest in BASE64 where both records want hex.
func extractMosquittoRecords(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	unb64 := func(s string) (string, bool) {
		raw, err := base64.StdEncoding.DecodeString(s)
		if err != nil || len(raw) == 0 {
			return "", false
		}
		return strings.ToUpper(hex.EncodeToString(raw)), true
	}

	var records []string
	s := bufio.NewScanner(f)
	for s.Scan() {
		line := strings.TrimSpace(s.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		user, body, ok := strings.Cut(line, ":")
		if !ok || user == "" || !strings.HasPrefix(body, "$") {
			continue
		}
		f := strings.Split(body, "$")
		switch {
		case len(f) == 5 && f[1] == "7": // PBKDF2-HMAC-SHA512
			iterations, err := strconv.Atoi(f[2])
			if err != nil || iterations < 1 {
				continue
			}
			salt, okSalt := unb64(f[3])
			digest, okDigest := unb64(f[4])
			if !okSalt || !okDigest {
				continue
			}
			records = append(records, fmt.Sprintf("%s:$pbkdf2-hmac-sha512$%d.%s.%s",
				user, iterations, salt, digest))

		case len(f) == 4 && f[1] == "6": // salted SHA-512
			salt, okSalt := unb64(f[2])
			digest, okDigest := unb64(f[3])
			if !okSalt || !okDigest {
				continue
			}
			// dynamic_82 is sha512($p.$s); the salt goes in as hex
			// because base64 carries characters a record would read
			// as structure.
			records = append(records, fmt.Sprintf("%s:$dynamic_82$%s$HEX$%s",
				user, strings.ToLower(digest), strings.ToLower(salt)))
		}
	}
	if err := s.Err(); err != nil {
		return nil, err
	}
	if len(records) == 0 {
		return nil, errors.New("no Mosquitto password lines found; each should be user:$6$… or user:$7$…")
	}
	return records, nil
}

// ── Encrypted PKCS#8, in John's spelling ──────────────────────────────────────

func runExtractPEM(args []string) error {
	return runFileRecordExtractor("pem2smith", args, extractPEMRecords)
}

// pemSaltBytes is the only salt length the $PEM$ record can hold. It is not a
// property of PBKDF2, which allows any length; it is a property of the record,
// and of the fixed-size buffers John and hashcat read it into.
const pemSaltBytes = 8

// pemCipherIDs maps a cipher to the number John's $PEM$ record uses. The
// numbering is John's and has no meaning beyond the table.
var pemCipherIDs = map[string]int{
	"des-ede3-cbc": 1,
	"aes-128-cbc":  2,
	"aes-192-cbc":  3,
	"aes-256-cbc":  4,
}

// extractPEMRecords converts an encrypted PKCS#8 key into the $PEM$ spelling.
//
// ssh2smith already reads these files, but it writes Hashsmith's own $pkcs8$
// record. This writes John and hashcat's, from the same bytes, so a key
// extracted here can be handed to either tool.
//
// The $PEM$ spelling is narrower than the file it describes, in two ways that
// both refuse rather than mislead here.
//
// It carries no PRF field: $PEM$1 MEANS PBKDF2-HMAC-SHA1, which was the only
// choice when the format was written. And its salt is fixed at eight bytes —
// John hard-codes SALTLEN 8 and hashcat's kernels do the same — where PBKDF2
// allows any length and OpenSSL 3 writes sixteen.
//
// So a key from a current OpenSSL cannot be expressed as $PEM$ AT ALL, by
// either tool. Hashsmith's own $pkcs8$ record, which ssh2smith writes, names
// the PRF and carries a salt of any length, and reads those keys. That is why
// both refusals point at ssh2smith instead of emitting a record that would
// parse and never crack.
func extractPEMRecords(path string) ([]string, error) {
	text, err := readExtractorFile(path)
	if err != nil {
		return nil, err
	}
	der, err := decodePEMBody(string(text), "ENCRYPTED PRIVATE KEY")
	if err != nil {
		return nil, errors.New("this file holds no ENCRYPTED PRIVATE KEY block; an unencrypted key has no password to find")
	}

	var epki encryptedPrivateKeyInfo
	if _, err := asn1.Unmarshal(der, &epki); err != nil {
		return nil, fmt.Errorf("cannot parse the PKCS#8 structure: %w", err)
	}
	if !epki.Algo.Algorithm.Equal(oidPBES2) {
		return nil, errors.New("this key does not use PBES2, which is the only scheme the $PEM$ record describes")
	}
	var params pbes2Params
	if _, err := asn1.Unmarshal(epki.Algo.Parameters.FullBytes, &params); err != nil {
		return nil, fmt.Errorf("cannot parse the PBES2 parameters: %w", err)
	}
	if !params.KDF.Algorithm.Equal(oidPBKDF2) {
		return nil, errors.New("this key does not use PBKDF2")
	}
	var kdf pbkdf2Params
	if _, err := asn1.Unmarshal(params.KDF.Parameters.FullBytes, &kdf); err != nil {
		return nil, fmt.Errorf("cannot parse the PBKDF2 parameters: %w", err)
	}

	// An absent PRF means SHA-1 by RFC 8018's default, which is exactly what
	// the $PEM$1 record means.
	if prf := prfName(kdf.PRF.Algorithm); kdf.PRF.Algorithm != nil && prf != "sha1" {
		return nil, fmt.Errorf("this key stretches with PBKDF2-HMAC-%s, and the $PEM$1 record has no field for that; use ssh2smith, whose record names the PRF",
			strings.ToUpper(prf))
	}
	if len(kdf.Salt) != pemSaltBytes {
		return nil, fmt.Errorf("this key has a %d-byte salt and the $PEM$ record has room for exactly %d; OpenSSL 3 writes sixteen, so most current keys cannot be written this way at all — use ssh2smith, whose record carries a salt of any length",
			len(kdf.Salt), pemSaltBytes)
	}
	cipherName, _, err := pkcs8CipherName(params.EncScheme.Algorithm)
	if err != nil {
		return nil, err
	}
	cipherID, ok := pemCipherIDs[cipherName]
	if !ok {
		return nil, fmt.Errorf("the $PEM$ record has no number for %s", cipherName)
	}
	var iv []byte
	if _, err := asn1.Unmarshal(params.EncScheme.Parameters.FullBytes, &iv); err != nil {
		return nil, fmt.Errorf("cannot parse the cipher IV: %w", err)
	}
	if kdf.Iter < 1 {
		return nil, errors.New("this key states no iteration count")
	}
	return []string{fmt.Sprintf("$PEM$1$%d$%s$%d$%s$%d$%s",
		cipherID, hex.EncodeToString(kdf.Salt), kdf.Iter,
		hex.EncodeToString(iv), len(epki.Data), hex.EncodeToString(epki.Data))}, nil
}
