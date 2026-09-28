package smith

// Credential files from appliances and web applications: pfSense, Oracle
// APEX, Adobe AEM, Gitea.
//
// None of these is an encrypted container. Each is a configuration file or a
// database dump holding hashes that were already crackable — what was missing
// was the reading, and in three of the four the reading is where the record
// gets its structure wrong if nobody is careful.

import (
	"bufio"
	"encoding/base64"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
)

// ── pfSense and OPNsense ──────────────────────────────────────────────────────

func runExtractPfSense(args []string) error {
	return runFileRecordExtractor("sense2smith", args, extractPfSenseRecords)
}

type pfSenseConfig struct {
	Users []struct {
		Name       string `xml:"name"`
		BcryptHash string `xml:"bcrypt-hash"`
		MD5Hash    string `xml:"md5-hash"`
		Password   string `xml:"password"`
	} `xml:"system>user"`
}

// extractPfSenseRecords reads a pfSense or OPNsense config.xml.
//
// A user element may carry any of three password fields, and which one is
// present says which era the account is from: <bcrypt-hash> is current,
// <md5-hash> is what pfSense stored before 2.3, and <password> is older still.
// All three are emitted as they stand — each is already a record this tool
// reads — and a user may carry more than one, because an upgrade adds the new
// field without removing the old, and the OLD one is still a way in.
func extractPfSenseRecords(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var doc pfSenseConfig
	if err := xml.NewDecoder(f).Decode(&doc); err != nil {
		return nil, errors.New("this file is not a pfSense or OPNsense configuration")
	}
	var records []string
	for _, u := range doc.Users {
		for _, h := range []string{u.BcryptHash, u.MD5Hash, u.Password} {
			if h = strings.TrimSpace(h); h != "" {
				records = append(records, h)
			}
		}
	}
	if len(records) == 0 {
		return nil, errors.New("no user in this configuration carries a stored password")
	}
	return records, nil
}

// ── Oracle APEX ───────────────────────────────────────────────────────────────

func runExtractAPEX(args []string) error {
	return runFileRecordExtractor("apex2smith", args, extractAPEXRecords)
}

// extractAPEXRecords reads an APEX credential export.
//
// The file is three comma-separated fields: a user name, a digest, and the
// workspace's security group id. The salt is the SECURITY GROUP ID FOLLOWED BY
// THE USER NAME, concatenated with no separator — so the record's second field
// is built from two of the file's three columns, in an order the file does not
// state. Reversing them gives a record that parses and never cracks.
func extractAPEXRecords(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var records []string
	s := bufio.NewScanner(f)
	for s.Scan() {
		fields := strings.Split(s.Text(), ",")
		if len(fields) != 3 {
			continue
		}
		user := strings.TrimSpace(fields[0])
		digest := strings.TrimSpace(fields[1])
		group := strings.TrimSpace(fields[2])
		if user == "" || group == "" || len(digest) != 32 || !isHex(digest) {
			continue
		}
		// dynamic_1 is md5($p.$s), so the concatenation is the salt.
		records = append(records, "$dynamic_1$"+strings.ToLower(digest)+"$"+group+user)
	}
	if err := s.Err(); err != nil {
		return nil, err
	}
	if len(records) == 0 {
		return nil, errors.New("no APEX rows found; each line should be user,hash,security-group-id")
	}
	return records, nil
}

// ── Adobe AEM ─────────────────────────────────────────────────────────────────

func runExtractAEM(args []string) error {
	return runFileRecordExtractor("aem2smith", args, extractAEMRecords)
}

// aemAlgorithms maps the tag a line carries to the number the record uses.
var aemAlgorithms = map[string]int{"{SHA-256}": 3, "{SHA-512}": 4}

// extractAEMRecords reads Adobe AEM's stored password lines.
//
// A line is [user:]{SHA-256}<salt>-<iterations>-<digest>, and the record is
// $sspr$<algorithm>$<iterations>$<salt>$<digest>. The ORDER CHANGES: the file
// puts the salt first and the iteration count second, the record the other way
// round. Copying the fields across in the order they appear produces a record
// whose iteration count is a salt, which fails without saying why.
func extractAEMRecords(path string) ([]string, error) {
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
		user := ""
		if name, rest, ok := strings.Cut(line, ":"); ok && strings.HasPrefix(rest, "{") {
			user, line = name+":", rest
		}
		algorithm := 0
		for tag, id := range aemAlgorithms {
			if strings.HasPrefix(line, tag) {
				algorithm, line = id, line[len(tag):]
				break
			}
		}
		if algorithm == 0 {
			continue
		}
		parts := strings.Split(line, "-")
		if len(parts) != 3 {
			continue
		}
		salt, iterations, digest := parts[0], parts[1], parts[2]
		if _, err := strconv.Atoi(iterations); err != nil {
			continue
		}
		if !isHex(salt) || !isHex(digest) {
			continue
		}
		records = append(records, fmt.Sprintf("%s$sspr$%d$%s$%s$%s",
			user, algorithm, iterations, salt, digest))
	}
	if err := s.Err(); err != nil {
		return nil, err
	}
	if len(records) == 0 {
		return nil, errors.New("no AEM password lines found; each should look like {SHA-256}<salt>-<iterations>-<digest>")
	}
	return records, nil
}

// ── Gitea ─────────────────────────────────────────────────────────────────────

func runExtractGitea(args []string) error {
	return runFileRecordExtractor("gitea2smith", args, extractGiteaRecords)
}

// giteaKeyBytes is how much of the derived key the record keeps. Gitea stores
// fifty bytes and the record carries thirty-two, because that is the width the
// PBKDF2-HMAC-SHA256 reader checks.
const giteaKeyBytes = 32

// extractGiteaRecords reads a dump of Gitea's user table.
//
// A row is name:salt:passwd:passwd_hash_algo, where the algorithm column is
// itself structured — "pbkdf2$50000$50" — and the iteration count has to be
// taken out of it. The two hash columns are HEX in the database and BASE64 in
// the record, which is the one conversion that has to happen and the one that
// looks like it does not: both spellings are ASCII, so a record carrying the
// hex would look perfectly well-formed.
func extractGiteaRecords(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var records []string
	s := bufio.NewScanner(f)
	for s.Scan() {
		// sqlite3's default output separates columns with "|".
		line := strings.ReplaceAll(strings.TrimSpace(s.Text()), "|", ":")
		fields := strings.Split(line, ":")
		if len(fields) != 4 {
			continue
		}
		saltHex, digestHex, algorithm := fields[1], fields[2], fields[3]

		parts := strings.Split(algorithm, "$")
		if len(parts) < 2 || parts[0] != "pbkdf2" {
			continue
		}
		iterations, err := strconv.Atoi(parts[1])
		if err != nil || iterations < 1 {
			continue
		}
		salt, err := hex.DecodeString(saltHex)
		if err != nil || len(salt) == 0 {
			continue
		}
		digest, err := hex.DecodeString(digestHex)
		if err != nil || len(digest) < giteaKeyBytes {
			continue
		}
		records = append(records, fmt.Sprintf("$pbkdf2-sha256$%d$%s$%s",
			iterations,
			base64.StdEncoding.EncodeToString(salt),
			base64.StdEncoding.EncodeToString(digest[:giteaKeyBytes])))
	}
	if err := s.Err(); err != nil {
		return nil, err
	}
	if len(records) == 0 {
		return nil, errors.New("no Gitea rows found; each should be name:salt:passwd:passwd_hash_algo with a pbkdf2 algorithm")
	}
	return records, nil
}
