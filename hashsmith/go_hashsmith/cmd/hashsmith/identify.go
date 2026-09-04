package main

import (
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"io"
	"math"
	"os"
	"regexp"
	"sort"
	"strings"
	"sync"

	"github.com/fatih/color"
)

// ── Compiled regexps (immutable, goroutine-safe) ──────────────────────────────

var (
	reBase64Std = regexp.MustCompile(`^[A-Za-z0-9+/]+=*$`)
	reBase64URL = regexp.MustCompile(`^[A-Za-z0-9_-]+=*$`)
	reBase32Std = regexp.MustCompile(`^[A-Z2-7]+=*$`)
	reBase32Hex = regexp.MustCompile(`^[0-9A-V]+=*$`)
	reBase58Pat = regexp.MustCompile(`^[123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz]+$`)
	reBase62Pat = regexp.MustCompile(`^[0-9A-Za-z]+$`)
	reBcrypt    = regexp.MustCompile(`^\$2[aby]\$\d{2}\$`)
	reArgon2    = regexp.MustCompile(`^\$argon2(i|d|id)\$`)
	reScrypt    = regexp.MustCompile(`(?i)^scrypt(?:\$|:)`)
	rePostgres  = regexp.MustCompile(`^md5[0-9a-fA-F]{32}$`)
	reMySQL41   = regexp.MustCompile(`^\*[0-9a-fA-F]{40}$`)
	reMSSQLNew  = regexp.MustCompile(`(?i)^0x0100[0-9a-fA-F]{48}$`)
	reURLEnc    = regexp.MustCompile(`%[0-9a-fA-F]{2}`)
	reJSONEsc   = regexp.MustCompile(`\\(?:["\\/bfnrt]|u[0-9a-fA-F]{4})`)
	reHexEsc    = regexp.MustCompile(`(?:\\[xX][0-9a-fA-F]{2})`)
	reJWT       = regexp.MustCompile(`^eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*$`)
	reUUID      = regexp.MustCompile(`(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	reNATOSep   = regexp.MustCompile(`[\s,]+`)
)

// English letter frequencies (a–z), used for chi-squared analysis.
var englishFreq = [26]float64{
	8.17, 1.49, 2.78, 4.25, 12.70, 2.23, 2.02, 6.09, 6.97, 0.15,
	0.77, 4.03, 2.41, 6.75, 7.51, 1.93, 0.10, 5.99, 6.33, 9.06,
	2.76, 0.98, 2.36, 0.15, 1.97, 0.07,
}

var entropyPool = sync.Pool{
	New: func() any { return new([256]int) },
}

// ── Types ─────────────────────────────────────────────────────────────────────

type candidate struct {
	name   string
	score  float64 // raw, pre-normalization
	reason string
}

// ── CLI entry ─────────────────────────────────────────────────────────────────

func runIdentify(args []string) error {
	fs := flag.NewFlagSet("identify", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	text := fs.String("i", "", "hash text or file path")
	filePath := fs.String("f", "", "file path (optional; -i also accepts a file)")
	outFile := fs.String("o", "", "output file")
	copyRes := fs.Bool("c", false, "copy to clipboard")
	if err := parseArgsFlexible(fs, args); err != nil {
		return err
	}

	inputs, err := collectIdentifyInputs(*text, *filePath, fs.Args())
	if err != nil {
		return err
	}

	// Identify every input; when more than one is given (a multi-line file)
	// each result is prefixed with the hash it describes.
	var sb strings.Builder
	for i, in := range inputs {
		if len(inputs) > 1 {
			if i > 0 {
				sb.WriteString("\n")
			}
			fmt.Fprintf(&sb, "── %s\n", in)
		}
		sb.WriteString(identifyText(in))
		if len(inputs) > 1 {
			sb.WriteString("\n")
		}
	}
	result := strings.TrimRight(sb.String(), "\n")

	if *outFile == "" && !*copyRes {
		color.New(themeAttr).Fprintln(os.Stdout, result)
		return nil
	}
	return outputResult(result, *outFile, *copyRes)
}

// collectIdentifyInputs resolves the identify target(s). Precedence:
//  1. -f <file>            → every non-empty, non-comment line
//  2. -i <value>           → a file's lines if the value is a readable file,
//     otherwise the literal value itself
//  3. positional argument  → same flexible handling as -i
//
// This lets `-i` accept inline text ('…' / "…") or a file path (hash.txt)
// interchangeably.
func collectIdentifyInputs(iVal, fVal string, positional []string) ([]string, error) {
	if strings.TrimSpace(fVal) != "" {
		return readInputLines(fVal)
	}
	// Gather from the -i value and any positional args, each of which may itself
	// be inline text, a comma-list, or a file path.
	var raw []string
	if strings.TrimSpace(iVal) != "" {
		raw = append(raw, iVal)
	}
	raw = append(raw, positional...)
	if len(raw) == 0 {
		return nil, errors.New("identify requires a hash value, a comma-list, or a file path")
	}
	return gatherInputs(raw)
}

// ── Public API ────────────────────────────────────────────────────────────────

// identifyText returns a confidence-ranked, percentage-annotated identification.
// Format: "%<pct> <name> (<rationale>)", sorted descending, summing to 100.
func identifyText(value string) string {
	cands := scoreCandidates(value)
	if len(cands) == 0 {
		return "%100 Unknown / High Entropy Data"
	}

	total := 0.0
	for _, c := range cands {
		total += c.score
	}
	if cands[0].score/total*100 < 10 {
		return "%100 Unknown / High Entropy Data"
	}

	type row struct {
		name   string
		reason string
		pct    int
		raw    float64
	}
	var rows []row
	sumPct := 0
	for _, c := range cands {
		pct := int(math.Round(c.score / total * 100))
		if pct < 5 {
			continue
		}
		rows = append(rows, row{c.name, c.reason, pct, c.score})
		sumPct += pct
	}
	if len(rows) == 0 {
		return "%100 Unknown / High Entropy Data"
	}

	rows[0].pct += 100 - sumPct

	sort.Slice(rows, func(i, j int) bool {
		if rows[i].pct != rows[j].pct {
			return rows[i].pct > rows[j].pct
		}
		return rows[i].raw > rows[j].raw
	})

	var sb strings.Builder
	for i, e := range rows {
		if i > 0 {
			sb.WriteByte('\n')
		}
		if e.reason != "" {
			fmt.Fprintf(&sb, "%%%d %s (%s)", e.pct, e.name, e.reason)
		} else {
			fmt.Fprintf(&sb, "%%%d %s", e.pct, e.name)
		}
	}
	return sb.String()
}

// ── Scoring engine ────────────────────────────────────────────────────────────

func scoreCandidates(v string) []candidate {
	if v == "" {
		return nil
	}

	// A "user:hash" or raw /etc/shadow line collapses to its crypt-hash field.
	v = stripShadowUsername(v)

	// Level 0 — signature-based (definitive, synchronous)
	if sig := signatureMatch(v); sig != nil {
		return sig
	}

	// Pre-compute shared properties once (O(n) each)
	entropy := shannonEntropy(v)
	lv := len(v)
	hexStr := isHex(v)
	lower := v == strings.ToLower(v)
	upper := v == strings.ToUpper(v)
	hashLenHex := hexStr && knownHashLen(lv)

	// Four parallel analysis groups write candidates to a buffered channel.
	ch := make(chan candidate, 32)
	var wg sync.WaitGroup

	wg.Add(1)
	go func() {
		defer wg.Done()
		scoreHashGroup(v, lv, entropy, hexStr, lower, upper, hashLenHex, ch)
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		scoreEncodingGroup(v, lv, entropy, hexStr, hashLenHex, ch)
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		scoreStructuralGroup(v, entropy, ch)
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		scoreCipherTextGroup(v, lv, entropy, hexStr, ch)
	}()

	go func() {
		wg.Wait()
		close(ch)
	}()

	var cands []candidate
	for c := range ch {
		if c.score > 0 {
			cands = append(cands, c)
		}
	}

	sort.Slice(cands, func(i, j int) bool {
		return cands[i].score > cands[j].score
	})
	return cands
}

// signatureMatch returns a definitive single-candidate result for inputs that
// carry an unambiguous structural signature, bypassing probabilistic scoring.
func signatureMatch(v string) []candidate {
	switch {
	case isBubbleBabble(v):
		return []candidate{{"Bubble Babble", 1000, "valid pronounceable Bubble Babble record"}}
	case isBech32(v, "bech32"):
		return []candidate{{"Bech32", 1000, "valid Bech32 polymod checksum"}}
	case isBech32(v, "bech32m"):
		return []candidate{{"Bech32m", 1000, "valid Bech32m polymod checksum"}}
	case isPEMData(v):
		return []candidate{{"PEM", 1000, "BEGIN/END block with valid Base64 payload"}}
	case strings.HasPrefix(v, "$sha1$"):
		return []candidate{{"NetBSD / Juniper sha1crypt", 1000, "$sha1$rounds$salt$checksum modular crypt record"}}
	case strings.HasPrefix(v, "$sm3$"):
		return []candidate{{"SM3 crypt", 1000, "$sm3$ salt/checksum modular crypt record"}}
	case strings.HasPrefix(v, "{CRAM-MD5}"):
		return []candidate{{"Dovecot CRAM-MD5", 1000, "Dovecot HMAC-MD5 chaining-state record"}}
	case strings.HasPrefix(v, "$6$"):
		return []candidate{{"sha512crypt (Unix $6$)", 1000, "$6$ prefix — glibc SHA-512 crypt shadow hash"}}
	case strings.HasPrefix(v, "$5$"):
		return []candidate{{"sha256crypt (Unix $5$)", 1000, "$5$ prefix — glibc SHA-256 crypt shadow hash"}}
	case strings.HasPrefix(v, "$1$"):
		return []candidate{{"md5crypt (Unix $1$)", 1000, "$1$ prefix — FreeBSD/Linux MD5 crypt shadow hash"}}
	case strings.HasPrefix(v, "$apr1$"):
		return []candidate{{"Apache apr1 (MD5)", 1000, "$apr1$ prefix — Apache .htpasswd MD5"}}
	case strings.HasPrefix(v, "$BLAKE2$") && len(v) == len("$BLAKE2$")+128 && isHex(v[len("$BLAKE2$"):]):
		return []candidate{{"BLAKE2b-512 (Hashcat format)", 1000, "$BLAKE2$ prefix + 128-char digest"}}
	case len(detectBlake2HashcatTypes(v)) > 0:
		return []candidate{{"BLAKE2 (Hashcat format)", 1000, "$BLAKE2$ digest record — width and salt determine compatible modes"}}
	case strings.HasPrefix(v, "$zipcrypto$"):
		return []candidate{{"ZIP (ZipCrypto encrypted)", 1000, "$zipcrypto$ prefix — traditional PKWARE encryption hash"}}
	case strings.HasPrefix(v, "$zipaes128$"):
		return []candidate{{"ZIP (WinZip AES-128 encrypted)", 1000, "$zipaes128$ prefix — WinZip AES-128 hash"}}
	case strings.HasPrefix(v, "$zipaes192$"):
		return []candidate{{"ZIP (WinZip AES-192 encrypted)", 1000, "$zipaes192$ prefix — WinZip AES-192 hash"}}
	case strings.HasPrefix(v, "$zipaes256$"):
		return []candidate{{"ZIP (WinZip AES-256 encrypted)", 1000, "$zipaes256$ prefix — WinZip AES-256 hash"}}
	case strings.HasPrefix(v, "$7z$"):
		return []candidate{{"7-Zip (AES-256 encrypted)", 1000, "$7z$ prefix — 7-Zip AES hash"}}
	case strings.HasPrefix(v, "$rar3$"):
		return []candidate{{"RAR3/RAR4 (AES encrypted)", 1000, "$rar3$ prefix — RAR4 header-encryption hash"}}
	case strings.HasPrefix(v, "$rar5$"):
		return []candidate{{"RAR5 (AES-256 encrypted)", 1000, "$rar5$ prefix — RAR5 PBKDF2 hash"}}
	case strings.HasPrefix(v, "$pdf$"):
		return []candidate{{"PDF (Standard encryption)", 1000, "$pdf$ prefix — PDF Standard security handler"}}
	case strings.HasPrefix(v, "$ssh$"):
		return []candidate{{"SSH private key", 1000, "$ssh$ prefix — encrypted SSH private key"}}
	case strings.HasPrefix(v, "$sshng$"):
		return []candidate{{"SSH private key", 1000, "$sshng$ record — ssh2john legacy PEM encryption"}}
	case strings.HasPrefix(v, "$pkcs8$"):
		return []candidate{{"PKCS#8 encrypted key", 1000, "$pkcs8$ prefix — PBES2 (PBKDF2) private key"}}
	case strings.HasPrefix(v, "$PEM$1$"):
		return []candidate{{"PKCS#8 PEM (PBKDF2-SHA1)", 1000, "Hashcat 24410 native $PEM$ record"}}
	case strings.HasPrefix(v, "$PEM$2$"):
		return []candidate{{"PKCS#8 PEM (PBKDF2-SHA256)", 1000, "Hashcat 24420 native $PEM$ record"}}
	case strings.HasPrefix(v, "$jksprivk$*"):
		return []candidate{{"Java KeyStore private key", 1000, "Hashcat 15500 / $jksprivk$ record"}}
	case strings.HasPrefix(v, "$vmx$"):
		return []candidate{{"VMware VMX encrypted key", 1000, "Hashcat 27400 / $vmx$ record"}}
	case strings.HasPrefix(v, "$vbox$"):
		return []candidate{{"VirtualBox encrypted password", 1000, "Hashcat 27500/27600 / $vbox$ record"}}
	case strings.HasPrefix(v, "$metamask-short$"):
		return []candidate{{"MetaMask short vault", 1000, "Hashcat 26610 / $metamask-short$ record"}}
	case strings.HasPrefix(v, "$metamask$"):
		return []candidate{{"MetaMask vault", 1000, "Hashcat 26600 / $metamask$ record"}}
	case strings.HasPrefix(v, "EXODUS:"):
		return []candidate{{"Exodus wallet", 1000, "Hashcat 28200 scrypt/AES-GCM record"}}
	case strings.HasPrefix(v, "$gpg$*"):
		return []candidate{{"GPG protected secret key", 1000, "$gpg$* record — OpenPGP S2K + CFB"}}
	case strings.HasPrefix(v, "$gpg$"):
		return []candidate{{"GPG symmetric", 1000, "$gpg$ prefix — gpg -c symmetric encryption"}}
	case strings.HasPrefix(v, "$office$2016$0$"):
		return []candidate{{"MS Office 2016 sheet protection", 1000, "$office$2016$0$ record"}}
	case strings.HasPrefix(v, "$oldoffice$"):
		return []candidate{{"MS Office 97-2003 (RC4 encrypted document)", 1000, "$oldoffice$ record — MD5/SHA-1 verifier"}}
	case strings.HasPrefix(v, "$office$"):
		return []candidate{{"MS Office (encrypted document)", 1000, "$office$ prefix — Office 2007/2010/2013"}}
	case strings.HasPrefix(v, "$mysqlna$"):
		return []candidate{{"MySQL CRAM-SHA1", 1000, "$mysqlna$ authentication-response record"}}
	case strings.HasPrefix(v, "$tacacs-plus$"):
		return []candidate{{"TACACS+", 1000, "$tacacs-plus$ packet record"}}
	case strings.HasPrefix(v, "$ASN$*"):
		return []candidate{{"Apple Secure Notes", 1000, "$ASN$ wrapped-key verifier"}}
	case strings.HasPrefix(v, "otm_sha256:"):
		return []candidate{{"Oracle Transportation Management SHA-256", 1000, "otm_sha256 record"}}
	case strings.HasPrefix(v, "$xmpp-scram$"):
		return []candidate{{"XMPP SCRAM", 1000, "$xmpp-scram$ stored-key record"}}
	case strings.HasPrefix(v, "$postgres$"):
		return []candidate{{"PostgreSQL challenge-response MD5", 1000, "$postgres$ user/salt/digest record"}}
	case strings.HasPrefix(v, "$SNMPv3$"):
		return []candidate{{"SNMPv3 USM authentication", 1000, "$SNMPv3$ packet record"}}
	case strings.HasPrefix(v, "@m@") || strings.HasPrefix(v, "@m,"):
		return []candidate{{"QNX shadow MD5", 1000, "@m@ / @m,rounds@ record"}}
	case strings.HasPrefix(v, "@s@") || strings.HasPrefix(v, "@s,"):
		return []candidate{{"QNX shadow SHA-256", 1000, "@s@ / @s,rounds@ record"}}
	case strings.HasPrefix(v, "@S@") || strings.HasPrefix(v, "@S,"):
		return []candidate{{"QNX shadow SHA-512", 1000, "@S@ / @S,rounds@ record"}}
	case strings.HasPrefix(v, "{x-issha, "):
		return []candidate{{"SAP CODVN H iSSHA-1", 1000, "{x-issha, rounds} record"}}
	case strings.HasPrefix(v, "{x-isSHA256, "):
		return []candidate{{"SAP CODVN H iSSHA-256", 1000, "{x-isSHA256, rounds} record"}}
	case strings.HasPrefix(v, "{x-isSHA384, "):
		return []candidate{{"SAP CODVN H iSSHA-384", 1000, "{x-isSHA384, rounds} record"}}
	case strings.HasPrefix(v, "{x-isSHA512, "):
		return []candidate{{"SAP CODVN H iSSHA-512", 1000, "{x-isSHA512, rounds} record"}}
	case strings.HasPrefix(v, "$stellar$"):
		return []candidate{{"Stargazer Stellar wallet", 1000, "$stellar$ AES-GCM wallet record"}}
	case strings.HasPrefix(v, "$telegram$0*"):
		return []candidate{{"Telegram mobile passcode", 1000, "$telegram$0* SHA-256 record"}}
	case strings.HasPrefix(v, "$telegram$1*"), strings.HasPrefix(v, "$telegram$2*"):
		return []candidate{{"Telegram Desktop local passcode", 1000, "$telegram$1/$2 PBKDF2 + AES-IGE record"}}
	case strings.HasPrefix(v, "$signal$"):
		return []candidate{{"Signal Android master password", 1000, "$signal$ PKCS#12-KDF + HMAC record"}}
	case strings.HasPrefix(v, "$keychain$*"):
		return []candidate{{"Legacy macOS Keychain", 1000, "$keychain$ PBKDF2-SHA1 + 3DES record"}}
	case strings.HasPrefix(v, "$vnc$*"):
		return []candidate{{"RFB VNC Authentication", 1000, "$vnc$ challenge-response record"}}
	case strings.HasPrefix(v, "$sntp-ms$"):
		return []candidate{{"Microsoft SNTP", 1000, "$sntp-ms$ authentication record"}}
	case strings.HasPrefix(v, "$NSEC3$"):
		return []candidate{{"DNSSEC NSEC3", 1000, "$NSEC3$ John the Ripper record"}}
	case strings.HasPrefix(v, "O$"):
		return []candidate{{"Oracle H", 1000, "O$USER#digest John the Ripper record"}}
	case isIPMIMD5(v):
		return []candidate{{"IPMI2 RAKP HMAC-MD5", 1000, "16-byte HMAC followed by a RAKP packet blob"}}
	case strings.HasPrefix(v, "$radmin3$"):
		return []candidate{{"Radmin3", 1000, "$radmin3$ username/salt/SRP verifier record"}}
	case strings.HasPrefix(v, "$vbk$*"):
		return []candidate{{"Veeam VBK", 1000, "$vbk$ backup-password record"}}
	case strings.HasPrefix(v, "$MSONLINEACCOUNT$0$"):
		return []candidate{{"Microsoft Online Account", 1000, "$MSONLINEACCOUNT$ PBKDF2/AES record"}}
	case strings.HasPrefix(v, "S:\"Config Passphrase\"=02:"):
		return []candidate{{"SecureCRT MasterPassphrase v2", 1000, "SecureCRT configuration passphrase record"}}
	case strings.HasPrefix(v, "$knx-ip-secure-device-authentication-code$*"):
		return []candidate{{"KNX IP Secure device authentication", 1000, "KNX Session_Response authentication record"}}
	case strings.HasPrefix(v, "$teamspeak$3$"):
		return []candidate{{"TeamSpeak 3 channel hash", 1000, "$teamspeak$3$ record"}}
	case strings.HasPrefix(v, "$bcrypt-sha256$"):
		return []candidate{{"Passlib bcrypt-SHA256", 1000, "$bcrypt-sha256$ record"}}
	case strings.HasPrefix(v, "sha256:") && len(strings.Split(v, ":")) == 3:
		return []candidate{{"Anope IRC enc_sha256", 1000, "sha256:digest:state record"}}
	case len(v) == 129 && v[0] == '5' && isHex(v[1:]):
		return []candidate{{"Citrix NetScaler PBKDF2", 1000, "5 + 32-byte salt + 32-byte digest"}}
	case len(v) == 137 && v[0] == '2' && isHex(v[1:]):
		return []candidate{{"Citrix NetScaler SHA-512", 1000, "2 + 8-character salt + SHA-512 digest"}}
	case len(v) == 63 && strings.HasPrefix(v, "SH2"):
		return []candidate{{"FortiGate256", 1000, "SH2 + Base64 salt/SHA-256 payload"}}
	case strings.HasPrefix(v, "$AWS-Sig-v4$"):
		return []candidate{{"Amazon AWS Signature Version 4", 1000, "$AWS-Sig-v4$ signing record"}}
	case isTOTPRecord(v):
		return []candidate{{"TOTP HMAC-SHA1", 1000, "six-digit code/timestamp pair record"}}
	case strings.HasPrefix(v, "$keepass$"):
		return []candidate{{"KeePass database", 1000, "$keepass$ prefix — KDBX 1/2 (AES-KDF)"}}
	case strings.HasPrefix(v, "WPA*01*"), isLegacyPMKID(v):
		return []candidate{{"WPA/WPA2 PMKID", 1000, "PMKID = HMAC-SHA1(PMK, \"PMK Name\"|AP|STA)"}}
	case strings.HasPrefix(v, "WPA*02*"):
		return []candidate{{"WPA/WPA2 EAPOL (4-way handshake)", 1000, "MIC over the EAPOL-Key frame"}}
	case strings.HasPrefix(v, "$ethereum$"):
		return []candidate{{"Ethereum wallet (Web3 keystore)", 1000, "$ethereum$ prefix — scrypt/PBKDF2 + keccak256 MAC"}}
	case strings.HasPrefix(v, "$bitcoin$"):
		return []candidate{{"Bitcoin/Litecoin wallet.dat", 1000, "$bitcoin$ prefix — iterated SHA-512 + AES-256-CBC"}}
	case strings.HasPrefix(v, "$dmg$"):
		return []candidate{{"Apple encrypted DMG", 1000, "$dmg$ prefix — PBKDF2-SHA1 + 3DES/AES verifier"}}
	case strings.HasPrefix(v, "$monero$0*"):
		return []candidate{{"Monero keys wallet", 1000, "$monero$0 CryptoNight v0 + ChaCha verifier"}}
	case strings.HasPrefix(v, "$bitwarden$"):
		return []candidate{{"Bitwarden vault", 1000, "$bitwarden$ prefix — layered PBKDF2-SHA256"}}
	case strings.HasPrefix(v, "$itunes_backup$"):
		return []candidate{{"iTunes backup", 1000, "$itunes_backup$ — PBKDF2 + AES key-unwrap"}}
	case strings.HasPrefix(v, "$ansible$"):
		return []candidate{{"Ansible Vault", 1000, "$ansible$ — PBKDF2-SHA256 + HMAC-SHA256"}}
	case strings.HasPrefix(v, "$blockchain$"):
		return []candidate{{"Blockchain.info My Wallet", 1000, "$blockchain$ — PBKDF2-SHA1 + AES-256-CBC"}}
	case isShiro1(v):
		return []candidate{{"Apache Shiro 1 SHA-512", 1000, "$shiro1$SHA-512$ — iterated salted SHA-512"}}
	case isSSPR(v):
		return []candidate{{"NetIQ/Adobe SSPR", 1000, "$sspr$ — iterated MD5/SHA record"}}
	case isNetIQPBKDF2(v):
		return []candidate{{"NetIQ SSPR PBKDF2", 1000, "$pbkdf2-hmac-sha* — PBKDF2 record"}}
	case isAS400SSHA1(v):
		return []candidate{{"AS/400 SSHA1", 1000, "$as400$ssha1$ — username-salted SHA-1"}}
	case isAuthMeSHA256(v):
		return []candidate{{"AuthMe SHA256", 1000, "$SHA$ — sha256(sha256(password).salt)"}}
	case isPHPS(v):
		return []candidate{{"PHPS", 1000, "$PHPS$ — md5(md5(password).salt)"}}
	case isMySQL8(v):
		return []candidate{{"MySQL 8 caching_sha2_password", 1000, "$mysql$A$ — 20-byte-salt SHA-256-crypt record"}}
	case strings.HasPrefix(v, "$mongodb-scram$"):
		return []candidate{{"MongoDB SCRAM", 1000, "$mongodb-scram$ — SHA-1/SHA-256 stored or server key"}}
	case strings.HasPrefix(v, "$solarwinds$"):
		return []candidate{{"SolarWinds Orion", 1000, "$solarwinds$ — PBKDF2-SHA1 (1024) + SHA-512"}}
	case strings.HasPrefix(v, "$sip$*"):
		return []candidate{{"SIP digest authentication", 1000, "$sip$ — HTTP Digest (MD5)"}}
	case strings.HasPrefix(v, "$electrum$"):
		return []candidate{{"Electrum wallet (salt-type 1-3)", 1000, "$electrum$ prefix — double SHA-256 + AES-256-CBC"}}
	case isDjangoHash(v):
		return []candidate{{"Django PBKDF2", 1000, "pbkdf2_sha256/sha1$ — Django/passlib password hash"}}
	case isPhpassHash(v):
		return []candidate{{"phpass (WordPress/phpBB)", 1000, "$P$/$H$ portable phpass hash"}}
	case isDrupal7Hash(v):
		return []candidate{{"Drupal 7", 1000, "$S$ prefix — SHA-512 phpass-style hash"}}
	case strings.HasPrefix(v, "$8$") && len(v) == 61:
		return []candidate{{"Cisco-IOS type 8", 1000, "$8$ prefix — PBKDF2-HMAC-SHA256"}}
	case strings.HasPrefix(v, "$9$") && len(v) == 61:
		return []candidate{{"Cisco-IOS type 9", 1000, "$9$ prefix — scrypt"}}
	case strings.HasPrefix(v, "$4$") && isCiscoType4(v):
		return []candidate{{"Cisco-IOS type 4", 1000, "$4$ prefix — SHA-256 with Cisco Base64"}}
	case strings.HasPrefix(v, "$ml$"):
		return []candidate{{"macOS 10.8+ (PBKDF2-SHA512)", 1000, "$ml$ prefix — macOS ShadowHashData"}}
	case strings.HasPrefix(v, "{PKCS5S2}"):
		return []candidate{{"Atlassian (PBKDF2-HMAC-SHA1)", 1000, "{PKCS5S2} prefix — Jira/Confluence/Crowd"}}
	case isPBKDF1SHA1(v):
		return []candidate{{"PBKDF1-SHA1", 1000, "PBKDF1:sha1:iterations:salt:digest record"}}
	case isGenericPBKDF2(v):
		return []candidate{{"PBKDF2 (generic)", 1000, "algo:iter:salt:dk — PBKDF2-HMAC"}}
	case isPasslibPBKDF2(v):
		return []candidate{{"Passlib PBKDF2", 1000, "$pbkdf2-sha*$ modular format"}}
	case isWerkzeug(v):
		return []candidate{{"Werkzeug password hash", 1000, "PBKDF2/scrypt method$salt$checksum"}}
	case isASPNetIdentity(v):
		return []candidate{{"ASP.NET Identity", 1000, "versioned PBKDF2 binary payload in Base64"}}
	case isGRUB2(v):
		return []candidate{{"GRUB2 PBKDF2-SHA512", 1000, "grub.pbkdf2.sha512 signature"}}
	case isOnePassword(v):
		return []candidate{{"1Password Agile Keychain", 1000, "iter:salt:data — PBKDF2-SHA1 + AES-128-CBC"}}
	case isIKE(v):
		return []candidate{{"IKE aggressive-mode PSK", 1000, "9-field IKE handshake — HMAC HASH_R"}}
	case strings.HasPrefix(v, "$DCC2$"):
		return []candidate{{"Domain Cached Credentials 2 (mscash2)", 1000, "$DCC2$ — PBKDF2-HMAC-SHA1 over the DCC"}}
	case strings.HasPrefix(v, "SCRAM-SHA-256$"):
		return []candidate{{"PostgreSQL SCRAM-SHA-256", 1000, "PBKDF2-SHA256 + HMAC/SHA-256 stored key"}}
	case strings.HasPrefix(v, "$cram_md5$"):
		return []candidate{{"CRAM-MD5", 1000, "$cram_md5$ — HMAC-MD5 challenge-response"}}
	case isCitrix(v):
		return []candidate{{"Citrix NetScaler", 1000, "1 + salt + sha1(salt.pass.\\0)"}}
	case isCiscoASA(v):
		return []candidate{{"Cisco-ASA MD5", 900, "PIX-style md5(pad16(pass.salt))"}}
	case isIPMI(v):
		return []candidate{{"IPMI2 RAKP (HMAC-SHA1)", 1000, "salt:hmac — BMC RAKP authentication"}}
	case isChap(v):
		return []candidate{{"iSCSI CHAP (MD5)", 900, "md5:challenge:id — CHAP authentication"}}
	case isRedHat389PBKDF2(v):
		return []candidate{{"Red Hat 389-DS PBKDF2-SHA256", 1000, "{PBKDF2_SHA256} — fixed binary PBKDF2 record"}}
	case isLDAP(v):
		return []candidate{{"LDAP salted digest", 1000, "{SSHA*}/{SMD5} — RFC 2307 salted hash"}}
	case isSybaseASE(v):
		return []candidate{{"Sybase ASE", 1000, "0xc007 prefix — sha256(utf16be(pass).pad.salt)"}}
	case isJuniper(v):
		return []candidate{{"Juniper NetScreen (ScreenOS)", 1000, "user$… — md5(user:Administration Tools:pass)"}}
	case isSAPCodvnFGRFCReadTable(v):
		return []candidate{{"SAP CODVN F/G from RFC_READ_TABLE", 1000, "user$truncated-sha1+zero-pad — Hashcat 7801"}}
	case isSAPCodvnBRFCReadTable(v):
		return []candidate{{"SAP CODVN B from RFC_READ_TABLE", 1000, "user$truncated-bcode+zero-pad — Hashcat 7701"}}
	case isSAPCodvnFG(v):
		return []candidate{{"SAP CODVN F/G (PASSCODE)", 900, "user$sha1 — iSSHA-1 with magic array"}}
	case isSAPCodvnB(v):
		return []candidate{{"SAP CODVN B (BCODE)", 900, "user$md5-8 — BCODE magic walk"}}
	case isMediaWiki(v):
		return []candidate{{"MediaWiki $B$", 1000, "$B$salt$ — md5(salt.\"-\".md5(pass))"}}
	case len(detectCompatSaltedTypes(v)) > 0:
		digest, _, _ := compatSaltedHashParts(v)
		name := map[int]string{32: "MD5", 40: "SHA-1", 56: "SHA-224", 64: "SHA-256", 96: "SHA-384", 128: "SHA-512"}[len(digest)]
		return []candidate{{"Generic salted " + name, 1000, "hash:salt record — pass/salt order and UTF-16LE variant are ambiguous"}}
	case isRedmine(v):
		return []candidate{{"Redmine", 900, "sha1:salt — sha1(salt.sha1(pass))"}}
	case isVBulletin(v):
		return []candidate{{"vBulletin", 900, "md5:salt — md5(md5(pass).salt)"}}
	case strings.HasPrefix(v, "$bitlocker$"):
		return []candidate{{"BitLocker", 1000, "$bitlocker$ prefix — 1M-round SHA-256 + AES-CTR VMK"}}
	case strings.HasPrefix(v, "$luks$"):
		return []candidate{{"LUKS v1", 1000, "$luks$ prefix — PBKDF2 + AF-splitter + master-key digest"}}
	case strings.HasPrefix(v, "$krb5asrep$"):
		return []candidate{{"Kerberos 5 AS-REP (etype 23)", 1000, "$krb5asrep$ prefix — AS-REP roastable hash"}}
	case strings.HasPrefix(v, "$krb5tgs$"):
		return []candidate{{"Kerberos 5 TGS-REP (etype 23)", 1000, "$krb5tgs$ prefix — Kerberoastable ticket"}}
	case reBcrypt.MatchString(v):
		return []candidate{{"bcrypt", 1000, "starts with $2[aby]$ cost-factor signature"}}
	case reArgon2.MatchString(v):
		return []candidate{{"argon2", 1000, "starts with $argon2(i|d|id)$ signature"}}
	case reScrypt.MatchString(v):
		return []candidate{{"scrypt", 1000, "recognized scrypt$ or Hashcat SCRYPT: record"}}
	case isHexPair(v, 8, 8):
		return []candidate{{"Seeded CRC32/CRC32C or MurmurHash/MurmurHash3", 1000, "8-hex checksum and 8-hex initial value/seed"}}
	case isHexPair(v, 16, 16):
		return []candidate{{"MurmurHash64A or CRC64-Jones", 1000, "16-hex checksum and 16-hex initial value/seed"}}
	case rePostgres.MatchString(v):
		return []candidate{{"PostgreSQL MD5", 1000, "md5 prefix + 32-char hex"}}
	case reMySQL41.MatchString(v):
		return []candidate{{"MySQL 4.1 / SHA-1", 1000, "* prefix + 40-char hex"}}
	case reMSSQLNew.MatchString(v):
		return []candidate{{"MSSQL 2005 / 2012", 1000, "0x0100 prefix + 48-char hex salt+sha1"}}
	case reJWT.MatchString(v):
		return []candidate{{"JWT (JSON Web Token)", 1000, "eyJ header + 3-part Base64URL structure"}}
	case reUUID.MatchString(v):
		return []candidate{{"UUID", 1000, "8-4-4-4-12 hex groups"}}
	case looksLikeDescrypt(v):
		return []candidate{{"descrypt (traditional DES crypt)", 1000, "13-char crypt-base64 — classic Unix DES password hash"}}
	}
	return nil
}

// ── Group 1: Hex hash detection ───────────────────────────────────────────────

func scoreHashGroup(v string, lv int, entropy float64, hexStr, lower, upper, hashLenHex bool, ch chan<- candidate) {
	if !hexStr || (!hashLenHex && lv != 8) {
		return
	}

	// Entropy bonus/penalty: genuine hash outputs cluster near 3.8–4.0 bits.
	eb := func(base float64) float64 {
		switch {
		case entropy > 3.8:
			return base + 30
		case entropy > 3.5:
			return base + 20
		case entropy > 3.0:
			return base + 10
		case entropy > 2.5:
			return base - 10
		default:
			return base - 25
		}
	}

	caseLabel := "mixed-case hex"
	if lower {
		caseLabel = "lowercase hex"
	} else if upper {
		caseLabel = "uppercase hex"
	}

	switch lv {
	case 8:
		ch <- candidate{"CRC-32 / CRC-32C / Adler-32", eb(58), fmt.Sprintf("8-char %s checksum-sized value", caseLabel)}
		ch <- candidate{"FNV-1a / xxHash / Murmur3 32-bit", eb(42), fmt.Sprintf("8-char %s checksum-sized value", caseLabel)}

	case 16:
		ch <- candidate{"MySQL 3.x", eb(75), fmt.Sprintf("16-char %s, entropy %.2f", caseLabel, entropy)}
		ch <- candidate{"CRC-64 / FNV-1a / xxHash64 / Half-MD5", eb(48), fmt.Sprintf("16-char %s", caseLabel)}

	case 32:
		// NTLM hashes are typically stored as uppercase in Windows credential stores;
		// MD5 is conventionally lowercase in most implementations.
		md5s := eb(80)
		ntlm := eb(68)
		md4s := eb(58)
		lm := eb(52)
		if lower {
			md5s += 20
			ntlm -= 15
		} else if upper {
			ntlm += 20
			md5s -= 5
		}
		ch <- candidate{"MD5", math.Max(md5s, 0), fmt.Sprintf("32-char %s, entropy %.2f", caseLabel, entropy)}
		ch <- candidate{"NTLM", math.Max(ntlm, 0), fmt.Sprintf("32-char %s, entropy %.2f", caseLabel, entropy)}
		ch <- candidate{"MD4", math.Max(md4s, 0), fmt.Sprintf("32-char %s, entropy %.2f", caseLabel, entropy)}
		ch <- candidate{"MD2", eb(42), fmt.Sprintf("32-char %s legacy digest", caseLabel)}
		ch <- candidate{"LM (LAN Manager)", math.Max(lm, 0), fmt.Sprintf("32-char %s legacy Windows digest", caseLabel)}

	case 40:
		ch <- candidate{"SHA-1", eb(80), fmt.Sprintf("40-char %s, entropy %.2f", caseLabel, entropy)}
		ch <- candidate{"SHA-0", eb(44), fmt.Sprintf("40-char %s legacy digest", caseLabel)}
		ch <- candidate{"RIPEMD-160", eb(62), fmt.Sprintf("40-char %s, entropy %.2f", caseLabel, entropy)}

	case 56:
		ch <- candidate{"SHA-224", eb(85), fmt.Sprintf("56-char %s, entropy %.2f", caseLabel, entropy)}
		ch <- candidate{"SHA-512/224", eb(63), fmt.Sprintf("56-char %s, entropy %.2f", caseLabel, entropy)}
		ch <- candidate{"SHA3-224", eb(58), fmt.Sprintf("56-char %s, entropy %.2f", caseLabel, entropy)}

	case 64:
		ch <- candidate{"SHA-256", eb(85), fmt.Sprintf("64-char %s, entropy %.2f", caseLabel, entropy)}
		ch <- candidate{"SHA3-256", eb(65), fmt.Sprintf("64-char %s, entropy %.2f", caseLabel, entropy)}
		ch <- candidate{"SM3", eb(55), fmt.Sprintf("64-char %s, entropy %.2f", caseLabel, entropy)}
		ch <- candidate{"BLAKE2s", eb(58), fmt.Sprintf("64-char %s, entropy %.2f", caseLabel, entropy)}
		ch <- candidate{"SHA-512/256", eb(54), fmt.Sprintf("64-char %s, entropy %.2f", caseLabel, entropy)}
		ch <- candidate{"Keccak-256", eb(52), fmt.Sprintf("64-char %s, entropy %.2f", caseLabel, entropy)}
		ch <- candidate{"BLAKE2b-256", eb(48), fmt.Sprintf("64-char %s, entropy %.2f", caseLabel, entropy)}
		ch <- candidate{"SHAKE128-256 / Streebog-256", eb(44), fmt.Sprintf("64-char %s", caseLabel)}

	case 96:
		ch <- candidate{"SHA-384", eb(85), fmt.Sprintf("96-char %s, entropy %.2f", caseLabel, entropy)}
		ch <- candidate{"SHA3-384", eb(62), fmt.Sprintf("96-char %s, entropy %.2f", caseLabel, entropy)}
		ch <- candidate{"BLAKE2b-384", eb(54), fmt.Sprintf("96-char %s, entropy %.2f", caseLabel, entropy)}

	case 128:
		ch <- candidate{"SHA-512", eb(85), fmt.Sprintf("128-char %s, entropy %.2f", caseLabel, entropy)}
		ch <- candidate{"SHA3-512", eb(65), fmt.Sprintf("128-char %s, entropy %.2f", caseLabel, entropy)}
		ch <- candidate{"BLAKE2b", eb(58), fmt.Sprintf("128-char %s, entropy %.2f", caseLabel, entropy)}
		ch <- candidate{"Keccak-512", eb(52), fmt.Sprintf("128-char %s, entropy %.2f", caseLabel, entropy)}
		ch <- candidate{"SHAKE256-512 / Whirlpool / Streebog-512", eb(46), fmt.Sprintf("128-char %s", caseLabel)}
	}
}

// ── Group 2: Encoding detection ───────────────────────────────────────────────

func scoreEncodingGroup(v string, lv int, entropy float64, hexStr, hashLenHex bool, ch chan<- candidate) {
	if isMIMEBase64(v) {
		ch <- candidate{"MIME Base64", 92, "valid Base64 wrapped at 76 columns"}
	}
	// Hex encoding — skip known hash lengths (those are handled by hash group)
	if hexStr && lv%2 == 0 && !hashLenHex {
		s := 30.0
		if entropy < 3.5 {
			s += 20
		}
		ch <- candidate{"Hex", s, fmt.Sprintf("%d-char hex, entropy %.2f", lv, entropy)}
	}

	// Base64 standard — skip all hex strings (hex ⊂ Base64 charset, would always match).
	// Speculative: if decoded bytes length matches a known hash size, label specifically.
	if !hexStr && reBase64Std.MatchString(v) && lv%4 != 1 {
		if dec, err := decodeBase64Flexible(v, false); err == nil {
			if len(dec) >= 2 && dec[0] == 0x1f && dec[1] == 0x8b {
				ch <- candidate{"Gzip + Base64", 96, "Base64 payload begins with gzip magic bytes"}
			} else if looksLikeZlib(dec) {
				ch <- candidate{"Zlib + Base64", 94, "Base64 payload has a valid zlib header"}
			} else if allPrintable(dec) {
				ch <- candidate{"Base64", 70, "decodes to printable text"}
			} else if algos, ok := hashByteLengths[len(dec)]; ok {
				for _, algo := range algos {
					ch <- candidate{
						"Base64-encoded " + algo, 85,
						fmt.Sprintf("decodes to %d bytes, matches %s digest size", len(dec), algo),
					}
				}
			} else {
				ch <- candidate{"Base64", 45, "decodes to binary data"}
			}
		} else {
			ch <- candidate{"Base64", 25, "valid Base64 charset"}
		}
	}

	// Base64 URL-safe — speculative hash detection; suppress generic "decodes successfully".
	if !hexStr && reBase64URL.MatchString(v) && !strings.ContainsAny(v, "+/") {
		if dec, err := decodeBase64Flexible(v, true); err == nil {
			if allPrintable(dec) {
				ch <- candidate{"Base64 URL", 55, "decodes to printable text"}
			} else if algos, ok := hashByteLengths[len(dec)]; ok {
				// Require at least one Base64URL-exclusive char (_ or -) to disambiguate
				// from Base58 strings whose charset is a strict subset of Base64URL.
				if strings.ContainsAny(v, "_-") {
					for _, algo := range algos {
						ch <- candidate{
							"Base64 URL-encoded " + algo, 85,
							fmt.Sprintf("decodes to %d bytes, matches %s digest size", len(dec), algo),
						}
					}
				}
			}
			// no generic "decodes to binary" — avoids false positives on arbitrary alphanumeric strings
		}
	}

	// Base32
	upper := strings.ToUpper(v)
	if reBase32Std.MatchString(upper) {
		if dec, err := decodeBase32Flexible(upper, false); err == nil {
			s := 40.0
			reason := "decodes successfully"
			if allPrintable(dec) {
				s += 25
				reason = "decodes to printable text"
			}
			if algos, ok := hashByteLengths[len(dec)]; ok && !allPrintable(dec) {
				for _, algo := range algos {
					ch <- candidate{"Base32-encoded " + algo, 82,
						fmt.Sprintf("decodes to %d bytes, matches %s digest size", len(dec), algo)}
				}
			} else {
				ch <- candidate{"Base32", s, reason}
			}
		}
	}

	// Extended-hex Base32. Require a digit outside the standard Base32 alphabet
	// to avoid reporting the same token as both alphabets.
	if reBase32Hex.MatchString(upper) && strings.ContainsAny(upper, "0189") {
		if dec, err := decodeBase32Flexible(upper, true); err == nil {
			s, reason := 42.0, "valid extended-hex Base32"
			if allPrintable(dec) {
				s, reason = 67, "decodes to printable text"
			}
			ch <- candidate{"Base32hex", s, reason}
		}
	}

	if isCrockfordCandidate(v) {
		dec, _ := decodeCrockford(v)
		score, reason := 48.0, "valid Crockford Base32 alphabet and padding bits"
		if allPrintable(dec) {
			score, reason = 72, "decodes to printable text"
		}
		ch <- candidate{"Crockford Base32", score, reason}
	}
	if isZBase32Candidate(v) {
		dec, _ := decodeZBase32(v)
		score, reason := 72.0, "canonical z-base-32 alphabet and padding bits"
		if allPrintable(dec) {
			score, reason = 170, "canonical form decodes to printable text"
		}
		ch <- candidate{"z-base-32", score, reason}
	}

	// Base58 — speculative: decode and cross-reference byte length against hash registry.
	// Falls back to generic Base58 when no hash length matches.
	if !hexStr && reBase58Pat.MatchString(v) && lv >= 8 {
		speculativeHit := false
		if payload, err := decodeBase58Check(v); err == nil {
			speculativeHit = true
			reason := fmt.Sprintf("valid double-SHA256 checksum over %d payload bytes", len(payload))
			ch <- candidate{"Base58Check", 96, reason}
		}
		if b, err := decodeBase58(v); err == nil {
			if algos, ok := hashByteLengths[len(b)]; ok {
				speculativeHit = true
				for _, algo := range algos {
					ch <- candidate{
						"Base58-encoded " + algo, 85,
						fmt.Sprintf("decodes to %d bytes, matches %s digest size", len(b), algo),
					}
				}
			}
		}
		if !speculativeHit {
			s := 22.0
			if entropy > 4.5 {
				s += 18
			} else if entropy > 3.5 {
				s += 8
			}
			ch <- candidate{"Base58", s, fmt.Sprintf("valid Base58 charset, entropy %.2f", entropy)}
		}
	}

	// Base62 — [0-9A-Za-z] charset, no +/=_- (distinguishes from Base64/Base64URL).
	// Speculative: if decoded bytes match a known hash size, label specifically.
	// Generic Base62 is only emitted when the string contains chars outside Base58
	// alphabet (0, O, I, l) to avoid shadowing the Base58 candidate.
	if !hexStr && reBase62Pat.MatchString(v) && !strings.ContainsAny(v, "+/=_-") && lv >= 8 {
		if b, err := decodeBase62(v); err == nil {
			if algos, ok := hashByteLengths[len(b)]; ok {
				for _, algo := range algos {
					ch <- candidate{
						"Base62-encoded " + algo, 82,
						fmt.Sprintf("decodes to %d bytes, matches %s digest size", len(b), algo),
					}
				}
			} else if hasBase62OnlyChar(v) {
				// Contains 0/O/I/l → cannot be Base58; emit generic Base62
				s := 30.0
				if entropy > 4.5 {
					s += 18
				} else if entropy > 3.5 {
					s += 8
				}
				ch <- candidate{"Base62", s, fmt.Sprintf("valid Base62 charset (contains Base62-only chars), entropy %.2f", entropy)}
			}
		}
	}

	// Base85 (ASCII85) — '!'–'u' charset, optional <~ ~> delimiters.
	// Without delimiters the charset overlaps heavily with hex, alpha, and Base64,
	// so apply guards to suppress obvious false positives.
	if isBase85, hasDelim := isBase85Str(v); isBase85 {
		if hasDelim {
			ch <- candidate{"Base85 (ASCII85)", 82, "has <~ ~> delimiters"}
		} else if !hexStr && !isAllAlpha(v) &&
			!strings.ContainsAny(v, " \t") &&
			!(reBase64Std.MatchString(v) && lv%4 == 0) &&
			!isBase64URLDecodable(v) {
			ch <- candidate{"Base85 (ASCII85)", 38, "valid ASCII85 charset (!–u)"}
		}
	}

	// UU encoding — length-prefixed lines with ' '–'`' charset
	if isUUStr(v) {
		ch <- candidate{"UU Encoded", 78, "length-prefixed UU line format"}
	}

	// Base45 and Z85 are block encodings with strict canonical forms. Their
	// alphabets overlap normal text, so confidence stays conservative unless the
	// decoded bytes are printable or the token contains encoding punctuation.
	if lv >= 4 && lv%3 != 1 && strings.ContainsAny(v, "0123456789$%*+-./:") {
		if dec, err := decodeBase45(v); err == nil && encodeBase45(dec) == v {
			s := 38.0
			if allPrintable(dec) {
				s = 70
			}
			ch <- candidate{"Base45", s, "valid RFC 9285 groups"}
		}
	}
	if lv >= 5 && lv%5 == 0 {
		if dec, err := decodeZ85(v); err == nil {
			s := 34.0
			if allPrintable(dec) || strings.ContainsAny(v, ".-:+=^!/*?&<>()[]{}@%$#") {
				s = 62
			}
			ch <- candidate{"Z85", s, "valid 5-character Z85 blocks"}
		}
	}
	if lv >= 6 && countDistinctRunesFrom(v, "!#$%&()*+,./:;<=>?@[]^_`{|}~\"") >= 2 {
		if dec, err := decodeBase91(v); err == nil && encodeBase91(dec) == v {
			s := 48.0
			if allPrintable(dec) {
				s = 72
			}
			ch <- candidate{"basE91", s, "canonical basE91 alphabet and bit packing"}
		}
	}

	// URL-encoded
	if reURLEnc.MatchString(v) {
		count := len(reURLEnc.FindAllString(v, -1))
		ch <- candidate{"URL Encoded",
			math.Min(30+float64(count)*8, 80),
			fmt.Sprintf("%d %%XX sequences", count)}
	}
	if matches := reJSONEsc.FindAllString(v, -1); len(matches) > 0 {
		ch <- candidate{"JSON String Escapes", math.Min(45+float64(len(matches))*8, 85),
			fmt.Sprintf("%d JSON escape sequences", len(matches))}
	}
	if matches := reHexEsc.FindAllString(v, -1); len(matches) > 0 && len(matches)*4 == len(v) {
		ch <- candidate{"C-style Hex Escapes", math.Min(55+float64(len(matches))*4, 92),
			fmt.Sprintf("%d \\xNN byte escapes", len(matches))}
	}
	if !hexStr && isCiscoType4(v) {
		ch <- candidate{"Cisco-IOS type 4", 36, "43-character Cisco crypt-64 SHA-256 value"}
	}
}

func countDistinctRunesFrom(text, set string) int {
	seen := make(map[rune]struct{})
	for _, r := range text {
		if strings.ContainsRune(set, r) {
			seen[r] = struct{}{}
		}
	}
	return len(seen)
}

// ── Group 3: Structural / cipher-format detection ─────────────────────────────

func scoreStructuralGroup(v string, entropy float64, ch chan<- candidate) {
	// NATO phonetic alphabet — checked first so multi-word NATO strings are not
	// mis-scored as plain text or substitution cipher.
	if ok, count := isNATOStr(v); ok {
		// Use a high raw score so NATO dominates over plain-text noise.
		// Plain text fires at ~33 pts for space-separated text; at 300 pts
		// NATO reaches ~90% (300/333) even when plain text also fires.
		score := 150.0
		if count > 3 {
			score = 300.0
		}
		ch <- candidate{"NATO Phonetic Alphabet", score,
			fmt.Sprintf("%d phonetic words detected", count)}
	}

	if isBinaryStr(v) {
		ch <- candidate{"Binary", 90, "space-separated 8-bit groups"}
	}
	if isDecimalStr(v) {
		ch <- candidate{"Decimal", 85, "space-separated byte values 0–255"}
	}
	if isOctalStr(v) {
		ch <- candidate{"Octal", 80, "space-separated octal byte values"}
	}
	morseMatch := isMorseStr(v)
	if morseMatch {
		ch <- candidate{"Morse Code", 88, "dot/dash/slash pattern"}
	}
	if isBaconianStr(v) {
		ch <- candidate{"Baconian Cipher", 88, "5-char A/B groups"}
	}
	if isPolybiusStr(v) {
		ch <- candidate{"Polybius Square", 88, "digit-pair groups (1–5)"}
	}
	if isLeetStr(v) {
		ch <- candidate{"Leet Speak", 62, fmt.Sprintf("alpha + leet substitutions, entropy %.2f", entropy)}
	}
	if !morseMatch && isBrainfuckStr(v) {
		ch <- candidate{"Brainf*ck", 85, "BF operator set (+-<>[].,)"}
	}
}

// ── Group 4: Cipher and plain-text analysis ───────────────────────────────────

func scoreCipherTextGroup(v string, lv int, entropy float64, hexStr bool, ch chan<- candidate) {
	allAlpha := isAllAlpha(v)
	hasSpaces := strings.ContainsAny(v, " \t")

	// Substitution cipher (Caesar / Vigenere / ROT13 / Atbash)
	// Signal: purely alphabetical, no spaces or digits.
	// Chi-squared against English letter frequency provides additional signal:
	// monoalphabetic ciphers of English preserve letter frequencies, so a low
	// chi-squared means the input could be either English plain text or a
	// Caesar/Atbash/ROT13 cipher of English; a high chi-squared suggests a
	// key-heavy cipher (Vigenere with random key) or non-English source text.
	if allAlpha && lv >= 4 {
		chiSq := chiSquaredEnglish(v)
		var cs float64
		var cipherReason string

		switch {
		case entropy <= 2.0:
			cs = 65
			cipherReason = fmt.Sprintf("very low entropy %.2f, repetitive pattern", entropy)
		case entropy <= 2.8:
			cs = 52
			cipherReason = fmt.Sprintf("low entropy %.2f", entropy)
		case entropy <= 3.5:
			cs = 33
			cipherReason = fmt.Sprintf("entropy %.2f", entropy)
		case entropy <= 4.2:
			cs = 16
			cipherReason = fmt.Sprintf("entropy %.2f", entropy)
		}

		if chiSq > 250 {
			cs += 18
			cipherReason += fmt.Sprintf(", unusual letter dist χ²=%.0f", chiSq)
		} else if chiSq < 40 {
			cs -= 12 // English-like distribution → plain text more likely
			cipherReason += fmt.Sprintf(", English-like dist χ²=%.0f", chiSq)
		}

		if cs > 0 {
			ch <- candidate{"Substitution Cipher (Caesar / Vigenere / ROT13)", cs, cipherReason}
		}
	}

	// Plain text
	ratio := printableRatio(v)
	if ratio >= 0.85 {
		s := 18.0
		ptReason := "printable ASCII"

		if hasSpaces {
			s += 15
			ptReason = "printable text with spaces"
		}
		if hexStr {
			s -= 14
		} else if reBase64Std.MatchString(v) {
			s -= 10
		}
		if allAlpha && !hasSpaces {
			s -= 8 // ambiguous with substitution cipher
		}

		// Entropy hard filter: for short single-token strings (no whitespace),
		// entropy > 4.2 is a strong signal against plain text.
		if entropy > 4.2 && !hasSpaces {
			s = 4
			ptReason = fmt.Sprintf("high entropy %.2f — likely not plain text", entropy)
		} else if allAlpha {
			chiSq := chiSquaredEnglish(v)
			if chiSq < 30 {
				s += 14
				ptReason += fmt.Sprintf(", English freq match χ²=%.0f", chiSq)
			}
		}

		ch <- candidate{"Plain Text", math.Max(s, 4), ptReason}
	}
}

// ── knownHashLen ──────────────────────────────────────────────────────────────

func knownHashLen(l int) bool {
	switch l {
	case 16, 32, 40, 56, 64, 96, 128:
		return true
	}
	return false
}

// ── Statistical helpers ───────────────────────────────────────────────────────

// shannonEntropy computes Shannon entropy in bits per character (O(n)).
// Uses a pooled buffer to avoid repeated heap allocation.
func shannonEntropy(s string) float64 {
	if len(s) == 0 {
		return 0
	}
	buf := entropyPool.Get().(*[256]int)
	freq := buf
	for i := range freq {
		freq[i] = 0
	}
	for i := 0; i < len(s); i++ {
		freq[s[i]]++
	}
	n := float64(len(s))
	var h float64
	for _, c := range freq {
		if c > 0 {
			p := float64(c) / n
			h -= p * math.Log2(p)
		}
	}
	entropyPool.Put(buf)
	return h
}

// chiSquaredEnglish computes the chi-squared statistic of a string's letter
// frequency distribution against expected English letter frequencies.
// Lower values indicate closer resemblance to English text.
func chiSquaredEnglish(s string) float64 {
	var freq [26]int
	n := 0
	for _, c := range s {
		switch {
		case c >= 'a' && c <= 'z':
			freq[c-'a']++
			n++
		case c >= 'A' && c <= 'Z':
			freq[c-'A']++
			n++
		}
	}
	if n == 0 {
		return math.MaxFloat64
	}
	fn := float64(n)
	var chi float64
	for i := 0; i < 26; i++ {
		expected := englishFreq[i] / 100.0 * fn
		if expected == 0 {
			continue
		}
		diff := float64(freq[i]) - expected
		chi += diff * diff / expected
	}
	return chi
}

// ── Format / charset classifiers ──────────────────────────────────────────────

func allPrintable(b []byte) bool {
	if len(b) == 0 {
		return false
	}
	for _, c := range b {
		if (c < 0x20 && c != '\t' && c != '\n' && c != '\r') || c == 0x7f {
			return false
		}
	}
	return true
}

func printableRatio(s string) float64 {
	if len(s) == 0 {
		return 0
	}
	n := 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 0x20 && c < 0x7f {
			n++
		}
	}
	return float64(n) / float64(len(s))
}

func isAllAlpha(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') {
			return false
		}
	}
	return true
}

func isBinaryStr(s string) bool {
	parts := strings.Fields(s)
	if len(parts) == 0 {
		return false
	}
	for _, p := range parts {
		if len(p) != 8 {
			return false
		}
		for _, c := range p {
			if c != '0' && c != '1' {
				return false
			}
		}
	}
	return true
}

func isDecimalStr(s string) bool {
	parts := strings.Fields(s)
	if len(parts) < 2 {
		return false
	}
	for _, p := range parts {
		if len(p) == 0 || len(p) > 3 {
			return false
		}
		n := 0
		for _, c := range p {
			if c < '0' || c > '9' {
				return false
			}
			n = n*10 + int(c-'0')
		}
		if n > 255 {
			return false
		}
	}
	return true
}

func isOctalStr(s string) bool {
	parts := strings.Fields(s)
	if len(parts) < 2 {
		return false
	}
	for _, p := range parts {
		if len(p) == 0 {
			return false
		}
		n := 0
		for _, c := range p {
			if c < '0' || c > '7' {
				return false
			}
			n = n*8 + int(c-'0')
		}
		if n > 255 {
			return false
		}
	}
	return true
}

func isMorseStr(s string) bool {
	if s == "" {
		return false
	}
	hasDot, hasDash := false, false
	for _, c := range s {
		switch c {
		case '.':
			hasDot = true
		case '-':
			hasDash = true
		case '/', ' ':
		default:
			return false
		}
	}
	return hasDot || hasDash
}

func isBaconianStr(s string) bool {
	parts := strings.Fields(s)
	if len(parts) < 1 {
		return false
	}
	for _, p := range parts {
		if len(p) != 5 {
			return false
		}
		for _, c := range strings.ToUpper(p) {
			if c != 'A' && c != 'B' {
				return false
			}
		}
	}
	return true
}

func isPolybiusStr(s string) bool {
	parts := strings.Fields(s)
	if len(parts) < 2 {
		return false
	}
	for _, p := range parts {
		if len(p) != 2 || p[0] < '1' || p[0] > '5' || p[1] < '1' || p[1] > '5' {
			return false
		}
	}
	return true
}

func isLeetStr(s string) bool {
	if len(s) < 4 || isHex(s) {
		return false
	}
	leet, alpha, other := 0, 0, 0
	for _, c := range s {
		switch {
		case (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z'):
			alpha++
		case c == '3' || c == '0' || c == '1' || c == '4' || c == '@' || c == '$' || c == '!':
			leet++
		default:
			other++
		}
	}
	total := leet + alpha + other
	if total == 0 {
		return false
	}
	return leet >= 1 && alpha >= 1 && (leet+alpha)*100/total >= 80
}

// isBrainfuckStr detects Brainf*ck source code: the 8 operators (+ - < > [ ] . ,)
// must constitute at least 60% of all non-whitespace characters.
// hasBase62OnlyChar returns true if s contains at least one character that is
// valid in Base62 but absent from the Base58 alphabet: '0', 'O', 'I', 'l'.
// This distinguishes a genuine Base62 string from one that is also valid Base58.
func hasBase62OnlyChar(s string) bool {
	for _, c := range s {
		if c == '0' || c == 'O' || c == 'I' || c == 'l' {
			return true
		}
	}
	return false
}

// isNATOStr checks whether s is a sequence of NATO phonetic words.
// Returns (match, wordCount). A match requires at least 2 tokens AND ≥75% of
// tokens must be valid NATO words (guards against false positives on plain text).
//
// Tokenisation: split on whitespace and commas only so that "X-ray" is kept
// as a single token and matched directly against natoWordSet.  Only when a
// whole-token lookup fails is the token expanded by splitting on dashes,
// enabling inputs like "Alpha-Bravo-Charlie" to be identified correctly.
func isNATOStr(s string) (bool, int) {
	cleaned := strings.ReplaceAll(s, ",", " ")
	rawTokens := strings.Fields(strings.TrimSpace(cleaned))

	// Expand tokens: keep token whole if it matches; dash-split otherwise.
	var tokens []string
	for _, t := range rawTokens {
		if t == "" || t == "/" {
			continue
		}
		if natoWordSet[strings.ToLower(t)] {
			tokens = append(tokens, t)
		} else {
			tokens = append(tokens, strings.Split(t, "-")...)
		}
	}

	natoCount, total := 0, 0
	for _, t := range tokens {
		if t == "" {
			continue
		}
		total++
		if natoWordSet[strings.ToLower(t)] {
			natoCount++
		}
	}
	if total < 2 || natoCount < 2 {
		return false, 0
	}
	if natoCount*100/total < 75 {
		return false, 0
	}
	return true, natoCount
}

func isBrainfuckStr(s string) bool {
	if len(s) < 4 {
		return false
	}
	ops, total := 0, 0
	for _, c := range s {
		switch c {
		case ' ', '\t', '\n', '\r':
			// whitespace is not counted
		case '+', '-', '<', '>', '[', ']', '.', ',':
			ops++
			total++
		default:
			total++
		}
	}
	return ops >= 4 && total > 0 && ops*100/total >= 60
}

// isBase85Str validates ASCII85 encoding (range '!'–'u', special 'z'/'y' blocks).
// Returns (isBase85, hasDelimiters) where hasDelimiters indicates <~ ~> wrapping.
func isBase85Str(v string) (bool, bool) {
	s := v
	hasDelim := strings.HasPrefix(s, "<~") && strings.HasSuffix(s, "~>")
	if hasDelim {
		s = s[2 : len(s)-2]
	}
	if len(s) == 0 {
		return false, false
	}
	for _, c := range s {
		switch {
		case c == 'z' || c == 'y':
		case c >= '!' && c <= 'u':
		case c == ' ' || c == '\n' || c == '\r':
		default:
			return false, false
		}
	}
	return true, hasDelim
}

// isUUStr validates a single UU-encoded line: the first byte encodes the count
// of decoded bytes (count + 0x20), and all subsequent bytes must be in [0x20,0x60].
// isBase64URLDecodable returns true if v successfully decodes as Base64URL
// (with auto-padding). Used to suppress Base85 false positives on Base64URL strings.
func isBase64URLDecodable(v string) bool {
	if len(v) < 8 || !reBase64URL.MatchString(v) || strings.ContainsAny(v, "+/") {
		return false
	}
	padding := strings.Repeat("=", (4-len(v)%4)%4)
	_, err := base64.URLEncoding.DecodeString(v + padding)
	return err == nil
}

func isUUStr(s string) bool {
	s = strings.TrimRight(s, "\r\n ")
	if len(s) < 2 {
		return false
	}
	lc := s[0]
	if lc < 0x20 || lc > 0x60 {
		return false
	}
	decodedLen := int(lc - 0x20)
	if decodedLen == 0 {
		return len(s) == 1
	}
	expectedEncLen := ((decodedLen + 2) / 3) * 4
	if len(s) != expectedEncLen+1 {
		return false
	}
	for i := 1; i < len(s); i++ {
		if s[i] < 0x20 || s[i] > 0x60 {
			return false
		}
	}
	return true
}

// ── Backward-compat (used by crack auto-detection) ────────────────────────────

// looksLikeCryptHash reports whether s is a bare Unix crypt(3) shadow hash:
// a $-tagged scheme ($1$/$apr1$/$5$/$6$ or bcrypt $2[aby]$) or a 13-char
// descrypt.
func looksLikeCryptHash(s string) bool {
	if strings.HasPrefix(s, "$1$") || strings.HasPrefix(s, "$apr1$") || strings.HasPrefix(s, "$5$") ||
		strings.HasPrefix(s, "$6$") || reBcrypt.MatchString(s) {
		return true
	}
	return looksLikeDescrypt(s)
}

// stripShadowUsername pulls the hash field out of a "user:hash[:...]" line — the
// shape produced by shadow2smith and by raw /etc/shadow entries. It
// only strips when the second colon-separated field is itself a crypt hash, so
// NetNTLM ("user::domain:…") and other colon-bearing formats are left intact.
func stripShadowUsername(s string) string {
	if !strings.Contains(s, ":") {
		return s
	}
	fields := strings.Split(s, ":")
	if len(fields) >= 2 && looksLikeCryptHash(fields[1]) {
		// Don't strip when the first field is itself an md5/sha1 hash — that is a
		// vBulletin/DCC/Redmine "hash:salt", not a "user:crypthash" shadow line.
		if isHex(fields[0]) && (len(fields[0]) == 32 || len(fields[0]) == 40) {
			return s
		}
		return fields[1]
	}
	return s
}

// detectHashTypes returns the candidate -t names for a target, in the order
// crack should try them. It consults the unified prototype table first and
// falls through to the not-yet-ported remainder of the original cascade.
func detectHashTypes(text string) []string {
	if types, served := detectTypesFromTable(text); served {
		return types
	}
	return legacyDetectHashTypes(text)
}

func legacyDetectHashTypes(text string) []string {
	t := strings.TrimSpace(text)
	// Unix crypt(3) shadow hashes may still carry a "user:" (or full passwd/
	// shadow line) prefix — crack the hash field directly.
	t = stripShadowUsername(t)
	// Archive/file hash formats produced by the *2smith extractors.
	if strings.HasPrefix(t, "$zipcrypto$") {
		return []string{"zipcrypto"}
	}
	if strings.HasPrefix(t, "$zipaes128$") {
		return []string{"zipaes128"}
	}
	if strings.HasPrefix(t, "$zipaes192$") {
		return []string{"zipaes192"}
	}
	if strings.HasPrefix(t, "$zipaes256$") {
		return []string{"zipaes256"}
	}
	if strings.HasPrefix(t, "$7z$") {
		return []string{"7z"}
	}
	if strings.HasPrefix(t, "$rar3$") || strings.HasPrefix(t, "$RAR3$") {
		return []string{"rar4"}
	}
	if strings.HasPrefix(t, "$rar5$") {
		return []string{"rar5"}
	}
	if isPDFR6(t) {
		return []string{"pdf-r6"}
	}
	if strings.HasPrefix(t, "$pdf$") {
		return []string{"pdf"}
	}
	if strings.HasPrefix(t, "$ssh$") {
		return []string{"ssh"}
	}
	if strings.HasPrefix(t, "$sshng$") {
		return []string{"ssh"}
	}
	if strings.HasPrefix(t, "$pkcs8$") {
		return []string{"pkcs8"}
	}
	if strings.HasPrefix(t, "$PEM$1$") {
		return []string{"pkcs8-pem-sha1"}
	}
	if strings.HasPrefix(t, "$PEM$2$") {
		return []string{"pkcs8-pem-sha256"}
	}
	if strings.HasPrefix(t, "$jksprivk$*") {
		return []string{"jks-private-key"}
	}
	if strings.HasPrefix(t, "$vmx$") {
		return []string{"vmware-vmx"}
	}
	if strings.HasPrefix(t, "$ab$") {
		return []string{"android-backup"}
	}
	if strings.HasPrefix(t, "$encfs$") {
		return []string{"encfs"}
	}
	if strings.HasPrefix(t, "$mozilla$*") {
		return []string{"mozilla-nss"}
	}
	if strings.HasPrefix(t, "$vbox$") {
		if strings.Contains(t, "$16$") {
			return []string{"virtualbox-aes256"}
		}
		return []string{"virtualbox-aes128"}
	}
	if strings.HasPrefix(t, "$metamask-short$") {
		return []string{"metamask-short"}
	}
	if strings.HasPrefix(t, "$metamask$") {
		return []string{"metamask"}
	}
	if strings.HasPrefix(t, "EXODUS:") {
		return []string{"exodus"}
	}
	if types := bitcoinAddressHashTypes(t); len(types) != 0 {
		return types
	}
	if strings.HasPrefix(t, "$gpg$") {
		return []string{"gpg"}
	}
	if strings.HasPrefix(t, "$office$2016$0$") {
		return []string{"office2016-sheet"}
	}
	if strings.HasPrefix(t, "$oldoffice$0*") || strings.HasPrefix(t, "$oldoffice$1*") {
		return []string{"office-old-md5"}
	}
	if strings.HasPrefix(t, "$oldoffice$3*") || strings.HasPrefix(t, "$oldoffice$4*") {
		return []string{"office-old-sha1"}
	}
	if strings.HasPrefix(t, "$office$") {
		return []string{"office"}
	}
	if strings.HasPrefix(t, "$mysqlna$") {
		return []string{"mysql-cram"}
	}
	if strings.HasPrefix(t, "$tacacs-plus$") {
		return []string{"tacacs-plus"}
	}
	if strings.HasPrefix(t, "$ASN$*") {
		return []string{"apple-secure-notes"}
	}
	if strings.HasPrefix(t, "otm_sha256:") {
		return []string{"oracle-otm"}
	}
	if strings.HasPrefix(t, "$xmpp-scram$") {
		return []string{"xmpp-scram"}
	}
	if strings.HasPrefix(t, "$postgres$") {
		return []string{"postgres-cram"}
	}
	if strings.HasPrefix(t, "$SNMPv3$") {
		return []string{"snmpv3"}
	}
	if strings.HasPrefix(t, "@m@") || strings.HasPrefix(t, "@m,") {
		return []string{"qnx-md5"}
	}
	if strings.HasPrefix(t, "@s@") || strings.HasPrefix(t, "@s,") {
		return []string{"qnx-sha256"}
	}
	if strings.HasPrefix(t, "@S@") || strings.HasPrefix(t, "@S,") {
		return []string{"qnx-sha512"}
	}
	if strings.HasPrefix(t, "{x-issha, ") {
		return []string{"sap-issha1"}
	}
	if strings.HasPrefix(t, "{x-isSHA256, ") {
		return []string{"sap-issha256"}
	}
	if strings.HasPrefix(t, "{x-isSHA384, ") {
		return []string{"sap-issha384"}
	}
	if strings.HasPrefix(t, "$stellar$") {
		return []string{"stellar-wallet"}
	}
	if strings.HasPrefix(t, "$telegram$0*") {
		return []string{"telegram-passcode"}
	}
	if strings.HasPrefix(t, "$telegram$1*") || strings.HasPrefix(t, "$telegram$2*") {
		return []string{"telegram-desktop"}
	}
	if strings.HasPrefix(t, "$signal$") {
		return []string{"signal"}
	}
	if strings.HasPrefix(t, "$keychain$*") {
		return []string{"macos-keychain"}
	}
	if strings.HasPrefix(t, "$vnc$*") {
		return []string{"vnc"}
	}
	if strings.HasPrefix(t, "$sm3$") {
		return []string{"sm3crypt"}
	}
	if strings.HasPrefix(t, "$chacha20$*") {
		return []string{"chacha20"}
	}
	if strings.HasPrefix(t, "{CRAM-MD5}") && len(t) == len("{CRAM-MD5}")+64 && isHex(t[len("{CRAM-MD5}"):]) {
		return []string{"dovecot-cram-md5"}
	}
	if separator := strings.LastIndex(t, "--"); separator > 0 && separator+66 == len(t) &&
		strings.Contains(t[:separator], "=") && isHex(t[separator+2:]) {
		return []string{"mojolicious"}
	}
	if _, _, _, err := parseBlockchainSecond(t); err == nil {
		return []string{"blockchain-second"}
	}
	if strings.HasPrefix(t, "$sntp-ms$") {
		return []string{"ms-sntp"}
	}
	if isNSEC3Record(t) {
		return []string{"dnssec-nsec3"}
	}
	if _, _, ok := parseOracleH(t); ok && strings.HasPrefix(t, "O$") {
		return []string{"oracle-h"}
	}
	if strings.HasPrefix(t, "$radmin3$") {
		return []string{"radmin3"}
	}
	if len(t) == 137 && t[0] == '2' && isHex(t[1:]) {
		return []string{"citrix-sha512"}
	}
	if len(t) == 63 && strings.HasPrefix(t, "SH2") {
		return []string{"fortigate256"}
	}
	if strings.HasPrefix(t, "$vbk$*") {
		return []string{"veeam-vbk"}
	}
	if strings.HasPrefix(t, "$MSONLINEACCOUNT$0$") {
		return []string{"ms-online-account"}
	}
	if strings.HasPrefix(t, "S:\"Config Passphrase\"=02:") {
		return []string{"securecrt-v2"}
	}
	if strings.HasPrefix(t, "$knx-ip-secure-device-authentication-code$*") {
		return []string{"knx-ip-secure"}
	}
	if strings.HasPrefix(t, "$teamspeak$3$") {
		return []string{"teamspeak3"}
	}
	if strings.HasPrefix(t, "$bcrypt-sha256$") {
		return []string{"passlib-bcrypt-sha256"}
	}
	if fields := strings.Split(t, ":"); len(fields) == 3 && fields[0] == "sha256" &&
		len(fields[1]) == 64 && isHex(fields[1]) && len(fields[2]) == 64 && isHex(fields[2]) {
		return []string{"anope-sha256"}
	}
	if len(t) == 129 && t[0] == '5' && isHex(t[1:]) {
		return []string{"citrix-pbkdf2"}
	}
	if isUmbracoHMACSHA1(t) {
		return []string{"umbraco-hmac-sha1"}
	}
	if strings.HasPrefix(t, "$AWS-Sig-v4$") {
		return []string{"aws-sig-v4"}
	}
	if isTOTPRecord(t) {
		return []string{"totp"}
	}
	if isHCCAPXHex(t) {
		return []string{"wpa-hccapx"}
	}
	if strings.HasPrefix(t, "$keepass$") {
		return []string{"keepass"}
	}
	if strings.HasPrefix(t, "WPA*01*") || strings.HasPrefix(t, "WPA*02*") || isLegacyPMKID(t) {
		return []string{"wpa"}
	}
	if typ := detectWPAPMKIDRecord(t); typ != "" {
		return []string{typ}
	}
	if strings.HasPrefix(t, "$ethereum$") {
		if strings.HasPrefix(t, "$ethereum$w*") {
			return []string{"ethereum-presale"}
		}
		return []string{"ethereum"}
	}
	if strings.HasPrefix(t, "$aescrypt$1*") {
		return []string{"aescrypt"}
	}
	if strings.HasPrefix(t, "$multibit$1*") {
		return []string{"multibit-key"}
	}
	if isTerraWallet(t) {
		return []string{"terra-wallet"}
	}
	if strings.HasPrefix(t, "$bitcoin$") {
		return []string{"bitcoin"}
	}
	if strings.HasPrefix(t, "$dmg$") {
		return []string{"dmg"}
	}
	if strings.HasPrefix(t, "$monero$0*") {
		return []string{"monero"}
	}
	if strings.HasPrefix(t, "$bitwarden$") {
		return []string{"bitwarden"}
	}
	if strings.HasPrefix(t, "$itunes_backup$") {
		return []string{"itunes"}
	}
	if strings.HasPrefix(t, "$ansible$") {
		return []string{"ansible"}
	}
	if strings.HasPrefix(t, "$blockchain$") {
		if _, _, err := parseBlockchainLegacy(t); err == nil {
			return []string{"blockchain-legacy"}
		}
		return []string{"blockchain"}
	}
	if strings.HasPrefix(t, "$rc4$") {
		return []string{"rc4-dropn"}
	}
	if isShiro1(t) {
		return []string{"shiro1-sha512"}
	}
	if isSSPR(t) {
		return []string{"sspr"}
	}
	if isNetIQPBKDF2(t) {
		return []string{"netiq-pbkdf2"}
	}
	if isAS400SSHA1(t) {
		return []string{"as400-ssha1"}
	}
	if isAuthMeSHA256(t) {
		return []string{"authme-sha256"}
	}
	if isPHPS(t) {
		return []string{"phps"}
	}
	if strings.HasPrefix(t, "pbkdf2(") && strings.Contains(t, ",sha512)$") {
		return []string{"web2py-pbkdf2"}
	}
	if strings.HasPrefix(t, "$wp$2") {
		return []string{"wordpress-bcrypt"}
	}
	if strings.HasPrefix(t, "$krb5db$17$") || strings.HasPrefix(t, "$krb5db$18$") {
		return []string{"krb5db"}
	}
	if fields := strings.Split(t, "."); len(fields) == 3 && len(fields[2]) == 27 {
		return []string{"flask-session"}
	}
	if fields := strings.Split(t, ":"); len(fields) == 2 && len(fields[0]) == 40 &&
		isHex(fields[0]) && len(fields[1]) >= 128 && isHex(fields[1]) {
		return []string{"peoplesoft-token"}
	}
	if fields := strings.Split(t, ":"); len(fields) == 2 && len(fields[0]) == 40 &&
		isHex(fields[0]) && len(fields[1]) == 20 {
		return []string{"sha1-cx"}
	}
	if fields := strings.Split(t, ":"); len(fields) == 3 && len(fields[0]) == 40 && isHex(fields[0]) {
		candidates := []string{"rails-restful-auth", "sha1-salt1-pass-salt2"}
		if len(fields[1]) <= 256 && len(fields[1])%2 == 0 && isHexOrEmpty(fields[1]) &&
			len(fields[2]) <= 256 && len(fields[2])%2 == 0 && isHexOrEmpty(fields[2]) {
			candidates = append(candidates, "sha1-salt-user-password")
		}
		return candidates
	}
	if isMySQL8(t) {
		return []string{"mysql8"}
	}
	if strings.HasPrefix(t, "$axcrypt_sha1$") {
		return []string{"axcrypt-sha1"}
	}
	if strings.HasPrefix(t, "$mongodb-scram$") {
		return []string{"mongodb"}
	}
	if strings.HasPrefix(t, "$solarwinds$") {
		return []string{"solarwinds"}
	}
	if strings.HasPrefix(t, "$sip$*") {
		return []string{"sip"}
	}
	if isDjangoHash(t) {
		return []string{"django"}
	}
	if strings.HasPrefix(t, "truecrypt:") {
		return []string{"truecrypt"}
	}
	if strings.HasPrefix(t, "veracrypt:") {
		return []string{"veracrypt"}
	}
	if strings.HasPrefix(t, "$truecrypt$") {
		return []string{"truecrypt"}
	}
	if strings.HasPrefix(t, "$veracrypt$") {
		return []string{"veracrypt"}
	}
	if strings.HasPrefix(t, "AK1") && len(t) == 47 {
		return []string{"fortigate"}
	}
	if strings.HasPrefix(t, "{x-isSHA512, ") {
		return []string{"sap-issha512"}
	}
	if fields := strings.Split(t, ":"); len(fields) == 4 && len(fields[0]) == 32 &&
		isHex(fields[0]) && len(fields[3]) == 32 && isHex(fields[3]) {
		return []string{"lastpass"}
	}
	if isChap(t) {
		return []string{"chap"}
	}
	if fields := strings.Split(t, ":"); len(fields) == 3 && len(fields[0]) == 32 && isHex(fields[0]) {
		return []string{"md5-salt1-pass-salt2", "md5-salt1-upper-md5-salt2-pass", "md5-triple-dual-salt", "md5-salt1-sha1salt2pass", "md5-triple-passsalt-dual", "empirecms"}
	}
	if strings.HasPrefix(t, "$bitlocker$") {
		return []string{"bitlocker"}
	}
	if strings.HasPrefix(t, "$electrum$") {
		return []string{"electrum"}
	}
	if isPhpassHash(t) {
		if strings.HasPrefix(t, "$H$") {
			return []string{"phpass", "phpass-md5"}
		}
		return []string{"phpass"}
	}
	if isDrupal7Hash(t) {
		return []string{"drupal7"}
	}
	if strings.HasPrefix(t, "$luks$") {
		return []string{"luks"}
	}
	if strings.HasPrefix(t, "$8$") && len(t) == 61 {
		return []string{"cisco8"}
	}
	if strings.HasPrefix(t, "$9$") && len(t) == 61 {
		return []string{"cisco9"}
	}
	if strings.HasPrefix(t, "$4$") && isCiscoType4(t) {
		return []string{"cisco4"}
	}
	if strings.HasPrefix(t, "$ml$") {
		return []string{"macos"}
	}
	if strings.HasPrefix(t, "{PKCS5S2}") {
		return []string{"atlassian"}
	}
	if isPBKDF1SHA1(t) {
		return []string{"pbkdf1"}
	}
	if isJWT(t) {
		return []string{"jwt"}
	}
	if isGenericPBKDF2(t) {
		return []string{"pbkdf2"}
	}
	if isPasslibPBKDF2(t) {
		return []string{"passlib-pbkdf2"}
	}
	if isWerkzeug(t) {
		return []string{"werkzeug"}
	}
	if isASPNetIdentity(t) {
		return []string{"aspnet-identity"}
	}
	if isGRUB2(t) {
		return []string{"grub2"}
	}
	if isOnePassword(t) {
		return []string{"1password"}
	}
	if isIKE(t) {
		return []string{"ike"}
	}
	if isDCC2(t) {
		return []string{"dcc2"}
	}
	if strings.HasPrefix(t, "SCRAM-SHA-256$") {
		return []string{"scram"}
	}
	if strings.HasPrefix(t, "$cram_md5$") {
		return []string{"cram-md5"}
	}
	if isCitrix(t) {
		return []string{"citrix"}
	}
	if isCiscoASA(t) {
		candidates := []string{"cisco-asa"}
		if _, _, ok := parseOracleH(t); ok {
			candidates = append(candidates, "oracle-h")
		}
		return candidates
	}
	if isIPMI(t) {
		return []string{"ipmi"}
	}
	if isIPMIMD5(t) {
		return []string{"ipmi-md5"}
	}
	if isAIX(t) {
		return []string{"aix"}
	}
	if isRedHat389PBKDF2(t) {
		return []string{"ldap-pbkdf2"}
	}
	if isLDAP(t) {
		return []string{"ldap"}
	}
	if isSybaseASE(t) {
		return []string{"sybase"}
	}
	if isSAPCodvnFGRFCReadTable(t) {
		return []string{"sap-fg-rfc-read-table"}
	}
	if isSAPCodvnBRFCReadTable(t) {
		return []string{"sap-b-rfc-read-table"}
	}
	if isSAPCodvnFG(t) {
		return []string{"sap-fg"}
	}
	if isJuniper(t) {
		return []string{"juniper"}
	}
	if isSAPCodvnB(t) {
		return []string{"sap-b"}
	}
	if isMediaWiki(t) {
		return []string{"mediawiki"}
	}
	if _, _, ok := parseOracleH(t); ok {
		return []string{"oracle-h"}
	}
	if generic := detectCompatSaltedTypes(t); len(generic) > 0 {
		// App-specific formats share the same outer hash:salt structure. Keep
		// their established precedence, then try generic Hashcat constructions.
		if isRedmine(t) {
			generic = append([]string{"redmine"}, generic...)
		}
		if isVBulletin(t) {
			generic = append([]string{"vbulletin", "dcc"}, generic...)
		}
		if isNetWitnessSHA256Record(t) {
			generic = append([]string{"netwitness-sha256"}, generic...)
		}
		if fields := strings.SplitN(t, ":", 2); len(fields) == 2 && len(fields[0]) == 64 && isHex(fields[0]) {
			generic = append([]string{"symfony-legacy"}, generic...)
		}
		if isHexPair(t, 32, 32) {
			generic = append([]string{"aes128-ecb-nokdf", "aes192-ecb-nokdf", "aes256-ecb-nokdf"}, generic...)
		}
		if isHexPair(t, 16, 16) {
			generic = append([]string{"des-plaintext", "3des-plaintext"}, generic...)
		}
		return generic
	}
	if strings.HasPrefix(t, "$krb5asrep$") {
		if strings.HasPrefix(t, "$krb5asrep$23$") {
			return []string{"krb5asrep", "krb5asrep-nt"}
		}
		return []string{"krb5asrep"}
	}
	if strings.HasPrefix(t, "$krb5tgs$") {
		if strings.HasPrefix(t, "$krb5tgs$23$") {
			return []string{"krb5tgs", "krb5tgs-nt"}
		}
		return []string{"krb5tgs"}
	}
	if strings.HasPrefix(t, "$krb5pa$") {
		return []string{"krb5pa"}
	}
	if isNetNTLMLine(t) {
		// v1 and v2 share the user::domain:… shape; try both.
		return []string{"netntlmv2", "netntlmv1"}
	}
	if reBcrypt.MatchString(t) {
		return []string{"bcrypt"}
	}
	if reArgon2.MatchString(t) {
		return []string{"argon2"}
	}
	if reScrypt.MatchString(t) {
		return []string{"scrypt"}
	}
	if rePostgres.MatchString(t) {
		return []string{"postgres"}
	}
	if reMySQL41.MatchString(t) {
		return []string{"mysql41"}
	}
	if reMSSQLNew.MatchString(t) {
		if strings.HasPrefix(strings.ToLower(t), "0x0200") {
			return []string{"mssql2012"}
		}
		return []string{"mssql2005"}
	}
	if looksLikeDescrypt(t) {
		return []string{"descrypt"}
	}
	// A 16-char crypt-base64 token with non-hex characters is a Cisco-PIX hash.
	if len(t) == 16 && isPixToken(t) && !isHex(t) {
		return []string{"cisco-pix"}
	}
	if isDahuaAuthToken(t) {
		return []string{"dahua-auth-md5", "besder-auth-md5"}
	}
	if !isHex(t) {
		return nil
	}
	if len(t) == 50 && strings.EqualFold(t[8:10], "01") {
		return []string{"arubaos"}
	}
	switch len(t) {
	case 16:
		return []string{"mysql323", "cisco-pix", "half-md5"}
	case 32:
		return []string{"md5", "md4", "md2", "ntlm", "lm"}
	case 40:
		return []string{"sha1", "sha0", "ripemd160"}
	case 56:
		return []string{"sha224", "sha512_224", "sha3_224", "keccak224"}
	case 60:
		return []string{"oracle11g"}
	case 160:
		return []string{"oracle12c"}
	case 64:
		return []string{"sha256", "sha3_256", "sm3", "blake2s", "streebog256", "sha512_256", "keccak256", "shake128-256", "blake2b256"}
	case 96:
		return []string{"sha384", "sha3_384", "blake2b384", "keccak384"}
	case 128:
		return []string{"sha512", "sha3_512", "blake2b", "whirlpool", "streebog512", "keccak512", "shake256-512", "cisco-ise"}
	default:
		return nil
	}
}

func unique(items []string) []string {
	seen := make(map[string]struct{}, len(items))
	out := make([]string, 0, len(items))
	for _, item := range items {
		if _, ok := seen[item]; !ok {
			seen[item] = struct{}{}
			out = append(out, item)
		}
	}
	return out
}
