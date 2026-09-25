package smith

// MongoDB SCRAM credential records:
//
//	$mongodb-scram$0$<user>$<iter>$<b64 salt>$<b64 storedKey>
//	$mongodb-scram$1$<user>$<iter>$<b64 salt>$<b64 SHA-256 storedKey>
//	$mongodb-scram$2$<user>$<iter>$<b64 salt>$<b64 SHA-256 serverKey>
//
// Version 0 is MongoDB's legacy SHA-1 mechanism, which first applies the old
// username:mongo:password MD5 transform. Versions 1 and 2 are SCRAM-SHA-256:
// they SASLprep the password and feed it directly to PBKDF2-HMAC-SHA256.

import (
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"strconv"
	"strings"

	"github.com/xdg-go/stringprep"
	"golang.org/x/crypto/pbkdf2"
)

// mongoDBSCRAM256Record holds one parsed SCRAM-SHA-256 (version 1 or 2)
// $mongodb-scram$ target — the one MongoDB shape the AVX2 lane hasher
// (pbkdf2_lane_mongodb.go) accelerates. verifyMongoDB above stays generic
// over the legacy MONGODB-CR and SCRAM-SHA-1 shapes as well, and is
// untouched; this is a second, narrower, fully independent parser used
// only by the lane hasher, whose own tests check it against verifyMongoDB
// on every candidate so the two can never silently drift. It duplicates
// verifyMongoDB's field parsing and dialect handling rather than sharing
// code with it, because verifyMongoDB's SHA-1 branches are woven through
// the same fields (the username, needed only for the MD5 legacy
// transform) in a way that resists a clean split without touching a
// working, already-shipped scalar path.
type mongoDBSCRAM256Record struct {
	salt       []byte
	iter       int
	label      string // "Client Key" or "Server Key"
	sha256Wrap bool   // version 1 only: SHA-256 the HMAC output before comparing
	want       []byte
}

// parseMongoDBSCRAM256 parses target, refusing the legacy MONGODB-CR shape,
// the SCRAM-SHA-1 shape (version 0), and John's "$scram$" spelling (which
// verifyMongoDB's own johnMongoDBSCRAM rewrite always maps to version 0,
// so it can never be SHA-256-eligible) — all three fall back to the scalar
// path, which already handles them.
func parseMongoDBSCRAM256(targetHash string) (mongoDBSCRAM256Record, error) {
	if !strings.HasPrefix(targetHash, "$mongodb-scram$") {
		return mongoDBSCRAM256Record{}, errors.New("not a MongoDB SCRAM record")
	}
	body := targetHash[len("$mongodb-scram$"):]
	sep, hashcatDialect := "$", false
	if strings.HasPrefix(body, "*") {
		body, sep, hashcatDialect = body[1:], "*", true
	}
	f := strings.Split(body, sep)
	if len(f) != 5 {
		return mongoDBSCRAM256Record{}, errors.New("invalid MongoDB hash (need ver$user$iter$salt$key, or hashcat's *-separated form)")
	}
	version, err := strconv.Atoi(f[0])
	if err != nil || version < 0 || version > 2 {
		return mongoDBSCRAM256Record{}, errors.New("unsupported MongoDB SCRAM record version")
	}
	iter, err := strconv.Atoi(f[2])
	if err != nil || iter < 1 || iter > maxKDFIterations || (version > 0 && iter < 4096) {
		return mongoDBSCRAM256Record{}, errors.New("invalid MongoDB iteration count")
	}
	salt, err := base64.StdEncoding.DecodeString(f[3])
	if err != nil || len(salt) == 0 || len(salt) > maxKDFFieldSize {
		return mongoDBSCRAM256Record{}, errors.New("invalid MongoDB salt")
	}
	want, err := base64.StdEncoding.DecodeString(f[4])
	wantLen := 20
	if version > 0 {
		wantLen = 32
	}
	if err != nil || len(want) != wantLen {
		return mongoDBSCRAM256Record{}, errors.New("invalid MongoDB stored key")
	}

	// See verifyMongoDB's own comment: hashcat's '*' spelling always means
	// the SHA-256 ServerKey once version 0 (SHA-1) is excluded.
	if hashcatDialect {
		if version == 0 {
			return mongoDBSCRAM256Record{}, errors.New("not a SCRAM-SHA-256 MongoDB record")
		}
		version = 2
	}
	if version == 0 {
		return mongoDBSCRAM256Record{}, errors.New("not a SCRAM-SHA-256 MongoDB record")
	}

	label := "Client Key"
	sha256Wrap := true
	if version == 2 {
		label = "Server Key"
		sha256Wrap = false
	}
	return mongoDBSCRAM256Record{salt: salt, iter: iter, label: label, sha256Wrap: sha256Wrap, want: want}, nil
}

// mongoDBSCRAM256Matches is the shared "does this salted password reach
// the stored key" check for the SCRAM-SHA-256 shapes, used only by the
// lane hasher (verifyMongoDB inlines the equivalent steps directly).
func mongoDBSCRAM256Matches(r *mongoDBSCRAM256Record, salted []byte) bool {
	key := hmac.New(sha256.New, salted)
	key.Write([]byte(r.label))
	result := key.Sum(nil)
	if r.sha256Wrap {
		digest := sha256.Sum256(result)
		result = digest[:]
	}
	return bytesEqualCT(result, r.want)
}

func verifyMongoDB(targetHash, candidate string) (bool, error) {
	// MONGODB-CR, the credential MongoDB used before SCRAM: one MD5 over the
	// username, a fixed separator and the password.
	if user, digest, ok := johnMongoDBLegacy(targetHash); ok {
		return strings.EqualFold(md5Hex([]byte(user+":mongo:"+candidate)), digest), nil
	}
	if rewritten, ok := johnMongoDBSCRAM(targetHash); ok {
		targetHash = rewritten
	}
	if !strings.HasPrefix(targetHash, "$mongodb-scram$") {
		return false, errors.New("invalid MongoDB hash (missing $mongodb-scram$ prefix)")
	}
	// Two spellings of the same record: John separates the fields with '$',
	// hashcat -m 24100 / -m 24200 with '*' and a leading '*'. Both are read.
	body := targetHash[len("$mongodb-scram$"):]
	sep, hashcatDialect := "$", false
	if strings.HasPrefix(body, "*") {
		body, sep, hashcatDialect = body[1:], "*", true
	}
	f := strings.Split(body, sep)
	// f: [version, user, iter, b64salt, b64storedkey]
	if len(f) != 5 {
		return false, errors.New("invalid MongoDB hash (need ver$user$iter$salt$key, or hashcat's *-separated form)")
	}
	version, err := strconv.Atoi(f[0])
	if err != nil || version < 0 || version > 2 {
		return false, errors.New("unsupported MongoDB SCRAM record version")
	}
	iter, err := strconv.Atoi(f[2])
	if err != nil || iter < 1 || iter > maxKDFIterations || (version > 0 && iter < 4096) {
		return false, errors.New("invalid MongoDB iteration count")
	}
	salt, err := base64.StdEncoding.DecodeString(f[3])
	if err != nil || len(salt) == 0 || len(salt) > maxKDFFieldSize {
		return false, errors.New("invalid MongoDB salt")
	}
	want, err := base64.StdEncoding.DecodeString(f[4])
	wantLen := 20
	if version > 0 {
		wantLen = 32
	}
	if err != nil || len(want) != wantLen {
		return false, errors.New("invalid MongoDB stored key")
	}

	// The two dialects disagree about what the version field selects, and the
	// separator is what tells them apart.
	//
	// In the '$' spelling, version picks the derived key: 0 = SHA-1 StoredKey,
	// 1 = SHA-256 StoredKey, 2 = SHA-256 ServerKey.
	//
	// In hashcat's '*' spelling it picks only the hash — 0 = SHA-1,
	// 1 = SHA-256 — and the derived key is ALWAYS the ServerKey, because both
	// modes that use this spelling are named "MongoDB ServerKey SCRAM-...".
	// Confirmed against hashcat's own -m 24100 record: HMAC-SHA1 of the salted
	// password under "Server Key", raw, reproduces the stored value, while
	// either Client Key form and the SHA-1-wrapped form do not.
	if hashcatDialect {
		// hashcat base64-encodes the username; the '$' spelling stores it plain.
		if u, err := base64.StdEncoding.DecodeString(f[1]); err == nil {
			f[1] = string(u)
		}
		if version == 0 {
			innerSum := md5.Sum([]byte(f[1] + ":mongo:" + candidate))
			inner := []byte(hex.EncodeToString(innerSum[:]))
			salted := pbkdf2.Key(inner, salt, iter, 20, sha1.New)
			sk := hmac.New(sha1.New, salted)
			sk.Write([]byte("Server Key"))
			return bytesEqualCT(sk.Sum(nil), want), nil
		}
		version = 2 // SHA-256 ServerKey, which the shared path below computes
	}

	if version == 0 {
		innerSum := md5.Sum([]byte(f[1] + ":mongo:" + candidate))
		inner := []byte(hex.EncodeToString(innerSum[:]))
		salted := pbkdf2.Key(inner, salt, iter, 20, sha1.New)
		ck := hmac.New(sha1.New, salted)
		ck.Write([]byte("Client Key"))
		stored := sha1.Sum(ck.Sum(nil))
		return bytesEqualCT(stored[:], want), nil
	}

	prepared, err := stringprep.SASLprep.Prepare(candidate)
	if err != nil {
		return false, errors.New("MongoDB SCRAM-SHA-256 password fails SASLprep")
	}
	salted := pbkdf2.Key([]byte(prepared), salt, iter, 32, sha256.New)
	label := "Client Key"
	if version == 2 {
		label = "Server Key"
	}
	key := hmac.New(sha256.New, salted)
	key.Write([]byte(label))
	result := key.Sum(nil)
	if version == 1 {
		digest := sha256.Sum256(result)
		result = digest[:]
	}
	return bytesEqualCT(result, want), nil
}
