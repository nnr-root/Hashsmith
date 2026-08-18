package main

// MongoDB SCRAM-SHA-1 (ServerKey / stored-key form):
//
//	$mongodb-scram$0$<user>$<iter>$<b64 salt>$<b64 storedKey>
//
//	inner      = hex(md5(user . ":mongo:" . password))
//	salted     = PBKDF2-HMAC-SHA1(inner, salt, iter, 20)
//	storedKey  = SHA1( HMAC-SHA1(salted, "Client Key") )

import (
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha1"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"strconv"
	"strings"

	"golang.org/x/crypto/pbkdf2"
)

func verifyMongoDB(targetHash, candidate string) (bool, error) {
	if !strings.HasPrefix(targetHash, "$mongodb-scram$") {
		return false, errors.New("invalid MongoDB hash (missing $mongodb-scram$ prefix)")
	}
	f := strings.Split(targetHash[len("$mongodb-scram$"):], "$")
	// f: [version, user, iter, b64salt, b64storedkey]
	if len(f) != 5 {
		return false, errors.New("invalid MongoDB hash (need ver$user$iter$salt$key)")
	}
	iter, err := strconv.Atoi(f[2])
	if err != nil || iter < 1 {
		return false, errors.New("invalid MongoDB iteration count")
	}
	salt, err := base64.StdEncoding.DecodeString(f[3])
	if err != nil {
		return false, errors.New("invalid MongoDB salt")
	}
	want, err := base64.StdEncoding.DecodeString(f[4])
	if err != nil || len(want) != 20 {
		return false, errors.New("invalid MongoDB stored key")
	}

	innerSum := md5.Sum([]byte(f[1] + ":mongo:" + candidate))
	inner := []byte(hex.EncodeToString(innerSum[:]))
	salted := pbkdf2.Key(inner, salt, iter, 20, sha1.New)
	ck := hmac.New(sha1.New, salted)
	ck.Write([]byte("Client Key"))
	stored := sha1.Sum(ck.Sum(nil))
	return bytesEqualCT(stored[:], want), nil
}
