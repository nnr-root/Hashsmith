package main

// Additional database password records whose on-disk representation differs
// from the usual modular-crypt formats.

import (
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

const mysql8Prefix = "$mysql$A$"

type mysql8Hash struct {
	cost   int
	salt   []byte
	digest string
}

// parseMySQL8 accepts Hashcat's binary-safe transport for MySQL 8
// caching_sha2_password records:
//
//	$mysql$A$005*<20-byte salt as hex>*<43-byte SHA-crypt text as hex>
func parseMySQL8(target string) (*mysql8Hash, error) {
	if !strings.HasPrefix(target, mysql8Prefix) {
		return nil, errors.New("invalid MySQL 8 hash prefix")
	}
	parts := strings.Split(strings.TrimPrefix(target, mysql8Prefix), "*")
	if len(parts) != 3 || len(parts[0]) != 3 {
		return nil, errors.New("invalid MySQL 8 hash fields")
	}
	cost, err := strconv.Atoi(parts[0])
	if err != nil || cost < 1 || cost > maxKDFIterations/1000 {
		return nil, errors.New("invalid MySQL 8 cost")
	}
	salt, err := hex.DecodeString(parts[1])
	if err != nil || len(salt) != 20 {
		return nil, errors.New("invalid MySQL 8 salt (want 20 bytes as hex)")
	}
	digestBytes, err := hex.DecodeString(parts[2])
	if err != nil || len(digestBytes) != 43 {
		return nil, errors.New("invalid MySQL 8 digest")
	}
	for _, ch := range digestBytes {
		if strings.IndexByte(itoa64, ch) < 0 {
			return nil, errors.New("invalid MySQL 8 SHA-crypt character")
		}
	}
	return &mysql8Hash{cost: cost, salt: salt, digest: string(digestBytes)}, nil
}

func verifyMySQL8(target, candidate string) (bool, error) {
	parsed, err := parseMySQL8(target)
	if err != nil {
		return false, err
	}
	encoded := shaCryptRawWithSaltLimit(
		sha256Params, candidate, string(parsed.salt), parsed.cost*1000, false, 20,
	)
	i := strings.LastIndexByte(encoded, '$')
	if i < 0 {
		return false, errors.New("internal MySQL 8 SHA-crypt error")
	}
	return bytesEqualCT([]byte(encoded[i+1:]), []byte(parsed.digest)), nil
}

func isMySQL8(target string) bool {
	_, err := parseMySQL8(target)
	return err == nil
}

func encodeMySQL8(password string, salt []byte, cost int) (string, error) {
	if len(salt) != 20 {
		return "", errors.New("MySQL 8 requires exactly 20 salt bytes")
	}
	if cost < 1 || cost > 999 {
		return "", errors.New("MySQL 8 cost must be between 1 and 999")
	}
	encoded := shaCryptRawWithSaltLimit(sha256Params, password, string(salt), cost*1000, false, 20)
	i := strings.LastIndexByte(encoded, '$')
	if i < 0 {
		return "", errors.New("internal MySQL 8 SHA-crypt error")
	}
	return fmt.Sprintf("%s%03d*%s*%s", mysql8Prefix, cost,
		hex.EncodeToString(salt), hex.EncodeToString([]byte(encoded[i+1:]))), nil
}
