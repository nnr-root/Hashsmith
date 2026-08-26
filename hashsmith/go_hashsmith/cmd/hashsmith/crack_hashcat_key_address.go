package main

// Hashcat 28501-28506 and 30901-30906 verify that a WIF or raw secp256k1
// private key derives to the supplied Bitcoin mainnet address. These are
// candidate-key verifiers (not password KDFs), but exposing the exact modes is
// useful when comparing Hashsmith's format coverage with Hashcat.

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"math/big"
	"strings"

	"golang.org/x/crypto/ripemd160"
)

var (
	secpP, _  = new(big.Int).SetString("fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f", 16)
	secpN, _  = new(big.Int).SetString("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141", 16)
	secpGX, _ = new(big.Int).SetString("79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798", 16)
	secpGY, _ = new(big.Int).SetString("483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8", 16)
)

type secpPoint struct{ x, y *big.Int }

func secpAdd(a, b secpPoint) secpPoint {
	if a.x == nil {
		return b
	}
	if b.x == nil {
		return a
	}
	if a.x.Cmp(b.x) == 0 {
		if new(big.Int).Add(a.y, b.y).Mod(new(big.Int).Add(a.y, b.y), secpP).Sign() == 0 {
			return secpPoint{}
		}
		return secpDouble(a)
	}
	num := new(big.Int).Sub(b.y, a.y)
	den := new(big.Int).Sub(b.x, a.x)
	den.ModInverse(den, secpP)
	lambda := num.Mul(num, den)
	lambda.Mod(lambda, secpP)
	x := new(big.Int).Mul(lambda, lambda)
	x.Sub(x, a.x).Sub(x, b.x).Mod(x, secpP)
	y := new(big.Int).Sub(a.x, x)
	y.Mul(lambda, y).Sub(y, a.y).Mod(y, secpP)
	return secpPoint{x, y}
}

func secpDouble(a secpPoint) secpPoint {
	if a.x == nil || a.y.Sign() == 0 {
		return secpPoint{}
	}
	num := new(big.Int).Mul(a.x, a.x)
	num.Mul(num, big.NewInt(3))
	den := new(big.Int).Lsh(new(big.Int).Set(a.y), 1)
	den.ModInverse(den, secpP)
	lambda := num.Mul(num, den)
	lambda.Mod(lambda, secpP)
	x := new(big.Int).Mul(lambda, lambda)
	twoX := new(big.Int).Lsh(new(big.Int).Set(a.x), 1)
	x.Sub(x, twoX).Mod(x, secpP)
	y := new(big.Int).Sub(a.x, x)
	y.Mul(lambda, y).Sub(y, a.y).Mod(y, secpP)
	return secpPoint{x, y}
}

func secpScalarBaseMult(k []byte) secpPoint {
	result := secpPoint{}
	addend := secpPoint{new(big.Int).Set(secpGX), new(big.Int).Set(secpGY)}
	for i := len(k)*8 - 1; i >= 0; i-- {
		result = secpDouble(result)
		if k[len(k)-1-i/8]&(1<<uint(i%8)) != 0 {
			result = secpAdd(result, addend)
		}
	}
	return result
}

func fixed32(v *big.Int) []byte {
	out := make([]byte, 32)
	v.FillBytes(out)
	return out
}

func bitcoinPublicKey(private []byte, compressed bool) ([]byte, error) {
	d := new(big.Int).SetBytes(private)
	if len(private) != 32 || d.Sign() <= 0 || d.Cmp(secpN) >= 0 {
		return nil, errors.New("invalid secp256k1 private key")
	}
	p := secpScalarBaseMult(private)
	if compressed {
		prefix := byte(2)
		if p.y.Bit(0) != 0 {
			prefix = 3
		}
		return append([]byte{prefix}, fixed32(p.x)...), nil
	}
	return append(append([]byte{4}, fixed32(p.x)...), fixed32(p.y)...), nil
}

func hash160(data []byte) []byte {
	s := sha256.Sum256(data)
	h := ripemd160.New()
	_, _ = h.Write(s[:])
	return h.Sum(nil)
}

func encodeSegWitV0(program []byte) (string, error) {
	values, err := convertBits(program, 8, 5, true)
	if err != nil {
		return "", err
	}
	values = append([]byte{0}, values...)
	check := append(bech32HRPExpand("bc"), values...)
	check = append(check, make([]byte, 6)...)
	polymod := bech32Polymod(check) ^ bech32Constant
	var out strings.Builder
	out.WriteString("bc1")
	for _, v := range values {
		out.WriteByte(bech32Alphabet[v])
	}
	for i := 0; i < 6; i++ {
		out.WriteByte(bech32Alphabet[(polymod>>uint(5*(5-i)))&31])
	}
	return out.String(), nil
}

func bitcoinAddress(private []byte, compressed bool, kind string) (string, error) {
	pub, err := bitcoinPublicKey(private, compressed)
	if err != nil {
		return "", err
	}
	pubHash := hash160(pub)
	switch kind {
	case "p2pkh":
		return encodeBase58Check(append([]byte{0}, pubHash...)), nil
	case "p2wpkh":
		return encodeSegWitV0(pubHash)
	case "p2sh-p2wpkh":
		redeem := append([]byte{0, 20}, pubHash...)
		return encodeBase58Check(append([]byte{5}, hash160(redeem)...)), nil
	default:
		return "", errors.New("unsupported Bitcoin address type")
	}
}

func verifyBitcoinPrivateKeyAddress(target, candidate, algo string) (bool, error) {
	wif := strings.HasPrefix(algo, "bitcoin-wif-")
	compressed := strings.HasSuffix(algo, "-compressed")
	kind := "p2pkh"
	if strings.Contains(algo, "p2sh-p2wpkh") {
		kind = "p2sh-p2wpkh"
	} else if strings.Contains(algo, "p2wpkh") {
		kind = "p2wpkh"
	}
	var private []byte
	if wif {
		payload, err := decodeBase58Check(candidate)
		if err != nil {
			return false, nil
		}
		wantLen := 33
		if compressed {
			wantLen = 34
		}
		if len(payload) != wantLen || payload[0] != 0x80 || (compressed && payload[33] != 1) {
			return false, nil
		}
		private = payload[1:33]
	} else {
		decoded, err := hex.DecodeString(candidate)
		if err != nil || len(decoded) != 32 {
			return false, nil
		}
		private = decoded
	}
	got, err := bitcoinAddress(private, compressed, kind)
	if err != nil {
		return false, nil
	}
	return got == target, nil
}

func bitcoinAddressHashTypes(target string) []string {
	kind := ""
	if strings.HasPrefix(strings.ToLower(target), "bc1q") {
		kind = "p2wpkh"
	} else if payload, err := decodeBase58Check(target); err == nil && len(payload) == 21 {
		switch payload[0] {
		case 0:
			kind = "p2pkh"
		case 5:
			kind = "p2sh-p2wpkh"
		}
	}
	if kind == "" {
		return nil
	}
	return []string{
		"bitcoin-wif-" + kind + "-compressed",
		"bitcoin-wif-" + kind + "-uncompressed",
		"bitcoin-raw-" + kind + "-compressed",
		"bitcoin-raw-" + kind + "-uncompressed",
	}
}
