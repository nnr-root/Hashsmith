package smith

// Android full-disk encryption — Hashcat 8800 and 12900.
//
//	8800   $fde$<len>$<salt>$<len>$<encrypted master key>$<sector data>
//	12900  <32 bytes><32 bytes><16 bytes>, run together with no separators
//
// The two share a name and nothing else.
//
// 8800 is the crypto-footer scheme used up to Android 4.3. PBKDF2-HMAC-SHA1
// at 2,000 rounds yields a key and an IV, which unwrap a 16-byte master key;
// that master key then decrypts the start of the filesystem under AES-CBC with
// ESSIV, where the IV for sector zero is AES-256(SHA-256(master key), 0).
//
// The proof is what comes out, and there are two possible answers because the
// partition may be either filesystem Android used. A FAT volume gives a boot
// sector whose OEM name reads "MSDOS5.0" three bytes in, past the jump
// instruction. An ext4 volume gives a superblock at byte 1024, checked on
// three of its fields: s_first_data_block below 2, s_log_block_size below 16,
// and s_magic exactly 0xEF53. Hashcat tries both and so does this; Hashcat's
// own example record is the ext4 one, and its first sector decrypts to zeros,
// so implementing only the FAT test passes no vector at all.
//
// 12900 is Samsung's, and has no cipher in it at all. PBKDF2-HMAC-SHA256 at
// 4,096 rounds produces a key, that key authenticates a 32-byte field with
// HMAC-SHA256, and the result is compared. The record is three fixed-width
// hex runs with no delimiters: the 32-byte field, the 32-byte expected MAC,
// and the 16-byte salt — in that order, so the salt a reader looks for first
// is last.

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"strings"

	"golang.org/x/crypto/pbkdf2"
)

const (
	androidFDEIterations     = 2000
	androidSamsungIterations = 4096
	// androidFDEMagicOffset skips the boot sector's three-byte jump.
	androidFDEMagicOffset = 3
)

var androidFDEMagic = []byte("MSDOS5.0")

func verifyAndroidFDE(target, candidate string) (bool, error) {
	t := strings.TrimSpace(target)
	if !strings.HasPrefix(t, "$fde$") {
		return false, errors.New("not an Android FDE record")
	}
	f := strings.Split(strings.TrimPrefix(t, "$fde$"), "$")
	if len(f) != 5 {
		return false, errors.New("Android FDE record must be $fde$<len>$<salt>$<len>$<key>$<data>")
	}
	salt, err := hex.DecodeString(f[1])
	if err != nil || len(salt) == 0 {
		return false, errors.New("Android FDE salt is not hex")
	}
	emk, err := hex.DecodeString(f[3])
	if err != nil || len(emk) != aes.BlockSize {
		return false, errors.New("Android FDE encrypted master key must be 16 hex-encoded bytes")
	}
	data, err := hex.DecodeString(f[4])
	if err != nil || len(data) < aes.BlockSize {
		return false, errors.New("Android FDE sector data is too short")
	}

	derived := pbkdf2.Key([]byte(candidate), salt, androidFDEIterations, 32, sha1.New)
	block, err := aes.NewCipher(derived[:16])
	if err != nil {
		return false, err
	}
	masterKey := make([]byte, aes.BlockSize)
	cipher.NewCBCDecrypter(block, derived[16:32]).CryptBlocks(masterKey, emk)

	// ESSIV: the sector IV is the sector number encrypted under SHA-256 of the
	// master key. Sector zero, so the plaintext is sixteen zero bytes.
	essivKey := sha256.Sum256(masterKey)
	essivBlock, err := aes.NewCipher(essivKey[:])
	if err != nil {
		return false, err
	}
	essiv := make([]byte, aes.BlockSize)
	essivBlock.Encrypt(essiv, make([]byte, aes.BlockSize))

	mkBlock, err := aes.NewCipher(masterKey)
	if err != nil {
		return false, err
	}
	plain := make([]byte, aes.BlockSize)
	cipher.NewCBCDecrypter(mkBlock, essiv).CryptBlocks(plain, data[:aes.BlockSize])
	end := androidFDEMagicOffset + len(androidFDEMagic)
	if string(plain[androidFDEMagicOffset:end]) == string(androidFDEMagic) {
		return true, nil
	}
	return androidFDEExt4Valid(mkBlock, data), nil
}

const (
	// ext4 puts its superblock at byte 1024 of the volume.
	ext4SuperblockOffset = 1024
	ext4SuperblockRead   = 48
	ext4Magic            = 0xEF53
)

// androidFDEExt4Valid decrypts the ext4 superblock and checks three fields
// that a wrong key cannot plausibly produce together.
//
// The block at the superblock's own offset is not decrypted: it only serves as
// the CBC chaining value for the blocks after it, which is where the fields
// being checked live.
func androidFDEExt4Valid(mkBlock cipher.Block, data []byte) bool {
	start := ext4SuperblockOffset + aes.BlockSize
	if len(data) < start+ext4SuperblockRead {
		return false
	}
	sb := make([]byte, ext4SuperblockRead)
	iv := data[ext4SuperblockOffset:start]
	cipher.NewCBCDecrypter(mkBlock, iv).CryptBlocks(sb, data[start:start+ext4SuperblockRead])

	// Offsets are relative to the superblock, and sb begins 16 bytes into it.
	firstDataBlock := binary.LittleEndian.Uint32(sb[0x14-aes.BlockSize:])
	logBlockSize := binary.LittleEndian.Uint32(sb[0x18-aes.BlockSize:])
	magic := binary.LittleEndian.Uint16(sb[0x38-aes.BlockSize:])
	return firstDataBlock < 2 && logBlockSize < 16 && magic == ext4Magic
}

const (
	samsungFDEDataLen = 32
	samsungFDEMACLen  = 32
	samsungFDESaltLen = 16
)

// androidSamsungFDERecord holds one parsed 12900 record, shared by the
// scalar verifyAndroidSamsungFDE and the AVX2-batched lane hasher
// (pbkdf2_lane_android_samsung_fde.go).
type androidSamsungFDERecord struct {
	data []byte
	mac  []byte
	salt []byte
}

// parseAndroidSamsungFDERecord parses target, or returns an error identical
// in wording and condition to what verifyAndroidSamsungFDE always returned
// before this was split out.
func parseAndroidSamsungFDERecord(target string) (androidSamsungFDERecord, error) {
	t := strings.TrimSpace(target)
	want := 2 * (samsungFDEDataLen + samsungFDEMACLen + samsungFDESaltLen)
	if len(t) != want || !isHex(t) {
		return androidSamsungFDERecord{}, errors.New("Samsung Android FDE record must be 160 hex characters")
	}
	raw, err := hex.DecodeString(t)
	if err != nil {
		return androidSamsungFDERecord{}, err
	}
	return androidSamsungFDERecord{
		data: raw[:samsungFDEDataLen],
		mac:  raw[samsungFDEDataLen : samsungFDEDataLen+samsungFDEMACLen],
		salt: raw[samsungFDEDataLen+samsungFDEMACLen:],
	}, nil
}

// androidSamsungFDEMatches is the shared "does this derived key authenticate
// the record" check. Used by verifyAndroidSamsungFDE for its single derived
// key and by the lane hasher for each of a batch's.
func androidSamsungFDEMatches(key []byte, r *androidSamsungFDERecord) bool {
	h := hmac.New(sha256.New, key)
	_, _ = h.Write(r.data)
	return hmac.Equal(h.Sum(nil), r.mac)
}

func verifyAndroidSamsungFDE(target, candidate string) (bool, error) {
	r, err := parseAndroidSamsungFDERecord(target)
	if err != nil {
		return false, err
	}
	key := pbkdf2.Key([]byte(candidate), r.salt, androidSamsungIterations, 32, sha256.New)
	return androidSamsungFDEMatches(key, &r), nil
}
