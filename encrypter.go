// Package laravelcrypt is a Go port of Laravel's Illuminate\Encryption\Encrypter,
// wire-compatible with Laravel 10 through 13. It lets a Go program decrypt values that Laravel
// encrypted with Crypt/Encrypter — and produce values Laravel can decrypt — using the same
// key (the APP_KEY "base64:..." form, or any dedicated key in that form).
//
// Payload format (identical to Laravel):
//
//		base64( json{ "iv": b64, "value": b64, "mac": hex, "tag": b64 } )
//
//	  - AES-256-CBC (Laravel default): random 16-byte IV, PKCS#7 padding, and an
//	    HMAC-SHA256 over the base64(iv)+base64(value) strings (hex, lower-case). tag = "".
//	  - AES-256-GCM (AEAD): random 12-byte IV, the 16-byte GCM tag in `tag`, mac = "".
//
// The key is the RAW key bytes (a Laravel APP_KEY "base64:XXXX" decodes to 32 bytes).
package laravelcrypt

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
)

type cipherInfo struct {
	size int
	aead bool
}

var supportedCiphers = map[string]cipherInfo{
	"aes-128-cbc": {16, false},
	"aes-256-cbc": {32, false},
	"aes-128-gcm": {16, true},
	"aes-256-gcm": {32, true},
}

// Errors mirror Laravel's DecryptException cases so callers can distinguish a tampered
// payload (ErrInvalidMAC / ErrDecrypt) from a malformed one (ErrInvalidPayload).
var (
	ErrUnsupportedCipher = errors.New("laravelcrypt: unsupported cipher or incorrect key length")
	ErrInvalidPayload    = errors.New("laravelcrypt: the payload is invalid")
	ErrInvalidMAC        = errors.New("laravelcrypt: the MAC is invalid")
	ErrDecrypt           = errors.New("laravelcrypt: could not decrypt the data")
	ErrEmptyKey          = errors.New("laravelcrypt: empty key")
)

// Encrypter is a single-key, single-cipher Laravel-compatible encrypter.
type Encrypter struct {
	key    []byte
	cipher string
	info   cipherInfo
}

type wirePayload struct {
	IV    string `json:"iv"`
	Value string `json:"value"`
	MAC   string `json:"mac"`
	Tag   string `json:"tag"`
}

// New builds an Encrypter. key accepts the Laravel "base64:..." form, a bare base64
// string, or raw key bytes. cipher is e.g. "aes-256-cbc" (Laravel default) or "aes-256-gcm".
func New(key, cipher string) (*Encrypter, error) {
	raw, err := ParseKey(key)
	if err != nil {
		return nil, err
	}

	c := strings.ToLower(cipher)
	info, ok := supportedCiphers[c]
	if !ok || len(raw) != info.size {
		return nil, ErrUnsupportedCipher
	}

	return &Encrypter{key: raw, cipher: c, info: info}, nil
}

// ParseKey resolves a key string to raw bytes. "base64:XXXX" (Laravel APP_KEY form) is
// base64-decoded; a bare base64 string that decodes to 16/32 bytes is used as-is;
// otherwise the string's raw bytes are used.
func ParseKey(key string) ([]byte, error) {
	if key == "" {
		return nil, ErrEmptyKey
	}
	if strings.HasPrefix(key, "base64:") {
		dec, err := base64.StdEncoding.DecodeString(key[len("base64:"):])
		if err != nil {
			return nil, ErrUnsupportedCipher
		}
		return dec, nil
	}
	if dec, err := base64.StdEncoding.DecodeString(key); err == nil && (len(dec) == 16 || len(dec) == 32) {
		return dec, nil
	}
	return []byte(key), nil
}

func (e *Encrypter) ivLen() int {
	if e.info.aead {
		return 12 // openssl_cipher_iv_length(aes-*-gcm) == 12
	}
	return 16 // CBC block size
}

// EncryptString encrypts a raw string (Laravel's encryptString — no PHP serialization),
// producing a payload Laravel's Crypt::decryptString can decrypt with the same key.
func (e *Encrypter) EncryptString(plaintext string) (string, error) {
	return e.encrypt([]byte(plaintext))
}

// DecryptString decrypts a Laravel encryptString payload back to the raw string.
func (e *Encrypter) DecryptString(payload string) (string, error) {
	b, err := e.decrypt(payload)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// Encrypt is the equivalent of Laravel's Crypt::encrypt($value): the value is PHP-serialized
// before encryption, so Laravel's Crypt::decrypt($payload) reconstructs the original value.
// Supported value types: nil, bool, int/uint kinds, float, string, []any and map[string]any
// (plus other slice/map kinds via reflection). For cross-language interop a plain string with
// your own JSON is simpler and recommended — see EncryptString.
func (e *Encrypter) Encrypt(value any) (string, error) {
	serialized, err := phpMarshal(value)
	if err != nil {
		return "", err
	}
	return e.encrypt([]byte(serialized))
}

// Decrypt is the equivalent of Laravel's Crypt::decrypt($payload): it decrypts and then
// PHP-unserializes the plaintext. Returns nil/bool/int64/float64/string/[]any/map[string]any;
// PHP objects decode to a map[string]any (class under "__class__"), never instantiated.
func (e *Encrypter) Decrypt(payload string) (any, error) {
	b, err := e.decrypt(payload)
	if err != nil {
		return nil, err
	}
	return phpUnmarshal(string(b))
}

func (e *Encrypter) encrypt(plain []byte) (string, error) {
	iv := make([]byte, e.ivLen())
	if _, err := rand.Read(iv); err != nil {
		return "", err
	}

	block, err := aes.NewCipher(e.key)
	if err != nil {
		return "", err
	}

	var ctRaw, tagRaw []byte
	if e.info.aead {
		gcm, err := cipher.NewGCMWithNonceSize(block, e.ivLen())
		if err != nil {
			return "", err
		}
		sealed := gcm.Seal(nil, iv, plain, nil) // ct || tag(16)
		ctRaw = sealed[:len(sealed)-gcm.Overhead()]
		tagRaw = sealed[len(sealed)-gcm.Overhead():]
	} else {
		padded := pkcs7Pad(plain, block.BlockSize())
		ctRaw = make([]byte, len(padded))
		cipher.NewCBCEncrypter(block, iv).CryptBlocks(ctRaw, padded)
	}

	ivB64 := base64.StdEncoding.EncodeToString(iv)
	valueB64 := base64.StdEncoding.EncodeToString(ctRaw)

	p := wirePayload{IV: ivB64, Value: valueB64}
	if e.info.aead {
		p.Tag = base64.StdEncoding.EncodeToString(tagRaw)
	} else {
		p.MAC = e.hash(ivB64, valueB64)
	}

	jsonBytes, err := json.Marshal(p)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(jsonBytes), nil
}

func (e *Encrypter) decrypt(encoded string) ([]byte, error) {
	jsonBytes, err := base64.StdEncoding.DecodeString(strings.TrimSpace(encoded))
	if err != nil {
		return nil, ErrInvalidPayload
	}

	var p wirePayload
	if err := json.Unmarshal(jsonBytes, &p); err != nil {
		return nil, ErrInvalidPayload
	}

	iv, err := base64.StdEncoding.DecodeString(p.IV)
	if err != nil || len(iv) != e.ivLen() {
		return nil, ErrInvalidPayload
	}
	ct, err := base64.StdEncoding.DecodeString(p.Value)
	if err != nil {
		return nil, ErrInvalidPayload
	}

	if e.info.aead {
		tag, err := base64.StdEncoding.DecodeString(p.Tag)
		if err != nil || len(tag) != 16 {
			return nil, ErrDecrypt // mirrors ensureTagIsValid
		}
		block, err := aes.NewCipher(e.key)
		if err != nil {
			return nil, err
		}
		gcm, err := cipher.NewGCMWithNonceSize(block, e.ivLen())
		if err != nil {
			return nil, err
		}
		combined := make([]byte, 0, len(ct)+len(tag))
		combined = append(combined, ct...)
		combined = append(combined, tag...)
		out, err := gcm.Open(nil, iv, combined, nil)
		if err != nil {
			return nil, ErrDecrypt
		}
		return out, nil
	}

	// CBC: authenticate (HMAC) before decrypting.
	expected := e.hash(p.IV, p.Value)
	if subtle.ConstantTimeCompare([]byte(expected), []byte(p.MAC)) != 1 {
		return nil, ErrInvalidMAC
	}

	block, err := aes.NewCipher(e.key)
	if err != nil {
		return nil, err
	}
	if len(ct) == 0 || len(ct)%block.BlockSize() != 0 {
		return nil, ErrDecrypt
	}
	out := make([]byte, len(ct))
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(out, ct)
	unpadded, err := pkcs7Unpad(out, block.BlockSize())
	if err != nil {
		return nil, ErrDecrypt
	}
	return unpadded, nil
}

// hash is Laravel's HMAC: hash_hmac('sha256', iv.value, key) over the base64 strings.
func (e *Encrypter) hash(ivB64, valueB64 string) string {
	m := hmac.New(sha256.New, e.key)
	m.Write([]byte(ivB64))
	m.Write([]byte(valueB64))
	return hex.EncodeToString(m.Sum(nil))
}

func pkcs7Pad(data []byte, blockSize int) []byte {
	pad := blockSize - len(data)%blockSize
	// pad is in [1, blockSize] (blockSize == aes.BlockSize == 16); the conversion is safe.
	return append(data, bytes.Repeat([]byte{byte(pad)}, pad)...) //nolint:gosec // bounded [1,blockSize]
}

func pkcs7Unpad(data []byte, blockSize int) ([]byte, error) {
	n := len(data)
	if n == 0 || n%blockSize != 0 {
		return nil, ErrDecrypt
	}
	pad := int(data[n-1])
	if pad == 0 || pad > blockSize || pad > n {
		return nil, ErrDecrypt
	}
	// constant-ish padding check
	for _, b := range data[n-pad:] {
		if int(b) != pad {
			return nil, ErrDecrypt
		}
	}
	return data[:n-pad], nil
}
