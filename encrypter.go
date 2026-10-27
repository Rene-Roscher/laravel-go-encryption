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
	"crypto/sha1" //nolint:gosec // Laravel derives its cookie prefix with HMAC-SHA1
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"unicode/utf8"
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
	ErrInvalidCookie     = errors.New("laravelcrypt: the cookie value prefix is invalid")
)

// Encrypter is a single-cipher Laravel-compatible encrypter with one current key and,
// optionally, previous keys that are tried when decrypting.
type Encrypter struct {
	key      []byte
	previous [][]byte
	cipher   string
	info     cipherInfo
}

// Option configures an Encrypter.
type Option func(*Encrypter) error

// WithPreviousKeys sets the keys that are tried when decrypting with the current key fails, like
// Laravel's previousKeys() and APP_PREVIOUS_KEYS (Laravel 11+). New payloads are always encrypted
// with the current key. Each key takes the same forms as New's key and must fit the cipher.
func WithPreviousKeys(keys ...string) Option {
	return func(e *Encrypter) error {
		previous := make([][]byte, 0, len(keys))
		for _, k := range keys {
			raw, err := ParseKey(k)
			if err != nil {
				return err
			}
			if len(raw) != e.info.size {
				return ErrUnsupportedCipher
			}
			previous = append(previous, raw)
		}
		e.previous = previous
		return nil
	}
}

type wirePayload struct {
	IV    string `json:"iv"`
	Value string `json:"value"`
	MAC   string `json:"mac"`
	Tag   string `json:"tag"`
}

// New builds an Encrypter. key accepts the Laravel "base64:..." form, a bare base64
// string, or raw key bytes. cipher is e.g. "aes-256-cbc" (Laravel default) or "aes-256-gcm".
func New(key, cipher string, opts ...Option) (*Encrypter, error) {
	raw, err := ParseKey(key)
	if err != nil {
		return nil, err
	}

	c := strings.ToLower(cipher)
	info, ok := supportedCiphers[c]
	if !ok || len(raw) != info.size {
		return nil, ErrUnsupportedCipher
	}

	e := &Encrypter{key: raw, cipher: c, info: info}
	for _, opt := range opts {
		if err := opt(e); err != nil {
			return nil, err
		}
	}
	return e, nil
}

// allKeys returns the current key followed by the previous keys, like getAllKeys().
func (e *Encrypter) allKeys() [][]byte {
	return append([][]byte{e.key}, e.previous...)
}

// ParseKey resolves a key string to raw bytes. "base64:XXXX" (Laravel APP_KEY form) is
// base64-decoded the way Laravel does, with PHP's lenient base64_decode (padding is optional and
// stray characters are skipped; a malformed value decodes to the wrong length, which New
// rejects); a bare base64 string that decodes to 16/32 bytes is used as-is; otherwise the
// string's raw bytes are used.
func ParseKey(key string) ([]byte, error) {
	if key == "" {
		return nil, ErrEmptyKey
	}
	if strings.HasPrefix(key, "base64:") {
		return phpBase64Decode(key[len("base64:"):]), nil
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

// EncryptCookie encrypts a cookie value the way Laravel's EncryptCookies middleware does: the
// value is prefixed with an HMAC of the cookie name and the key, and encrypted without
// serialization. Laravel decrypts it back to value for the cookie name.
func (e *Encrypter) EncryptCookie(name, value string) (string, error) {
	return e.encrypt([]byte(cookiePrefix(name, e.key) + value))
}

// DecryptCookie decrypts a cookie that Laravel's EncryptCookies middleware encrypted, and checks
// that it was issued for the cookie name by this application: the prefix must match the current
// key or one of the previous keys, otherwise the result is ErrInvalidCookie (Laravel treats such
// a cookie as absent).
//
// payload is the raw cookie value; URL-decode it first if it comes from a Cookie header. Cookies
// that an application serializes on purpose (EncryptCookies::serialized()) are not supported.
func (e *Encrypter) DecryptCookie(name, payload string) (string, error) {
	plain, err := e.decrypt(payload)
	if err != nil {
		return "", err
	}
	for _, key := range e.allKeys() {
		prefix := cookiePrefix(name, key)
		if len(plain) >= len(prefix) && subtle.ConstantTimeCompare(plain[:len(prefix)], []byte(prefix)) == 1 {
			return string(plain[len(prefix):]), nil
		}
	}
	return "", ErrInvalidCookie
}

// cookiePrefix is Laravel's CookieValuePrefix::create(): hash_hmac('sha1', $name.'v2', $key).'|'.
func cookiePrefix(name string, key []byte) string {
	m := hmac.New(sha1.New, key)
	m.Write([]byte(name + "v2"))
	return hex.EncodeToString(m.Sum(nil)) + "|"
}

// PHPSerialize writes v as PHP serialize() output, for example the serialized attributes of an
// encrypted Laravel session. It accepts the types Encrypt does.
func PHPSerialize(v any) (string, error) { return phpMarshal(v) }

// PHPUnserialize parses PHP serialize() output into the types Decrypt returns. It rejects trailing
// data and nesting deeper than 128 levels, and never instantiates PHP objects.
func PHPUnserialize(s string) (any, error) { return phpUnmarshal(s) }

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
		p.MAC = hash(e.key, ivB64, valueB64)
	}

	jsonBytes, err := json.Marshal(p)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(jsonBytes), nil
}

func (e *Encrypter) decrypt(encoded string) ([]byte, error) {
	p, err := e.parsePayload(encoded)
	if err != nil {
		return nil, err
	}

	if e.info.aead {
		// Laravel's ensureTagIsValid: an AEAD payload needs a 16-byte tag.
		if len(p.tag) != 16 {
			return nil, ErrDecrypt
		}
		// Try the current key first, then the previous keys, until one authenticates.
		for _, key := range e.allKeys() {
			if out, ok := e.openGCM(key, p); ok {
				return out, nil
			}
		}
		return nil, ErrDecrypt
	}

	// A CBC payload must not carry a tag.
	if p.tag != nil {
		return nil, ErrDecrypt
	}

	// CBC: authenticate (HMAC) before decrypting, and use the first key whose MAC matches.
	for _, key := range e.allKeys() {
		expected := hash(key, p.ivB64, p.valueB64)
		if subtle.ConstantTimeCompare([]byte(expected), []byte(p.mac)) == 1 {
			return e.decryptCBC(key, p)
		}
	}
	return nil, ErrInvalidMAC
}

func (e *Encrypter) openGCM(key []byte, p *payload) ([]byte, bool) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, false
	}
	gcm, err := cipher.NewGCMWithNonceSize(block, e.ivLen())
	if err != nil {
		return nil, false
	}
	combined := make([]byte, 0, len(p.value)+len(p.tag))
	combined = append(combined, p.value...)
	combined = append(combined, p.tag...)
	out, err := gcm.Open(nil, p.iv, combined, nil)
	return out, err == nil
}

func (e *Encrypter) decryptCBC(key []byte, p *payload) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	if len(p.value) == 0 || len(p.value)%block.BlockSize() != 0 {
		return nil, ErrDecrypt
	}
	out := make([]byte, len(p.value))
	cipher.NewCBCDecrypter(block, p.iv).CryptBlocks(out, p.value)
	unpadded, err := pkcs7Unpad(out, block.BlockSize())
	if err != nil {
		return nil, ErrDecrypt
	}
	return unpadded, nil
}

// payload is a parsed and validated Laravel payload.
type payload struct {
	// ivB64 and valueB64 are the base64 strings as sent; the MAC covers these.
	ivB64, valueB64, mac string
	iv, value, tag       []byte // tag is nil when the payload carries none
}

// parsePayload mirrors Encrypter::getJsonPayload / validPayload, including PHP's loose
// base64_decode and empty() semantics.
func (e *Encrypter) parsePayload(encoded string) (*payload, error) {
	raw := phpBase64Decode(encoded) // json_decode(base64_decode($payload), true)
	if !utf8.Valid(raw) {
		return nil, ErrInvalidPayload // PHP's json_decode rejects invalid UTF-8
	}
	var fields map[string]any
	if err := json.Unmarshal(raw, &fields); err != nil || fields == nil {
		return nil, ErrInvalidPayload
	}

	str := func(name string) (string, bool) {
		s, ok := fields[name].(string)
		return s, ok
	}
	ivB64, ok1 := str("iv")
	valueB64, ok2 := str("value")
	mac, ok3 := str("mac")
	if !ok1 || !ok2 || !ok3 {
		return nil, ErrInvalidPayload
	}
	tagB64 := ""
	if t, present := fields["tag"]; present && t != nil {
		s, ok := t.(string)
		if !ok {
			return nil, ErrInvalidPayload
		}
		tagB64 = s
	}

	iv, ok := phpBase64DecodeStrict(ivB64)
	if !ok || len(iv) != e.ivLen() {
		return nil, ErrInvalidPayload
	}
	p := &payload{
		ivB64:    ivB64,
		valueB64: valueB64,
		mac:      mac,
		iv:       iv,
		value:    phpBase64Decode(valueB64), // openssl_decrypt decodes leniently
	}
	// PHP's empty("0") is true, so Laravel sees neither "" nor "0" as a tag.
	if tagB64 != "" && tagB64 != "0" {
		p.tag = phpBase64Decode(tagB64)
	}
	return p, nil
}

// hash is Laravel's HMAC: hash_hmac('sha256', iv.value, key) over the base64 strings.
func hash(key []byte, ivB64, valueB64 string) string {
	m := hmac.New(sha256.New, key)
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

// phpBase64Decode is PHP's base64_decode($input, false): it skips every character outside the
// alphabet (including "=" and whitespace) and never fails.
func phpBase64Decode(input string) []byte {
	out, _ := phpBase64(input, false)
	return out
}

// phpBase64DecodeStrict is PHP's base64_decode($input, true): it skips only whitespace, fails
// on other invalid characters, data after padding, a dangling sixth bit and wrong padding,
// and accepts missing padding.
func phpBase64DecodeStrict(input string) ([]byte, bool) {
	return phpBase64(input, true)
}

func phpBase64(input string, strict bool) ([]byte, bool) {
	out := make([]byte, 0, len(input)/4*3+3)
	var acc uint32
	count, padding := 0, 0

	for i := 0; i < len(input); i++ {
		c := input[i]
		var v byte
		switch {
		case c == '=':
			padding++
			continue
		case c >= 'A' && c <= 'Z':
			v = c - 'A'
		case c >= 'a' && c <= 'z':
			v = c - 'a' + 26
		case c >= '0' && c <= '9':
			v = c - '0' + 52
		case c == '+':
			v = 62
		case c == '/':
			v = 63
		case c == '\t' || c == '\n' || c == '\r' || c == ' ':
			continue
		case strict:
			return nil, false
		default:
			continue
		}
		if strict && padding > 0 {
			return nil, false
		}
		acc = acc<<6 | uint32(v)
		count++
		if count%4 == 0 {
			out = append(out, byte(acc>>16&0xff), byte(acc>>8&0xff), byte(acc&0xff))
			acc = 0
		}
	}

	// A trailing group of 2 or 3 characters yields 1 or 2 bytes; 1 character yields none.
	switch count % 4 {
	case 2:
		out = append(out, byte(acc>>4&0xff))
	case 3:
		out = append(out, byte(acc>>10&0xff), byte(acc>>2&0xff))
	}
	if strict {
		if count%4 == 1 {
			return nil, false
		}
		if padding > 0 && (padding > 2 || (count+padding)%4 != 0) {
			return nil, false
		}
	}
	return out, true
}
