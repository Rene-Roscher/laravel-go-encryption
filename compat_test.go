package laravelcrypt

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"reflect"
	"strings"
	"sync"
	"testing"
)

var allCiphers = []string{"aes-128-cbc", "aes-256-cbc", "aes-128-gcm", "aes-256-gcm"}

func isCBC(cipher string) bool { return strings.HasSuffix(cipher, "-cbc") }

func keySize(cipher string) int {
	if strings.Contains(cipher, "128") {
		return 16
	}
	return 32
}

func rawKey(cipher string, b byte) []byte { return bytes.Repeat([]byte{b}, keySize(cipher)) }

func newEncWithKey(t *testing.T, cipher string, b byte) *Encrypter {
	t.Helper()
	enc, err := New("base64:"+b64Encode(rawKey(cipher, b)), cipher)
	if err != nil {
		t.Fatalf("New(%s): %v", cipher, err)
	}
	return enc
}

// newEnc builds an Encrypter for the fixed 0x2b test key, truncated to the cipher's size.
func newEnc(t *testing.T, cipher string) *Encrypter { return newEncWithKey(t, cipher, 0x2b) }

func unwrapPayload(t *testing.T, payload string) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(mustB64Decode(t, payload), &m); err != nil {
		t.Fatalf("unmarshal payload: %v", err)
	}
	return m
}

func wrapPayload(t *testing.T, m map[string]any) string {
	t.Helper()
	raw, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return b64Encode(raw)
}

// editPayload re-encodes payload after applying edit to its JSON fields.
func editPayload(t *testing.T, payload string, edit func(m map[string]any)) string {
	t.Helper()
	m := unwrapPayload(t, payload)
	edit(m)
	return wrapPayload(t, m)
}

func TestValuesRoundTripAllCiphers(t *testing.T) {
	value := map[string]any{
		"user": "alice", "id": int64(7), "active": true, "score": 2.5,
		"tags": []any{"x", "y"}, "meta": nil,
	}
	for _, c := range allCiphers {
		enc := newEnc(t, c)
		payload, err := enc.Encrypt(value)
		if err != nil {
			t.Fatalf("%s: %v", c, err)
		}
		got, err := enc.Decrypt(payload)
		if err != nil {
			t.Fatalf("%s: %v", c, err)
		}
		if !reflect.DeepEqual(got, value) {
			t.Errorf("%s: got %#v want %#v", c, got, value)
		}
	}
}

func TestBytesRoundTrip(t *testing.T) {
	binary := "\x00\x01\x02\xff\xfe\x7f\x80"
	for _, c := range allCiphers {
		enc := newEnc(t, c)
		payload, _ := enc.EncryptString(binary)
		if got, err := enc.DecryptString(payload); err != nil || got != binary {
			t.Errorf("%s: binary round-trip: %q %v", c, got, err)
		}
	}
}

// Crypt::encrypt serializes; Crypt::encryptString does not. Each path shows through the other.
func TestStringAndValuePathsAreDistinct(t *testing.T) {
	enc := newEnc(t, "aes-256-cbc")

	payload, _ := enc.Encrypt("hello")
	if got, err := enc.DecryptString(payload); err != nil || got != `s:5:"hello";` {
		t.Errorf("DecryptString of an Encrypt payload = %q, %v; want the PHP serialization", got, err)
	}

	payload, _ = enc.EncryptString("hello")
	if _, err := enc.Decrypt(payload); err == nil {
		t.Error("Decrypt of an EncryptString payload must fail: it is not PHP-serialized")
	}
}

func TestCBCPayloadLayout(t *testing.T) {
	for _, c := range []string{"aes-128-cbc", "aes-256-cbc"} {
		key := rawKey(c, 0x2b)
		enc := newEnc(t, c)
		payload, _ := enc.EncryptString("hello")

		// Field order matches Laravel's json_encode(['iv', 'value', 'mac', 'tag']).
		js := string(mustB64Decode(t, payload))
		last := -1
		for _, f := range []string{`"iv"`, `"value"`, `"mac"`, `"tag"`} {
			at := strings.Index(js, f)
			if at <= last {
				t.Fatalf("%s: field %s out of order in %s", c, f, js)
			}
			last = at
		}

		m := unwrapPayload(t, payload)
		iv, value := m["iv"].(string), m["value"].(string)
		if n := len(mustB64Decode(t, iv)); n != 16 {
			t.Errorf("%s: iv is %d bytes, want 16", c, n)
		}
		if n := len(mustB64Decode(t, value)); n != 16 { // "hello" + PKCS#7 padding
			t.Errorf("%s: value is %d bytes, want 16", c, n)
		}
		if m["tag"] != "" {
			t.Errorf("%s: tag = %v, want empty", c, m["tag"])
		}

		// mac = lower-case hex HMAC-SHA256(base64(iv) . base64(value), key)
		mac := hmac.New(sha256.New, key)
		mac.Write([]byte(iv + value))
		if want := hex.EncodeToString(mac.Sum(nil)); m["mac"] != want {
			t.Errorf("%s: mac = %v, want %s", c, m["mac"], want)
		}
	}
}

func TestGCMPayloadLayout(t *testing.T) {
	for _, c := range []string{"aes-128-gcm", "aes-256-gcm"} {
		m := unwrapPayload(t, mustEncrypt(t, newEnc(t, c), "hello"))
		if n := len(mustB64Decode(t, m["iv"].(string))); n != 12 {
			t.Errorf("%s: iv is %d bytes, want 12", c, n)
		}
		if n := len(mustB64Decode(t, m["value"].(string))); n != 5 { // stream mode, no padding
			t.Errorf("%s: value is %d bytes, want 5", c, n)
		}
		if n := len(mustB64Decode(t, m["tag"].(string))); n != 16 {
			t.Errorf("%s: tag is %d bytes, want 16", c, n)
		}
		if m["mac"] != "" {
			t.Errorf("%s: mac = %v, want empty", c, m["mac"])
		}
	}
}

func mustEncrypt(t *testing.T, enc *Encrypter, s string) string {
	t.Helper()
	p, err := enc.EncryptString(s)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestEveryEncryptionUsesAFreshIV(t *testing.T) {
	for _, c := range allCiphers {
		enc := newEnc(t, c)
		a, b := mustEncrypt(t, enc, "same"), mustEncrypt(t, enc, "same")
		if a == b || unwrapPayload(t, a)["iv"] == unwrapPayload(t, b)["iv"] {
			t.Errorf("%s: two encryptions share a payload or IV", c)
		}
	}
}

func TestTamperedCBCValueOrMACIsInvalidMAC(t *testing.T) {
	enc := newEnc(t, "aes-256-cbc")
	payload := mustEncrypt(t, enc, "a secret payload")
	for _, field := range []string{"value", "mac"} {
		bad := editPayload(t, payload, func(m map[string]any) { m[field] = flipFirst(m[field].(string)) })
		if _, err := enc.DecryptString(bad); !errors.Is(err, ErrInvalidMAC) {
			t.Errorf("tampered %s: err = %v, want ErrInvalidMAC", field, err)
		}
	}
	// hash_equals is case-sensitive: an upper-case MAC does not match.
	upper := editPayload(t, payload, func(m map[string]any) { m["mac"] = strings.ToUpper(m["mac"].(string)) })
	if _, err := enc.DecryptString(upper); !errors.Is(err, ErrInvalidMAC) {
		t.Errorf("upper-case mac: err = %v, want ErrInvalidMAC", err)
	}
}

func TestTamperedGCMValueOrTagFailsAuthentication(t *testing.T) {
	enc := newEnc(t, "aes-256-gcm")
	payload := mustEncrypt(t, enc, "a secret payload")
	for _, field := range []string{"value", "tag"} {
		bad := editPayload(t, payload, func(m map[string]any) { m[field] = flipFirst(m[field].(string)) })
		if _, err := enc.DecryptString(bad); !errors.Is(err, ErrDecrypt) {
			t.Errorf("tampered %s: err = %v, want ErrDecrypt", field, err)
		}
	}
}

// Fields Laravel does not authenticate stay unauthenticated here too.
func TestUnauthenticatedFieldsAreIgnoredLikeLaravel(t *testing.T) {
	enc := newEnc(t, "aes-256-cbc")
	payload := mustEncrypt(t, enc, "x")
	for name, edit := range map[string]func(map[string]any){
		"unknown key": func(m map[string]any) { m["extra"] = "ignored" },
		"no tag":      func(m map[string]any) { delete(m, "tag") },
		"null tag":    func(m map[string]any) { m["tag"] = nil },
		`"0" tag`:     func(m map[string]any) { m["tag"] = "0" }, // PHP: empty("0") is true
	} {
		if got, err := enc.DecryptString(editPayload(t, payload, edit)); err != nil || got != "x" {
			t.Errorf("%s: got %q, %v", name, got, err)
		}
	}

	gcm := newEnc(t, "aes-256-gcm")
	junk := editPayload(t, mustEncrypt(t, gcm, "x"), func(m map[string]any) { m["mac"] = "whatever" })
	if got, err := gcm.DecryptString(junk); err != nil || got != "x" {
		t.Errorf("gcm junk mac: got %q, %v", got, err)
	}
}

func TestTagRulesFollowLaravel(t *testing.T) {
	// A CBC payload must not carry a tag.
	cbc := newEnc(t, "aes-256-cbc")
	withTag := editPayload(t, mustEncrypt(t, cbc, "x"), func(m map[string]any) { m["tag"] = b64Encode(make([]byte, 16)) })
	if _, err := cbc.DecryptString(withTag); !errors.Is(err, ErrDecrypt) {
		t.Errorf("cbc with tag: err = %v, want ErrDecrypt", err)
	}

	// A GCM payload needs a 16-byte tag.
	gcm := newEnc(t, "aes-256-gcm")
	payload := mustEncrypt(t, gcm, "x")
	tag := mustB64Decode(t, unwrapPayload(t, payload)["tag"].(string))
	for name, bad := range map[string]any{
		"empty": "", "short": b64Encode(tag[:15]), "not base64": "!!!", "null": nil,
	} {
		edited := editPayload(t, payload, func(m map[string]any) { m["tag"] = bad })
		if _, err := gcm.DecryptString(edited); !errors.Is(err, ErrDecrypt) {
			t.Errorf("gcm %s tag: err = %v, want ErrDecrypt", name, err)
		}
	}
	missing := editPayload(t, payload, func(m map[string]any) { delete(m, "tag") })
	if _, err := gcm.DecryptString(missing); !errors.Is(err, ErrDecrypt) {
		t.Errorf("gcm missing tag: err = %v, want ErrDecrypt", err)
	}
}

// Laravel base64-decodes the GCM value with base64_decode() in non-strict mode, which skips
// characters outside the alphabet. The tag authenticates the decoded bytes, not the text.
func TestGCMValueIsDecodedLeniently(t *testing.T) {
	enc := newEnc(t, "aes-256-gcm")
	payload := mustEncrypt(t, enc, "hello")
	value := unwrapPayload(t, payload)["value"].(string)

	noisy := editPayload(t, payload, func(m map[string]any) {
		m["value"] = value[:2] + "\n" + value[2:4] + "*" + value[4:]
	})
	if got, err := enc.DecryptString(noisy); err != nil || got != "hello" {
		t.Errorf("noisy value: got %q, %v", got, err)
	}

	// ...but the decoded bytes themselves are authenticated.
	bad := editPayload(t, payload, func(m map[string]any) { m["value"] = flipFirst(value) })
	if _, err := enc.DecryptString(bad); !errors.Is(err, ErrDecrypt) {
		t.Errorf("flipped value: err = %v, want ErrDecrypt", err)
	}
}

func TestWrongKeyIsRejectedForAllCiphers(t *testing.T) {
	for _, c := range allCiphers {
		payload := mustEncrypt(t, newEnc(t, c), "secret")
		_, err := newEncWithKey(t, c, 0x7a).DecryptString(payload)
		want := ErrDecrypt
		if isCBC(c) {
			want = ErrInvalidMAC
		}
		if !errors.Is(err, want) {
			t.Errorf("%s: err = %v, want %v", c, err, want)
		}
	}
}

// The IV length differs between CBC (16) and GCM (12), so a payload never decrypts under
// the wrong mode.
func TestPayloadForAnotherCipherIsRejected(t *testing.T) {
	cbc := mustEncrypt(t, newEnc(t, "aes-256-cbc"), "x")
	gcm := mustEncrypt(t, newEnc(t, "aes-256-gcm"), "x")
	if _, err := newEnc(t, "aes-256-gcm").DecryptString(cbc); !errors.Is(err, ErrInvalidPayload) {
		t.Errorf("cbc payload under gcm: err = %v", err)
	}
	if _, err := newEnc(t, "aes-256-cbc").DecryptString(gcm); !errors.Is(err, ErrInvalidPayload) {
		t.Errorf("gcm payload under cbc: err = %v", err)
	}
}

func TestMalformedPayloadsAreInvalidPayloadErrors(t *testing.T) {
	enc := newEnc(t, "aes-256-cbc")
	valid := mustEncrypt(t, enc, "x")
	wrap := func(s string) string { return b64Encode([]byte(s)) }

	cases := map[string]string{
		"empty":             "",
		"not base64":        "not base64!!",
		"not json":          "Zm9vYmFy",
		"json null":         wrap("null"),
		"json list":         wrap("[]"),
		"json string":       wrap(`"a string"`),
		"empty object":      wrap("{}"),
		"only iv":           wrap(`{"iv":"x"}`),
		"numeric iv":        wrap(`{"iv":1,"value":"x","mac":"x"}`),
		"missing mac":       editPayload(t, valid, func(m map[string]any) { delete(m, "mac") }),
		"null mac":          editPayload(t, valid, func(m map[string]any) { m["mac"] = nil }),
		"numeric value":     editPayload(t, valid, func(m map[string]any) { m["value"] = 5 }),
		"array iv":          editPayload(t, valid, func(m map[string]any) { m["iv"] = []any{"a"} }),
		"numeric tag":       editPayload(t, valid, func(m map[string]any) { m["tag"] = 5 }),
		"iv not base64":     editPayload(t, valid, func(m map[string]any) { m["iv"] = "***" }),
		"iv too short":      editPayload(t, valid, func(m map[string]any) { m["iv"] = b64Encode(make([]byte, 15)) }),
		"iv too long":       editPayload(t, valid, func(m map[string]any) { m["iv"] = b64Encode(make([]byte, 17)) }),
		"truncated":         valid[:len(valid)/2],
		"invalid utf-8":     wrap("{\"iv\":\"\xff\",\"value\":\"x\",\"mac\":\"x\"}"),
		"upper-case fields": wrap(`{"IV":"x","VALUE":"x","MAC":"x"}`),
	}
	for name, payload := range cases {
		if _, err := enc.DecryptString(payload); !errors.Is(err, ErrInvalidPayload) {
			t.Errorf("%s: err = %v, want ErrInvalidPayload", name, err)
		}
		if _, err := enc.Decrypt(payload); err == nil {
			t.Errorf("%s: Decrypt accepted it", name)
		}
	}
}

// The value is decoded leniently (see the GCM test), so for CBC the MAC over the text is
// what rejects a value that is not base64.
func TestCBCValueThatIsNotBase64FailsTheMAC(t *testing.T) {
	enc := newEnc(t, "aes-256-cbc")
	bad := editPayload(t, mustEncrypt(t, enc, "x"), func(m map[string]any) { m["value"] = "***" })
	if _, err := enc.DecryptString(bad); !errors.Is(err, ErrInvalidMAC) {
		t.Errorf("err = %v, want ErrInvalidMAC", err)
	}
}

func TestUnusualButValidEncodingsAreAccepted(t *testing.T) {
	enc := newEnc(t, "aes-256-cbc")
	payload := mustEncrypt(t, enc, "x")
	for name, p := range map[string]string{
		"surrounding whitespace": " " + payload + "\n",
		"no padding":             strings.TrimRight(payload, "="),
	} {
		if got, err := enc.DecryptString(p); err != nil || got != "x" {
			t.Errorf("%s: got %q, %v", name, got, err)
		}
	}
}

// A correctly authenticated CBC payload whose plaintext has invalid PKCS#7 padding can only
// be built with the key.
func TestBadPaddingIsADecryptError(t *testing.T) {
	key := rawKey("aes-256-cbc", 0x2b)
	enc := newEnc(t, "aes-256-cbc")
	for _, value := range [][]byte{{}, make([]byte, 15), make([]byte, 16)} {
		iv, val := b64Encode(make([]byte, 16)), b64Encode(value)
		mac := hmac.New(sha256.New, key)
		mac.Write([]byte(iv + val))
		payload := wrapPayload(t, map[string]any{
			"iv": iv, "value": val, "mac": hex.EncodeToString(mac.Sum(nil)), "tag": "",
		})
		if _, err := enc.DecryptString(payload); !errors.Is(err, ErrDecrypt) {
			t.Errorf("%d-byte value: err = %v, want ErrDecrypt", len(value), err)
		}
	}
}

func TestKeySizesAreEnforcedForAllCiphers(t *testing.T) {
	for _, c := range allCiphers {
		size := keySize(c)
		if _, err := New("base64:"+b64Encode(make([]byte, size)), c); err != nil {
			t.Errorf("%s: %d-byte key rejected: %v", c, size, err)
		}
		for _, bad := range []int{1, size - 1, size + 1, 64} {
			if _, err := New("base64:"+b64Encode(make([]byte, bad)), c); !errors.Is(err, ErrUnsupportedCipher) {
				t.Errorf("%s: %d-byte key: err = %v, want ErrUnsupportedCipher", c, bad, err)
			}
		}
	}
}

func TestCipherNamesAreCaseInsensitive(t *testing.T) {
	for _, name := range []string{"AES-256-CBC", "Aes-128-Gcm"} {
		enc, err := New("base64:"+b64Encode(rawKey(name, 1)), name)
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		if got, err := enc.DecryptString(mustEncrypt(t, enc, "x")); err != nil || got != "x" {
			t.Errorf("%s: round-trip: %q %v", name, got, err)
		}
	}
	for _, bad := range []string{"", "aes-256", "aes-192-cbc", "aes-256-ecb", "aes-256-ctr", "des"} {
		if _, err := New("base64:"+b64Encode(make([]byte, 32)), bad); !errors.Is(err, ErrUnsupportedCipher) {
			t.Errorf("%q: err = %v, want ErrUnsupportedCipher", bad, err)
		}
	}
}

func TestKeyForms(t *testing.T) {
	raw := repeat32(0x2b)
	b64 := b64Encode(raw)
	rawText := "this-is-a-32-byte-raw-secret-key"

	for _, c := range []struct {
		name, in string
		want     []byte
		wantErr  error
	}{
		{"base64: prefix", "base64:" + b64, raw, nil},
		{"bare base64, 32 bytes", b64, raw, nil},
		{"bare base64, 16 bytes", b64Encode(bytes.Repeat([]byte{7}, 16)), bytes.Repeat([]byte{7}, 16), nil},
		{"raw 32 characters", rawText, []byte(rawText), nil},
		{"raw 16 characters", "0123456789abcdef", []byte("0123456789abcdef"), nil},
		{"empty", "", nil, ErrEmptyKey},
		// Laravel decodes the base64: form with PHP's lenient base64_decode: padding is optional
		// and characters outside the alphabet are skipped.
		{"unpadded base64:", "base64:" + strings.TrimRight(b64Encode(bytes.Repeat([]byte{0xfb}, 32)), "="), bytes.Repeat([]byte{0xfb}, 32), nil},
		{"base64: with a newline", "base64:" + b64Encode(bytes.Repeat([]byte{0xfb}, 32)) + "\n", bytes.Repeat([]byte{0xfb}, 32), nil},
		// PHP: bin2hex(base64_decode("!!!not base64!!!")) === "9e8b5b6ac7ba"
		{"malformed base64: value", "base64:!!!not base64!!!", []byte{0x9e, 0x8b, 0x5b, 0x6a, 0xc7, 0xba}, nil},
	} {
		got, err := ParseKey(c.in)
		if !errors.Is(err, c.wantErr) || !bytes.Equal(got, c.want) {
			t.Errorf("%s: ParseKey = %q, %v; want %q, %v", c.name, got, err, c.want, c.wantErr)
		}
	}

	// The three forms select the same key.
	a, _ := New("base64:"+b64, "aes-256-cbc")
	b, _ := New(b64, "aes-256-cbc")
	payload := mustEncrypt(t, a, "x")
	if got, err := b.DecryptString(payload); err != nil || got != "x" {
		t.Errorf("bare base64 key does not match the prefixed one: %q %v", got, err)
	}
	if _, err := New(rawText, "aes-256-cbc"); err != nil {
		t.Errorf("raw 32-character key rejected: %v", err)
	}
	// A malformed value decodes to the wrong length, which New rejects.
	if _, err := New("base64:!!!not base64!!!", "aes-256-cbc"); !errors.Is(err, ErrUnsupportedCipher) {
		t.Errorf("malformed base64: key: err = %v, want ErrUnsupportedCipher", err)
	}
}

// Expected values are PHP's base64_decode($s, true) and base64_decode($s).
func TestPHPBase64MatchesPHP(t *testing.T) {
	type c struct {
		in        string
		strict    *string // nil: PHP returns false
		nonStrict string
	}
	s := func(v string) *string { return &v }
	for _, tc := range []c{
		{"", s(""), ""},
		{"A", nil, ""},
		{"AA", s("\x00"), "\x00"},
		{"AAAA", s("\x00\x00\x00"), "\x00\x00\x00"},
		{"QQ==", s("A"), "A"},
		{"QQ=", nil, "A"},
		{"QQ", s("A"), "A"},
		{"Q", nil, ""},
		{"QUJD", s("ABC"), "ABC"},
		{"QU JD", s("ABC"), "ABC"},
		{"QUJD=", nil, "ABC"},
		{"QUJD====", nil, "ABC"},
		{"QQ==QQ==", nil, "A\x04\x10"},
		{"QQ=Q", nil, "A\x04"},
		{"Q=Q=", nil, "A"},
		{"QR==", s("A"), "A"},
		{"QUJ*", nil, "AB"},
		{"!!", nil, ""},
		{"A=", nil, ""},
		{"AA=", nil, "\x00"},
		{"AAA==", nil, "\x00\x00"},
		{"====", nil, ""},
		{"QUI=\n", s("AB"), "AB"},
		{"Zm9v\nYmFy", s("foobar"), "foobar"},
	} {
		strict, ok := phpBase64DecodeStrict(tc.in)
		switch {
		case tc.strict == nil && ok:
			t.Errorf("strict %q: accepted as %q, PHP rejects it", tc.in, strict)
		case tc.strict != nil && (!ok || string(strict) != *tc.strict):
			t.Errorf("strict %q: got %q, %v; want %q", tc.in, strict, ok, *tc.strict)
		}
		if got := phpBase64Decode(tc.in); string(got) != tc.nonStrict {
			t.Errorf("non-strict %q: got %q, want %q", tc.in, got, tc.nonStrict)
		}
	}
}

func TestEncrypterIsSafeForConcurrentUse(t *testing.T) {
	enc := newEnc(t, "aes-256-gcm")
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			text := fmt.Sprintf("message %d", i)
			got, err := enc.DecryptString(mustEncrypt(t, enc, text))
			if err != nil || got != text {
				t.Errorf("goroutine %d: %q %v", i, got, err)
			}
		}(i)
	}
	wg.Wait()
}

// The decrypter must reject, never panic on, arbitrary input: random garbage, and valid
// payloads with bytes flipped, inserted or cut. (FuzzDecryptString explores further.)
func TestArbitraryInputNeverPanics(t *testing.T) {
	state := uint64(0x2545F4914F6CDD1D)
	next := func() uint64 {
		state ^= state << 13
		state ^= state >> 7
		state ^= state << 17
		return state
	}
	for _, c := range allCiphers {
		enc := newEnc(t, c)
		valid, _ := enc.Encrypt([]any{"a", "b"})
		for i := 0; i < 3000; i++ {
			b := []byte(valid)
			for n := next() % 4; n > 0; n-- {
				at := int(next() % uint64(len(b))) //nolint:gosec // bounded by len(b)
				switch next() % 3 {
				case 0:
					b[at] = byte(next() & 0x7f)
				case 1:
					b = append(b[:at], append([]byte{'A' + byte(next()%26)}, b[at:]...)...)
				default:
					if at > 0 {
						b = b[:at]
					}
				}
			}
			_, _ = enc.Decrypt(string(b))
			_, _ = enc.DecryptString(string(b))
		}
		for i := 0; i < 1000; i++ {
			g := make([]byte, next()%200)
			for j := range g {
				g[j] = byte(next() & 0x7f)
			}
			_, _ = enc.Decrypt(string(g))
			_, _ = enc.Decrypt(b64Encode(g))
		}
	}
}

// --- Laravel-generated serialized values (fixtures/vectors.json) ---

// Crypt::encrypt payloads decode, and the decoded value serializes again to something PHP
// reads back as the same value.
func TestLaravelSerializedValuesRoundTrip(t *testing.T) {
	vf := loadVectors(t)
	for _, v := range vf.Serialized {
		enc := fixtureEncrypter(t, vf, v.Cipher)
		value, err := enc.Decrypt(v.Payload)
		if err != nil {
			t.Fatalf("%s: %v", v.Name, err)
		}

		// The plaintext is exactly the PHP serialize() output the fixture recorded.
		plain, err := enc.DecryptString(v.Payload)
		if err != nil || plain != string(mustB64Decode(t, v.SerializedB64)) {
			t.Fatalf("%s: plaintext differs from PHP's serialize(): %v", v.Name, err)
		}

		again, err := enc.Encrypt(value)
		if err != nil {
			t.Fatalf("%s: re-encrypt: %v", v.Name, err)
		}
		back, err := enc.Decrypt(again)
		if err != nil {
			t.Fatalf("%s: re-decrypt: %v", v.Name, err)
		}
		if !sameValue(value, back) {
			t.Errorf("%s: %#v became %#v", v.Name, value, back)
		}
	}
}

// sameValue is reflect.DeepEqual that treats NaN as equal to itself and compares floats by
// their bits (so -0 differs from 0).
func sameValue(a, b any) bool {
	switch x := a.(type) {
	case float64:
		y, ok := b.(float64)
		return ok && (x == y && math.Signbit(x) == math.Signbit(y) || math.IsNaN(x) && math.IsNaN(y))
	case []any:
		y, ok := b.([]any)
		if !ok || len(x) != len(y) {
			return false
		}
		for i := range x {
			if !sameValue(x[i], y[i]) {
				return false
			}
		}
		return true
	case map[string]any:
		y, ok := b.(map[string]any)
		if !ok || len(x) != len(y) {
			return false
		}
		for k, xv := range x {
			yv, present := y[k]
			if !present || !sameValue(xv, yv) {
				return false
			}
		}
		return true
	}
	return reflect.DeepEqual(a, b)
}

func TestLaravelValuesDecodeToExpectedTypes(t *testing.T) {
	vf := loadVectors(t)
	enc := fixtureEncrypter(t, vf, "aes-256-cbc")
	get := func(name string) any {
		t.Helper()
		for _, v := range vf.Serialized {
			if v.Name == "aes-256-cbc/"+name {
				got, err := enc.Decrypt(v.Payload)
				if err != nil {
					t.Fatalf("%s: %v", name, err)
				}
				return got
			}
		}
		t.Fatalf("no case %s", name)
		return nil
	}

	for name, want := range map[string]any{
		"null":                nil,
		"true":                true,
		"int_min":             int64(math.MinInt64),
		"int_max":             int64(math.MaxInt64),
		"float_whole":         2.0,
		"float_small":         1.5e-7,
		"float_inf":           math.Inf(1),
		"float_negative_inf":  math.Inf(-1),
		"string_binary":       "\x00\xff\xfe\x80",
		"string_quotes":       `say "hi"; s:3:"x";`,
		"empty_array":         []any{},
		"list":                []any{int64(1), "two", true, nil, []any{int64(3), int64(4)}},
		"assoc":               map[string]any{"user": "alice", "id": int64(7), "active": true, "score": 2.5, "tags": []any{"x", "y"}, "meta": nil},
		"non_sequential_list": map[string]any{"1": "a", "0": "b"},
		"mixed_keys":          map[string]any{"5": "a", "x": "b", "7": map[string]any{"nested": []any{int64(1), int64(2)}}},
	} {
		if got := get(name); !sameValue(got, want) {
			t.Errorf("%s: got %#v, want %#v", name, got, want)
		}
	}
	if f, ok := get("float_negative_zero").(float64); !ok || f != 0 || !math.Signbit(f) {
		t.Errorf("float_negative_zero: got %v", get("float_negative_zero"))
	}
	if f, ok := get("float_nan").(float64); !ok || !math.IsNaN(f) {
		t.Errorf("float_nan: got %v", get("float_nan"))
	}
}

// Random doubles written by PHP's serialize() decode to the exact same float64.
func TestLaravelFloatSweepIsExact(t *testing.T) {
	vf := loadVectors(t)
	enc := fixtureEncrypter(t, vf, "aes-128-gcm")
	for _, v := range vf.Serialized {
		if v.Name != "aes-128-gcm/float_sweep" {
			continue
		}
		got, err := enc.Decrypt(v.Payload)
		if err != nil {
			t.Fatal(err)
		}
		list, ok := got.([]any)
		if !ok || len(list) < 300 {
			t.Fatalf("float sweep: got %T of %d", got, len(list))
		}
		// Re-encoding must give PHP back the same bits.
		again, _ := enc.Encrypt(got)
		back, err := enc.Decrypt(again)
		if err != nil || !sameValue(got, back) {
			t.Fatalf("float sweep does not survive a round-trip: %v", err)
		}
		return
	}
	t.Fatal("no float_sweep fixture")
}

func TestLaravelObjectsDecodeWithoutInstantiation(t *testing.T) {
	vf := loadVectors(t)
	for _, v := range vf.Objects {
		enc := fixtureEncrypter(t, vf, v.Cipher)
		got, err := enc.Decrypt(v.Payload)
		if err != nil {
			t.Fatal(err)
		}
		want := map[string]any{"__class__": "stdClass", "a": int64(1), "b": []any{"two"}}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("object: got %#v, want %#v", got, want)
		}
	}
}

func TestAppearsEncryptedInspectsThePayloadShape(t *testing.T) {
	for _, c := range allCiphers {
		if !AppearsEncrypted(mustEncrypt(t, newEnc(t, c), "x")) {
			t.Errorf("%s: a real payload does not appear encrypted", c)
		}
	}
	valid := mustEncrypt(t, newEnc(t, "aes-256-cbc"), "x")
	wrap := func(s string) string { return b64Encode([]byte(s)) }
	for name, v := range map[string]string{
		"empty": "", "plain text": "plain text", "empty object": "e30=", "json null": "bnVsbA==",
		"list":          wrap("[]"),
		"missing mac":   editPayload(t, valid, func(m map[string]any) { delete(m, "mac") }),
		"null iv":       editPayload(t, valid, func(m map[string]any) { m["iv"] = nil }),
		"invalid utf-8": wrap("{\"iv\":\"\xff\",\"value\":\"x\",\"mac\":\"x\"}"),
		// base64_decode($value, true) is strict: other characters are rejected
		"not strict base64": valid + "!",
	} {
		if AppearsEncrypted(v) {
			t.Errorf("%s appears encrypted", name)
		}
	}
	// Only the presence of the three fields counts, as in Laravel.
	if !AppearsEncrypted(wrap(`{"iv":1,"value":[],"mac":false}`)) {
		t.Error("a payload with the three fields of any type appears encrypted")
	}
}
