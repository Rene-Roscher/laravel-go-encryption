package laravelcrypt

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

var base64Std = base64.StdEncoding

// testKey is a fixed 32-byte key (0x2b repeated), the same key the committed fixtures were
// generated with, in Laravel's APP_KEY "base64:" form.
const testKey = "base64:KysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKys="

type vector struct {
	Name          string `json:"name"`
	Cipher        string `json:"cipher"`
	PlaintextB64  string `json:"plaintext_b64"`
	SerializedB64 string `json:"serialized_b64"`
	Payload       string `json:"payload"`
}

type vectorFile struct {
	Laravel    string   `json:"laravel"`
	KeyB64     string   `json:"key_b64"`
	Vectors    []vector `json:"vectors"`
	Serialized []vector `json:"serialized"`
	Objects    []vector `json:"objects"`
	Rotated    []vector `json:"rotated"`

	PreviousKeyB64 string `json:"previous_key_b64"`
}

func loadVectors(t *testing.T) vectorFile {
	t.Helper()
	data, err := os.ReadFile("fixtures/vectors.json")
	if err != nil {
		t.Fatalf("read fixtures/vectors.json: %v", err)
	}
	var vf vectorFile
	if err := json.Unmarshal(data, &vf); err != nil {
		t.Fatalf("parse fixtures/vectors.json: %v", err)
	}
	if vf.KeyB64 == "" || len(vf.Vectors) == 0 || len(vf.Serialized) == 0 || len(vf.Objects) == 0 {
		t.Fatal("fixtures/vectors.json is incomplete")
	}
	return vf
}

// fixtureEncrypter returns an Encrypter for the fixture key, truncated to the cipher's key
// size (aes-128-* uses the first 16 bytes), like scripts/generate_vectors.php does.
func fixtureEncrypter(t *testing.T, vf vectorFile, cipherName string) *Encrypter {
	t.Helper()
	key := mustB64Decode(t, vf.KeyB64)
	size := 32
	if strings.Contains(cipherName, "128") {
		size = 16
	}
	enc, err := New("base64:"+b64Encode(key[:size]), cipherName)
	if err != nil {
		t.Fatalf("New(%s): %v", cipherName, err)
	}
	return enc
}

// TestDecryptLaravelVectors decrypts real payloads produced by the actual Laravel
// Encrypter (fixtures/vectors.json, regenerated in CI by scripts/generate_vectors.php) and
// asserts each matches the source plaintext — byte-level Laravel→Go interop for all four
// ciphers, across unicode/empty/JSON/multiline/binary/block-aligned/long inputs.
func TestDecryptLaravelVectors(t *testing.T) {
	vf := loadVectors(t)
	for _, v := range vf.Vectors {
		t.Run(v.Name, func(t *testing.T) {
			enc := fixtureEncrypter(t, vf, v.Cipher)
			got, err := enc.DecryptString(v.Payload)
			if err != nil {
				t.Fatalf("DecryptString: %v", err)
			}
			if want := string(mustB64Decode(t, v.PlaintextB64)); got != want {
				t.Errorf("decrypt mismatch\n got=%q\nwant=%q", got, want)
			}
		})
	}
}

// TestRoundTrip exercises Go encrypt → Go decrypt for both ciphers across edge cases,
// including empty, unicode, large/multiline, and raw binary input.
func TestRoundTrip(t *testing.T) {
	cases := []string{
		"", "x", "Hello, World!", "Grüße 世界 🚀 café",
		strings.Repeat("line of text 0123456789\n", 500),
		string([]byte{0x00, 0x01, 0x02, 0xff, 0xfe, 0x7f, 0x80}),
	}
	for _, ciph := range allCiphers {
		enc := newEnc(t, ciph)
		for i, pt := range cases {
			payload, err := enc.EncryptString(pt)
			if err != nil {
				t.Fatalf("%s case %d encrypt: %v", ciph, i, err)
			}
			got, err := enc.DecryptString(payload)
			if err != nil {
				t.Fatalf("%s case %d decrypt: %v", ciph, i, err)
			}
			if got != pt {
				t.Errorf("%s case %d round-trip mismatch", ciph, i)
			}
		}
	}
}

// TestTamperRejected is the core security property: modifying any AUTHENTICATED field must
// be rejected. The authenticated material is iv+value (CBC, via the HMAC) and iv+value+tag
// (GCM, via the AEAD); the `mac` field on CBC must also match. Cosmetic fields (the unused
// `tag` on CBC, the empty `mac` on GCM, or unknown JSON keys) are intentionally NOT
// authenticated — exactly like Laravel — so we only assert on the authenticated ones.
func TestTamperRejected(t *testing.T) {
	cases := []struct {
		cipher  string
		targets []string
	}{
		{"aes-128-cbc", []string{"iv", "value", "mac"}},
		{"aes-256-cbc", []string{"iv", "value", "mac"}},
		{"aes-128-gcm", []string{"iv", "value", "tag"}},
		{"aes-256-gcm", []string{"iv", "value", "tag"}},
	}
	for _, c := range cases {
		enc := newEnc(t, c.cipher)
		payload, _ := enc.EncryptString("a secret payload")

		var m map[string]string
		if err := json.Unmarshal(mustB64Decode(t, payload), &m); err != nil {
			t.Fatalf("%s: unmarshal payload: %v", c.cipher, err)
		}

		for _, field := range c.targets {
			if m[field] == "" {
				t.Fatalf("%s: field %q unexpectedly empty", c.cipher, field)
			}
			tampered := make(map[string]string, len(m))
			for k, v := range m {
				tampered[k] = v
			}
			tampered[field] = flipFirst(m[field])

			raw, _ := json.Marshal(tampered)
			if _, err := enc.DecryptString(b64Encode(raw)); err == nil {
				t.Errorf("%s: tampering authenticated field %q was accepted — must be rejected", c.cipher, field)
			}
		}
	}
}

func TestWrongKeyRejected(t *testing.T) {
	enc, _ := New(testKey, "aes-256-cbc")
	payload, _ := enc.EncryptString("secret")

	other, _ := New("base64:"+b64Encode(repeat32(0x7a)), "aes-256-cbc")
	if _, err := other.DecryptString(payload); err == nil {
		t.Fatal("decrypt with the wrong key must fail (MAC)")
	}
}

func TestInvalidPayloadsRejected(t *testing.T) {
	enc, _ := New(testKey, "aes-256-cbc")
	for _, bad := range []string{
		"", "not base64!!", "Zm9vYmFy" /* "foobar" */, b64Encode([]byte(`{"iv":"x"}`)),
	} {
		if _, err := enc.DecryptString(bad); err == nil {
			t.Errorf("invalid payload %q must be rejected", bad)
		}
	}
}

func TestNewValidation(t *testing.T) {
	if _, err := New("base64:"+b64Encode(repeat32(0x01)), "aes-256-cbc"); err != nil {
		t.Errorf("valid 32-byte key/cbc should construct: %v", err)
	}
	if _, err := New("base64:"+b64Encode(make([]byte, 16)), "aes-256-cbc"); err == nil {
		t.Error("16-byte key with aes-256-cbc must fail (size mismatch)")
	}
	if _, err := New(testKey, "aes-512-cbc"); err == nil {
		t.Error("unsupported cipher must fail")
	}
	if _, err := New("", "aes-256-cbc"); err == nil {
		t.Error("empty key must fail")
	}
}

func TestParseKey(t *testing.T) {
	raw := repeat32(0x2b)
	got, err := ParseKey("base64:" + b64Encode(raw))
	if err != nil || len(got) != 32 {
		t.Fatalf("base64: form: %v len=%d", err, len(got))
	}
}

// helpers
func repeat32(b byte) []byte {
	out := make([]byte, 32)
	for i := range out {
		out[i] = b
	}
	return out
}

func b64Encode(b []byte) string { return base64Std.EncodeToString(b) }

// flipFirst returns s with its first character changed to a different one, so the value is
// altered while staying a plausible base64/hex string.
func flipFirst(s string) string {
	b := []byte(s)
	if b[0] == 'A' {
		b[0] = 'B'
	} else {
		b[0] = 'A'
	}
	return string(b)
}

func mustB64Decode(t *testing.T, s string) []byte {
	t.Helper()
	b, err := base64Std.DecodeString(s)
	if err != nil {
		t.Fatalf("b64 decode: %v", err)
	}
	return b
}
