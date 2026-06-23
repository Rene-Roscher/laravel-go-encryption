package laravelcrypt

import "testing"

// FuzzDecryptString asserts the decrypter never panics on arbitrary input — it must always
// return a value or a typed error, regardless of how malformed/hostile the payload is.
func FuzzDecryptString(f *testing.F) {
	enc, err := New(testKey, "aes-256-cbc")
	if err != nil {
		f.Fatal(err)
	}
	gcm, _ := New(testKey, "aes-256-gcm")

	// Seeds: valid payloads, near-valid JSON, and obvious garbage.
	valid, _ := enc.EncryptString("seed")
	validGCM, _ := gcm.EncryptString("seed")
	for _, s := range []string{
		"", "x", "not-base64-!!", "Zm9vYmFy",
		valid, validGCM,
		b64Encode([]byte(`{"iv":"","value":"","mac":"","tag":""}`)),
		b64Encode([]byte(`{"iv":"AAAA","value":"AAAA","mac":"00","tag":""}`)),
	} {
		f.Add(s)
	}

	f.Fuzz(func(_ *testing.T, payload string) {
		// Must not panic; result is intentionally ignored.
		_, _ = enc.DecryptString(payload)
		_, _ = gcm.DecryptString(payload)
	})
}
