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

// FuzzPHPUnmarshal asserts the PHP unserializer never panics, whatever the input.
func FuzzPHPUnmarshal(f *testing.F) {
	for _, s := range []string{
		"", "N;", "b:1;", "i:7;", "d:2.5;", `s:3:"abc";`,
		`a:2:{i:0;s:1:"x";i:1;a:0:{}}`, `O:8:"stdClass":1:{s:1:"a";i:1;}`,
		"a:9223372036854775807:{}", "a:1:{b:1;b:1;}", "d:inf;",
	} {
		f.Add(s)
	}
	f.Fuzz(func(_ *testing.T, s string) {
		v, err := phpUnmarshal(s)
		if err == nil {
			// Whatever decoded must serialize again without panicking.
			_, _ = phpMarshal(v)
		}
	})
}
