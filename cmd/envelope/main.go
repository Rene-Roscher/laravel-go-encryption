// Command envelope prints, as JSON on stdout, Interop Envelope tokens made by this package, for
// bin/verify-tokens.php of the laravel-interop package to judge with the real Laravel encrypter:
//
//   - verdicts: every document of fixtures/envelope-vectors.json, encrypted here. PHP has to reach
//     the verdict the vector names.
//   - sealed: tokens made by Seal for each of the vector file's seal cases. PHP has to open them
//     and read back what was sealed.
package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"time"

	laravelcrypt "github.com/Rene-Roscher/laravel-go-encryption"
)

func main() {
	raw, err := os.ReadFile("fixtures/envelope-vectors.json")
	check(err)
	var fixtures struct {
		KeyB64    string                       `json:"key_b64"`
		Vectors   []map[string]any             `json:"vectors"`
		SealCases []map[string]json.RawMessage `json:"seal_cases"`
	}
	check(json.Unmarshal(raw, &fixtures))
	key, err := base64.StdEncoding.DecodeString(fixtures.KeyB64)
	check(err)

	encrypter := func(cipher string) *laravelcrypt.Encrypter {
		size := 32
		if cipher == "aes-128-cbc" || cipher == "aes-128-gcm" {
			size = 16
		}
		enc, err := laravelcrypt.New("base64:"+base64.StdEncoding.EncodeToString(key[:size]), cipher)
		check(err)
		return enc
	}

	var verdicts []map[string]any
	for _, v := range fixtures.Vectors {
		plaintext, ok := v["plaintext_b64"].(string) // empty is a document too
		if !ok || v["key"] != "current" || v["expect"] == "decrypt_error" {
			continue
		}
		decoded, err := base64.StdEncoding.DecodeString(plaintext)
		check(err)
		token, err := encrypter(v["cipher"].(string)).EncryptString(string(decoded))
		check(err)
		v["token"] = token
		verdicts = append(verdicts, v)
	}

	var sealed []map[string]any
	for _, cipher := range []string{"aes-256-cbc", "aes-128-gcm"} {
		for _, c := range fixtures.SealCases {
			var (
				name, scope string
				now         int64
				expiry      map[string]json.RawMessage
				notBefore   *int64
				data        any
			)
			check(json.Unmarshal(c["name"], &name))
			check(json.Unmarshal(c["scope"], &scope))
			check(json.Unmarshal(c["now"], &now))
			check(json.Unmarshal(c["expiry"], &expiry))
			check(json.Unmarshal(c["data"], &data))
			if raw, ok := c["not_before"]; ok {
				check(json.Unmarshal(raw, &notBefore))
			}

			var exp laravelcrypt.Expiry
			if raw, ok := expiry["in"]; ok {
				var seconds int64
				check(json.Unmarshal(raw, &seconds))
				exp = laravelcrypt.ExpiresIn(time.Duration(seconds) * time.Second)
			} else if raw, ok := expiry["at"]; ok {
				var ts int64
				check(json.Unmarshal(raw, &ts))
				exp = laravelcrypt.ExpiresAt(time.Unix(ts, 0))
			} else {
				exp = laravelcrypt.NeverExpires()
			}
			opts := []laravelcrypt.EnvelopeOption{laravelcrypt.WithClock(func() time.Time { return time.Unix(now, 0) })}
			if notBefore != nil {
				opts = append(opts, laravelcrypt.WithNotBefore(time.Unix(*notBefore, 0)))
			}
			token, err := encrypter(cipher).Seal(scope, data, exp, opts...)
			check(err)
			sealed = append(sealed, map[string]any{"cipher": cipher, "name": name, "token": token, "case": c})
		}
	}

	check(json.NewEncoder(os.Stdout).Encode(map[string]any{
		"key_b64": fixtures.KeyB64, "verdicts": verdicts, "sealed": sealed,
	}))
}

func check(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
