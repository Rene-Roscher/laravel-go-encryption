// Command envelope-judge reads tokens as the implementations print them (see cmd/envelope) on
// stdin and prints, as JSON on stdout, what this package makes of each one. e2e/compare.php of the
// laravel-interop package holds the result against what the tokens should give.
package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"time"

	laravelcrypt "github.com/Rene-Roscher/laravel-go-encryption"
)

type token struct {
	Cipher string `json:"cipher"`
	Token  string `json:"token"`
	Scope  string `json:"scope"`
	Now    int64  `json:"now"`
	Leeway int64  `json:"leeway"`
	Case   struct {
		Scope     string `json:"scope"`
		Now       int64  `json:"now"`
		NotBefore *int64 `json:"not_before"`
	} `json:"case"`
}

func main() {
	raw, err := io.ReadAll(os.Stdin)
	check(err)
	var input struct {
		KeyB64   string  `json:"key_b64"`
		Verdicts []token `json:"verdicts"`
		Sealed   []token `json:"sealed"`
	}
	check(json.Unmarshal(raw, &input))
	key, err := base64.StdEncoding.DecodeString(input.KeyB64)
	check(err)

	judge := func(t token, scope string, leeway, now int64) map[string]any {
		size := 32
		if t.Cipher == "aes-128-cbc" || t.Cipher == "aes-128-gcm" {
			size = 16
		}
		enc, err := laravelcrypt.New("base64:"+base64.StdEncoding.EncodeToString(key[:size]), t.Cipher)
		check(err)
		o, err := enc.Open(t.Token, scope,
			laravelcrypt.WithLeeway(time.Duration(leeway)*time.Second),
			laravelcrypt.WithClock(func() time.Time { return time.Unix(now, 0) }))
		if err != nil {
			return map[string]any{"verdict": laravelcrypt.EnvelopeVerdict(err)}
		}
		result := map[string]any{"verdict": "ok", "iat": o.IssuedAt.Unix(), "nbf": nil, "exp": nil, "data": o.Data}
		if !o.NotBefore.IsZero() {
			result["nbf"] = o.NotBefore.Unix()
		}
		if !o.ExpiresAt.IsZero() {
			result["exp"] = o.ExpiresAt.Unix()
		}
		return result
	}

	out := map[string][]map[string]any{"verdicts": {}, "sealed": {}}
	for _, t := range input.Verdicts {
		out["verdicts"] = append(out["verdicts"], judge(t, t.Scope, t.Leeway, t.Now))
	}
	for _, t := range input.Sealed {
		// Open it once it is valid, so the check is about the fields and not the clock.
		now := t.Case.Now + 1
		if t.Case.NotBefore != nil && *t.Case.NotBefore > now {
			now = *t.Case.NotBefore
		}
		out["sealed"] = append(out["sealed"], judge(t, t.Case.Scope, 0, now))
	}
	check(json.NewEncoder(os.Stdout).Encode(out))
}

func check(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
