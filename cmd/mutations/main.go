// Command mutations emits valid and mutated payloads together with this package's verdict on
// each, as JSON on stdout. CI pipes this into scripts/verify_mutations.php, which asks the
// real Laravel encrypter about the same payloads: both must accept and reject exactly the
// same ones, and return the same plaintext for the accepted ones.
package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	laravelcrypt "github.com/Rene-Roscher/laravel-go-encryption"
)

type verdict struct {
	Cipher  string  `json:"cipher"`
	Payload string  `json:"payload"`
	Plain   *string `json:"plain"`
}

func main() {
	key := bytes.Repeat([]byte{0x2b}, 32)
	b64 := base64.StdEncoding

	// xorshift64: deterministic, so a failing case is reproducible.
	state := uint64(0x123456789abcdef1)
	next := func() uint64 {
		state ^= state << 13
		state ^= state >> 7
		state ^= state << 17
		return state
	}
	encode := func(m map[string]any) string {
		raw, err := json.Marshal(m)
		check(err)
		return b64.EncodeToString(raw)
	}

	// Field values that exercise PHP's loose typing: null, empty, "0", numbers, arrays,
	// short or invalid base64.
	odd := []any{nil, "", "0", 5, true, []any{}, "AAAA", "***", "AAAAAAAAAAAAAAAAAAAAAA=="}

	var cases []verdict
	for _, c := range []struct {
		name string
		size int
	}{{"aes-128-cbc", 16}, {"aes-256-cbc", 32}, {"aes-128-gcm", 16}, {"aes-256-gcm", 32}} {
		enc, err := laravelcrypt.New("base64:"+b64.EncodeToString(key[:c.size]), c.name)
		check(err)

		for _, text := range []string{"", "hello", "0123456789abcdef"} {
			valid, err := enc.EncryptString(text)
			check(err)
			var base map[string]any
			raw, err := b64.DecodeString(valid)
			check(err)
			check(json.Unmarshal(raw, &base))

			clone := func() map[string]any {
				m := make(map[string]any, len(base))
				for k, v := range base {
					m[k] = v
				}
				return m
			}

			payloads := []string{valid, " " + valid + "\n", strings.TrimRight(valid, "=")}

			// Field-level edits: odd values, removal, upper case, an extra character.
			for _, field := range []string{"iv", "value", "mac", "tag"} {
				for _, o := range odd {
					m := clone()
					m[field] = o
					payloads = append(payloads, encode(m))
				}
				m := clone()
				delete(m, field)
				payloads = append(payloads, encode(m))

				text := base[field].(string)
				m = clone()
				m[field] = strings.ToUpper(text)
				payloads = append(payloads, encode(m))
				m = clone()
				m[field] = text + "A"
				payloads = append(payloads, encode(m))
			}

			// Byte-level edits of the outer base64 text.
			for i := 0; i < 600; i++ {
				b := []byte(valid)
				at := int(next() % uint64(len(b))) //nolint:gosec // bounded by len(b)
				switch next() % 5 {
				case 0:
					b[at] = "ABCxyz09+/=!\n "[next()%14]
				case 1:
					b = append(b[:at], b[at+1:]...)
				case 2:
					b = b[:at]
				case 3:
					b = append(b[:at], append([]byte{" \n=*"[next()%4]}, b[at:]...)...)
				default:
					other := int(next() % uint64(len(b))) //nolint:gosec // bounded by len(b)
					b[at], b[other] = b[other], b[at]
				}
				payloads = append(payloads, strings.ToValidUTF8(string(b), "�"))
			}

			for _, p := range payloads {
				v := verdict{Cipher: c.name, Payload: p}
				if plain, err := enc.DecryptString(p); err == nil {
					v.Plain = &plain
				}
				cases = append(cases, v)
			}
		}
	}

	check(json.NewEncoder(os.Stdout).Encode(map[string]any{
		"key_b64": b64.EncodeToString(key),
		"cases":   cases,
	}))
}

func check(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
