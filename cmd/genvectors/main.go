// Command genvectors emits Go-encrypted Laravel payloads as JSON on stdout. CI pipes this
// into scripts/verify_go_vectors.php, which decrypts each with the real Laravel encrypter
// and asserts equality — proving the Go -> Laravel direction (PHP-generated fixtures prove
// Laravel -> Go).
//
// "string" vectors use EncryptString/decryptString; "serialized" vectors use Encrypt/decrypt
// (the PHP-serialize path) and build the values named in scripts/cases.php.
package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math"
	"os"
	"strings"

	laravelcrypt "github.com/Rene-Roscher/laravel-go-encryption"
)

func main() {
	b64 := base64.StdEncoding
	key := bytes.Repeat([]byte{0x2b}, 32)

	plaintexts := []struct{ name, text string }{
		{"simple", "Hello from Go"},
		{"empty", ""},
		{"unicode", "Grüße 世界 🚀 café"},
		{"json", `{"user":"alice","id":7,"active":true}`},
		{"multiline", "first line\nsecond line\n"},
		{"binary", "\x00\x01\xff\xfe\x80\x7f"},
		{"block_aligned", strings.Repeat("a", 32)},
		{"long", strings.Repeat("The quick brown fox 0123456789 ", 50)},
	}

	type vector struct {
		Kind         string `json:"kind"`
		Name         string `json:"name"`
		Case         string `json:"case,omitempty"`
		Cipher       string `json:"cipher"`
		PlaintextB64 string `json:"plaintext_b64"`
		Payload      string `json:"payload"`
	}

	var vectors []vector
	for _, c := range []struct {
		name string
		size int
	}{{"aes-128-cbc", 16}, {"aes-256-cbc", 32}, {"aes-128-gcm", 16}, {"aes-256-gcm", 32}} {
		enc, err := laravelcrypt.New("base64:"+b64.EncodeToString(key[:c.size]), c.name)
		check(err)

		for _, p := range plaintexts {
			payload, err := enc.EncryptString(p.text)
			check(err)
			vectors = append(vectors, vector{
				Kind: "string", Name: c.name + "/" + p.name, Cipher: c.name,
				PlaintextB64: b64.EncodeToString([]byte(p.text)), Payload: payload,
			})
		}
		for _, k := range cases() {
			payload, err := enc.Encrypt(k.value)
			check(err)
			vectors = append(vectors, vector{
				Kind: "serialized", Name: c.name + "/" + k.name, Case: k.name, Cipher: c.name, Payload: payload,
			})
		}
	}

	check(json.NewEncoder(os.Stdout).Encode(map[string]any{
		"key_b64": b64.EncodeToString(key),
		"vectors": vectors,
	}))
}

type namedValue struct {
	name  string
	value any
}

// cases builds the values named in scripts/cases.php. Go maps have no order and string keys
// only: PHP normalizes numeric string keys to integers, and the verifier ignores key order.
func cases() []namedValue {
	return []namedValue{
		{"null", nil},
		{"true", true},
		{"false", false},
		{"int_zero", int64(0)},
		{"int_negative", int64(-42)},
		{"int_max", int64(math.MaxInt64)},
		{"int_min", int64(math.MinInt64)},
		{"float", 2.5},
		{"float_whole", 2.0},
		{"float_tenth", 0.1},
		{"float_large", 1.0e25},
		{"float_small", 1.5e-7},
		{"float_negative_zero", math.Copysign(0, -1)},
		{"float_pi", math.Pi},
		{"float_max", math.MaxFloat64},
		{"float_min_subnormal", 4.9e-324},
		{"float_inf", math.Inf(1)},
		{"float_negative_inf", math.Inf(-1)},
		{"float_nan", math.NaN()},
		{"string_empty", ""},
		{"string_unicode", "Grüße 世界 🚀 café"},
		{"string_quotes", `say "hi"; s:3:"x";`},
		{"string_binary", "\x00\xff\xfe\x80"},
		{"list", []any{int64(1), "two", true, nil, []any{int64(3), int64(4)}}},
		{"empty_array", []any{}},
		{"assoc", map[string]any{
			"user": "alice", "id": int64(7), "active": true, "score": 2.5,
			"tags": []any{"x", "y"}, "meta": nil,
		}},
		{"mixed_keys", map[string]any{
			"5": "a", "x": "b", "7": map[string]any{"nested": []any{int64(1), int64(2)}},
		}},
		{"non_sequential_list", map[string]any{"1": "a", "0": "b"}},
		{"nested", map[string]any{"l1": map[string]any{"l2": map[string]any{
			"l3": []any{"deep", 1.5, false},
		}}}},
	}
}

func check(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
