// Command genvectors emits Go-encrypted Laravel payloads as JSON on stdout. CI pipes this
// into a PHP script that decrypts each with the same key and asserts equality — proving the
// Go -> Laravel direction (PHP-generated vectors prove Laravel -> Go).
//
// "string" vectors use EncryptString/decryptString; "serialized" vectors use Encrypt/decrypt
// (the PHP-serialize path) and carry a fixed nested structure both sides agree on.
package main

import (
	"encoding/json"
	"fmt"
	"os"

	laravelcrypt "github.com/Rene-Roscher/laravel-go-encryption"
)

func main() {
	key := "base64:KysrKysrKysrKysrKysrKysrKysrKysrKysrKysrKys="

	strings := []string{
		"Hello from Go",
		"Grüße 世界 🚀 café",
		`{"user":"alice","id":7,"active":true}`,
		"first line\nsecond line\n",
	}

	// Fixed structure; scripts/verify_go_vectors.php hardcodes the same one.
	typed := map[string]any{
		"user": "alice", "id": 7, "active": true, "score": 2.5,
		"tags": []any{"x", "y"}, "meta": nil,
	}

	type out struct {
		Kind      string `json:"kind"`
		Cipher    string `json:"cipher"`
		Plaintext string `json:"plaintext"`
		Payload   string `json:"payload"`
	}

	var vectors []out
	for _, c := range []string{"aes-256-cbc", "aes-256-gcm"} {
		enc, err := laravelcrypt.New(key, c)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		for _, pt := range strings {
			p, err := enc.EncryptString(pt)
			if err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(1)
			}
			vectors = append(vectors, out{"string", c, pt, p})
		}
		p, err := enc.Encrypt(typed)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		vectors = append(vectors, out{"serialized", c, "", p})
	}

	_ = json.NewEncoder(os.Stdout).Encode(map[string]any{"key": key, "vectors": vectors})
}
