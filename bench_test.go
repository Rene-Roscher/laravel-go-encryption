package laravelcrypt

import (
	"strings"
	"testing"
)

// Representative sizes: a tiny value and a ~4 KB blob (about the size of a PEM cert+key
// bundle), which is the relevant case for just-in-time decryption on a hot path.
var benchSizes = []struct {
	name string
	data string
}{
	{"32B", strings.Repeat("x", 32)},
	{"4KB", strings.Repeat("x", 4096)},
}

func BenchmarkEncryptString(b *testing.B) {
	for _, cipher := range []string{"aes-256-cbc", "aes-256-gcm"} {
		enc, _ := New(testKey, cipher)
		for _, s := range benchSizes {
			b.Run(cipher+"/"+s.name, func(b *testing.B) {
				b.ReportAllocs()
				b.SetBytes(int64(len(s.data)))
				for i := 0; i < b.N; i++ {
					if _, err := enc.EncryptString(s.data); err != nil {
						b.Fatal(err)
					}
				}
			})
		}
	}
}

func BenchmarkDecryptString(b *testing.B) {
	for _, cipher := range []string{"aes-256-cbc", "aes-256-gcm"} {
		enc, _ := New(testKey, cipher)
		for _, s := range benchSizes {
			payload, _ := enc.EncryptString(s.data)
			b.Run(cipher+"/"+s.name, func(b *testing.B) {
				b.ReportAllocs()
				b.SetBytes(int64(len(s.data)))
				for i := 0; i < b.N; i++ {
					if _, err := enc.DecryptString(payload); err != nil {
						b.Fatal(err)
					}
				}
			})
		}
	}
}

// New parses the key on every call; relevant if a caller constructs an Encrypter per use
// rather than once. (Reuse the Encrypter to avoid this.)
func BenchmarkNew(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, err := New(testKey, "aes-256-cbc"); err != nil {
			b.Fatal(err)
		}
	}
}
