# laravel-go-encryption

[![CI](https://github.com/Rene-Roscher/laravel-go-encryption/actions/workflows/ci.yml/badge.svg)](https://github.com/Rene-Roscher/laravel-go-encryption/actions/workflows/ci.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/Rene-Roscher/laravel-go-encryption.svg)](https://pkg.go.dev/github.com/Rene-Roscher/laravel-go-encryption)
[![Go Report Card](https://goreportcard.com/badge/github.com/Rene-Roscher/laravel-go-encryption)](https://goreportcard.com/report/github.com/Rene-Roscher/laravel-go-encryption)

A Go port of Laravel's `Illuminate\Encryption\Encrypter`, **wire-compatible** with Laravel 10
through 13. Decrypt in Go what Laravel encrypted with `Crypt` / `Encrypter`, and produce
payloads Laravel can decrypt — sharing encrypted data seamlessly across platforms using the
same key.

## Features

- AES-256-CBC (Laravel's default) **and** AES-256-GCM (AEAD).
- Both Laravel paths: `EncryptString`/`DecryptString` (raw strings) and `Encrypt`/`Decrypt`
  (the PHP-`serialize` path — strings, numbers, bools, null, arrays and nested structures).
- Accepts the Laravel `APP_KEY` `base64:...` form, a bare base64 key, or raw key bytes.
- Constant-time MAC verification (CBC) / AEAD tag verification (GCM).
- Tampered, wrong-key and malformed payloads are **always rejected** with typed errors.
- Zero dependencies (standard library only).
- Payload validation mirrors `Illuminate\Encryption\Encrypter`, including PHP's lenient
  `base64_decode` and `empty()` quirks.
- Verified **both directions** against the real Laravel encrypter in CI (Laravel 10/11/12/13).

## Install

```sh
go get github.com/Rene-Roscher/laravel-go-encryption
```

## Usage

```go
import laravelcrypt "github.com/Rene-Roscher/laravel-go-encryption"

enc, err := laravelcrypt.New(os.Getenv("APP_KEY"), "aes-256-cbc") // "base64:...." form
if err != nil {
    log.Fatal(err)
}

// Decrypt something Laravel encrypted (Crypt::encryptString(...) in PHP):
plain, err := enc.DecryptString(payloadFromLaravel)

// Encrypt something Laravel can decrypt (Crypt::decryptString($payload) in PHP):
payload, err := enc.EncryptString("hello")
```

On the Laravel side (no PHP serialization, so the Go side stays simple — JSON-encode
structured data yourself):

```php
use Illuminate\Support\Facades\Crypt;

$payload = Crypt::encryptString('hello');     // -> DecryptString in Go
$plain   = Crypt::decryptString($payloadFromGo);
```

### Structured values (the PHP-`serialize` path)

`Encrypt` / `Decrypt` mirror Laravel's default `Crypt::encrypt` / `Crypt::decrypt`, which
PHP-`serialize` the value:

```go
payload, _ := enc.Encrypt(map[string]any{"user": "alice", "id": 7, "tags": []any{"x", "y"}})
// PHP: Crypt::decrypt($payload) === ['user' => 'alice', 'id' => 7, 'tags' => ['x', 'y']]

v, _ := enc.Decrypt(payloadFromLaravelCryptEncrypt) // -> any (map[string]any / []any / scalar)
```

Supported: `nil`, `bool`, ints, floats, `string`, `[]any`, `map[string]any` (and other
slice/map kinds via reflection). PHP **objects decode to a `map[string]any`** (class under
`"__class__"`) and are never instantiated — so decoding untrusted payloads can't trigger
unserialize-gadget chains. Numbers decoded from JSON in Go are `float64`; pass explicit
`int`/`int64` for PHP integers.

> For cross-language interop, a plain string carrying your own JSON (`EncryptString` +
> `encoding/json`) is the simplest, least surprising option.

### Type mapping & type-safety

| PHP (Laravel)   | Go                              |
|-----------------|---------------------------------|
| `string`        | `string`                        |
| `int`           | `int64`                         |
| `float`         | `float64`                       |
| `bool`          | `bool`                          |
| `null`          | `nil`                           |
| `array` (list)  | `[]any`                         |
| `array` (assoc) | `map[string]any`                |
| `object`        | `map[string]any` (`"__class__"`; decode-only, never instantiated) |

`Decrypt` returns exactly one of the Go types above — assert with the comma-ok form. The
decoder **never panics** on any input (verified by `FuzzDecryptString`); unsupported
`Encrypt` inputs (channels, funcs, structs, …) return a typed error rather than panicking.
Note that PHP `int` ↔ Go `int64` and PHP `float` ↔ `float64`; numbers decoded from JSON in Go
are `float64`, so pass explicit `int`/`int64` when you need a PHP integer.

**For full compile-time type safety**, prefer the string path and let the Go compiler check
your own types end-to-end:

```go
b, _ := json.Marshal(cfg)               // cfg is your typed struct
payload, _ := enc.EncryptString(string(b))

plain, _ := enc.DecryptString(payload)
var got Config                          // typed
_ = json.Unmarshal([]byte(plain), &got)
```

## Wire format (identical to Laravel)

```
base64( json{ "iv": b64, "value": b64, "mac": hex, "tag": b64 } )
```

- **AES-256-CBC**: random 16-byte IV, PKCS#7 padding, `mac = HMAC-SHA256(base64(iv)+base64(value), key)`
  (lower-case hex), `tag = ""`.
- **AES-256-GCM**: random 12-byte IV, 16-byte GCM tag in `tag`, `mac = ""`.

The key is the raw key bytes — a Laravel `APP_KEY` `base64:XXXX` decodes to 32 bytes.

## Security

- CBC payloads are authenticated with HMAC-SHA256 and compared in constant time before
  decryption; GCM is authenticated by the AEAD tag.
- Any modification of the payload (iv/value/mac/tag), a wrong key, an unsupported cipher or
  key length, or a malformed payload returns a typed error — never a silent/partial result.
- `DecryptString` never panics on arbitrary input (covered by a fuzz test).

## Testing & cross-language proof

```sh
go test ./...                       # unit + Laravel-generated vectors + round-trip + tamper
make race                           # with the race detector
make fuzz                           # fuzz the decoder
make interop                        # all of the below vs the REAL Laravel encrypter (needs PHP)
```

`fixtures/vectors.json` holds payloads produced by the real `illuminate/encryption`: all four
ciphers, strings (unicode, binary, block-aligned, long) and serialized values (floats, nested
arrays, mixed keys, objects).

CI runs, for Laravel 10, 11, 12 and 13 with the real `illuminate/encryption`:

- **Laravel → Go**: `scripts/generate_vectors.php` → `TestDecryptLaravelVectors` and the
  serialized-value tests.
- **Go → Laravel**: `go run ./cmd/genvectors` → `scripts/verify_go_vectors.php`.
- **Malformed input**: `go run ./cmd/mutations` emits valid and mutated payloads (edited
  fields, odd JSON types, broken base64) with Go's verdict on each;
  `scripts/verify_mutations.php` asks Laravel about the same payloads. Both must accept and
  reject exactly the same ones and return the same plaintext.

## License

MIT © René Roscher
