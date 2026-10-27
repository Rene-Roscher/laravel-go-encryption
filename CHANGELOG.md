# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed
- `ParseKey` decodes the `base64:` form with PHP's lenient `base64_decode`, like Laravel's
  `EncryptionServiceProvider`: padding is optional and stray characters are skipped. A malformed
  value now fails in `New` as `ErrUnsupportedCipher` (wrong length) instead of in `ParseKey`.
- Payload validation now mirrors Laravel's `Encrypter` exactly: PHP's lenient `base64_decode`
  for the payload, `value` and `tag`, strict decoding for `iv`, `mac` required to be a string,
  a tag on a CBC payload rejected, `"0"` treated as no tag, JSON with invalid UTF-8 or
  non-string fields rejected, and field names matched case-sensitively.
- The PHP unserializer rejects float spellings PHP does not accept (`inf`, `nan`, hex floats),
  array keys that are not integers or strings, trailing data, and nesting deeper than 128 levels.

### Fixed
- A hostile element count in a serialized array (for example `a:9223372036854775807:{}`) made
  the unserializer panic or reserve huge amounts of memory.

### Added
- `AppearsEncrypted`, like Laravel's `Encrypter::appearsEncrypted`, compared with Laravel on the
  mutated payloads.
- `WithPreviousKeys` option (previous keys, as in Laravel 11+), `EncryptCookie` / `DecryptCookie`
  for Laravel's `EncryptCookies` middleware, and `PHPSerialize` / `PHPUnserialize` for the
  serialized attributes of encrypted sessions.
- Tests against the real `EncryptCookies` logic, `EncryptedStore` and Eloquent encrypted casts for
  Laravel 10 to 13, with random keys.
- Test coverage across all four ciphers: payload layout, tamper and tag rules, malformed
  payloads, key forms and sizes, serialized values from real Laravel, concurrency, and
  arbitrary-input robustness.
- `cmd/mutations` and `scripts/verify_mutations.php`: Go and Laravel must judge thousands of
  mutated payloads identically.
- Interop in CI for Laravel 10 and for all four ciphers in both directions.
- Initial release: `Encrypter` with `EncryptString` / `DecryptString`, wire-compatible with
  Laravel's `Illuminate\Encryption\Encrypter` (AES-256-CBC and AES-256-GCM), Laravel 10–13.
- `Encrypt` / `Decrypt` (the PHP-`serialize` path) with a built-in PHP serializer for nil,
  bool, ints, floats, strings, lists and maps; PHP objects decode to a map (never
  instantiated).
- `base64:` / bare-base64 / raw key parsing via `New` and `ParseKey`.
- Constant-time MAC verification (CBC) and AEAD tag verification (GCM); tampered, wrong-key,
  and malformed payloads are always rejected with typed errors.
- Cross-language test harness: decrypts real Laravel-generated vectors, and a PHP verifier
  decrypts Go-generated vectors (both directions, both ciphers) in CI.
- Fuzz test ensuring the decrypter never panics on arbitrary input.
