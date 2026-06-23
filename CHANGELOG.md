# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
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
