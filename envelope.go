package laravelcrypt

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strconv"
	"time"
	"unicode/utf8"
)

// Interop Envelope v1: a JSON document with a scope, timestamps and data, encrypted with
// EncryptString. The encryption authenticates it, so neither the scope nor the timestamps can be
// changed without the key. The rene-roscher/laravel-interop package for Laravel, and the Rust and
// Node.js packages, read and write the same format.
//
// The plaintext is {"typ":"env","v":1,"iat":…,"nbf":…,"exp":…,"scope":…,"data":…}. Open checks, in
// this order, and the first failure wins: the structure, the version, the scope, nbf and exp. A
// token is valid for nbf - leeway <= now < exp + leeway.

const (
	envelopeType    = "env"
	envelopeVersion = 1
)

// Envelope errors. A failure to decrypt is not one of them: Open returns the errors of
// DecryptString (ErrInvalidPayload, ErrInvalidMAC, ErrDecrypt) before it looks at the envelope.
var (
	ErrEnvelopeInvalid     = errors.New("laravelcrypt: the payload is not a valid envelope")
	ErrUnsupportedVersion  = errors.New("laravelcrypt: the envelope version is not supported")
	ErrScopeMismatch       = errors.New("laravelcrypt: the envelope was issued for another scope")
	ErrNotYetValid         = errors.New("laravelcrypt: the envelope is not valid yet")
	ErrExpired             = errors.New("laravelcrypt: the envelope has expired")
	errEnvelopeBadArgument = errors.New("laravelcrypt: invalid envelope argument")
)

// Expiry says when an envelope stops being valid. Seal requires one, so that a token never lives
// forever by accident.
type Expiry struct {
	in    time.Duration
	at    time.Time
	never bool
}

// ExpiresIn makes an envelope valid for d after it is sealed. d must be at least one second.
func ExpiresIn(d time.Duration) Expiry { return Expiry{in: d} }

// ExpiresAt makes an envelope valid until t.
func ExpiresAt(t time.Time) Expiry { return Expiry{at: t} }

// NeverExpires makes an envelope valid forever. Prefer a lifetime unless the scope itself limits
// the token.
func NeverExpires() Expiry { return Expiry{never: true} }

type envelopeConfig struct {
	notBefore time.Time
	leeway    time.Duration
	now       func() time.Time
}

// EnvelopeOption configures Seal or Open. An option that does not apply to the call is ignored.
type EnvelopeOption func(*envelopeConfig)

// WithNotBefore (Seal) makes the envelope invalid before t.
func WithNotBefore(t time.Time) EnvelopeOption {
	return func(c *envelopeConfig) { c.notBefore = t }
}

// WithLeeway (Open) tolerates this much clock difference, in whole seconds, on both time checks.
func WithLeeway(d time.Duration) EnvelopeOption {
	return func(c *envelopeConfig) { c.leeway = d }
}

// WithClock (Seal and Open) overrides time.Now, for tests.
func WithClock(now func() time.Time) EnvelopeOption {
	return func(c *envelopeConfig) { c.now = now }
}

func newEnvelopeConfig(opts []EnvelopeOption) envelopeConfig {
	c := envelopeConfig{now: time.Now}
	for _, o := range opts {
		o(&c)
	}
	return c
}

// Opened is a verified envelope.
type Opened struct {
	// Scope is the scope it was sealed for (the one that was asked for).
	Scope string
	// Data is the sealed JSON; Decode reads it into a Go value.
	Data json.RawMessage
	// IssuedAt is when it was sealed.
	IssuedAt time.Time
	// NotBefore and ExpiresAt are the zero time when the envelope has none.
	NotBefore, ExpiresAt time.Time
}

// Decode reads the data into v, like json.Unmarshal.
func (o *Opened) Decode(v any) error { return json.Unmarshal(o.Data, v) }

// Seal seals data for scope. data is encoded with encoding/json, which the Laravel package reads
// as the equivalent PHP value.
func (e *Encrypter) Seal(scope string, data any, expiry Expiry, opts ...EnvelopeOption) (string, error) {
	if scope == "" {
		return "", fmt.Errorf("%w: the scope must not be empty", errEnvelopeBadArgument)
	}
	c := newEnvelopeConfig(opts)
	now := c.now().Unix()

	var exp string
	switch {
	case expiry.never:
	case !expiry.at.IsZero():
		if expiry.at.Unix() <= 0 {
			return "", fmt.Errorf("%w: the expiry must be a positive Unix timestamp", errEnvelopeBadArgument)
		}
		exp = `"exp":` + strconv.FormatInt(expiry.at.Unix(), 10) + ","
	case expiry.in >= time.Second:
		exp = `"exp":` + strconv.FormatInt(now+int64(expiry.in/time.Second), 10) + ","
	default:
		return "", fmt.Errorf("%w: choose an expiry of at least one second, a time, or NeverExpires", errEnvelopeBadArgument)
	}
	var nbf string
	if !c.notBefore.IsZero() {
		nbf = `"nbf":` + strconv.FormatInt(c.notBefore.Unix(), 10) + ","
	}

	scopeJSON, err := marshalJSON(scope)
	if err != nil {
		return "", err
	}
	dataJSON, err := marshalJSON(data)
	if err != nil {
		return "", err
	}
	document := `{"typ":"` + envelopeType + `","v":` + strconv.Itoa(envelopeVersion) +
		`,"iat":` + strconv.FormatInt(now, 10) + `,` + nbf + exp + `"scope":` + scopeJSON + `,"data":` + dataJSON + `}`
	return e.EncryptString(document)
}

// marshalJSON encodes v without escaping <, > and &.
func marshalJSON(v any) (string, error) {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return "", err
	}
	return string(bytes.TrimRight(b.Bytes(), "\n")), nil
}

// Open verifies and opens an envelope that was sealed for scope. Open returns the errors of
// DecryptString when the token does not decrypt, and one of the envelope errors otherwise.
func (e *Encrypter) Open(token, scope string, opts ...EnvelopeOption) (*Opened, error) {
	c := newEnvelopeConfig(opts)

	plaintext, err := e.decrypt(token)
	if err != nil {
		return nil, err
	}
	if !utf8.Valid(plaintext) {
		return nil, ErrEnvelopeInvalid // PHP's json_decode rejects invalid UTF-8
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(plaintext, &fields); err != nil || fields == nil {
		return nil, ErrEnvelopeInvalid
	}
	var typ string
	if raw, ok := fields["typ"]; !ok || json.Unmarshal(raw, &typ) != nil || typ != envelopeType {
		return nil, ErrEnvelopeInvalid
	}

	version, present, err := envelopeInteger(fields, "v")
	if err != nil || !present {
		return nil, ErrEnvelopeInvalid
	}
	if version != envelopeVersion {
		return nil, ErrUnsupportedVersion
	}
	issuedAt, present, err := envelopeInteger(fields, "iat")
	if err != nil || !present {
		return nil, ErrEnvelopeInvalid
	}
	notBefore, hasNotBefore, err := envelopeInteger(fields, "nbf")
	if err != nil {
		return nil, ErrEnvelopeInvalid
	}
	expiresAt, hasExpiry, err := envelopeInteger(fields, "exp")
	if err != nil {
		return nil, ErrEnvelopeInvalid
	}
	var sealedScope string
	if raw, ok := fields["scope"]; !ok || json.Unmarshal(raw, &sealedScope) != nil || sealedScope == "" {
		return nil, ErrEnvelopeInvalid
	}
	data, ok := fields["data"]
	if !ok {
		return nil, ErrEnvelopeInvalid
	}

	if sealedScope != scope {
		return nil, ErrScopeMismatch
	}

	now := c.now().Unix()
	leeway := int64(c.leeway / time.Second)
	if hasNotBefore && now < notBefore-leeway {
		return nil, ErrNotYetValid
	}
	if hasExpiry && now >= expiresAt+leeway {
		return nil, ErrExpired
	}

	o := &Opened{Scope: sealedScope, Data: data, IssuedAt: time.Unix(issuedAt, 0)}
	if hasNotBefore {
		o.NotBefore = time.Unix(notBefore, 0)
	}
	if hasExpiry {
		o.ExpiresAt = time.Unix(expiresAt, 0)
	}
	return o, nil
}

// envelopeInteger reads a version or timestamp field. Any JSON number without a fractional part is
// accepted, because JavaScript cannot tell 1 from 1.0; everything else is invalid. present is false
// for an absent field.
func envelopeInteger(fields map[string]json.RawMessage, name string) (value int64, present bool, err error) {
	raw, ok := fields[name]
	if !ok {
		return 0, false, nil
	}
	if i, err := strconv.ParseInt(string(raw), 10, 64); err == nil {
		return i, true, nil
	}
	f, err := strconv.ParseFloat(string(raw), 64)
	if err != nil || math.IsInf(f, 0) || math.IsNaN(f) || f != math.Trunc(f) || math.Abs(f) >= 1<<53 {
		return 0, true, ErrEnvelopeInvalid
	}
	return int64(f), true, nil
}

// EnvelopeVerdict names the outcome of Open for err in the words all implementations share:
// "ok" (nil), "invalid", "unsupported_version", "scope_mismatch", "not_yet_valid", "expired", or
// "decrypt_error" for a token that does not decrypt.
func EnvelopeVerdict(err error) string {
	switch {
	case err == nil:
		return "ok"
	case errors.Is(err, ErrUnsupportedVersion):
		return "unsupported_version"
	case errors.Is(err, ErrScopeMismatch):
		return "scope_mismatch"
	case errors.Is(err, ErrNotYetValid):
		return "not_yet_valid"
	case errors.Is(err, ErrExpired):
		return "expired"
	case errors.Is(err, ErrEnvelopeInvalid), errors.Is(err, errEnvelopeBadArgument):
		return "invalid"
	default:
		return "decrypt_error"
	}
}
