package laravelcrypt

import (
	"reflect"
	"testing"
)

// Canonical serialize() outputs produced by real PHP (Laravel), used to verify the codec
// without needing PHP at test time.
func TestPHPUnmarshal(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want any
	}{
		{"string-with-embedded-quotes", `s:14:"héllo "world"";`, `héllo "world"`},
		{"int", `i:7;`, int64(7)},
		{"negative-int", `i:-42;`, int64(-42)},
		{"float", `d:2.5;`, 2.5},
		{"bool-true", `b:1;`, true},
		{"bool-false", `b:0;`, false},
		{"null", `N;`, nil},
		{"list", `a:4:{i:0;s:1:"x";i:1;s:1:"y";i:2;i:1;i:3;b:1;}`, []any{"x", "y", int64(1), true}},
		{
			"map",
			`a:6:{s:4:"user";s:5:"alice";s:2:"id";i:7;s:6:"active";b:1;s:5:"score";d:2.5;s:4:"tags";a:2:{i:0;s:1:"x";i:1;s:1:"y";}s:4:"meta";N;}`,
			map[string]any{"user": "alice", "id": int64(7), "active": true, "score": 2.5, "tags": []any{"x", "y"}, "meta": nil},
		},
		{
			"object-decodes-to-map",
			`O:8:"stdClass":2:{s:1:"a";i:1;s:1:"b";s:3:"two";}`,
			map[string]any{"__class__": "stdClass", "a": int64(1), "b": "two"},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := phpUnmarshal(c.in)
			if err != nil {
				t.Fatalf("phpUnmarshal: %v", err)
			}
			if !reflect.DeepEqual(got, c.want) {
				t.Errorf("got %#v, want %#v", got, c.want)
			}
		})
	}
}

// Scalars and lists serialize byte-identically to PHP (maps differ only in key order, which
// PHP ignores on unserialize — covered by the round-trip test).
func TestPHPMarshal_Canonical(t *testing.T) {
	cases := []struct {
		in   any
		want string
	}{
		{nil, "N;"},
		{true, "b:1;"},
		{false, "b:0;"},
		{int64(7), "i:7;"},
		{2.5, "d:2.5;"},
		{2.0, "d:2;"},
		{`héllo "world"`, `s:14:"héllo "world"";`},
		{[]any{"x", "y", int64(1), true}, `a:4:{i:0;s:1:"x";i:1;s:1:"y";i:2;i:1;i:3;b:1;}`},
	}
	for _, c := range cases {
		got, err := phpMarshal(c.in)
		if err != nil {
			t.Fatalf("phpMarshal(%v): %v", c.in, err)
		}
		if got != c.want {
			t.Errorf("phpMarshal(%v) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestPHPRoundTrip(t *testing.T) {
	values := []any{
		nil, true, false, int64(0), int64(-99), 3.14159, "", "plain",
		[]any{int64(1), "two", true, nil, []any{"nested"}},
		map[string]any{
			"user": "alice", "id": int64(7), "active": true, "score": 2.5,
			"tags": []any{"x", "y"}, "meta": nil,
			"nested": map[string]any{"deep": []any{int64(1), int64(2)}},
		},
	}
	for i, v := range values {
		s, err := phpMarshal(v)
		if err != nil {
			t.Fatalf("case %d marshal: %v", i, err)
		}
		got, err := phpUnmarshal(s)
		if err != nil {
			t.Fatalf("case %d unmarshal: %v", i, err)
		}
		if !reflect.DeepEqual(got, v) {
			t.Errorf("case %d round-trip:\n got=%#v\nwant=%#v", i, got, v)
		}
	}
}

func TestPHPUnmarshalRejectsGarbage(t *testing.T) {
	for _, bad := range []string{"", "x", "i:notanint;", `s:5:"ab";`, "a:1:{i:0;", "b:2;"} {
		if _, err := phpUnmarshal(bad); err == nil {
			t.Errorf("expected error for %q", bad)
		}
	}
}

// Cross-language: a payload from the REAL Laravel Crypt::encrypt(<nested array>) decrypts
// and PHP-unserializes in Go to the equivalent structure (the complete encrypt() path).
func TestDecryptLaravelTypedPayload(t *testing.T) {
	const payload = "eyJpdiI6ImZiVCtvNFZJZ2IrdkZkaWl6djJYOVE9PSIsInZhbHVlIjoiTWZKeDZCc0FrdDhYNGFVdmJYa0daWG0yN2NGRzFlNnZlNVhwUjFiMXd1NzM5SXVXRjhRR05IZldDYzJIczl0MngzdlBiS2g3VHpUYkltQXh1cllXdnZrL1VTYlVMeDhMeGkrU2Vqc2FaWEdSejFaNUFHS3FxQXQzeUVGZDNvcTRvVWpJSitvSWc4RlpJaWpHR1cyN29JNVpkK3gvWGVqWmRxUTZITFA1QlBNYklzaXdCU01iQnQyVDZVZ0doaEw2IiwibWFjIjoiMWY3NTY4M2MxNDQ5YTQ0MjVjNzc1MjFjMmMwM2UxNzlmZDdkOGVhNzZjZWQ1MDlhMzI0NjAxNWVjYWM4NjMzZiIsInRhZyI6IiJ9"

	enc, err := New(testKey, "aes-256-cbc")
	if err != nil {
		t.Fatal(err)
	}
	got, err := enc.Decrypt(payload)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	want := map[string]any{
		"user": "alice", "id": int64(7), "active": true, "score": 2.5,
		"tags": []any{"x", "y"}, "meta": nil,
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("typed decrypt:\n got=%#v\nwant=%#v", got, want)
	}
}

// Encrypt -> Decrypt round-trip for a structured value (Go side).
func TestEncryptDecryptRoundTrip(t *testing.T) {
	enc, _ := New(testKey, "aes-256-gcm")
	value := map[string]any{"a": int64(1), "b": []any{"x", true, nil}, "c": 1.5}
	payload, err := enc.Encrypt(value)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	got, err := enc.Decrypt(payload)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if !reflect.DeepEqual(got, value) {
		t.Errorf("got %#v want %#v", got, value)
	}
}
