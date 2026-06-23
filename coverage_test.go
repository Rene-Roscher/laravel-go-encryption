package laravelcrypt

import (
	"math"
	"reflect"
	"testing"
)

// All Go scalar kinds serialize to the expected PHP token.
func TestPHPMarshal_ScalarKinds(t *testing.T) {
	cases := []struct {
		in   any
		want string
	}{
		{int(5), "i:5;"},
		{int8(-8), "i:-8;"},
		{int16(16), "i:16;"},
		{int32(32), "i:32;"},
		{int64(64), "i:64;"},
		{uint(5), "i:5;"},
		{uint8(8), "i:8;"},
		{uint16(16), "i:16;"},
		{uint32(32), "i:32;"},
		{uint64(64), "i:64;"},
		{float32(1.5), "d:1.5;"},
		{float64(2.0), "d:2;"},
	}
	for _, c := range cases {
		got, err := phpMarshal(c.in)
		if err != nil {
			t.Fatalf("phpMarshal(%v): %v", c.in, err)
		}
		if got != c.want {
			t.Errorf("phpMarshal(%T %v) = %q, want %q", c.in, c.in, got, c.want)
		}
	}
}

// Slices/arrays/maps/pointers of concrete element types go through the reflect fallback.
func TestPHPMarshal_ReflectFallback(t *testing.T) {
	five := 5
	cases := []struct {
		in   any
		want any // expected after marshal->unmarshal
	}{
		{[]string{"a", "b"}, []any{"a", "b"}},
		{[2]int{1, 2}, []any{int64(1), int64(2)}},
		{map[string]int{"a": 1}, map[string]any{"a": int64(1)}},
		{&five, int64(5)},
		{(*int)(nil), nil},
	}
	for _, c := range cases {
		s, err := phpMarshal(c.in)
		if err != nil {
			t.Fatalf("phpMarshal(%v): %v", c.in, err)
		}
		got, err := phpUnmarshal(s)
		if err != nil {
			t.Fatalf("phpUnmarshal(%q): %v", s, err)
		}
		if !reflect.DeepEqual(got, c.want) {
			t.Errorf("%T: got %#v, want %#v", c.in, got, c.want)
		}
	}
}

func TestPHPMarshal_UnsupportedType(t *testing.T) {
	for _, v := range []any{make(chan int), func() {}, struct{ X int }{1}} {
		if _, err := phpMarshal(v); err == nil {
			t.Errorf("expected error marshalling %T", v)
		}
	}
}

func TestPHPFloat_SpecialValues(t *testing.T) {
	// encode
	enc := map[float64]string{
		math.Inf(1):  "d:INF;",
		math.Inf(-1): "d:-INF;",
	}
	for f, want := range enc {
		got, _ := phpMarshal(f)
		if got != want {
			t.Errorf("phpMarshal(%v) = %q, want %q", f, got, want)
		}
	}
	if got, _ := phpMarshal(math.NaN()); got != "d:NAN;" {
		t.Errorf("phpMarshal(NaN) = %q, want d:NAN;", got)
	}

	// decode
	if v, _ := phpUnmarshal("d:INF;"); !math.IsInf(v.(float64), 1) {
		t.Error("decode d:INF; should be +Inf")
	}
	if v, _ := phpUnmarshal("d:-INF;"); !math.IsInf(v.(float64), -1) {
		t.Error("decode d:-INF; should be -Inf")
	}
	if v, _ := phpUnmarshal("d:NAN;"); !math.IsNaN(v.(float64)) {
		t.Error("decode d:NAN; should be NaN")
	}
}

func TestParseKey_Forms(t *testing.T) {
	raw := repeat32(0x2b)

	// base64: prefix
	if k, err := ParseKey("base64:" + b64Encode(raw)); err != nil || len(k) != 32 {
		t.Fatalf("base64: form: %v len=%d", err, len(k))
	}
	// bare base64 that decodes to 32 bytes
	if k, err := ParseKey(b64Encode(raw)); err != nil || len(k) != 32 {
		t.Fatalf("bare base64: %v len=%d", err, len(k))
	}
	// raw string that isn't valid base64 of 16/32 bytes -> used verbatim
	rawKey := "this-is-a-32-byte-raw-secret-key" // 32 chars
	if k, err := ParseKey(rawKey); err != nil || string(k) != rawKey {
		t.Fatalf("raw form: %v got=%q", err, string(k))
	}
	// malformed base64: prefix
	if _, err := ParseKey("base64:!!!notbase64!!!"); err == nil {
		t.Error("malformed base64: payload must error")
	}
}

func TestEncrypt_UnsupportedTypeErrors(t *testing.T) {
	enc, _ := New(testKey, "aes-256-cbc")
	if _, err := enc.Encrypt(make(chan int)); err == nil {
		t.Error("Encrypt of an unsupported type must return an error")
	}
}

func TestEncryptDecrypt_CBC_Structured(t *testing.T) {
	enc, _ := New(testKey, "aes-256-cbc")
	val := map[string]any{"a": int64(1), "b": []any{"x", false, nil}, "n": int64(-3)}
	payload, err := enc.Encrypt(val)
	if err != nil {
		t.Fatal(err)
	}
	got, err := enc.Decrypt(payload)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, val) {
		t.Errorf("got %#v want %#v", got, val)
	}
}

func TestDecrypt_MalformedErrors(t *testing.T) {
	enc, _ := New(testKey, "aes-256-cbc")
	if _, err := enc.Decrypt("not-a-valid-payload"); err == nil {
		t.Error("Decrypt of a malformed payload must error")
	}
}

// pkcs7 padding is validated directly, including the defensive bad-padding branches that
// a valid (authenticated) payload can never reach through the public API.
func TestPKCS7(t *testing.T) {
	const block = 16
	// round-trip
	for _, in := range [][]byte{{}, []byte("a"), []byte("0123456789abcde"), []byte("0123456789abcdef")} {
		out, err := pkcs7Unpad(pkcs7Pad(in, block), block)
		if err != nil || string(out) != string(in) {
			t.Fatalf("round-trip %q: err=%v out=%q", in, err, out)
		}
	}
	// bad inputs
	bad := [][]byte{
		{},                 // empty
		make([]byte, 15),   // not a block multiple
		paddedEnding(0x00), // pad byte 0
		paddedEnding(0x11), // pad byte 17 > block
		inconsistentPad(),  // last byte says 5 but bytes differ
	}
	for i, b := range bad {
		if _, err := pkcs7Unpad(b, block); err == nil {
			t.Errorf("bad padding case %d should error", i)
		}
	}
}

// Every decoder error branch is exercised by a malformed input — none may panic, all must
// return an error (defence-in-depth for the unserializer).
func TestPHPUnmarshal_MalformedBranches(t *testing.T) {
	malformed := []string{
		"X;",             // unknown type token
		"",               // empty
		"b:",             // bool: no terminator
		"b:2;",           // bool: invalid value
		"i:;",            // int: empty
		"i:abc;",         // int: not a number
		"i:5",            // int: no terminator
		"d:;",            // float: empty
		"d:abc;",         // float: not a number
		"d:5",            // float: no terminator
		`s:abc:"x";`,     // string: bad length
		`s:-1:"";`,       // string: negative length
		`s:2:ab";`,       // string: missing opening quote
		`s:2:"ab`,        // string: missing closing quote/terminator
		`s:5:"ab";`,      // string: length exceeds data
		"a:x:{}",         // array: bad count
		"a:1:",           // array: missing opening brace
		`a:1:{i:0;}`,     // array: pair value missing
		`a:2:{i:0;b:1;}`, // array: count larger than pairs
		`a:1:{i:0;b:1;`,  // array: missing closing brace
		`O:abc:"x":0:{}`, // object: bad class length
		`O:8:"stdClass"`, // object: truncated
		`O:3:abc":1:{}`,  // object: missing class opening quote
	}
	for _, m := range malformed {
		if _, err := phpUnmarshal(m); err == nil {
			t.Errorf("expected error for malformed input %q", m)
		}
	}
}

func paddedEnding(last byte) []byte {
	b := make([]byte, 16)
	b[15] = last
	return b
}

func inconsistentPad() []byte {
	b := make([]byte, 16)
	for i := 11; i < 16; i++ {
		b[i] = 0x05
	}
	b[12] = 0x04 // claims 5 bytes of padding but one differs
	return b
}
