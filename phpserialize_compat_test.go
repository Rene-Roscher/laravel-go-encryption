package laravelcrypt

import (
	"errors"
	"math"
	"strings"
	"testing"
)

// Expected strings are the output of PHP's serialize(). Go prints the shortest digits that
// round-trip in %G form (1E+25 where PHP writes 1.0E+25); both parse to the same double, so
// floats are checked through a round-trip rather than byte for byte.
func TestPHPFloatsRoundTripExactly(t *testing.T) {
	for _, f := range []float64{
		2, 2.5, 0.1, 0.1 + 0.2, 100, 0.5, 1e14, 1e15, 1e16, 1e17, 1e18, 123456789012345678,
		0.0001, 0.00009, 0.00001, 1.5e-7, -1.5e25, 5e-324, math.MaxFloat64,
		math.SmallestNonzeroFloat64, math.Copysign(0, -1), math.Inf(1), math.Inf(-1),
	} {
		s, err := phpMarshal(f)
		if err != nil {
			t.Fatalf("%v: %v", f, err)
		}
		back, err := phpUnmarshal(s)
		if err != nil || !sameValue(back, f) {
			t.Errorf("%v -> %q -> %v (%v)", f, s, back, err)
		}
	}
	s, _ := phpMarshal(math.NaN())
	if back, err := phpUnmarshal(s); err != nil || !math.IsNaN(back.(float64)) {
		t.Errorf("NaN -> %q -> %v (%v)", s, back, err)
	}
}

func TestPHPMarshalCanonicalFormsFromPHP(t *testing.T) {
	for _, c := range []struct {
		in   any
		want string
	}{
		{int64(-42), "i:-42;"},
		{int64(math.MinInt64), "i:-9223372036854775808;"},
		{uint64(math.MaxUint64), "i:18446744073709551615;"},
		{"héllo \"w\"", "s:10:\"héllo \"w\"\";"},
		{"\x00\xff", "s:2:\"\x00\xff\";"},
		{[]any{}, "a:0:{}"},
		{math.Inf(1), "d:INF;"},
		{math.Inf(-1), "d:-INF;"},
		{math.NaN(), "d:NAN;"},
		{map[string]any{"b": int64(1), "a": nil}, `a:2:{s:1:"a";N;s:1:"b";i:1;}`}, // keys sorted
	} {
		got, err := phpMarshal(c.in)
		if err != nil || got != c.want {
			t.Errorf("phpMarshal(%#v) = %q, %v; want %q", c.in, got, err, c.want)
		}
	}
}

func TestPHPUnmarshalNumbersAndStrings(t *testing.T) {
	for _, c := range []struct {
		in   string
		want any
	}{
		{"i:-9223372036854775808;", int64(math.MinInt64)},
		{"d:1.0E+25;", 1e25},
		{"d:2;", 2.0},
		{"d:INF;", math.Inf(1)},
		{"d:-INF;", math.Inf(-1)},
		{`s:0:"";`, ""},
		{"s:2:\"\x00\x00\";", "\x00\x00"},
		{"s:2:\"\xff\xfe\";", "\xff\xfe"},
		{`a:0:{}`, []any{}},
		{`a:1:{i:1;s:1:"a";}`, map[string]any{"1": "a"}},
		{`a:2:{i:1;s:1:"a";i:0;s:1:"b";}`, map[string]any{"1": "a", "0": "b"}},
		{`a:1:{s:1:"0";s:1:"a";}`, map[string]any{"0": "a"}},
		{`O:13:"Evil\Gadget\X":0:{}`, map[string]any{"__class__": `Evil\Gadget\X`}},
	} {
		got, err := phpUnmarshal(c.in)
		if err != nil || !sameValue(got, c.want) {
			t.Errorf("phpUnmarshal(%q) = %#v, %v; want %#v", c.in, got, err, c.want)
		}
	}
}

func TestPHPUnmarshalRejectsMalformedInput(t *testing.T) {
	for _, bad := range []string{
		"", "x", "X;", "N", "N:", "b:", "b:2;", "b:1",
		"i:;", "i:abc;", "i:5", "i:9223372036854775808;",
		"d:;", "d:abc;", "d:inf;", "d:nan;", "d:infinity;", "d:0x1p-2;", "d:1_0;", "d:5",
		`s:abc:"x";`, `s:-1:"";`, `s:2:ab";`, `s:2:"ab`, `s:2:"ab"`, `s:5:"ab";`,
		"s:99999999999999999999:\"ab\";",
		"a:x:{}", "a:-1:{}", "a:1:", "a:1:{i:0;}", "a:2:{i:0;b:1;}", "a:1:{i:0;b:1;",
		`O:abc:"x":0:{}`, `O:8:"stdClass"`, `O:3:abc":1:{}`, `O:3:"abc":x:{}`, `O:99:"abc":0:{}`,
		// Unsupported PHP features.
		`S:1:"a";`, `C:3:"Foo":0:{}`, "r:1;", "R:1;", `E:7:"Foo:Bar";`,
	} {
		if _, err := phpUnmarshal(bad); err == nil {
			t.Errorf("phpUnmarshal(%q) must fail", bad)
		}
	}
}

func TestPHPMarshalErrorsPropagateFromNestedValues(t *testing.T) {
	bad := make(chan int)
	for name, v := range map[string]any{
		"list": []any{"ok", bad},
		"map":  map[string]any{"k": bad},
		"deep": map[string]any{"a": []any{map[string]any{"b": bad}}},
		"func": func() {},
	} {
		if _, err := phpMarshal(v); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
}

func TestEncryptRejectsUnsupportedTypesWithoutPanicking(t *testing.T) {
	enc := newEnc(t, "aes-256-cbc")
	for name, v := range map[string]any{
		"chan": make(chan int), "func": func() {}, "struct": struct{ A int }{1},
		"complex": complex(1, 2), "nested chan": []any{make(chan int)},
	} {
		if _, err := enc.Encrypt(v); err == nil {
			t.Errorf("%s: Encrypt must fail", name)
		}
	}
}

func TestPHPMarshalPointersAndTypedContainers(t *testing.T) {
	s := "ptr"
	var nilPtr *string
	for _, c := range []struct {
		in   any
		want string
	}{
		{&s, `s:3:"ptr";`},
		{nilPtr, "N;"},
		{[]string{"a", "b"}, `a:2:{i:0;s:1:"a";i:1;s:1:"b";}`},
		{[2]int{1, 2}, "a:2:{i:0;i:1;i:1;i:2;}"},
		{map[string]int{"x": 1}, `a:1:{s:1:"x";i:1;}`},
		{map[int]string{5: "a"}, `a:1:{s:1:"5";s:1:"a";}`},
		{int8(-1), "i:-1;"},
		{uint8(255), "i:255;"},
		{float32(0.5), "d:0.5;"},
	} {
		got, err := phpMarshal(c.in)
		if err != nil || got != c.want {
			t.Errorf("phpMarshal(%#v) = %q, %v; want %q", c.in, got, err, c.want)
		}
	}
}

func TestErrorsAreDistinguishable(t *testing.T) {
	enc := newEnc(t, "aes-256-cbc")
	if _, err := enc.Decrypt(mustEncrypt(t, enc, "not serialized")); !errors.Is(err, errPHPSerialize) {
		t.Errorf("err = %v, want errPHPSerialize", err)
	}
	if _, err := enc.DecryptString("garbage"); !errors.Is(err, ErrInvalidPayload) {
		t.Errorf("err = %v, want ErrInvalidPayload", err)
	}
	for _, e := range []error{ErrUnsupportedCipher, ErrInvalidPayload, ErrInvalidMAC, ErrDecrypt, ErrEmptyKey} {
		if !strings.HasPrefix(e.Error(), "laravelcrypt: ") {
			t.Errorf("%q lacks the package prefix", e)
		}
	}
}

func TestPHPUnmarshalRejectsTrailingData(t *testing.T) {
	// PHP warns about extra data, and Laravel's error handler turns that into an exception.
	for _, bad := range []string{"N;N;", "i:1;x", `a:0:{}a:0:{}`, `s:1:"a";;`} {
		if _, err := phpUnmarshal(bad); err == nil {
			t.Errorf("phpUnmarshal(%q) must fail", bad)
		}
	}
}

func TestPHPUnmarshalRejectsKeysThatAreNotIntOrString(t *testing.T) {
	for _, bad := range []string{
		"a:1:{b:1;b:1;}", "a:1:{d:1.5;b:1;}", "a:1:{N;b:1;}", "a:1:{a:0:{}b:1;}",
		`O:8:"stdClass":1:{b:1;b:1;}`,
	} {
		if _, err := phpUnmarshal(bad); err == nil {
			t.Errorf("phpUnmarshal(%q) must fail", bad)
		}
	}
}

func TestPHPUnmarshalLimitsNesting(t *testing.T) {
	nested := func(depth int) string {
		return strings.Repeat("a:1:{i:0;", depth) + "N;" + strings.Repeat("}", depth)
	}
	if _, err := phpUnmarshal(nested(maxPHPDepth)); err != nil {
		t.Errorf("nesting of %d must be accepted: %v", maxPHPDepth, err)
	}
	for _, depth := range []int{maxPHPDepth + 1, 100_000} {
		if _, err := phpUnmarshal(nested(depth)); err == nil {
			t.Errorf("nesting of %d must be rejected", depth)
		}
	}
}

// A hostile element count must neither allocate for it nor panic.
func TestPHPUnmarshalSurvivesHostileCounts(t *testing.T) {
	for _, bad := range []string{
		"a:9223372036854775807:{}",
		"a:4000000000:{i:0;N;}",
		`O:8:"stdClass":9223372036854775807:{}`,
	} {
		if _, err := phpUnmarshal(bad); err == nil {
			t.Errorf("phpUnmarshal(%q) must fail", bad)
		}
	}
}
