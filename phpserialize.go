package laravelcrypt

import (
	"errors"
	"fmt"
	"math"
	"reflect"
	"sort"
	"strconv"
	"strings"
)

// PHP (un)serialization for the value set that crosses language boundaries — the same data
// Laravel's Crypt::encrypt / decrypt round-trips: nil, bool, int (int64), float (float64),
// string, lists ([]any) and maps (map[string]any).
//
// Decoding additionally accepts PHP objects ("O:...") — their properties are returned as a
// map[string]any with the class name under the "__class__" key. Objects are NEVER
// instantiated, so decoding untrusted payloads cannot trigger PHP-style unserialize gadget
// chains. Integer-keyed arrays decode to []any when the keys are exactly 0..n-1, otherwise
// to a map[string]any with stringified keys (matching how PHP blurs lists and maps).
//
// Note: numbers decoded from JSON in Go are float64; pass explicit int/int64 if you need
// PHP integers. Floats are round-tripped by value (Go's shortest representation), which PHP
// parses back to the identical double — they are not guaranteed byte-identical to PHP's own
// serializer output, but that never affects correctness (the IV is random anyway).

var errPHPSerialize = errors.New("laravelcrypt: invalid PHP serialization")

// phpMarshal serializes v into PHP's serialize() format.
func phpMarshal(v any) (string, error) {
	var b strings.Builder
	if err := phpEncode(&b, v); err != nil {
		return "", err
	}
	return b.String(), nil
}

func phpEncode(b *strings.Builder, v any) error {
	if v == nil {
		b.WriteString("N;")
		return nil
	}

	switch x := v.(type) {
	case bool:
		if x {
			b.WriteString("b:1;")
		} else {
			b.WriteString("b:0;")
		}
		return nil
	case string:
		phpEncodeString(b, x)
		return nil
	case float32:
		phpEncodeFloat(b, float64(x))
		return nil
	case float64:
		phpEncodeFloat(b, x)
		return nil
	case int:
		fmt.Fprintf(b, "i:%d;", x)
		return nil
	case int8:
		fmt.Fprintf(b, "i:%d;", x)
		return nil
	case int16:
		fmt.Fprintf(b, "i:%d;", x)
		return nil
	case int32:
		fmt.Fprintf(b, "i:%d;", x)
		return nil
	case int64:
		fmt.Fprintf(b, "i:%d;", x)
		return nil
	case uint, uint8, uint16, uint32, uint64:
		fmt.Fprintf(b, "i:%d;", reflect.ValueOf(x).Uint())
		return nil
	case []any:
		return phpEncodeList(b, x)
	case map[string]any:
		return phpEncodeMap(b, x)
	}

	// Reflect fallback for other slice/array/map kinds (e.g. []string, map[string]int).
	rv := reflect.ValueOf(v)
	switch rv.Kind() {
	case reflect.Slice, reflect.Array:
		list := make([]any, rv.Len())
		for i := 0; i < rv.Len(); i++ {
			list[i] = rv.Index(i).Interface()
		}
		return phpEncodeList(b, list)
	case reflect.Map:
		m := make(map[string]any, rv.Len())
		for _, k := range rv.MapKeys() {
			m[fmt.Sprintf("%v", k.Interface())] = rv.MapIndex(k).Interface()
		}
		return phpEncodeMap(b, m)
	case reflect.Pointer:
		if rv.IsNil() {
			b.WriteString("N;")
			return nil
		}
		return phpEncode(b, rv.Elem().Interface())
	}

	return fmt.Errorf("laravelcrypt: cannot PHP-serialize value of type %T", v)
}

func phpEncodeString(b *strings.Builder, s string) {
	fmt.Fprintf(b, "s:%d:\"%s\";", len(s), s)
}

func phpEncodeFloat(b *strings.Builder, f float64) {
	switch {
	case math.IsInf(f, 1):
		b.WriteString("d:INF;")
	case math.IsInf(f, -1):
		b.WriteString("d:-INF;")
	case math.IsNaN(f):
		b.WriteString("d:NAN;")
	default:
		fmt.Fprintf(b, "d:%s;", strconv.FormatFloat(f, 'G', -1, 64))
	}
}

func phpEncodeList(b *strings.Builder, list []any) error {
	fmt.Fprintf(b, "a:%d:{", len(list))
	for i, e := range list {
		fmt.Fprintf(b, "i:%d;", i)
		if err := phpEncode(b, e); err != nil {
			return err
		}
	}
	b.WriteString("}")
	return nil
}

func phpEncodeMap(b *strings.Builder, m map[string]any) error {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys) // deterministic output
	fmt.Fprintf(b, "a:%d:{", len(m))
	for _, k := range keys {
		phpEncodeString(b, k)
		if err := phpEncode(b, m[k]); err != nil {
			return err
		}
	}
	b.WriteString("}")
	return nil
}

// phpUnmarshal parses a PHP serialize() string into Go values.
func phpUnmarshal(s string) (any, error) {
	d := &phpDecoder{s: s}
	v, err := d.value()
	if err != nil {
		return nil, err
	}
	return v, nil
}

type phpDecoder struct {
	s string
	i int
}

func (d *phpDecoder) value() (any, error) {
	if d.i >= len(d.s) {
		return nil, errPHPSerialize
	}
	switch d.s[d.i] {
	case 'N':
		return nil, d.lit("N;")
	case 'b':
		return d.boolean()
	case 'i':
		return d.integer()
	case 'd':
		return d.double()
	case 's':
		return d.str()
	case 'a':
		return d.array()
	case 'O':
		return d.object()
	default:
		return nil, errPHPSerialize
	}
}

func (d *phpDecoder) lit(s string) error {
	if !strings.HasPrefix(d.s[d.i:], s) {
		return errPHPSerialize
	}
	d.i += len(s)
	return nil
}

// readUntil consumes up to (not including) sep and advances past it.
func (d *phpDecoder) readUntil(sep byte) (string, error) {
	j := strings.IndexByte(d.s[d.i:], sep)
	if j < 0 {
		return "", errPHPSerialize
	}
	out := d.s[d.i : d.i+j]
	d.i += j + 1
	return out, nil
}

func (d *phpDecoder) boolean() (any, error) {
	if err := d.lit("b:"); err != nil {
		return nil, err
	}
	v, err := d.readUntil(';')
	if err != nil {
		return nil, err
	}
	switch v {
	case "1":
		return true, nil
	case "0":
		return false, nil
	}
	return nil, errPHPSerialize
}

func (d *phpDecoder) integer() (any, error) {
	if err := d.lit("i:"); err != nil {
		return nil, err
	}
	v, err := d.readUntil(';')
	if err != nil {
		return nil, err
	}
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil {
		return nil, errPHPSerialize
	}
	return n, nil
}

func (d *phpDecoder) double() (any, error) {
	if err := d.lit("d:"); err != nil {
		return nil, err
	}
	v, err := d.readUntil(';')
	if err != nil {
		return nil, err
	}
	switch v {
	case "INF":
		return math.Inf(1), nil
	case "-INF":
		return math.Inf(-1), nil
	case "NAN":
		return math.NaN(), nil
	}
	f, err := strconv.ParseFloat(v, 64)
	if err != nil {
		return nil, errPHPSerialize
	}
	return f, nil
}

func (d *phpDecoder) str() (string, error) {
	if err := d.lit("s:"); err != nil {
		return "", err
	}
	lenStr, err := d.readUntil(':')
	if err != nil {
		return "", err
	}
	n, err := strconv.Atoi(lenStr)
	if err != nil || n < 0 {
		return "", errPHPSerialize
	}
	// expect opening quote, exactly n bytes, closing quote, semicolon
	if d.i >= len(d.s) || d.s[d.i] != '"' {
		return "", errPHPSerialize
	}
	d.i++
	if d.i+n > len(d.s) {
		return "", errPHPSerialize
	}
	out := d.s[d.i : d.i+n]
	d.i += n
	if !strings.HasPrefix(d.s[d.i:], "\";") {
		return "", errPHPSerialize
	}
	d.i += 2
	return out, nil
}

func (d *phpDecoder) array() (any, error) {
	if err := d.lit("a:"); err != nil {
		return nil, err
	}
	count, err := d.count()
	if err != nil {
		return nil, err
	}
	keys, vals, err := d.pairs(count)
	if err != nil {
		return nil, err
	}
	return assemble(keys, vals), nil
}

func (d *phpDecoder) object() (any, error) {
	if err := d.lit("O:"); err != nil {
		return nil, err
	}
	// class name is a length-prefixed string: <len>:"<class>":
	clenStr, err := d.readUntil(':')
	if err != nil {
		return nil, err
	}
	clen, err := strconv.Atoi(clenStr)
	if err != nil || clen < 0 || d.i >= len(d.s) || d.s[d.i] != '"' {
		return nil, errPHPSerialize
	}
	d.i++
	if d.i+clen > len(d.s) {
		return nil, errPHPSerialize
	}
	class := d.s[d.i : d.i+clen]
	d.i += clen
	if !strings.HasPrefix(d.s[d.i:], "\":") {
		return nil, errPHPSerialize
	}
	d.i += 2
	count, err := d.count()
	if err != nil {
		return nil, err
	}
	keys, vals, err := d.pairs(count)
	if err != nil {
		return nil, err
	}
	out := map[string]any{"__class__": class}
	for i, k := range keys {
		out[fmt.Sprintf("%v", k)] = vals[i]
	}
	return out, nil
}

// count parses "<n>:{" (the element count plus the opening brace).
func (d *phpDecoder) count() (int, error) {
	cStr, err := d.readUntil(':')
	if err != nil {
		return 0, err
	}
	n, err := strconv.Atoi(cStr)
	if err != nil || n < 0 {
		return 0, errPHPSerialize
	}
	if d.i >= len(d.s) || d.s[d.i] != '{' {
		return 0, errPHPSerialize
	}
	d.i++
	return n, nil
}

func (d *phpDecoder) pairs(count int) (keys, vals []any, err error) {
	keys = make([]any, count)
	vals = make([]any, count)
	for i := 0; i < count; i++ {
		k, kerr := d.value()
		if kerr != nil {
			return nil, nil, kerr
		}
		v, verr := d.value()
		if verr != nil {
			return nil, nil, verr
		}
		keys[i] = k
		vals[i] = v
	}
	if d.i >= len(d.s) || d.s[d.i] != '}' {
		return nil, nil, errPHPSerialize
	}
	d.i++
	return keys, vals, nil
}

// assemble returns a []any when keys are exactly 0..n-1 (a PHP list), else a string-keyed map.
func assemble(keys, vals []any) any {
	isList := true
	for i, k := range keys {
		ki, ok := k.(int64)
		if !ok || ki != int64(i) {
			isList = false
			break
		}
	}
	if isList {
		return vals
	}
	m := make(map[string]any, len(keys))
	for i, k := range keys {
		m[fmt.Sprintf("%v", k)] = vals[i]
	}
	return m
}
