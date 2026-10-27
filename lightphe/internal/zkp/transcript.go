// Package zkp implements the zero-knowledge proofs of threshold decryption,
// proofs of correct decryption, proofs of knowledge, proofs of allowed values,
// range proofs and one-hot proofs.
//
// Proofs are made non-interactive with the Fiat-Shamir heuristic. Challenge is
// the hash of everything the verifier sees, so the prover cannot pick it. The
// hashed transcript is the same JSON the Python library hashes, so proofs made
// by one library verify in the other.
//
// Reference: Fiat, A., Shamir, A. (1986). How to Prove Yourself.
//
// Reference: Chaum, D., Pedersen, T. P. (1992). Wallet Databases with
// Observers.
package zkp

import (
	"bytes"
	"crypto/sha512"
	"encoding/json"
	"fmt"
	"math"
	"math/big"
	"reflect"
	"sort"
	"strconv"
	"unicode/utf16"

	"github.com/serengil/lightphe-go/lightphe/ecc"
	"github.com/serengil/lightphe-go/lightphe/phe"
)

// Challenge is the Fiat-Shamir challenge, the SHA-512 hash of a domain and
// all public items of a proof, reduced in modulo. Domain separates challenges
// of different proofs.
func Challenge(domain string, modulo *big.Int, items ...interface{}) *big.Int {
	var buf bytes.Buffer
	buf.WriteByte('[')
	encode(&buf, domain)
	buf.WriteByte(',')
	encode(&buf, items)
	buf.WriteByte(']')
	digest := sha512.Sum512(buf.Bytes())
	e := new(big.Int).SetBytes(digest[:])
	return e.Mod(e, modulo)
}

// encode writes an item as Python's json.dumps with compact separators does,
// after the canonicalization of the Python library: tuples are lists, curve
// points are pairs of coordinates, and floats are strings.
func encode(buf *bytes.Buffer, item interface{}) {
	switch v := item.(type) {
	case nil:
		buf.WriteString("null")
	case string:
		encodeString(buf, v)
	case bool:
		buf.WriteString(strconv.FormatBool(v))
	case int:
		buf.WriteString(strconv.Itoa(v))
	case int64:
		buf.WriteString(strconv.FormatInt(v, 10))
	case uint64:
		buf.WriteString(strconv.FormatUint(v, 10))
	case float64:
		encodeString(buf, pythonFloat(v))
	case *big.Int:
		if v == nil {
			buf.WriteString("null")
			return
		}
		buf.WriteString(v.String())
	case json.Number:
		buf.WriteString(v.String())
	case phe.Int:
		encode(buf, v.V)
	case phe.Tuple:
		encode(buf, v.Items)
	case phe.Point:
		if v.Infinity {
			encode(buf, []interface{}{"inf", "inf"})
			return
		}
		encode(buf, []interface{}{v.X, v.Y})
	case ecc.Point:
		if v.Infinity {
			encode(buf, []interface{}{"inf", "inf"})
			return
		}
		encode(buf, []interface{}{v.X, v.Y})
	default:
		encodeReflected(buf, item)
	}
}

// encodeReflected encodes slices, maps and anything else JSON can marshal.
func encodeReflected(buf *bytes.Buffer, item interface{}) {
	rv := reflect.ValueOf(item)
	switch rv.Kind() {
	case reflect.Slice, reflect.Array:
		if rv.Kind() == reflect.Slice && rv.IsNil() {
			buf.WriteString("null")
			return
		}
		buf.WriteByte('[')
		for i := 0; i < rv.Len(); i++ {
			if i > 0 {
				buf.WriteByte(',')
			}
			encode(buf, rv.Index(i).Interface())
		}
		buf.WriteByte(']')
		return
	case reflect.Map:
		if rv.Type().Key().Kind() == reflect.String {
			keys := make([]string, 0, rv.Len())
			for _, key := range rv.MapKeys() {
				keys = append(keys, key.String())
			}
			sort.Strings(keys)
			buf.WriteByte('{')
			for i, key := range keys {
				if i > 0 {
					buf.WriteByte(',')
				}
				encodeString(buf, key)
				buf.WriteByte(':')
				encode(buf, rv.MapIndex(reflect.ValueOf(key).Convert(rv.Type().Key())).Interface())
			}
			buf.WriteByte('}')
			return
		}
	case reflect.Ptr:
		if rv.IsNil() {
			buf.WriteString("null")
			return
		}
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32:
		buf.WriteString(strconv.FormatInt(rv.Int(), 10))
		return
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32:
		buf.WriteString(strconv.FormatUint(rv.Uint(), 10))
		return
	}

	// structs and other types are encoded as their JSON
	data, err := json.Marshal(item)
	if err != nil {
		encodeString(buf, fmt.Sprint(item))
		return
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	var decoded interface{}
	if err := decoder.Decode(&decoded); err != nil {
		encodeString(buf, fmt.Sprint(item))
		return
	}
	encode(buf, decoded)
}

// encodeString escapes a string as Python's json.dumps does with ensure_ascii.
func encodeString(buf *bytes.Buffer, s string) {
	buf.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			buf.WriteString(`\"`)
		case '\\':
			buf.WriteString(`\\`)
		case '\n':
			buf.WriteString(`\n`)
		case '\r':
			buf.WriteString(`\r`)
		case '\t':
			buf.WriteString(`\t`)
		case '\b':
			buf.WriteString(`\b`)
		case '\f':
			buf.WriteString(`\f`)
		default:
			switch {
			case r < 0x20 || (r >= 0x7f && r < 0x10000):
				if r < 0x7f {
					fmt.Fprintf(buf, `\u%04x`, r)
				} else if r == 0x7f {
					buf.WriteRune(r)
				} else {
					fmt.Fprintf(buf, `\u%04x`, r)
				}
			case r >= 0x10000:
				high, low := utf16.EncodeRune(r)
				fmt.Fprintf(buf, `\u%04x\u%04x`, high, low)
			default:
				buf.WriteRune(r)
			}
		}
	}
	buf.WriteByte('"')
}

// pythonFloat formats a float as Python's str does for common values.
func pythonFloat(f float64) string {
	switch {
	case math.IsInf(f, 1):
		return "inf"
	case math.IsInf(f, -1):
		return "-inf"
	case math.IsNaN(f):
		return "nan"
	case f == math.Trunc(f) && math.Abs(f) < 1e16:
		return strconv.FormatFloat(f, 'f', 1, 64)
	}
	return strconv.FormatFloat(f, 'g', -1, 64)
}
