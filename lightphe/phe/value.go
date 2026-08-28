package phe

import (
	"encoding/json"
	"fmt"
	"math/big"
	"strings"
)

// Value is a ciphertext payload. The interface is deliberately closed: only the
// four concrete types declared in this file implement it, which lets every
// cryptosystem type-switch over the complete set of shapes a ciphertext can
// take without a default branch that silently accepts nonsense.
//
// Values are treated as immutable once created. Homomorphic operations always
// return a new Value instead of mutating their operands, which makes them safe
// to share between goroutines.
type Value interface {
	// sealed keeps the implementation set closed to this package.
	sealed()

	// Equal reports whether the two values carry identical contents.
	Equal(other Value) bool

	// Clone returns a deep copy.
	Clone() Value

	fmt.Stringer
	json.Marshaler
}

// Int is a single integer ciphertext, used by RSA, Paillier, Damgard-Jurik,
// Okamoto-Uchiyama, Benaloh and Naccache-Stern.
type Int struct {
	V *big.Int
}

// NewInt wraps v in an Int value. The argument is copied.
func NewInt(v *big.Int) Int { return Int{V: new(big.Int).Set(v)} }

func (Int) sealed() {}

// Equal implements Value.
func (i Int) Equal(other Value) bool {
	o, ok := other.(Int)
	return ok && i.V.Cmp(o.V) == 0
}

// Clone implements Value.
func (i Int) Clone() Value { return Int{V: new(big.Int).Set(i.V)} }

// String implements fmt.Stringer.
func (i Int) String() string { return i.V.String() }

// MarshalJSON implements json.Marshaler.
func (i Int) MarshalJSON() ([]byte, error) { return i.V.MarshalJSON() }

// Tuple is an ordered collection of values. It models the (c1, c2) pairs of
// ElGamal and elliptic curve ElGamal, the per-bit ciphertext lists of
// Goldwasser-Micali, and the per-bit vectors of Sander-Young-Yung, which nest
// one Tuple inside another.
type Tuple struct {
	Items []Value
}

// NewTuple builds a Tuple from the given items.
func NewTuple(items ...Value) Tuple { return Tuple{Items: items} }

func (Tuple) sealed() {}

// Len returns the number of items in the tuple.
func (t Tuple) Len() int { return len(t.Items) }

// Equal implements Value.
func (t Tuple) Equal(other Value) bool {
	o, ok := other.(Tuple)
	if !ok || len(t.Items) != len(o.Items) {
		return false
	}
	for i := range t.Items {
		if !t.Items[i].Equal(o.Items[i]) {
			return false
		}
	}
	return true
}

// Clone implements Value.
func (t Tuple) Clone() Value {
	items := make([]Value, len(t.Items))
	for i, item := range t.Items {
		items[i] = item.Clone()
	}
	return Tuple{Items: items}
}

// String implements fmt.Stringer.
func (t Tuple) String() string {
	parts := make([]string, len(t.Items))
	for i, item := range t.Items {
		parts[i] = item.String()
	}
	return "(" + strings.Join(parts, ", ") + ")"
}

// MarshalJSON implements json.Marshaler.
func (t Tuple) MarshalJSON() ([]byte, error) { return json.Marshal(t.Items) }

// Ints is a convenience accessor returning the tuple items as integers. It
// reports an error when any item is not an Int.
func (t Tuple) Ints() ([]*big.Int, error) {
	out := make([]*big.Int, len(t.Items))
	for i, item := range t.Items {
		v, ok := item.(Int)
		if !ok {
			return nil, InvalidCiphertextf("tuple item %d is %T, want an integer", i, item)
		}
		out[i] = v.V
	}
	return out, nil
}

// Point is an affine point on an elliptic curve, carried without a reference to
// the curve itself. The owning cryptosystem knows which curve the coordinates
// belong to.
type Point struct {
	X, Y     *big.Int
	Infinity bool
}

// NewPoint builds an affine point value. The coordinates are copied.
func NewPoint(x, y *big.Int) Point {
	return Point{X: new(big.Int).Set(x), Y: new(big.Int).Set(y)}
}

// InfinityPoint returns the point at infinity.
func InfinityPoint() Point { return Point{Infinity: true} }

func (Point) sealed() {}

// Equal implements Value.
func (p Point) Equal(other Value) bool {
	o, ok := other.(Point)
	if !ok {
		return false
	}
	if p.Infinity || o.Infinity {
		return p.Infinity == o.Infinity
	}
	return p.X.Cmp(o.X) == 0 && p.Y.Cmp(o.Y) == 0
}

// Clone implements Value.
func (p Point) Clone() Value {
	if p.Infinity {
		return Point{Infinity: true}
	}
	return Point{X: new(big.Int).Set(p.X), Y: new(big.Int).Set(p.Y)}
}

// String implements fmt.Stringer.
func (p Point) String() string {
	if p.Infinity {
		return "O"
	}
	return fmt.Sprintf("(%s, %s)", p.X, p.Y)
}

// MarshalJSON implements json.Marshaler. Points serialise as a two element
// array so that exported keys stay interchangeable with the Python library.
func (p Point) MarshalJSON() ([]byte, error) {
	if p.Infinity {
		return []byte("null"), nil
	}
	return json.Marshal([]*big.Int{p.X, p.Y})
}

// UnmarshalJSON implements json.Unmarshaler, accepting the same two element
// array MarshalJSON produces.
func (p *Point) UnmarshalJSON(data []byte) error {
	if string(data) == "null" {
		p.X, p.Y, p.Infinity = nil, nil, true
		return nil
	}
	var coords []*big.Int
	if err := json.Unmarshal(data, &coords); err != nil {
		return InvalidKeysf("decoding a curve point: %v", err)
	}
	if len(coords) != 2 {
		return InvalidKeysf("a curve point needs exactly 2 coordinates, got %d", len(coords))
	}
	p.X, p.Y, p.Infinity = coords[0], coords[1], false
	return nil
}

// FP2 is an element a + b*i of the quadratic extension field F_{p^2}. It is the
// target group of the Boneh-Goh-Nissim pairing, so a BGN ciphertext turns into
// an FP2 after its single allowed homomorphic multiplication.
type FP2 struct {
	A, B *big.Int
}

// NewFP2 builds an F_{p^2} element. The coordinates are copied.
func NewFP2(a, b *big.Int) FP2 {
	return FP2{A: new(big.Int).Set(a), B: new(big.Int).Set(b)}
}

func (FP2) sealed() {}

// Equal implements Value.
func (f FP2) Equal(other Value) bool {
	o, ok := other.(FP2)
	return ok && f.A.Cmp(o.A) == 0 && f.B.Cmp(o.B) == 0
}

// Clone implements Value.
func (f FP2) Clone() Value {
	return FP2{A: new(big.Int).Set(f.A), B: new(big.Int).Set(f.B)}
}

// String implements fmt.Stringer.
func (f FP2) String() string { return fmt.Sprintf("(%s + %s*i)", f.A, f.B) }

// MarshalJSON implements json.Marshaler.
func (f FP2) MarshalJSON() ([]byte, error) { return json.Marshal([]*big.Int{f.A, f.B}) }

// AsInt returns the integer carried by v, or an error when v has another shape.
func AsInt(v Value) (*big.Int, error) {
	i, ok := v.(Int)
	if !ok {
		return nil, InvalidCiphertextf("expected an integer ciphertext, got %T", v)
	}
	return i.V, nil
}

// AsTuple returns the tuple carried by v, or an error when v has another shape.
func AsTuple(v Value) (Tuple, error) {
	t, ok := v.(Tuple)
	if !ok {
		return Tuple{}, InvalidCiphertextf("expected a tuple ciphertext, got %T", v)
	}
	return t, nil
}

// AsPair returns the two components of a two element tuple.
func AsPair(v Value) (Value, Value, error) {
	t, err := AsTuple(v)
	if err != nil {
		return nil, nil, err
	}
	if len(t.Items) != 2 {
		return nil, nil, InvalidCiphertextf("expected a ciphertext pair, got %d components", len(t.Items))
	}
	return t.Items[0], t.Items[1], nil
}

// AsPoint returns the curve point carried by v, or an error otherwise.
func AsPoint(v Value) (Point, error) {
	p, ok := v.(Point)
	if !ok {
		return Point{}, InvalidCiphertextf("expected an elliptic curve point, got %T", v)
	}
	return p, nil
}
