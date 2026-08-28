// Package ecc implements elliptic curve arithmetic over prime and binary
// fields in short Weierstrass, twisted Edwards and Koblitz form, together with
// the Weil and modified Tate pairings. It is a pure Go port of the LightECC
// library and depends on nothing outside the standard library.
//
// Curves and points are immutable: every operation allocates its result, so a
// curve may be shared freely between goroutines.
package ecc

import (
	"errors"
	"fmt"
	"math/big"

	"github.com/serengil/lightphe-go/lightphe/ecc/curves"
)

// Errors reported by this package.
var (
	// ErrPointNotOnCurve reports coordinates that do not satisfy the curve
	// equation.
	ErrPointNotOnCurve = errors.New("ecc: point is not on the curve")

	// ErrInvalidCurveOrder reports a curve whose declared order n does not
	// annihilate the base point.
	ErrInvalidCurveOrder = errors.New("ecc: invalid curve order")

	// ErrDifferentCurves reports an attempt to combine points from two curves.
	ErrDifferentCurves = errors.New("ecc: points are not on the same curve")

	// ErrNotSupported reports an operation the selected curve form cannot do.
	ErrNotSupported = errors.New("ecc: operation is not supported for this curve form")
)

// Curve is the arithmetic backend for a single elliptic curve. Implementations
// are immutable.
type Curve interface {
	// Name is the curve identifier, for example "secp256k1".
	Name() string

	// Form reports which equation shape the curve uses.
	Form() curves.Form

	// Modulo is the field modulus: the prime p for prime fields, or the
	// reduction polynomial packed into an integer for binary fields.
	Modulo() *big.Int

	// Order is the order n of the base point.
	Order() *big.Int

	// A returns the first equation coefficient.
	A() *big.Int

	// B returns the second Weierstrass or Koblitz coefficient.
	B() *big.Int

	// D returns the twisted Edwards coefficient.
	D() *big.Int

	// Identity returns the neutral element: the point at infinity for
	// Weierstrass and Koblitz curves, (0, 1) for Edwards curves.
	Identity() Point

	// Base returns the generator G.
	Base() Point

	// IsOnCurve reports whether p satisfies the curve equation.
	IsOnCurve(p Point) bool

	// Add returns p + q.
	Add(p, q Point) (Point, error)

	// Double returns 2p.
	Double(p Point) (Point, error)

	// Negate returns -p.
	Negate(p Point) Point
}

// Point is an affine point on a curve. The zero Point is not usable; obtain
// points from a Curve or from NewPoint.
type Point struct {
	X, Y     *big.Int
	Infinity bool

	curve Curve
}

// NewPoint validates the coordinates against the curve and returns the point.
func NewPoint(curve Curve, x, y *big.Int) (Point, error) {
	p := Point{X: new(big.Int).Set(x), Y: new(big.Int).Set(y), curve: curve}
	if !curve.IsOnCurve(p) {
		return Point{}, fmt.Errorf("ecc: (%s, %s) is not on curve %s: %w", x, y, curve.Name(), ErrPointNotOnCurve)
	}
	return p, nil
}

// Curve returns the curve the point belongs to.
func (p Point) Curve() Curve { return p.curve }

// IsIdentity reports whether p is the neutral element of its curve.
func (p Point) IsIdentity() bool {
	if p.curve == nil {
		return p.Infinity
	}
	return p.Equal(p.curve.Identity())
}

// Equal reports whether two points have the same coordinates. Points on
// different curves are never equal.
func (p Point) Equal(q Point) bool {
	if p.curve != nil && q.curve != nil && !sameCurve(p.curve, q.curve) {
		return false
	}
	if p.Infinity || q.Infinity {
		return p.Infinity == q.Infinity
	}
	return p.X.Cmp(q.X) == 0 && p.Y.Cmp(q.Y) == 0
}

// Add returns p + q.
func (p Point) Add(q Point) (Point, error) {
	if !sameCurve(p.curve, q.curve) {
		return Point{}, ErrDifferentCurves
	}
	return p.curve.Add(p, q)
}

// Sub returns p - q.
func (p Point) Sub(q Point) (Point, error) { return p.Add(q.Negate()) }

// Negate returns -p.
func (p Point) Negate() Point { return p.curve.Negate(p) }

// Double returns 2p.
func (p Point) Double() (Point, error) { return p.curve.Double(p) }

// ScalarMul returns k*p, computed with left-to-right double-and-add. Negative
// scalars are handled by negating the result; scalars are first reduced modulo
// the curve order.
func (p Point) ScalarMul(k *big.Int) (Point, error) {
	curve := p.curve
	scalar := new(big.Int).Set(k)

	if n := curve.Order(); n != nil && n.Sign() > 0 {
		if scalar.CmpAbs(n) >= 0 {
			scalar.Mod(scalar, n)
		}
	}
	if scalar.Sign() == 0 {
		return curve.Identity(), nil
	}
	if scalar.Sign() < 0 {
		res, err := p.ScalarMul(scalar.Neg(scalar))
		if err != nil {
			return Point{}, err
		}
		return res.Negate(), nil
	}

	acc := p
	var err error
	for i := scalar.BitLen() - 2; i >= 0; i-- {
		acc, err = curve.Double(acc)
		if err != nil {
			return Point{}, err
		}
		if scalar.Bit(i) == 1 {
			acc, err = curve.Add(acc, p)
			if err != nil {
				return Point{}, err
			}
		}
	}
	return acc, nil
}

// String implements fmt.Stringer.
func (p Point) String() string {
	if p.Infinity {
		return "O"
	}
	return fmt.Sprintf("(%s, %s)", p.X, p.Y)
}

// Coordinates returns the affine coordinates of the point.
func (p Point) Coordinates() (x, y *big.Int) {
	if p.Infinity {
		return nil, nil
	}
	return new(big.Int).Set(p.X), new(big.Int).Set(p.Y)
}

// sameCurve compares two curves by their defining parameters rather than by
// pointer identity, so that a point keeps working after its curve has been
// rebuilt from the same configuration.
func sameCurve(a, b Curve) bool {
	if a == nil || b == nil {
		return a == b
	}
	if a == b {
		return true
	}
	if a.Form() != b.Form() {
		return false
	}
	return a.Modulo().Cmp(b.Modulo()) == 0 &&
		cmpNilable(a.Order(), b.Order()) &&
		a.A().Cmp(b.A()) == 0 &&
		a.B().Cmp(b.B()) == 0 &&
		a.D().Cmp(b.D()) == 0
}

func cmpNilable(a, b *big.Int) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return a.Cmp(b) == 0
}

// DiscreteLog recovers k from target = k*base by exhaustive search. This is the
// hard problem the security of every elliptic curve scheme rests on; it is only
// tractable here because homomorphic schemes keep their plaintexts small.
// The search gives up after limit steps.
func DiscreteLog(target, base Point, limit *big.Int) (*big.Int, error) {
	if target.IsIdentity() {
		return new(big.Int), nil
	}
	if target.Equal(base) {
		return big.NewInt(1), nil
	}

	acc := base
	k := big.NewInt(1)
	one := big.NewInt(1)
	var err error
	for {
		k.Add(k, one)
		if limit != nil && k.Cmp(limit) > 0 {
			return nil, fmt.Errorf("ecc: could not recover the scalar behind %s within %s steps", target, limit)
		}
		acc, err = acc.Add(base)
		if err != nil {
			return nil, err
		}
		if acc.Equal(target) {
			return new(big.Int).Set(k), nil
		}
		if acc.IsIdentity() {
			return nil, fmt.Errorf("ecc: could not recover the scalar behind %s: the subgroup was exhausted", target)
		}
	}
}
