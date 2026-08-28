package ecc

import (
	"fmt"
	"math/big"

	"github.com/serengil/lightphe-go/lightphe/ecc/curves"
)

// koblitz implements y^2 + x*y = x^3 + a*x^2 + b over the binary field
// F_{2^m}. Field elements are polynomials packed into big.Ints and reduced
// modulo the irreducible polynomial derived from the curve's coefficient list.
type koblitz struct {
	name         string
	m            int
	coefficients []int
	a, b         *big.Int
	modulo       *big.Int
	gx, gy       *big.Int
	n            *big.Int
}

// NewKoblitz builds a named Koblitz curve from the inventory.
func NewKoblitz(name string) (Curve, error) {
	if name == "" {
		name = curves.DefaultKoblitzCurve
	}
	params, err := curves.LookupKoblitz(name)
	if err != nil {
		return nil, err
	}

	// The reduction polynomial has a set bit at every listed exponent.
	modulo := new(big.Int)
	for _, exp := range params.Coefficients {
		modulo.SetBit(modulo, exp, 1)
	}

	c := &koblitz{
		name:         params.Name,
		m:            params.M,
		coefficients: params.Coefficients,
		a:            params.A,
		b:            params.B,
		modulo:       modulo,
		gx:           params.Gx,
		gy:           params.Gy,
		n:            params.N,
	}
	if !c.IsOnCurve(c.Base()) {
		return nil, fmt.Errorf("ecc: base point of %s is off the curve: %w", params.Name, ErrPointNotOnCurve)
	}
	return c, nil
}

func (c *koblitz) Name() string      { return c.name }
func (c *koblitz) Form() curves.Form { return curves.FormKoblitz }
func (c *koblitz) Modulo() *big.Int  { return new(big.Int).Set(c.modulo) }
func (c *koblitz) Order() *big.Int   { return new(big.Int).Set(c.n) }
func (c *koblitz) A() *big.Int       { return new(big.Int).Set(c.a) }
func (c *koblitz) B() *big.Int       { return new(big.Int).Set(c.b) }
func (c *koblitz) D() *big.Int       { return new(big.Int) }
func (c *koblitz) Identity() Point   { return Point{Infinity: true, curve: c} }
func (c *koblitz) Base() Point       { return Point{X: c.gx, Y: c.gy, curve: c} }

// IsOnCurve implements Curve.
func (c *koblitz) IsOnCurve(p Point) bool {
	if p.Infinity {
		return true
	}
	if p.X == nil || p.Y == nil {
		return false
	}
	lhs := binMod(binAdd(binSquare(p.Y), binMul(p.X, p.Y)), c.modulo)
	rhs := binMod(
		binAdd(binAdd(binExp(p.X, 3, c.modulo), binMul(c.a, binSquare(p.X))), c.b),
		c.modulo,
	)
	return lhs.Cmp(rhs) == 0
}

// Add implements Curve.
func (c *koblitz) Add(p, q Point) (Point, error) {
	switch {
	case p.Infinity:
		return q, nil
	case q.Infinity:
		return p, nil
	case p.Equal(c.Negate(q)):
		return c.Identity(), nil
	case p.Equal(q):
		return c.Double(p)
	case p.X.Cmp(q.X) == 0:
		return c.Identity(), nil
	}

	// beta = (y1 + y2) / (x1 + x2), where + is XOR
	beta := binDivide(binAdd(p.Y, q.Y), binAdd(p.X, q.X), c.modulo)
	if beta == nil {
		return Point{}, fmt.Errorf("ecc: cannot invert the slope denominator on curve %s", c.name)
	}

	// x3 = beta^2 + beta + x1 + x2 + a
	x3 := binAdd(binAdd(binAdd(binAdd(binSquare(beta), beta), p.X), q.X), c.a)
	// y3 = beta*(x1 + x3) + x3 + y1
	y3 := binAdd(binAdd(binMul(binAdd(p.X, x3), beta), x3), p.Y)

	return Point{X: binMod(x3, c.modulo), Y: binMod(y3, c.modulo), curve: c}, nil
}

// Double implements Curve.
func (c *koblitz) Double(p Point) (Point, error) {
	if p.Infinity || p.X.Sign() == 0 {
		return c.Identity(), nil
	}
	if p.Equal(c.Negate(p)) {
		return c.Identity(), nil
	}

	// beta = x1 + y1/x1
	quotient := binDivide(p.Y, p.X, c.modulo)
	if quotient == nil {
		return Point{}, fmt.Errorf("ecc: cannot invert %s on curve %s", p.X, c.name)
	}
	beta := binAdd(p.X, quotient)

	// x2 = beta^2 + beta + a
	x2 := binAdd(binAdd(binSquare(beta), beta), c.a)
	// y2 = x1^2 + beta*x2 + x2
	y2 := binAdd(binAdd(binSquare(p.X), binMul(beta, x2)), x2)

	return Point{X: binMod(x2, c.modulo), Y: binMod(y2, c.modulo), curve: c}, nil
}

// Negate implements Curve. Over a binary field -y is x XOR y.
func (c *koblitz) Negate(p Point) Point {
	if p.Infinity {
		return p
	}
	return Point{X: new(big.Int).Set(p.X), Y: binAdd(p.X, p.Y), curve: c}
}
