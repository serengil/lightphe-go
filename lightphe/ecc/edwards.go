package ecc

import (
	"fmt"
	"math/big"

	"github.com/serengil/lightphe-go/lightphe/ecc/curves"
)

// twistedEdwards implements a*x^2 + y^2 = 1 + d*x^2*y^2 over the prime field
// F_p. Unlike the Weierstrass form the addition law is complete, so there is no
// special case for doubling or for the neutral element (0, 1).
type twistedEdwards struct {
	name string
	a, d *big.Int
	p    *big.Int
	gx   *big.Int
	gy   *big.Int
	n    *big.Int
}

// NewEdwards builds a named twisted Edwards curve from the inventory.
func NewEdwards(name string) (Curve, error) {
	if name == "" {
		name = curves.DefaultEdwardsCurve
	}
	params, err := curves.LookupEdwards(name)
	if err != nil {
		return nil, err
	}
	return &twistedEdwards{
		name: params.Name,
		a:    params.A,
		d:    params.D,
		p:    params.P,
		gx:   params.Gx,
		gy:   params.Gy,
		n:    params.N,
	}, nil
}

func (c *twistedEdwards) Name() string      { return c.name }
func (c *twistedEdwards) Form() curves.Form { return curves.FormEdwards }
func (c *twistedEdwards) Modulo() *big.Int  { return new(big.Int).Set(c.p) }
func (c *twistedEdwards) Order() *big.Int   { return new(big.Int).Set(c.n) }
func (c *twistedEdwards) A() *big.Int       { return new(big.Int).Set(c.a) }
func (c *twistedEdwards) B() *big.Int       { return new(big.Int) }
func (c *twistedEdwards) D() *big.Int       { return new(big.Int).Set(c.d) }
func (c *twistedEdwards) Base() Point       { return Point{X: c.gx, Y: c.gy, curve: c} }

// Identity implements Curve. Edwards curves have a neutral element on the curve
// itself rather than a point at infinity.
func (c *twistedEdwards) Identity() Point {
	return Point{X: new(big.Int), Y: big.NewInt(1), curve: c}
}

// IsOnCurve implements Curve.
func (c *twistedEdwards) IsOnCurve(p Point) bool {
	if p.X == nil || p.Y == nil {
		return false
	}
	x2 := new(big.Int).Mul(p.X, p.X)
	y2 := new(big.Int).Mul(p.Y, p.Y)

	lhs := new(big.Int).Mul(c.a, x2)
	lhs.Add(lhs, y2)
	lhs.Mod(lhs, c.p)

	rhs := new(big.Int).Mul(c.d, x2)
	rhs.Mul(rhs, y2)
	rhs.Add(rhs, big.NewInt(1))
	rhs.Mod(rhs, c.p)

	return lhs.Cmp(rhs) == 0
}

// Add implements Curve using the complete twisted Edwards addition law:
//
//	x3 = (x1*y2 + y1*x2) / (1 + d*x1*x2*y1*y2)
//	y3 = (y1*y2 - a*x1*x2) / (1 - d*x1*x2*y1*y2)
func (c *twistedEdwards) Add(p, q Point) (Point, error) {
	// common = d * x1 * x2 * y1 * y2
	common := new(big.Int).Mul(c.d, p.X)
	common.Mul(common, q.X)
	common.Mul(common, p.Y)
	common.Mul(common, q.Y)

	numX := new(big.Int).Mul(p.X, q.Y)
	numX.Add(numX, new(big.Int).Mul(p.Y, q.X))
	numX.Mod(numX, c.p)

	denX := new(big.Int).Add(big.NewInt(1), common)
	invX := new(big.Int).ModInverse(denX.Mod(denX, c.p), c.p)
	if invX == nil {
		return Point{}, fmt.Errorf("ecc: cannot invert the x denominator on curve %s", c.name)
	}

	numY := new(big.Int).Mul(p.Y, q.Y)
	numY.Sub(numY, new(big.Int).Mul(c.a, new(big.Int).Mul(p.X, q.X)))
	numY.Mod(numY, c.p)

	denY := new(big.Int).Sub(big.NewInt(1), common)
	invY := new(big.Int).ModInverse(denY.Mod(denY, c.p), c.p)
	if invY == nil {
		return Point{}, fmt.Errorf("ecc: cannot invert the y denominator on curve %s", c.name)
	}

	x3 := numX.Mul(numX, invX)
	x3.Mod(x3, c.p)
	y3 := numY.Mul(numY, invY)
	y3.Mod(y3, c.p)

	return Point{X: x3, Y: y3, curve: c}, nil
}

// Double implements Curve. The addition law is complete, so doubling is just
// addition with equal operands.
func (c *twistedEdwards) Double(p Point) (Point, error) { return c.Add(p, p) }

// Negate implements Curve.
func (c *twistedEdwards) Negate(p Point) Point {
	x := new(big.Int).Neg(p.X)
	x.Mod(x, c.p)
	return Point{X: x, Y: new(big.Int).Set(p.Y), curve: c}
}
