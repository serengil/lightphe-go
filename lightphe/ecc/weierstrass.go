package ecc

import (
	"fmt"
	"math/big"

	"github.com/serengil/lightphe-go/lightphe/ecc/curves"
)

// weierstrass implements y^2 = x^3 + a*x + b over the prime field F_p.
type weierstrass struct {
	name string
	a, b *big.Int
	p    *big.Int
	gx   *big.Int
	gy   *big.Int
	n    *big.Int
}

// NewWeierstrass builds a named short Weierstrass curve from the inventory.
func NewWeierstrass(name string) (Curve, error) {
	if name == "" {
		name = curves.DefaultWeierstrassCurve
	}
	params, err := curves.LookupWeierstrass(name)
	if err != nil {
		return nil, err
	}
	return &weierstrass{
		name: params.Name,
		a:    params.A,
		b:    params.B,
		p:    params.P,
		gx:   params.Gx,
		gy:   params.Gy,
		n:    params.N,
	}, nil
}

// NewCustomWeierstrass builds a short Weierstrass curve from explicit
// parameters. It is used by Boneh-Goh-Nissim, which generates a fresh
// supersingular curve for every key pair.
func NewCustomWeierstrass(a, b, p, gx, gy, n *big.Int) (Curve, error) {
	if p == nil || p.Sign() <= 0 {
		return nil, fmt.Errorf("ecc: custom weierstrass curve needs a positive modulus")
	}
	return &weierstrass{
		name: "custom",
		a:    new(big.Int).Mod(a, p),
		b:    new(big.Int).Mod(b, p),
		p:    new(big.Int).Set(p),
		gx:   new(big.Int).Mod(gx, p),
		gy:   new(big.Int).Mod(gy, p),
		n:    new(big.Int).Set(n),
	}, nil
}

func (c *weierstrass) Name() string      { return c.name }
func (c *weierstrass) Form() curves.Form { return curves.FormWeierstrass }
func (c *weierstrass) Modulo() *big.Int  { return new(big.Int).Set(c.p) }
func (c *weierstrass) Order() *big.Int   { return new(big.Int).Set(c.n) }
func (c *weierstrass) A() *big.Int       { return new(big.Int).Set(c.a) }
func (c *weierstrass) B() *big.Int       { return new(big.Int).Set(c.b) }
func (c *weierstrass) D() *big.Int       { return new(big.Int) }
func (c *weierstrass) Identity() Point   { return Point{Infinity: true, curve: c} }
func (c *weierstrass) Base() Point       { return Point{X: c.gx, Y: c.gy, curve: c} }

// IsOnCurve implements Curve.
func (c *weierstrass) IsOnCurve(p Point) bool {
	if p.Infinity {
		return true
	}
	if p.X == nil || p.Y == nil {
		return false
	}
	lhs := new(big.Int).Mul(p.Y, p.Y)
	lhs.Mod(lhs, c.p)

	rhs := new(big.Int).Exp(p.X, big.NewInt(3), c.p)
	rhs.Add(rhs, new(big.Int).Mul(c.a, p.X))
	rhs.Add(rhs, c.b)
	rhs.Mod(rhs, c.p)

	return lhs.Cmp(rhs) == 0
}

// Add implements Curve.
func (c *weierstrass) Add(p, q Point) (Point, error) {
	switch {
	case p.Infinity:
		return q, nil
	case q.Infinity:
		return p, nil
	case p.Equal(c.Negate(q)):
		return c.Identity(), nil
	case p.Equal(q):
		return c.Double(p)
	}

	// beta = (y2 - y1) / (x2 - x1)
	dx := new(big.Int).Sub(q.X, p.X)
	inv := new(big.Int).ModInverse(dx.Mod(dx, c.p), c.p)
	if inv == nil {
		return Point{}, fmt.Errorf("ecc: cannot invert %s modulo %s", dx, c.p)
	}
	beta := new(big.Int).Sub(q.Y, p.Y)
	beta.Mul(beta, inv)
	beta.Mod(beta, c.p)

	return c.fromSlope(beta, p, q.X)
}

// Double implements Curve.
func (c *weierstrass) Double(p Point) (Point, error) {
	if p.Infinity || p.Y.Sign() == 0 {
		return c.Identity(), nil
	}

	// beta = (3*x^2 + a) / (2*y)
	den := new(big.Int).Lsh(p.Y, 1)
	inv := new(big.Int).ModInverse(den.Mod(den, c.p), c.p)
	if inv == nil {
		return Point{}, fmt.Errorf("ecc: cannot invert %s modulo %s", den, c.p)
	}
	beta := new(big.Int).Mul(p.X, p.X)
	beta.Mul(beta, big.NewInt(3))
	beta.Add(beta, c.a)
	beta.Mul(beta, inv)
	beta.Mod(beta, c.p)

	return c.fromSlope(beta, p, p.X)
}

// fromSlope finishes a chord or tangent computation:
//
//	x3 = beta^2 - x1 - x2
//	y3 = beta*(x1 - x3) - y1
func (c *weierstrass) fromSlope(beta *big.Int, p Point, x2 *big.Int) (Point, error) {
	x3 := new(big.Int).Mul(beta, beta)
	x3.Sub(x3, p.X)
	x3.Sub(x3, x2)
	x3.Mod(x3, c.p)

	y3 := new(big.Int).Sub(p.X, x3)
	y3.Mul(y3, beta)
	y3.Sub(y3, p.Y)
	y3.Mod(y3, c.p)

	res := Point{X: x3, Y: y3, curve: c}
	if !c.IsOnCurve(res) {
		return Point{}, fmt.Errorf("ecc: computed %s which is off curve %s: %w", res, c.name, ErrPointNotOnCurve)
	}
	return res, nil
}

// Negate implements Curve.
func (c *weierstrass) Negate(p Point) Point {
	if p.Infinity {
		return p
	}
	y := new(big.Int).Neg(p.Y)
	y.Mod(y, c.p)
	return Point{X: new(big.Int).Set(p.X), Y: y, curve: c}
}
