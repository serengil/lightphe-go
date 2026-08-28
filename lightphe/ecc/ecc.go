package ecc

import (
	"fmt"
	"math/big"

	"github.com/serengil/lightphe-go/lightphe/ecc/curves"
)

// ECC bundles a curve with its base point, neutral element and order. It is the
// entry point cryptosystems use; construct one with New or NewFromCurve.
//
// An ECC is immutable and safe for concurrent use.
type ECC struct {
	curve  Curve
	g      Point
	o      Point
	n      *big.Int
	modulo *big.Int
}

// New builds a curve of the given form. An empty form defaults to Weierstrass
// and an empty curve name defaults to that form's standard curve.
func New(form curves.Form, curveName string) (*ECC, error) {
	if form == "" {
		form = curves.FormWeierstrass
	}

	var (
		curve Curve
		err   error
	)
	switch form {
	case curves.FormWeierstrass:
		curve, err = NewWeierstrass(curveName)
	case curves.FormEdwards:
		curve, err = NewEdwards(curveName)
	case curves.FormKoblitz:
		curve, err = NewKoblitz(curveName)
	default:
		return nil, fmt.Errorf("ecc: unsupported curve form %q", form)
	}
	if err != nil {
		return nil, err
	}
	return NewFromCurve(curve)
}

// NewFromCurve wraps an already built curve and validates its declared order.
func NewFromCurve(curve Curve) (*ECC, error) {
	e := &ECC{
		curve:  curve,
		g:      curve.Base(),
		o:      curve.Identity(),
		n:      curve.Order(),
		modulo: curve.Modulo(),
	}

	if !curve.IsOnCurve(e.g) {
		return nil, fmt.Errorf("ecc: base point %s is off curve %s: %w", e.g, curve.Name(), ErrPointNotOnCurve)
	}

	// Validate n by computing (n-1)*G + G rather than n*G: scalar
	// multiplication short-circuits to the neutral element whenever the scalar
	// equals the declared order, which would make the check vacuous.
	if e.n != nil && e.n.Sign() > 0 {
		nMinusOne := new(big.Int).Sub(e.n, big.NewInt(1))
		partial, err := e.g.ScalarMul(nMinusOne)
		if err != nil {
			return nil, err
		}
		total, err := partial.Add(e.g)
		if err != nil {
			return nil, err
		}
		if !total.IsIdentity() {
			return nil, fmt.Errorf("ecc: n*G is not the identity element on curve %s: %w", curve.Name(), ErrInvalidCurveOrder)
		}
	}

	return e, nil
}

// NewCustomWeierstrassECC builds and validates a custom short Weierstrass
// curve in one step.
func NewCustomWeierstrassECC(a, b, p, gx, gy, n *big.Int) (*ECC, error) {
	curve, err := NewCustomWeierstrass(a, b, p, gx, gy, n)
	if err != nil {
		return nil, err
	}
	return NewFromCurve(curve)
}

// Curve returns the underlying curve.
func (e *ECC) Curve() Curve { return e.curve }

// G returns the base point.
func (e *ECC) G() Point { return e.g }

// O returns the neutral element.
func (e *ECC) O() Point { return e.o }

// N returns the order of the base point.
func (e *ECC) N() *big.Int { return new(big.Int).Set(e.n) }

// Modulo returns the field modulus.
func (e *ECC) Modulo() *big.Int { return new(big.Int).Set(e.modulo) }

// Form reports the curve form.
func (e *ECC) Form() curves.Form { return e.curve.Form() }

// Name reports the curve name.
func (e *ECC) Name() string { return e.curve.Name() }

// Point validates the coordinates and returns the corresponding curve point.
func (e *ECC) Point(x, y *big.Int) (Point, error) { return NewPoint(e.curve, x, y) }

// Pairing computes e_n(p, q) with the curve order as the torsion order.
func (e *ECC) Pairing(p, q Point) (PairingResult, error) { return Pairing(p, q, e.n) }

// PairingWithOrder computes e_r(p, q) for an explicit torsion order r.
func (e *ECC) PairingWithOrder(p, q Point, r *big.Int) (PairingResult, error) {
	return Pairing(p, q, r)
}
