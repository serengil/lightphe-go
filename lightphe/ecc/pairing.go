package ecc

import (
	"fmt"
	"math/big"

	"github.com/serengil/lightphe-go/lightphe/ecc/curves"
)

// Pairings computed with Miller's algorithm on short Weierstrass curves.
//
// Two flavours are implemented:
//
//   - the Weil pairing over F_p, for curves whose full r-torsion already lives
//     in E(F_p);
//   - the modified Tate pairing over F_{p^2} with the distortion map
//     phi(x, y) = (-x, i*y), for supersingular curves y^2 = x^3 + a*x with
//     embedding degree 2. This is the flavour Boneh-Goh-Nissim needs.
//
// The pairing e_r(P, Q) maps two r-torsion points to an r-th root of unity and
// is bilinear: e(aP, bQ) = e(P, Q)^(ab).
//
// Reference: Washington, Elliptic Curves: Number Theory and Cryptography, ch. 11.

// PairingResult carries the outcome of a pairing computation. Supersingular
// curves with embedding degree 2 land in the quadratic extension and set
// Extended; every other curve returns a base field element.
type PairingResult struct {
	Base     *big.Int
	Extended bool
	Value    FP2
}

// IsSupersingularEmbedding2 reports whether the curve is y^2 = x^3 + a*x with
// a != 0 over a field with p = 3 (mod 4). Such curves are supersingular with
// embedding degree 2.
func IsSupersingularEmbedding2(c Curve) bool {
	if c.Form() != curves.FormWeierstrass {
		return false
	}
	if c.B().Sign() != 0 || c.A().Sign() == 0 {
		return false
	}
	return new(big.Int).Mod(c.Modulo(), big.NewInt(4)).Cmp(big.NewInt(3)) == 0
}

// Pairing computes e_r(p, q) for the torsion order r, dispatching between the
// Weil and the modified Tate pairing based on the curve.
func Pairing(p, q Point, r *big.Int) (PairingResult, error) {
	curve := p.Curve()
	if curve.Form() != curves.FormWeierstrass {
		return PairingResult{}, fmt.Errorf("ecc: pairings need a weierstrass curve: %w", ErrNotSupported)
	}
	if !sameCurve(curve, q.Curve()) {
		return PairingResult{}, ErrDifferentCurves
	}
	if p.IsIdentity() || q.IsIdentity() {
		return PairingResult{Base: big.NewInt(1)}, nil
	}

	modulus := curve.Modulo()

	// When r divides p-1 the full r-torsion is already rational over F_p and
	// the plain Weil pairing suffices, so only take the extension path when it
	// does not.
	pMinusOne := new(big.Int).Sub(modulus, big.NewInt(1))
	if IsSupersingularEmbedding2(curve) && new(big.Int).Mod(pMinusOne, r).Sign() != 0 {
		// P == Q is allowed here: the distortion map moves Q off the subgroup
		// spanned by P, so e(P, phi(P)) stays non-degenerate.
		if err := requireTorsion(p, r, "P"); err != nil {
			return PairingResult{}, err
		}
		if !p.Equal(q) {
			if err := requireTorsion(q, r, "Q"); err != nil {
				return PairingResult{}, err
			}
		}
		value, err := tatePairingSupersingular(p, q, r)
		if err != nil {
			return PairingResult{}, err
		}
		return PairingResult{Extended: true, Value: value}, nil
	}

	if p.Equal(q) {
		// The Weil pairing is alternating.
		return PairingResult{Base: big.NewInt(1)}, nil
	}
	if err := requireTorsion(p, r, "P"); err != nil {
		return PairingResult{}, err
	}
	if err := requireTorsion(q, r, "Q"); err != nil {
		return PairingResult{}, err
	}

	value, err := weilPairing(p, q, r)
	if err != nil {
		return PairingResult{}, err
	}
	return PairingResult{Base: value}, nil
}

func requireTorsion(p Point, r *big.Int, label string) error {
	rp, err := p.ScalarMul(r)
	if err != nil {
		return err
	}
	if !rp.IsIdentity() {
		return fmt.Errorf("ecc: %s = %s is not an %s-torsion point", label, p, r)
	}
	return nil
}

// ---------------------------------------------------------------------------
// Weil pairing over F_p
// ---------------------------------------------------------------------------

// lineEval evaluates the Miller line function g_{T,P}(R) = l_{T,P}(R) /
// v_{T+P}(R) in F_p.
func lineEval(t, p, r Point) (*big.Int, error) {
	if t.IsIdentity() || p.IsIdentity() || r.IsIdentity() {
		return big.NewInt(1), nil
	}
	curve := t.Curve()
	modulus := curve.Modulo()

	sum, err := t.Add(p)
	if err != nil {
		return nil, err
	}
	if sum.IsIdentity() {
		// Vertical line through T.
		v := new(big.Int).Sub(r.X, t.X)
		return v.Mod(v, modulus), nil
	}

	lambda, err := slope(t, p)
	if err != nil {
		return nil, err
	}

	// numerator = yR - yT - lambda*(xR - xT)
	num := new(big.Int).Sub(r.X, t.X)
	num.Mul(num, lambda)
	num.Sub(new(big.Int).Sub(r.Y, t.Y), num)
	num.Mod(num, modulus)

	// denominator = xR - x_{T+P}
	den := new(big.Int).Sub(r.X, sum.X)
	den.Mod(den, modulus)
	if den.Sign() == 0 {
		if num.Sign() != 0 {
			return num, nil
		}
		return big.NewInt(1), nil
	}

	inv := new(big.Int).ModInverse(den, modulus)
	if inv == nil {
		return nil, fmt.Errorf("ecc: cannot invert %s modulo %s during pairing", den, modulus)
	}
	return num.Mul(num, inv).Mod(num, modulus), nil
}

// slope returns the slope of the chord through t and p, or of the tangent at t
// when the two points coincide.
func slope(t, p Point) (*big.Int, error) {
	curve := t.Curve()
	modulus := curve.Modulo()

	var num, den *big.Int
	if t.Equal(p) {
		num = new(big.Int).Mul(t.X, t.X)
		num.Mul(num, big.NewInt(3))
		num.Add(num, curve.A())
		den = new(big.Int).Lsh(t.Y, 1)
	} else {
		num = new(big.Int).Sub(p.Y, t.Y)
		den = new(big.Int).Sub(p.X, t.X)
	}
	inv := new(big.Int).ModInverse(den.Mod(den, modulus), modulus)
	if inv == nil {
		return nil, fmt.Errorf("ecc: cannot invert %s modulo %s during pairing", den, modulus)
	}
	return num.Mul(num, inv).Mod(num, modulus), nil
}

// miller computes f_{r,P}(R) over F_p.
func miller(p, r Point, order *big.Int) (*big.Int, error) {
	if p.IsIdentity() || r.IsIdentity() {
		return big.NewInt(1), nil
	}
	modulus := p.Curve().Modulo()

	f := big.NewInt(1)
	t := p

	for i := order.BitLen() - 2; i >= 0; i-- {
		if t.IsIdentity() {
			f.Mul(f, f).Mod(f, modulus)
		} else {
			g, err := lineEval(t, t, r)
			if err != nil {
				return nil, err
			}
			f.Mul(f, f)
			f.Mul(f, g)
			f.Mod(f, modulus)
			doubled, err := t.Add(t)
			if err != nil {
				return nil, err
			}
			t = doubled
		}

		if order.Bit(i) == 1 {
			if t.IsIdentity() {
				t = p
			} else {
				g, err := lineEval(t, p, r)
				if err != nil {
					return nil, err
				}
				f.Mul(f, g).Mod(f, modulus)
				sum, err := t.Add(p)
				if err != nil {
					return nil, err
				}
				t = sum
			}
		}
	}
	return f.Mod(f, modulus), nil
}

// auxiliaryPoint picks a point S that avoids the degenerate cases of the Weil
// pairing computation.
func auxiliaryPoint(p, q Point) (Point, error) {
	curve := p.Curve()
	g := curve.Base()

	pMinusQ, err := p.Sub(q)
	if err != nil {
		return Point{}, err
	}
	qMinusP, err := q.Sub(p)
	if err != nil {
		return Point{}, err
	}
	pPlusQ, err := p.Add(q)
	if err != nil {
		return Point{}, err
	}
	bad := []Point{p, p.Negate(), q, q.Negate(), pMinusQ, qMinusP, pPlusQ}

	limit := 1000
	if n := curve.Order(); n != nil && n.IsInt64() && n.Int64() < int64(limit) {
		limit = int(n.Int64())
	}

	s := curve.Identity()
	for k := 1; k < limit; k++ {
		s, err = s.Add(g)
		if err != nil {
			return Point{}, err
		}
		if s.IsIdentity() {
			continue
		}
		degenerate := false
		for _, b := range bad {
			if s.Equal(b) {
				degenerate = true
				break
			}
		}
		if degenerate {
			continue
		}
		qPlusS, err := q.Add(s)
		if err != nil {
			return Point{}, err
		}
		pMinusS, err := p.Sub(s)
		if err != nil {
			return Point{}, err
		}
		if qPlusS.IsIdentity() || pMinusS.IsIdentity() {
			continue
		}
		return s, nil
	}
	return Point{}, fmt.Errorf("ecc: no suitable auxiliary point for the Weil pairing on %s", curve.Name())
}

// weilPairing computes the standard Weil pairing over F_p.
func weilPairing(p, q Point, r *big.Int) (*big.Int, error) {
	modulus := p.Curve().Modulo()

	s, err := auxiliaryPoint(p, q)
	if err != nil {
		return nil, err
	}
	negS := s.Negate()
	qPlusS, err := q.Add(s)
	if err != nil {
		return nil, err
	}
	pMinusS, err := p.Sub(s)
	if err != nil {
		return nil, err
	}

	fpQpS, err := miller(p, qPlusS, r)
	if err != nil {
		return nil, err
	}
	fpS, err := miller(p, s, r)
	if err != nil {
		return nil, err
	}
	fqPmS, err := miller(q, pMinusS, r)
	if err != nil {
		return nil, err
	}
	fqNegS, err := miller(q, negS, r)
	if err != nil {
		return nil, err
	}

	if fpS.Sign() == 0 || fqPmS.Sign() == 0 {
		return nil, fmt.Errorf("ecc: degenerate Weil pairing, try different input points")
	}

	num := new(big.Int).Mul(fpQpS, fqNegS)
	num.Mod(num, modulus)
	den := new(big.Int).Mul(fpS, fqPmS)
	den.Mod(den, modulus)
	inv := new(big.Int).ModInverse(den, modulus)
	if inv == nil {
		return nil, fmt.Errorf("ecc: degenerate Weil pairing, denominator is not invertible")
	}
	return num.Mul(num, inv).Mod(num, modulus), nil
}

// ---------------------------------------------------------------------------
// Modified Tate pairing over F_{p^2}
// ---------------------------------------------------------------------------

// lineEvalFP2 evaluates the Miller line function at a point whose coordinates
// live in F_{p^2}.
func lineEvalFP2(t, p Point, xr, yr FP2) (FP2, error) {
	if t.IsIdentity() || p.IsIdentity() {
		return FP2One(), nil
	}
	modulus := t.Curve().Modulo()

	sum, err := t.Add(p)
	if err != nil {
		return FP2{}, err
	}
	if sum.IsIdentity() {
		return xr.Sub(FromBase(t.X), modulus), nil
	}

	lambda, err := slope(t, p)
	if err != nil {
		return FP2{}, err
	}

	// numerator = yR - yT - lambda*(xR - xT)
	num := yr.Sub(FromBase(t.Y), modulus).
		Sub(FromBase(lambda).Mul(xr.Sub(FromBase(t.X), modulus), modulus), modulus)

	den := xr.Sub(FromBase(sum.X), modulus)
	if den.IsZero() {
		if !num.IsZero() {
			return num, nil
		}
		return FP2One(), nil
	}
	inv, err := den.Inverse(modulus)
	if err != nil {
		return FP2{}, err
	}
	return num.Mul(inv, modulus), nil
}

// millerFP2 computes f_{r,P}(R) where R has coordinates in F_{p^2}.
func millerFP2(p Point, xr, yr FP2, r *big.Int) (FP2, error) {
	if p.IsIdentity() {
		return FP2One(), nil
	}
	modulus := p.Curve().Modulo()

	f := FP2One()
	t := p

	for i := r.BitLen() - 2; i >= 0; i-- {
		if t.IsIdentity() {
			f = f.Mul(f, modulus)
		} else {
			g, err := lineEvalFP2(t, t, xr, yr)
			if err != nil {
				return FP2{}, err
			}
			f = f.Mul(f, modulus).Mul(g, modulus)
			doubled, err := t.Add(t)
			if err != nil {
				return FP2{}, err
			}
			t = doubled
		}

		if r.Bit(i) == 1 {
			if t.IsIdentity() {
				t = p
			} else {
				g, err := lineEvalFP2(t, p, xr, yr)
				if err != nil {
					return FP2{}, err
				}
				f = f.Mul(g, modulus)
				sum, err := t.Add(p)
				if err != nil {
					return FP2{}, err
				}
				t = sum
			}
		}
	}
	return f, nil
}

// tatePairingSupersingular computes e_r(P, Q) = f_{r,P}(phi(Q))^((p^2-1)/r) for
// a supersingular curve with the distortion map phi(x, y) = (-x, i*y).
func tatePairingSupersingular(p, q Point, r *big.Int) (FP2, error) {
	modulus := p.Curve().Modulo()

	// phi(Q) = (-x_Q, i*y_Q)
	negX := new(big.Int).Neg(q.X)
	negX.Mod(negX, modulus)
	xPhi := FP2{A: negX, B: new(big.Int)}
	yPhi := FP2{A: new(big.Int), B: new(big.Int).Mod(q.Y, modulus)}

	f, err := millerFP2(p, xPhi, yPhi, r)
	if err != nil {
		return FP2{}, err
	}

	// Final exponentiation with (p^2 - 1) / r.
	exp := new(big.Int).Mul(modulus, modulus)
	exp.Sub(exp, big.NewInt(1))
	exp.Div(exp, r)
	return f.Exp(exp, modulus)
}
