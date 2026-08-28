package ecc

import (
	"errors"
	"fmt"
	"math/big"
)

// ErrDivideByZero reports an attempt to invert the zero element of F_{p^2}.
var ErrDivideByZero = errors.New("ecc: cannot invert zero in F_{p^2}")

// FP2 is an element a + b*i of the quadratic extension F_{p^2}, where i^2 = -1.
// The representation is only valid for p = 3 (mod 4), which is exactly the case
// the supersingular curves used by Boneh-Goh-Nissim satisfy.
type FP2 struct {
	A, B *big.Int
}

// NewFP2 builds an F_{p^2} element from its two coordinates.
func NewFP2(a, b *big.Int) FP2 {
	return FP2{A: new(big.Int).Set(a), B: new(big.Int).Set(b)}
}

// FP2One returns the multiplicative identity 1 + 0*i.
func FP2One() FP2 { return FP2{A: big.NewInt(1), B: new(big.Int)} }

// FP2Zero returns the additive identity.
func FP2Zero() FP2 { return FP2{A: new(big.Int), B: new(big.Int)} }

// FromBase embeds an element of F_p into F_{p^2}.
func FromBase(a *big.Int) FP2 { return FP2{A: new(big.Int).Set(a), B: new(big.Int)} }

// IsZero reports whether f is the additive identity.
func (f FP2) IsZero() bool { return f.A.Sign() == 0 && f.B.Sign() == 0 }

// IsOne reports whether f is the multiplicative identity.
func (f FP2) IsOne() bool { return f.A.Cmp(big.NewInt(1)) == 0 && f.B.Sign() == 0 }

// Equal reports whether two elements are identical.
func (f FP2) Equal(g FP2) bool { return f.A.Cmp(g.A) == 0 && f.B.Cmp(g.B) == 0 }

// String implements fmt.Stringer.
func (f FP2) String() string { return fmt.Sprintf("%s + %s*i", f.A, f.B) }

// Add returns f + g modulo p.
func (f FP2) Add(g FP2, p *big.Int) FP2 {
	return FP2{
		A: new(big.Int).Mod(new(big.Int).Add(f.A, g.A), p),
		B: new(big.Int).Mod(new(big.Int).Add(f.B, g.B), p),
	}
}

// Sub returns f - g modulo p.
func (f FP2) Sub(g FP2, p *big.Int) FP2 {
	return FP2{
		A: new(big.Int).Mod(new(big.Int).Sub(f.A, g.A), p),
		B: new(big.Int).Mod(new(big.Int).Sub(f.B, g.B), p),
	}
}

// Mul returns f * g modulo p: (a+bi)(c+di) = (ac-bd) + (ad+bc)i.
func (f FP2) Mul(g FP2, p *big.Int) FP2 {
	ac := new(big.Int).Mul(f.A, g.A)
	bd := new(big.Int).Mul(f.B, g.B)
	ad := new(big.Int).Mul(f.A, g.B)
	bc := new(big.Int).Mul(f.B, g.A)
	return FP2{
		A: new(big.Int).Mod(ac.Sub(ac, bd), p),
		B: new(big.Int).Mod(ad.Add(ad, bc), p),
	}
}

// Inverse returns f^-1 modulo p: (a+bi)^-1 = (a-bi) / (a^2+b^2).
func (f FP2) Inverse(p *big.Int) (FP2, error) {
	norm := new(big.Int).Mul(f.A, f.A)
	norm.Add(norm, new(big.Int).Mul(f.B, f.B))
	norm.Mod(norm, p)
	if norm.Sign() == 0 {
		return FP2{}, ErrDivideByZero
	}
	inv := new(big.Int).ModInverse(norm, p)
	if inv == nil {
		return FP2{}, ErrDivideByZero
	}
	return FP2{
		A: new(big.Int).Mod(new(big.Int).Mul(f.A, inv), p),
		B: new(big.Int).Mod(new(big.Int).Mul(new(big.Int).Neg(f.B), inv), p),
	}, nil
}

// Exp returns f^n modulo p by square-and-multiply. Negative exponents invert f
// first.
func (f FP2) Exp(n, p *big.Int) (FP2, error) {
	if n.Sign() == 0 {
		return FP2One(), nil
	}
	base := f
	exp := new(big.Int).Set(n)
	if exp.Sign() < 0 {
		var err error
		base, err = f.Inverse(p)
		if err != nil {
			return FP2{}, err
		}
		exp.Neg(exp)
	}

	result := FP2One()
	for i := 0; i < exp.BitLen(); i++ {
		if exp.Bit(i) == 1 {
			result = result.Mul(base, p)
		}
		base = base.Mul(base, p)
	}
	return result, nil
}
