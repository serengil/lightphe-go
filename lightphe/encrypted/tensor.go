package encrypted

import (
	"fmt"

	"github.com/serengil/lightphe-go/lightphe/internal/fixedpoint"
	"github.com/serengil/lightphe-go/lightphe/phe"
)

// Fraction is one element of an encrypted tensor. Real numbers are stored as a
// scaled integer over a scale factor, both encrypted, with the sign kept in the
// clear because no partially homomorphic scheme can recover it.
//
// Dividend and AbsDividend differ only for negative values: the first carries
// the modular representative of the signed value, the second the magnitude.
// Keeping both lets multiplication track signs without ever decrypting.
type Fraction struct {
	Dividend    phe.Value
	AbsDividend phe.Value
	Divisor     phe.Value
	Sign        int
}

// String implements fmt.Stringer.
func (f Fraction) String() string {
	sign := "+"
	if f.Sign == -1 {
		sign = "-"
	}
	return fmt.Sprintf("Fraction(%s%s / %s)", sign, f.AbsDividend, f.Divisor)
}

// Tensor is a vector of encrypted real numbers.
type Tensor struct {
	Fractions []Fraction

	cs        phe.Homomorphic
	precision int
}

// NewTensor binds a slice of fractions to the cryptosystem that can evaluate on
// them. Callers normally get a Tensor from Cryptosystem.EncryptTensor instead.
func NewTensor(cs phe.Homomorphic, fractions []Fraction, precision int) *Tensor {
	return &Tensor{Fractions: fractions, cs: cs, precision: precision}
}

// Len returns the number of elements.
func (t *Tensor) Len() int { return len(t.Fractions) }

// Precision reports how many decimal digits were kept during encryption.
func (t *Tensor) Precision() int { return t.precision }

// Scheme exposes the public cryptosystem bound to this tensor. It never holds a
// private key.
func (t *Tensor) Scheme() phe.Homomorphic { return t.cs }

// Add evaluates the element-wise sum of two encrypted tensors.
//
// When two elements have opposite signs the sign of the result cannot be
// determined without decrypting, so the result is reported as positive and the
// caller reads the modular representative. Same-sign additions are exact.
func (t *Tensor) Add(other *Tensor) (*Tensor, error) {
	if other == nil || len(t.Fractions) != len(other.Fractions) {
		return nil, fmt.Errorf("encrypted: tensor sizes must match for addition")
	}

	fractions := make([]Fraction, len(t.Fractions))
	for i, alpha := range t.Fractions {
		beta := other.Fractions[i]

		dividend, err := t.cs.Add(alpha.Dividend, beta.Dividend)
		if err != nil {
			return nil, err
		}

		if alpha.Sign == -1 && beta.Sign == -1 {
			absDividend, err := t.cs.Add(alpha.AbsDividend, beta.AbsDividend)
			if err != nil {
				return nil, err
			}
			fractions[i] = Fraction{
				Dividend:    dividend,
				AbsDividend: absDividend,
				Divisor:     alpha.Divisor,
				Sign:        -1,
			}
			continue
		}

		fractions[i] = Fraction{
			Dividend:    dividend,
			AbsDividend: dividend,
			Divisor:     alpha.Divisor,
			Sign:        1,
		}
	}
	return t.derive(fractions), nil
}

// Multiply evaluates the element-wise product of two encrypted tensors. It
// needs a multiplicatively homomorphic cryptosystem such as RSA.
func (t *Tensor) Multiply(other *Tensor) (*Tensor, error) {
	if other == nil || len(t.Fractions) != len(other.Fractions) {
		return nil, fmt.Errorf("encrypted: tensor sizes must match for multiplication")
	}

	fractions := make([]Fraction, len(t.Fractions))
	for i, alpha := range t.Fractions {
		beta := other.Fractions[i]

		dividend, err := t.cs.Multiply(alpha.Dividend, beta.Dividend)
		if err != nil {
			return nil, err
		}
		absDividend, err := t.cs.Multiply(alpha.AbsDividend, beta.AbsDividend)
		if err != nil {
			return nil, err
		}
		// The scale factors multiply too, so the result carries scale^2.
		divisor, err := t.cs.Multiply(alpha.Divisor, beta.Divisor)
		if err != nil {
			return nil, err
		}

		fractions[i] = Fraction{
			Dividend:    dividend,
			AbsDividend: absDividend,
			Divisor:     divisor,
			Sign:        alpha.Sign * beta.Sign,
		}
	}
	return t.derive(fractions), nil
}

// MultiplyByConstant scales every element by a known constant, which may be
// negative.
//
// A fractional constant is encoded as a modular fraction, so the result is only
// meaningful when the scaled element stays divisible by the constant's
// denominator. Scaling 7.002 (stored as 700199 after truncation) by 1.05 does
// not divide evenly by 100 and comes back as the modular representative rather
// than 7.3521. Integer-valued elements, and constants whose denominator divides
// the scale factor, are exact.
func (t *Tensor) MultiplyByConstant(constant float64) (*Tensor, error) {
	sign := 1
	if constant < 0 {
		sign = -1
		constant = -constant
	}

	k, err := fixedpoint.Normalize(constant, t.cs.PlaintextModulo())
	if err != nil {
		return nil, err
	}

	fractions := make([]Fraction, len(t.Fractions))
	for i, alpha := range t.Fractions {
		dividend, err := t.cs.MultiplyByConstant(alpha.Dividend, k)
		if err != nil {
			return nil, err
		}
		absDividend, err := t.cs.MultiplyByConstant(alpha.AbsDividend, k)
		if err != nil {
			return nil, err
		}
		// The scale factor is unchanged: only the numerator was scaled.
		fractions[i] = Fraction{
			Dividend:    dividend,
			AbsDividend: absDividend,
			Divisor:     alpha.Divisor,
			Sign:        sign * alpha.Sign,
		}
	}
	return t.derive(fractions), nil
}

// MultiplyByPlain evaluates the element-wise product with a plain vector. Both
// vectors must be non-negative: the sign bookkeeping only works when the
// magnitudes are known to be the values themselves.
func (t *Tensor) MultiplyByPlain(plain []float64) (*Tensor, error) {
	if len(t.Fractions) != len(plain) {
		return nil, fmt.Errorf("encrypted: tensor sizes must match for element-wise multiplication")
	}
	for _, v := range plain {
		if v < 0 {
			return nil, fmt.Errorf("encrypted: element-wise multiplication needs a non-negative plain tensor")
		}
	}
	for _, f := range t.Fractions {
		if f.Sign < 0 {
			return nil, fmt.Errorf("encrypted: element-wise multiplication needs a non-negative encrypted tensor")
		}
	}

	modulo := t.cs.PlaintextModulo()
	fractions := make([]Fraction, len(t.Fractions))
	var divisor phe.Value

	for i, alpha := range t.Fractions {
		scaled, scale := fixedpoint.Fractionize(plain[i], modulo, t.precision)

		dividend, err := t.cs.MultiplyByConstant(alpha.AbsDividend, scaled)
		if err != nil {
			return nil, err
		}
		if divisor == nil {
			// Every element shares the same scale factor, so derive it once.
			if divisor, err = t.cs.MultiplyByConstant(alpha.Divisor, scale); err != nil {
				return nil, err
			}
		}

		fractions[i] = Fraction{
			Dividend:    dividend,
			AbsDividend: dividend,
			Divisor:     divisor,
			Sign:        1,
		}
	}
	return t.derive(fractions), nil
}

// Dot evaluates the dot product with a plain vector and returns it as a single
// element tensor. This is the operation behind encrypted cosine similarity.
func (t *Tensor) Dot(plain []float64) (*Tensor, error) {
	products, err := t.MultiplyByPlain(plain)
	if err != nil {
		return nil, err
	}
	if len(products.Fractions) == 0 {
		return nil, fmt.Errorf("encrypted: cannot take the dot product of an empty tensor")
	}

	sum := products.Fractions[0].AbsDividend
	for _, fraction := range products.Fractions[1:] {
		if sum, err = t.cs.Add(sum, fraction.AbsDividend); err != nil {
			return nil, err
		}
	}

	return t.derive([]Fraction{{
		Dividend:    sum,
		AbsDividend: sum,
		Divisor:     products.Fractions[0].Divisor,
		Sign:        1,
	}}), nil
}

func (t *Tensor) derive(fractions []Fraction) *Tensor {
	return &Tensor{Fractions: fractions, cs: t.cs, precision: t.precision}
}
