// Package encrypted holds the values a cryptosystem hands back: a single
// Ciphertext, and a Tensor of them carrying fixed point reals.
//
// Neither type ever carries a private key, so both are safe to hand to an
// untrusted evaluator. Both are immutable: every operation returns a new value
// and leaves the receiver alone, which also makes them safe to share between
// goroutines.
package encrypted

import (
	"math/big"

	"github.com/serengil/lightphe-go/lightphe/internal/fixedpoint"
	"github.com/serengil/lightphe-go/lightphe/phe"
)

// Ciphertext is an encrypted message together with the public cryptosystem
// needed to evaluate on it.
type Ciphertext struct {
	cs phe.Homomorphic

	// Value is the raw ciphertext payload. Send this over the wire and rebuild
	// a Ciphertext on the other side with Cryptosystem.CreateCiphertext.
	Value phe.Value
}

// NewCiphertext binds a raw ciphertext payload to the cryptosystem that can
// evaluate on it. Callers normally get a Ciphertext from Cryptosystem.Encrypt
// instead.
func NewCiphertext(cs phe.Homomorphic, value phe.Value) *Ciphertext {
	return &Ciphertext{cs: cs, Value: value}
}

// Algorithm reports which cryptosystem produced this ciphertext.
func (c *Ciphertext) Algorithm() phe.Algorithm { return c.cs.Algorithm() }

// Scheme exposes the public cryptosystem bound to this ciphertext. It never
// holds a private key.
func (c *Ciphertext) Scheme() phe.Homomorphic { return c.cs }

// String implements fmt.Stringer.
func (c *Ciphertext) String() string { return "Ciphertext(" + c.Value.String() + ")" }

// Add evaluates E(m1 + m2). It fails for schemes that are not additively
// homomorphic.
func (c *Ciphertext) Add(other *Ciphertext) (*Ciphertext, error) {
	if err := c.compatible(other); err != nil {
		return nil, err
	}
	value, err := c.cs.Add(c.Value, other.Value)
	if err != nil {
		return nil, err
	}
	return c.wrap(value), nil
}

// Multiply evaluates E(m1 * m2). It fails for schemes that are not
// multiplicatively homomorphic.
func (c *Ciphertext) Multiply(other *Ciphertext) (*Ciphertext, error) {
	if err := c.compatible(other); err != nil {
		return nil, err
	}
	value, err := c.cs.Multiply(c.Value, other.Value)
	if err != nil {
		return nil, err
	}
	return c.wrap(value), nil
}

// MultiplyByConstant evaluates E(m * k) for a known integer k.
func (c *Ciphertext) MultiplyByConstant(constant *big.Int) (*Ciphertext, error) {
	value, err := c.cs.MultiplyByConstant(c.Value, constant)
	if err != nil {
		return nil, err
	}
	return c.wrap(value), nil
}

// MultiplyByInt evaluates E(m * k) for a known integer k.
func (c *Ciphertext) MultiplyByInt(constant int64) (*Ciphertext, error) {
	return c.MultiplyByConstant(big.NewInt(constant))
}

// MultiplyByFloat evaluates E(m * k) for a known non-negative float k, which is
// mapped onto the message space as a modular fraction first.
func (c *Ciphertext) MultiplyByFloat(constant float64) (*Ciphertext, error) {
	k, err := fixedpoint.Normalize(constant, c.cs.PlaintextModulo())
	if err != nil {
		return nil, err
	}
	return c.MultiplyByConstant(k)
}

// Xor evaluates E(m1 ^ m2). It fails for schemes that are not homomorphic with
// respect to exclusive or.
func (c *Ciphertext) Xor(other *Ciphertext) (*Ciphertext, error) {
	if err := c.compatible(other); err != nil {
		return nil, err
	}
	value, err := c.cs.Xor(c.Value, other.Value)
	if err != nil {
		return nil, err
	}
	return c.wrap(value), nil
}

// And evaluates E(m1 & m2). It fails for schemes that are not homomorphic with
// respect to bitwise and.
func (c *Ciphertext) And(other *Ciphertext) (*Ciphertext, error) {
	if err := c.compatible(other); err != nil {
		return nil, err
	}
	value, err := c.cs.And(c.Value, other.Value)
	if err != nil {
		return nil, err
	}
	return c.wrap(value), nil
}

// Reencrypt returns a different ciphertext for the same plaintext.
func (c *Ciphertext) Reencrypt() (*Ciphertext, error) {
	value, err := c.cs.Reencrypt(c.Value)
	if err != nil {
		return nil, err
	}
	return c.wrap(value), nil
}

func (c *Ciphertext) wrap(value phe.Value) *Ciphertext {
	return &Ciphertext{cs: c.cs, Value: value}
}

// compatible rejects operands that were produced by different cryptosystems,
// which would otherwise combine into silent nonsense.
func (c *Ciphertext) compatible(other *Ciphertext) error {
	if other == nil {
		return phe.InvalidCiphertextf("encrypted: nil operand")
	}
	if c.cs.Algorithm() != other.cs.Algorithm() {
		return phe.InvalidCiphertextf("encrypted: cannot combine a %s ciphertext with a %s one",
			c.cs.Algorithm(), other.cs.Algorithm())
	}
	return nil
}
