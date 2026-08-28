// Package elgamal implements the ElGamal cryptosystem in both of its flavours.
//
// Textbook ElGamal encrypts m as (g^r, m*y^r) and is homomorphic with respect
// to multiplication. Exponential ElGamal encrypts m as (g^r, g^m*y^r) and is
// homomorphic with respect to addition, at the cost of a discrete logarithm
// during decryption - which is why it is only usable for small plaintexts.
//
// Reference: https://sefiks.com/2023/03/27/a-step-by-step-partially-homomorphic-encryption-example-with-elgamal-in-python/
package elgamal

import (
	"encoding/json"
	"fmt"
	"math/big"

	"github.com/serengil/lightphe-go/lightphe/internal/mathutil"
	"github.com/serengil/lightphe-go/lightphe/phe"
)

// DefaultKeySize is the key size in bits used when none is requested. As in the
// reference implementation the prime modulus takes half of it.
const DefaultKeySize = 1024

// PublicKey is the ElGamal public key.
type PublicKey struct {
	P *big.Int `json:"p"`
	G *big.Int `json:"g"`
	Y *big.Int `json:"y"`
}

// PrivateKey is the ElGamal private exponent.
type PrivateKey struct {
	X *big.Int `json:"x"`
}

// Keys bundles the key pair. PrivateKey is nil for encryption-only setups.
type Keys struct {
	PublicKey  *PublicKey  `json:"public_key,omitempty"`
	PrivateKey *PrivateKey `json:"private_key,omitempty"`
}

// Validate reports missing or malformed key material.
func (k Keys) Validate(alg phe.Algorithm) error {
	if k.PublicKey == nil {
		return phe.RequireSection(alg, phe.SectionPublic)
	}
	if err := phe.RequireFields(alg, phe.SectionPublic,
		phe.Field("p", k.PublicKey.P != nil),
		phe.Field("g", k.PublicKey.G != nil),
		phe.Field("y", k.PublicKey.Y != nil),
	); err != nil {
		return err
	}
	if k.PrivateKey != nil {
		if err := phe.RequireFields(alg, phe.SectionPrivate,
			phe.Field("x", k.PrivateKey.X != nil),
		); err != nil {
			return err
		}
	}
	return nil
}

// Cryptosystem is a configured ElGamal instance. It is immutable and safe for
// concurrent use.
type Cryptosystem struct {
	phe.Base

	keys        Keys
	p, g, y, x  *big.Int
	exponential bool
	hasSecret   bool
}

var _ phe.Homomorphic = (*Cryptosystem)(nil)

// Generate creates a fresh key pair. Set exponential to true for the additively
// homomorphic variant.
func Generate(keySize int, exponential bool) (*Cryptosystem, error) {
	if keySize <= 0 {
		keySize = DefaultKeySize
	}
	p, err := mathutil.RandPrime(keySize / 2)
	if err != nil {
		return nil, fmt.Errorf("elgamal: %w", err)
	}

	// g is drawn from [2, sqrt(p)] the same way the reference implementation
	// does, which keeps g^m cheap for the exponential variant.
	upper := new(big.Int).Sqrt(p)
	if upper.Cmp(big.NewInt(2)) < 0 {
		upper = big.NewInt(2)
	}
	g, err := mathutil.RandRange(big.NewInt(2), upper)
	if err != nil {
		return nil, fmt.Errorf("elgamal: %w", err)
	}

	x, err := mathutil.RandRange(big.NewInt(1), new(big.Int).Sub(p, big.NewInt(2)))
	if err != nil {
		return nil, fmt.Errorf("elgamal: %w", err)
	}
	y := new(big.Int).Exp(g, x, p)

	return New(Keys{
		PublicKey:  &PublicKey{P: p, G: g, Y: y},
		PrivateKey: &PrivateKey{X: x},
	}, exponential)
}

// New builds a cryptosystem around an existing key pair.
func New(keys Keys, exponential bool) (*Cryptosystem, error) {
	alg := phe.ElGamal
	if exponential {
		alg = phe.ExponentialElGamal
	}
	if err := keys.Validate(alg); err != nil {
		return nil, err
	}

	c := &Cryptosystem{
		Base:        phe.Base{Alg: alg},
		keys:        keys,
		p:           new(big.Int).Set(keys.PublicKey.P),
		g:           new(big.Int).Set(keys.PublicKey.G),
		y:           new(big.Int).Set(keys.PublicKey.Y),
		exponential: exponential,
	}
	if keys.PrivateKey != nil {
		c.x = new(big.Int).Set(keys.PrivateKey.X)
		c.hasSecret = true
	}
	return c, nil
}

// FromJSON rebuilds a cryptosystem from exported key material.
func FromJSON(data []byte, exponential bool) (*Cryptosystem, error) {
	var keys Keys
	if err := json.Unmarshal(data, &keys); err != nil {
		return nil, phe.InvalidKeysf("elgamal: decoding keys: %v", err)
	}
	return New(keys, exponential)
}

// Keys returns a copy of the key material.
func (c *Cryptosystem) Keys() Keys { return c.keys }

// IsExponential reports whether this is the additively homomorphic variant.
func (c *Cryptosystem) IsExponential() bool { return c.exponential }

// PlaintextModulo implements phe.Homomorphic.
func (c *Cryptosystem) PlaintextModulo() *big.Int { return new(big.Int).Set(c.p) }

// CiphertextModulo implements phe.Homomorphic.
func (c *Cryptosystem) CiphertextModulo() *big.Int { return new(big.Int).Set(c.p) }

// HasPrivateKey implements phe.Homomorphic.
func (c *Cryptosystem) HasPrivateKey() bool { return c.hasSecret }

// PublicOnly implements phe.Homomorphic.
func (c *Cryptosystem) PublicOnly() (phe.Homomorphic, error) {
	return New(Keys{PublicKey: c.keys.PublicKey}, c.exponential)
}

// ExportKeys implements phe.Homomorphic.
func (c *Cryptosystem) ExportKeys(includePrivate bool) ([]byte, error) {
	keys := Keys{PublicKey: c.keys.PublicKey}
	if includePrivate {
		keys.PrivateKey = c.keys.PrivateKey
	}
	return json.Marshal(keys)
}

// Encrypt implements phe.Homomorphic.
func (c *Cryptosystem) Encrypt(plaintext *big.Int) (phe.Value, error) {
	r, err := mathutil.RandRange(big.NewInt(1), new(big.Int).Sub(c.p, big.NewInt(1)))
	if err != nil {
		return nil, fmt.Errorf("elgamal: %w", err)
	}
	return c.EncryptWith(plaintext, r)
}

// EncryptWith encrypts using a caller supplied random key. Never reuse a random
// key in production; this entry point exists for reproducible tests.
func (c *Cryptosystem) EncryptWith(plaintext, random *big.Int) (phe.Value, error) {
	m := new(big.Int).Mod(plaintext, c.p)

	c1 := new(big.Int).Exp(c.g, random, c.p)

	c2 := new(big.Int).Exp(c.y, random, c.p)
	if c.exponential {
		c2.Mul(c2, new(big.Int).Exp(c.g, m, c.p))
	} else {
		c2.Mul(c2, m)
	}
	c2.Mod(c2, c.p)

	return phe.NewTuple(phe.Int{V: c1}, phe.Int{V: c2}), nil
}

// Decrypt implements phe.Homomorphic. For the exponential variant it recovers
// the plaintext by solving a discrete logarithm, which is only feasible while
// plaintexts stay small.
func (c *Cryptosystem) Decrypt(ciphertext phe.Value) (*big.Int, error) {
	if !c.hasSecret {
		return nil, phe.ErrMissingPrivateKey
	}
	c1, c2, err := c.components(ciphertext)
	if err != nil {
		return nil, err
	}

	// m' = c2 * (c1^x)^-1 mod p
	shared := new(big.Int).Exp(c1, c.x, c.p)
	inv, err := mathutil.ModInverse(shared, c.p)
	if err != nil {
		return nil, fmt.Errorf("elgamal: %v: %w", err, phe.ErrDecryptionFailed)
	}
	mPrime := new(big.Int).Mul(c2, inv)
	mPrime.Mod(mPrime, c.p)

	if !c.exponential {
		return mPrime, nil
	}

	// m' = g^m, so recover m by exhaustive search over the message space.
	acc := big.NewInt(1)
	m := new(big.Int)
	one := big.NewInt(1)
	for {
		if acc.Cmp(mPrime) == 0 {
			return m, nil
		}
		m.Add(m, one)
		if m.Cmp(c.p) > 0 {
			return nil, fmt.Errorf("elgamal: cannot restore a message in [0, %s]: %w", c.p, phe.ErrDecryptionFailed)
		}
		acc.Mul(acc, c.g).Mod(acc, c.p)
	}
}

// Multiply implements phe.Homomorphic for textbook ElGamal.
func (c *Cryptosystem) Multiply(a, b phe.Value) (phe.Value, error) {
	if c.exponential {
		return nil, phe.Unsupportedf(c.Alg, phe.OpMultiplication)
	}
	return c.componentwiseProduct(a, b)
}

// Add implements phe.Homomorphic for exponential ElGamal.
func (c *Cryptosystem) Add(a, b phe.Value) (phe.Value, error) {
	if !c.exponential {
		return nil, phe.Unsupportedf(c.Alg, phe.OpAddition)
	}
	return c.componentwiseProduct(a, b)
}

// MultiplyByConstant implements phe.Homomorphic for exponential ElGamal.
func (c *Cryptosystem) MultiplyByConstant(ciphertext phe.Value, constant *big.Int) (phe.Value, error) {
	if !c.exponential {
		return nil, phe.Unsupportedf(c.Alg, phe.OpScalarMultiplcation)
	}
	c1, c2, err := c.components(ciphertext)
	if err != nil {
		return nil, err
	}
	k := new(big.Int).Mod(constant, c.p)
	return phe.NewTuple(
		phe.Int{V: new(big.Int).Exp(c1, k, c.p)},
		phe.Int{V: new(big.Int).Exp(c2, k, c.p)},
	), nil
}

// Reencrypt implements phe.Homomorphic by combining the ciphertext with a fresh
// encryption of the neutral element of the supported operation.
func (c *Cryptosystem) Reencrypt(ciphertext phe.Value) (phe.Value, error) {
	neutral := big.NewInt(1)
	if c.exponential {
		neutral = new(big.Int)
	}
	encrypted, err := c.Encrypt(neutral)
	if err != nil {
		return nil, err
	}
	return c.componentwiseProduct(ciphertext, encrypted)
}

// componentwiseProduct multiplies the two ciphertext components pairwise, which
// is the single group operation behind both flavours of homomorphism.
func (c *Cryptosystem) componentwiseProduct(a, b phe.Value) (phe.Value, error) {
	a1, a2, err := c.components(a)
	if err != nil {
		return nil, err
	}
	b1, b2, err := c.components(b)
	if err != nil {
		return nil, err
	}
	r1 := new(big.Int).Mul(a1, b1)
	r2 := new(big.Int).Mul(a2, b2)
	return phe.NewTuple(
		phe.Int{V: r1.Mod(r1, c.p)},
		phe.Int{V: r2.Mod(r2, c.p)},
	), nil
}

// components splits an ElGamal ciphertext into its c1 and c2 halves.
func (c *Cryptosystem) components(v phe.Value) (c1, c2 *big.Int, err error) {
	first, second, err := phe.AsPair(v)
	if err != nil {
		return nil, nil, err
	}
	if c1, err = phe.AsInt(first); err != nil {
		return nil, nil, err
	}
	if c2, err = phe.AsInt(second); err != nil {
		return nil, nil, err
	}
	return c1, c2, nil
}
