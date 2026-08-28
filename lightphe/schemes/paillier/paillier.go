// Package paillier implements the Paillier cryptosystem, which is homomorphic
// with respect to addition and supports multiplying a ciphertext by a known
// plain constant.
//
// Reference: https://sefiks.com/2023/04/03/a-step-by-step-partially-homomorphic-encryption-example-with-paillier-in-python/
package paillier

import (
	"encoding/json"
	"fmt"
	"math/big"

	"github.com/serengil/lightphe-go/lightphe/internal/mathutil"
	"github.com/serengil/lightphe-go/lightphe/phe"
)

// DefaultKeySize is the modulus size in bits used when none is requested.
const DefaultKeySize = 1024

// PublicKey is the Paillier public key: the modulus n and the generator g.
type PublicKey struct {
	G *big.Int `json:"g"`
	N *big.Int `json:"n"`
}

// PrivateKey is the Paillier private key, Euler's totient of n.
type PrivateKey struct {
	Phi *big.Int `json:"phi"`
}

// Keys bundles the key pair. PrivateKey is nil for encryption-only setups.
type Keys struct {
	PublicKey  *PublicKey  `json:"public_key,omitempty"`
	PrivateKey *PrivateKey `json:"private_key,omitempty"`
}

// Validate reports missing or malformed key material.
func (k Keys) Validate() error {
	if k.PublicKey == nil {
		return phe.RequireSection(phe.Paillier, phe.SectionPublic)
	}
	if err := phe.RequireFields(phe.Paillier, phe.SectionPublic,
		phe.Field("g", k.PublicKey.G != nil),
		phe.Field("n", k.PublicKey.N != nil),
	); err != nil {
		return err
	}
	if k.PrivateKey != nil {
		if err := phe.RequireFields(phe.Paillier, phe.SectionPrivate,
			phe.Field("phi", k.PrivateKey.Phi != nil),
		); err != nil {
			return err
		}
	}
	return nil
}

// Cryptosystem is a configured Paillier instance. It is immutable and safe for
// concurrent use.
type Cryptosystem struct {
	phe.Base

	keys      Keys
	n         *big.Int
	nSquared  *big.Int
	g         *big.Int
	phi       *big.Int
	mu        *big.Int // phi^-1 mod n, precomputed for decryption
	hasSecret bool
}

var _ phe.Homomorphic = (*Cryptosystem)(nil)

// Generate creates a fresh key pair with a modulus of keySize bits.
func Generate(keySize int) (*Cryptosystem, error) {
	if keySize <= 0 {
		keySize = DefaultKeySize
	}
	p, q, err := mathutil.RandDistinctPrimes(keySize / 2)
	if err != nil {
		return nil, fmt.Errorf("paillier: %w", err)
	}

	n := new(big.Int).Mul(p, q)
	phi := new(big.Int).Mul(new(big.Int).Sub(p, big.NewInt(1)), new(big.Int).Sub(q, big.NewInt(1)))

	// The standard simplification g = n + 1 keeps encryption cheap because
	// g^m mod n^2 collapses to 1 + m*n.
	g := new(big.Int).Add(n, big.NewInt(1))

	return New(Keys{
		PublicKey:  &PublicKey{G: g, N: n},
		PrivateKey: &PrivateKey{Phi: phi},
	})
}

// New builds a cryptosystem around an existing key pair.
func New(keys Keys) (*Cryptosystem, error) {
	if err := keys.Validate(); err != nil {
		return nil, err
	}

	c := &Cryptosystem{
		Base:     phe.Base{Alg: phe.Paillier},
		keys:     keys,
		n:        new(big.Int).Set(keys.PublicKey.N),
		g:        new(big.Int).Set(keys.PublicKey.G),
		nSquared: new(big.Int),
	}
	c.nSquared.Mul(c.n, c.n)

	if keys.PrivateKey != nil {
		c.phi = new(big.Int).Set(keys.PrivateKey.Phi)
		mu, err := mathutil.ModInverse(c.phi, c.n)
		if err != nil {
			return nil, phe.InvalidKeysf("paillier: phi is not invertible modulo n")
		}
		c.mu = mu
		c.hasSecret = true
	}
	return c, nil
}

// FromJSON rebuilds a cryptosystem from exported key material.
func FromJSON(data []byte) (*Cryptosystem, error) {
	var keys Keys
	if err := json.Unmarshal(data, &keys); err != nil {
		return nil, phe.InvalidKeysf("paillier: decoding keys: %v", err)
	}
	return New(keys)
}

// Keys returns a copy of the key material.
func (c *Cryptosystem) Keys() Keys { return c.keys }

// PlaintextModulo implements phe.Homomorphic.
func (c *Cryptosystem) PlaintextModulo() *big.Int { return new(big.Int).Set(c.n) }

// CiphertextModulo implements phe.Homomorphic.
func (c *Cryptosystem) CiphertextModulo() *big.Int { return new(big.Int).Set(c.nSquared) }

// HasPrivateKey implements phe.Homomorphic.
func (c *Cryptosystem) HasPrivateKey() bool { return c.hasSecret }

// PublicOnly implements phe.Homomorphic.
func (c *Cryptosystem) PublicOnly() (phe.Homomorphic, error) {
	return New(Keys{PublicKey: c.keys.PublicKey})
}

// ExportKeys implements phe.Homomorphic.
func (c *Cryptosystem) ExportKeys(includePrivate bool) ([]byte, error) {
	keys := Keys{PublicKey: c.keys.PublicKey}
	if includePrivate {
		keys.PrivateKey = c.keys.PrivateKey
	}
	return json.Marshal(keys)
}

// Encrypt implements phe.Homomorphic. Paillier is probabilistic: a one-time
// random unit r is drawn for every encryption, so encrypting the same plaintext
// twice yields different ciphertexts.
func (c *Cryptosystem) Encrypt(plaintext *big.Int) (phe.Value, error) {
	r, err := mathutil.RandCoprime(c.n)
	if err != nil {
		return nil, fmt.Errorf("paillier: %w", err)
	}
	return c.EncryptWith(plaintext, r)
}

// EncryptWith encrypts using a caller supplied random key. Reusing a random key
// across encryptions destroys semantic security; it exists for reproducible
// tests and for interoperability checks.
func (c *Cryptosystem) EncryptWith(plaintext, random *big.Int) (phe.Value, error) {
	if !mathutil.IsCoprime(random, c.n) {
		return nil, fmt.Errorf("paillier: the random key must be coprime to n")
	}
	m := new(big.Int).Mod(plaintext, c.n)

	// c = g^m * r^n mod n^2
	left := new(big.Int).Exp(c.g, m, c.nSquared)
	right := new(big.Int).Exp(random, c.n, c.nSquared)
	return phe.Int{V: left.Mul(left, right).Mod(left, c.nSquared)}, nil
}

// Decrypt implements phe.Homomorphic.
func (c *Cryptosystem) Decrypt(ciphertext phe.Value) (*big.Int, error) {
	if !c.hasSecret {
		return nil, phe.ErrMissingPrivateKey
	}
	v, err := phe.AsInt(ciphertext)
	if err != nil {
		return nil, err
	}

	// m = L(c^phi mod n^2) * phi^-1 mod n, where L(x) = (x-1)/n
	powered := new(big.Int).Exp(v, c.phi, c.nSquared)
	l, err := c.l(powered)
	if err != nil {
		return nil, err
	}
	return l.Mul(l, c.mu).Mod(l, c.n), nil
}

// l is the L function of the Paillier construction: L(x) = (x-1)/n.
func (c *Cryptosystem) l(x *big.Int) (*big.Int, error) {
	num := new(big.Int).Sub(x, big.NewInt(1))
	quo, rem := new(big.Int).QuoRem(num, c.n, new(big.Int))
	if rem.Sign() != 0 {
		return nil, fmt.Errorf("paillier: %s is not congruent to 1 modulo n: %w", x, phe.ErrDecryptionFailed)
	}
	return quo, nil
}

// Add implements phe.Homomorphic: multiplying ciphertexts adds plaintexts.
func (c *Cryptosystem) Add(a, b phe.Value) (phe.Value, error) {
	x, err := phe.AsInt(a)
	if err != nil {
		return nil, err
	}
	y, err := phe.AsInt(b)
	if err != nil {
		return nil, err
	}
	sum := new(big.Int).Mul(x, y)
	return phe.Int{V: sum.Mod(sum, c.nSquared)}, nil
}

// MultiplyByConstant implements phe.Homomorphic: raising a ciphertext to a
// known exponent multiplies the plaintext by it.
func (c *Cryptosystem) MultiplyByConstant(ciphertext phe.Value, constant *big.Int) (phe.Value, error) {
	v, err := phe.AsInt(ciphertext)
	if err != nil {
		return nil, err
	}
	k := new(big.Int).Mod(constant, c.n)
	return phe.Int{V: new(big.Int).Exp(v, k, c.nSquared)}, nil
}

// Reencrypt implements phe.Homomorphic by adding an encryption of zero, which
// re-randomises the ciphertext without changing the plaintext.
func (c *Cryptosystem) Reencrypt(ciphertext phe.Value) (phe.Value, error) {
	zero, err := c.Encrypt(new(big.Int))
	if err != nil {
		return nil, err
	}
	return c.Add(ciphertext, zero)
}
