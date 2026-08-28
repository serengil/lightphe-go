// Package damgardjurik implements the Damgard-Jurik cryptosystem, a
// generalisation of Paillier that works modulo n^(s+1). With s = 1 it degrades
// exactly to Paillier; larger s buys a larger ciphertext for a plaintext space
// that stays the same size, which is useful when many homomorphic additions
// have to accumulate without wrapping.
//
// Reference: https://sefiks.com/2023/10/20/a-step-by-step-partially-homomorphic-encryption-example-with-damgard-jurik-in-python/
package damgardjurik

import (
	"encoding/json"
	"fmt"
	"math/big"

	"github.com/serengil/lightphe-go/lightphe/internal/mathutil"
	"github.com/serengil/lightphe-go/lightphe/phe"
)

// Defaults used when the caller does not specify them.
const (
	DefaultKeySize = 1024
	DefaultS       = 2
)

// PublicKey is the Damgard-Jurik public key. S is the exponent that fixes the
// ciphertext modulus n^(s+1).
type PublicKey struct {
	G *big.Int `json:"g"`
	N *big.Int `json:"n"`
	S *big.Int `json:"s"`
}

// PrivateKey is Euler's totient of n.
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
		return phe.RequireSection(phe.DamgardJurik, phe.SectionPublic)
	}
	if err := phe.RequireFields(phe.DamgardJurik, phe.SectionPublic,
		phe.Field("g", k.PublicKey.G != nil),
		phe.Field("n", k.PublicKey.N != nil),
		phe.Field("s", k.PublicKey.S != nil),
	); err != nil {
		return err
	}
	if k.PrivateKey != nil {
		if err := phe.RequireFields(phe.DamgardJurik, phe.SectionPrivate,
			phe.Field("phi", k.PrivateKey.Phi != nil),
		); err != nil {
			return err
		}
	}
	return nil
}

// Cryptosystem is a configured Damgard-Jurik instance. It is immutable and safe
// for concurrent use.
type Cryptosystem struct {
	phe.Base

	keys      Keys
	n, g, phi *big.Int
	modulus   *big.Int // n^(s+1)
	mu        *big.Int // phi^-1 mod n
	hasSecret bool
}

var _ phe.Homomorphic = (*Cryptosystem)(nil)

// Generate creates a fresh key pair. Pass s <= 0 to use DefaultS.
func Generate(keySize, s int) (*Cryptosystem, error) {
	if keySize <= 0 {
		keySize = DefaultKeySize
	}
	if s <= 0 {
		s = DefaultS
	}
	p, q, err := mathutil.RandDistinctPrimes(keySize / 2)
	if err != nil {
		return nil, fmt.Errorf("damgardjurik: %w", err)
	}

	one := big.NewInt(1)
	n := new(big.Int).Mul(p, q)
	phi := new(big.Int).Mul(new(big.Int).Sub(p, one), new(big.Int).Sub(q, one))
	g := new(big.Int).Add(n, one)

	return New(Keys{
		PublicKey:  &PublicKey{G: g, N: n, S: big.NewInt(int64(s))},
		PrivateKey: &PrivateKey{Phi: phi},
	})
}

// New builds a cryptosystem around an existing key pair.
func New(keys Keys) (*Cryptosystem, error) {
	if err := keys.Validate(); err != nil {
		return nil, err
	}
	if keys.PublicKey.S.Sign() <= 0 {
		return nil, phe.InvalidKeysf("damgardjurik: s must be positive, got %s", keys.PublicKey.S)
	}

	c := &Cryptosystem{
		Base: phe.Base{Alg: phe.DamgardJurik},
		keys: keys,
		n:    new(big.Int).Set(keys.PublicKey.N),
		g:    new(big.Int).Set(keys.PublicKey.G),
	}
	c.modulus = new(big.Int).Exp(c.n, new(big.Int).Add(keys.PublicKey.S, big.NewInt(1)), nil)

	if keys.PrivateKey != nil {
		c.phi = new(big.Int).Set(keys.PrivateKey.Phi)
		mu, err := mathutil.ModInverse(c.phi, c.n)
		if err != nil {
			return nil, phe.InvalidKeysf("damgardjurik: phi is not invertible modulo n")
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
		return nil, phe.InvalidKeysf("damgardjurik: decoding keys: %v", err)
	}
	return New(keys)
}

// Keys returns a copy of the key material.
func (c *Cryptosystem) Keys() Keys { return c.keys }

// PlaintextModulo implements phe.Homomorphic.
func (c *Cryptosystem) PlaintextModulo() *big.Int { return new(big.Int).Set(c.n) }

// CiphertextModulo implements phe.Homomorphic.
func (c *Cryptosystem) CiphertextModulo() *big.Int { return new(big.Int).Set(c.modulus) }

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

// Encrypt implements phe.Homomorphic.
func (c *Cryptosystem) Encrypt(plaintext *big.Int) (phe.Value, error) {
	r, err := mathutil.RandCoprime(c.n)
	if err != nil {
		return nil, fmt.Errorf("damgardjurik: %w", err)
	}
	return c.EncryptWith(plaintext, r)
}

// EncryptWith encrypts using a caller supplied random key.
func (c *Cryptosystem) EncryptWith(plaintext, random *big.Int) (phe.Value, error) {
	m := new(big.Int).Mod(plaintext, c.n)

	// c = g^m * r^n mod n^(s+1)
	left := new(big.Int).Exp(c.g, m, c.modulus)
	right := new(big.Int).Exp(random, c.n, c.modulus)
	return phe.Int{V: left.Mul(left, right).Mod(left, c.modulus)}, nil
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

	powered := new(big.Int).Exp(v, c.phi, c.modulus)
	num := new(big.Int).Sub(powered, big.NewInt(1))
	quo, rem := new(big.Int).QuoRem(num, c.n, new(big.Int))
	if rem.Sign() != 0 {
		return nil, fmt.Errorf("damgardjurik: ciphertext is not congruent to 1 modulo n: %w", phe.ErrDecryptionFailed)
	}
	return quo.Mul(quo, c.mu).Mod(quo, c.n), nil
}

// Add implements phe.Homomorphic.
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
	return phe.Int{V: sum.Mod(sum, c.modulus)}, nil
}

// MultiplyByConstant implements phe.Homomorphic.
func (c *Cryptosystem) MultiplyByConstant(ciphertext phe.Value, constant *big.Int) (phe.Value, error) {
	v, err := phe.AsInt(ciphertext)
	if err != nil {
		return nil, err
	}
	k := new(big.Int).Mod(constant, c.n)
	return phe.Int{V: new(big.Int).Exp(v, k, c.modulus)}, nil
}

// Reencrypt implements phe.Homomorphic.
func (c *Cryptosystem) Reencrypt(ciphertext phe.Value) (phe.Value, error) {
	zero, err := c.Encrypt(new(big.Int))
	if err != nil {
		return nil, err
	}
	return c.Add(ciphertext, zero)
}
