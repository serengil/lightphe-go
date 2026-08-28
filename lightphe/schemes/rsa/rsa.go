// Package rsa implements textbook RSA, which is partially homomorphic with
// respect to multiplication.
//
// The encryption here is deliberately unpadded: OAEP padding would destroy the
// multiplicative structure that makes the scheme homomorphic. Do not use this
// package as a general purpose RSA implementation - reach for crypto/rsa for
// that. Its purpose is homomorphic evaluation over already-confidential data.
//
// Reference: https://sefiks.com/2023/03/06/a-step-by-step-partially-homomorphic-encryption-example-with-rsa-in-python/
package rsa

import (
	"encoding/json"
	"fmt"
	"math/big"

	"github.com/serengil/lightphe-go/lightphe/internal/mathutil"
	"github.com/serengil/lightphe-go/lightphe/phe"
)

// DefaultKeySize is the modulus size in bits used when none is requested.
const DefaultKeySize = 1024

// DefaultMaxTries bounds the randomized search for a valid key pair.
const DefaultMaxTries = 10000

// PublicKey is the RSA public key.
type PublicKey struct {
	N *big.Int `json:"n"`
	E *big.Int `json:"e"`
}

// PrivateKey is the RSA private exponent.
type PrivateKey struct {
	D *big.Int `json:"d"`
}

// Keys bundles the key pair. PrivateKey is nil for encryption-only setups.
type Keys struct {
	PublicKey  *PublicKey  `json:"public_key,omitempty"`
	PrivateKey *PrivateKey `json:"private_key,omitempty"`
}

// Validate reports missing or malformed key material.
func (k Keys) Validate() error {
	if k.PublicKey == nil {
		return phe.RequireSection(phe.RSA, phe.SectionPublic)
	}
	if err := phe.RequireFields(phe.RSA, phe.SectionPublic,
		phe.Field("n", k.PublicKey.N != nil),
		phe.Field("e", k.PublicKey.E != nil),
	); err != nil {
		return err
	}
	if k.PrivateKey != nil {
		if err := phe.RequireFields(phe.RSA, phe.SectionPrivate,
			phe.Field("d", k.PrivateKey.D != nil),
		); err != nil {
			return err
		}
	}
	return nil
}

// Cryptosystem is a configured RSA instance. It is immutable and safe for
// concurrent use.
type Cryptosystem struct {
	phe.Base

	keys      Keys
	n, e, d   *big.Int
	hasSecret bool

	// encryptWithPublic selects which exponent encryption uses. The default,
	// true, is confidentiality: encrypt with e, decrypt with d. Setting it to
	// false swaps the roles, which is the digital signature arrangement.
	encryptWithPublic bool
}

var _ phe.Homomorphic = (*Cryptosystem)(nil)

// Generate creates a fresh key pair with a modulus of keySize bits.
func Generate(keySize, maxTries int) (*Cryptosystem, error) {
	if keySize <= 0 {
		keySize = DefaultKeySize
	}
	if maxTries <= 0 {
		maxTries = DefaultMaxTries
	}

	one := big.NewInt(1)
	for i := 0; i < maxTries; i++ {
		p, q, err := mathutil.RandDistinctPrimes(keySize / 2)
		if err != nil {
			return nil, fmt.Errorf("rsa: %w", err)
		}
		n := new(big.Int).Mul(p, q)
		phi := new(big.Int).Mul(new(big.Int).Sub(p, one), new(big.Int).Sub(q, one))

		// Pick a random public exponent coprime to phi rather than fixing
		// e = 65537, matching the reference implementation.
		for j := 0; j < 1000; j++ {
			e, err := mathutil.RandRange(big.NewInt(2), new(big.Int).Sub(phi, one))
			if err != nil {
				return nil, fmt.Errorf("rsa: %w", err)
			}
			if !mathutil.IsCoprime(e, phi) {
				continue
			}
			d, err := mathutil.ModInverse(e, phi)
			if err != nil {
				continue
			}
			return New(Keys{
				PublicKey:  &PublicKey{N: n, E: e},
				PrivateKey: &PrivateKey{D: d},
			})
		}
	}
	return nil, fmt.Errorf("rsa: no valid key pair after %d attempts: %w", maxTries, phe.ErrKeyGeneration)
}

// New builds a cryptosystem around an existing key pair, encrypting with the
// public exponent.
func New(keys Keys) (*Cryptosystem, error) { return NewWithMode(keys, true) }

// NewWithMode builds a cryptosystem and chooses which exponent encrypts. Pass
// false to encrypt with the private exponent, the digital signature setup.
func NewWithMode(keys Keys, encryptWithPublic bool) (*Cryptosystem, error) {
	if err := keys.Validate(); err != nil {
		return nil, err
	}
	if !encryptWithPublic && keys.PrivateKey == nil {
		return nil, phe.InvalidKeysf("rsa: encrypting with the private exponent needs a private key")
	}

	c := &Cryptosystem{
		Base:              phe.Base{Alg: phe.RSA},
		keys:              keys,
		n:                 new(big.Int).Set(keys.PublicKey.N),
		e:                 new(big.Int).Set(keys.PublicKey.E),
		encryptWithPublic: encryptWithPublic,
	}
	if keys.PrivateKey != nil {
		c.d = new(big.Int).Set(keys.PrivateKey.D)
		c.hasSecret = true
	}
	return c, nil
}

// FromJSON rebuilds a cryptosystem from exported key material.
func FromJSON(data []byte) (*Cryptosystem, error) {
	var keys Keys
	if err := json.Unmarshal(data, &keys); err != nil {
		return nil, phe.InvalidKeysf("rsa: decoding keys: %v", err)
	}
	return New(keys)
}

// Keys returns a copy of the key material.
func (c *Cryptosystem) Keys() Keys { return c.keys }

// PlaintextModulo implements phe.Homomorphic.
func (c *Cryptosystem) PlaintextModulo() *big.Int { return new(big.Int).Set(c.n) }

// CiphertextModulo implements phe.Homomorphic.
func (c *Cryptosystem) CiphertextModulo() *big.Int { return new(big.Int).Set(c.n) }

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

// Encrypt implements phe.Homomorphic. RSA is deterministic: the same plaintext
// always maps to the same ciphertext under a given key.
func (c *Cryptosystem) Encrypt(plaintext *big.Int) (phe.Value, error) {
	m := new(big.Int).Mod(plaintext, c.n)
	exponent := c.e
	if !c.encryptWithPublic {
		exponent = c.d
	}
	return phe.Int{V: new(big.Int).Exp(m, exponent, c.n)}, nil
}

// Decrypt implements phe.Homomorphic.
func (c *Cryptosystem) Decrypt(ciphertext phe.Value) (*big.Int, error) {
	v, err := phe.AsInt(ciphertext)
	if err != nil {
		return nil, err
	}
	exponent := c.e
	if c.encryptWithPublic {
		if !c.hasSecret {
			return nil, phe.ErrMissingPrivateKey
		}
		exponent = c.d
	}
	return new(big.Int).Exp(v, exponent, c.n), nil
}

// Multiply implements phe.Homomorphic: multiplying ciphertexts multiplies
// plaintexts.
func (c *Cryptosystem) Multiply(a, b phe.Value) (phe.Value, error) {
	x, err := phe.AsInt(a)
	if err != nil {
		return nil, err
	}
	y, err := phe.AsInt(b)
	if err != nil {
		return nil, err
	}
	product := new(big.Int).Mul(x, y)
	return phe.Int{V: product.Mod(product, c.n)}, nil
}
