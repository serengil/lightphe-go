// Package okamotouchiyama implements the Okamoto-Uchiyama cryptosystem, which
// is homomorphic with respect to addition. Its modulus has the shape n = p^2*q,
// and decryption works in the subgroup of order p, so plaintexts must stay
// below p even though ciphertext arithmetic happens modulo n.
//
// Reference: https://sefiks.com/2023/10/20/a-step-by-step-partially-homomorphic-encryption-example-with-okamoto-uchiyama-in-python/
package okamotouchiyama

import (
	"encoding/json"
	"fmt"
	"math/big"

	"github.com/serengil/lightphe-go/lightphe/internal/mathutil"
	"github.com/serengil/lightphe-go/lightphe/phe"
)

// DefaultKeySize is the size in bits of each of the two primes when none is
// requested. The resulting modulus n = p^2*q is roughly 1.5 times as long.
const DefaultKeySize = 1024

// DefaultMaxTries bounds the search for a generator.
const DefaultMaxTries = 10000

// PublicKey is the Okamoto-Uchiyama public key.
type PublicKey struct {
	N *big.Int `json:"n"`
	G *big.Int `json:"g"`
	H *big.Int `json:"h"`
}

// PrivateKey holds the two primes behind n.
type PrivateKey struct {
	P *big.Int `json:"p"`
	Q *big.Int `json:"q"`
}

// Keys bundles the key pair. PrivateKey is nil for encryption-only setups.
type Keys struct {
	PublicKey  *PublicKey  `json:"public_key,omitempty"`
	PrivateKey *PrivateKey `json:"private_key,omitempty"`
}

// Validate reports missing or malformed key material.
func (k Keys) Validate() error {
	if k.PublicKey == nil {
		return phe.RequireSection(phe.OkamotoUchiyama, phe.SectionPublic)
	}
	if err := phe.RequireFields(phe.OkamotoUchiyama, phe.SectionPublic,
		phe.Field("n", k.PublicKey.N != nil),
		phe.Field("g", k.PublicKey.G != nil),
		phe.Field("h", k.PublicKey.H != nil),
	); err != nil {
		return err
	}
	if k.PrivateKey != nil {
		if err := phe.RequireFields(phe.OkamotoUchiyama, phe.SectionPrivate,
			phe.Field("p", k.PrivateKey.P != nil),
			phe.Field("q", k.PrivateKey.Q != nil),
		); err != nil {
			return err
		}
	}
	return nil
}

// Cryptosystem is a configured Okamoto-Uchiyama instance. It is immutable and
// safe for concurrent use.
type Cryptosystem struct {
	phe.Base

	keys      Keys
	n, g, h   *big.Int
	p, q      *big.Int
	pSquared  *big.Int
	gpInv     *big.Int // (L(g^(p-1) mod p^2))^-1 mod p, precomputed
	hasSecret bool
}

var _ phe.Homomorphic = (*Cryptosystem)(nil)

// Generate creates a fresh key pair from two primes of keySize/2 bits each.
func Generate(keySize, maxTries int) (*Cryptosystem, error) {
	if keySize <= 0 {
		keySize = DefaultKeySize
	}
	if maxTries <= 0 {
		maxTries = DefaultMaxTries
	}

	p, q, err := mathutil.RandDistinctPrimes(keySize / 2)
	if err != nil {
		return nil, fmt.Errorf("okamotouchiyama: %w", err)
	}

	// n = p^2 * q
	n := new(big.Int).Mul(p, p)
	n.Mul(n, q)

	pSquared := new(big.Int).Mul(p, p)
	pMinusOne := new(big.Int).Sub(p, big.NewInt(1))
	one := big.NewInt(1)

	// g must not satisfy Fermat's little theorem modulo p^2, otherwise the
	// L function collapses and decryption cannot recover the message.
	for i := 0; i < maxTries; i++ {
		g, err := mathutil.RandRange(big.NewInt(2), new(big.Int).Sub(n, one))
		if err != nil {
			return nil, fmt.Errorf("okamotouchiyama: %w", err)
		}
		if new(big.Int).Exp(g, pMinusOne, pSquared).Cmp(one) == 0 {
			continue
		}
		h := new(big.Int).Exp(g, n, n)
		return New(Keys{
			PublicKey:  &PublicKey{N: n, G: g, H: h},
			PrivateKey: &PrivateKey{P: p, Q: q},
		})
	}
	return nil, fmt.Errorf("okamotouchiyama: no valid generator after %d attempts: %w", maxTries, phe.ErrKeyGeneration)
}

// New builds a cryptosystem around an existing key pair.
func New(keys Keys) (*Cryptosystem, error) {
	if err := keys.Validate(); err != nil {
		return nil, err
	}

	c := &Cryptosystem{
		Base: phe.Base{Alg: phe.OkamotoUchiyama},
		keys: keys,
		n:    new(big.Int).Set(keys.PublicKey.N),
		g:    new(big.Int).Set(keys.PublicKey.G),
		h:    new(big.Int).Set(keys.PublicKey.H),
	}

	if keys.PrivateKey != nil {
		c.p = new(big.Int).Set(keys.PrivateKey.P)
		c.q = new(big.Int).Set(keys.PrivateKey.Q)
		c.pSquared = new(big.Int).Mul(c.p, c.p)

		pMinusOne := new(big.Int).Sub(c.p, big.NewInt(1))
		base, err := c.l(new(big.Int).Exp(c.g, pMinusOne, c.pSquared))
		if err != nil {
			return nil, phe.InvalidKeysf("okamotouchiyama: generator does not admit decryption: %v", err)
		}
		inv, err := mathutil.ModInverse(base, c.p)
		if err != nil {
			return nil, phe.InvalidKeysf("okamotouchiyama: generator does not admit decryption: %v", err)
		}
		c.gpInv = inv
		c.hasSecret = true
	}
	return c, nil
}

// FromJSON rebuilds a cryptosystem from exported key material.
func FromJSON(data []byte) (*Cryptosystem, error) {
	var keys Keys
	if err := json.Unmarshal(data, &keys); err != nil {
		return nil, phe.InvalidKeysf("okamotouchiyama: decoding keys: %v", err)
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

// Encrypt implements phe.Homomorphic.
func (c *Cryptosystem) Encrypt(plaintext *big.Int) (phe.Value, error) {
	r, err := mathutil.RandRange(big.NewInt(1), new(big.Int).Sub(c.n, big.NewInt(1)))
	if err != nil {
		return nil, fmt.Errorf("okamotouchiyama: %w", err)
	}
	return c.EncryptWith(plaintext, r)
}

// EncryptWith encrypts using a caller supplied random key.
func (c *Cryptosystem) EncryptWith(plaintext, random *big.Int) (phe.Value, error) {
	m := new(big.Int).Mod(plaintext, c.n)

	// The message space really is [0, p), so reduce further when the private
	// key is at hand. Without it the caller has to keep plaintexts small.
	if c.hasSecret {
		m.Mod(m, c.p)
	}

	left := new(big.Int).Exp(c.g, m, c.n)
	right := new(big.Int).Exp(c.h, random, c.n)
	return phe.Int{V: left.Mul(left, right).Mod(left, c.n)}, nil
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

	pMinusOne := new(big.Int).Sub(c.p, big.NewInt(1))
	a, err := c.l(new(big.Int).Exp(v, pMinusOne, c.pSquared))
	if err != nil {
		return nil, err
	}
	return a.Mul(a, c.gpInv).Mod(a, c.p), nil
}

// l is the L function of the construction: L(x) = (x-1)/p, defined for x that
// are congruent to 1 modulo p and coprime to p^2.
func (c *Cryptosystem) l(x *big.Int) (*big.Int, error) {
	if new(big.Int).Mod(x, c.p).Cmp(big.NewInt(1)) != 0 {
		return nil, fmt.Errorf("okamotouchiyama: %s is not congruent to 1 modulo p: %w", x, phe.ErrDecryptionFailed)
	}
	if !mathutil.IsCoprime(x, c.pSquared) {
		return nil, fmt.Errorf("okamotouchiyama: %s is not coprime to p^2: %w", x, phe.ErrDecryptionFailed)
	}
	return new(big.Int).Div(new(big.Int).Sub(x, big.NewInt(1)), c.p), nil
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
	return phe.Int{V: sum.Mod(sum, c.n)}, nil
}

// MultiplyByConstant implements phe.Homomorphic.
func (c *Cryptosystem) MultiplyByConstant(ciphertext phe.Value, constant *big.Int) (phe.Value, error) {
	v, err := phe.AsInt(ciphertext)
	if err != nil {
		return nil, err
	}
	k := new(big.Int).Mod(constant, c.n)
	return phe.Int{V: new(big.Int).Exp(v, k, c.n)}, nil
}

// Reencrypt implements phe.Homomorphic.
func (c *Cryptosystem) Reencrypt(ciphertext phe.Value) (phe.Value, error) {
	zero, err := c.Encrypt(new(big.Int))
	if err != nil {
		return nil, err
	}
	return c.Add(ciphertext, zero)
}
