// Package benaloh implements the Benaloh cryptosystem, which is homomorphic
// with respect to addition over the small message space [0, r).
//
// Decryption searches that space exhaustively, so r is deliberately kept small:
// it is either a random prime in [1000, 2000] or the next prime above a
// caller-supplied plaintext limit.
//
// Reference: https://sefiks.com/2023/10/06/a-step-by-step-partially-homomorphic-encryption-example-with-benaloh-in-python-from-scratch/
package benaloh

import (
	"encoding/json"
	"fmt"
	"math/big"

	"github.com/serengil/lightphe-go/lightphe/internal/mathutil"
	"github.com/serengil/lightphe-go/lightphe/phe"
)

// Defaults used when the caller does not specify them.
const (
	DefaultKeySize  = 1024
	DefaultMaxTries = 10000
)

// PublicKey is the Benaloh public key. R bounds the message space.
type PublicKey struct {
	Y *big.Int `json:"y"`
	R *big.Int `json:"r"`
	N *big.Int `json:"n"`
}

// PrivateKey holds the factorisation of n together with the precomputed
// decryption base x.
type PrivateKey struct {
	P   *big.Int `json:"p"`
	Q   *big.Int `json:"q"`
	Phi *big.Int `json:"phi"`
	X   *big.Int `json:"x"`
}

// Keys bundles the key pair. PrivateKey is nil for encryption-only setups.
type Keys struct {
	PublicKey  *PublicKey  `json:"public_key,omitempty"`
	PrivateKey *PrivateKey `json:"private_key,omitempty"`
}

// Validate reports missing or malformed key material.
func (k Keys) Validate() error {
	if k.PublicKey == nil {
		return phe.RequireSection(phe.Benaloh, phe.SectionPublic)
	}
	if err := phe.RequireFields(phe.Benaloh, phe.SectionPublic,
		phe.Field("y", k.PublicKey.Y != nil),
		phe.Field("r", k.PublicKey.R != nil),
		phe.Field("n", k.PublicKey.N != nil),
	); err != nil {
		return err
	}
	if k.PrivateKey != nil {
		if err := phe.RequireFields(phe.Benaloh, phe.SectionPrivate,
			phe.Field("p", k.PrivateKey.P != nil),
			phe.Field("q", k.PrivateKey.Q != nil),
			phe.Field("phi", k.PrivateKey.Phi != nil),
			phe.Field("x", k.PrivateKey.X != nil),
		); err != nil {
			return err
		}
	}
	return nil
}

// Cryptosystem is a configured Benaloh instance. It is immutable and safe for
// concurrent use.
type Cryptosystem struct {
	phe.Base

	keys      Keys
	n, r, y   *big.Int
	phi, x    *big.Int
	phiOverR  *big.Int
	hasSecret bool
}

var _ phe.Homomorphic = (*Cryptosystem)(nil)

// Generate creates a fresh key pair. When plaintextLimit is non-nil the message
// space is sized to hold it; otherwise a random block size is chosen.
func Generate(keySize int, plaintextLimit *big.Int, maxTries int) (*Cryptosystem, error) {
	if keySize <= 0 {
		keySize = DefaultKeySize
	}
	if maxTries <= 0 {
		maxTries = DefaultMaxTries
	}
	primeBits := keySize / 2
	one := big.NewInt(1)

	for attempt := 0; attempt < maxTries; attempt++ {
		r, err := blockSize(plaintextLimit)
		if err != nil {
			return nil, err
		}
		if r.BitLen() >= primeBits-1 {
			return nil, fmt.Errorf("benaloh: block size %s does not fit in a %d-bit prime; raise the key size or lower the plaintext limit: %w",
				r, primeBits, phe.ErrKeyGeneration)
		}

		// p is built as k*r + 1 so that r divides p-1 by construction. Drawing
		// p at random and hoping for the congruence, as a naive search would,
		// wastes roughly r attempts per success.
		p, k, err := primeCongruentToOne(r, primeBits)
		if err != nil {
			continue
		}
		// r and (p-1)/r must be coprime.
		if !mathutil.IsCoprime(r, k) {
			continue
		}

		q, err := mathutil.RandPrime(primeBits)
		if err != nil {
			return nil, fmt.Errorf("benaloh: %w", err)
		}
		if p.Cmp(q) == 0 || !mathutil.IsCoprime(r, new(big.Int).Sub(q, one)) {
			continue
		}

		n := new(big.Int).Mul(p, q)
		phi := new(big.Int).Mul(new(big.Int).Sub(p, one), new(big.Int).Sub(q, one))

		y, x, err := findGenerator(n, phi, r, maxTries)
		if err != nil {
			continue
		}

		return New(Keys{
			PublicKey:  &PublicKey{Y: y, R: r, N: n},
			PrivateKey: &PrivateKey{P: p, Q: q, Phi: phi, X: x},
		})
	}
	return nil, fmt.Errorf("benaloh: no valid key pair after %d attempts: %w", maxTries, phe.ErrKeyGeneration)
}

// blockSize picks r, the size of the message space.
func blockSize(plaintextLimit *big.Int) (*big.Int, error) {
	if plaintextLimit != nil {
		if plaintextLimit.Sign() < 0 {
			return nil, fmt.Errorf("benaloh: the plaintext limit must not be negative")
		}
		return mathutil.NextPrime(plaintextLimit), nil
	}
	return mathutil.RandRangePrime(big.NewInt(1000), big.NewInt(2000))
}

// primeCongruentToOne returns a prime p of the requested bit length with
// p = 1 (mod r), together with the cofactor k = (p-1)/r.
func primeCongruentToOne(r *big.Int, bits int) (p, k *big.Int, err error) {
	kBits := bits - r.BitLen()
	if kBits < 2 {
		return nil, nil, fmt.Errorf("benaloh: block size %s leaves no room in a %d-bit prime", r, bits)
	}

	lo := new(big.Int).Lsh(big.NewInt(1), uint(kBits-1))
	hi := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), uint(kBits)), big.NewInt(1))

	for i := 0; i < 20000; i++ {
		k, err = mathutil.RandRange(lo, hi)
		if err != nil {
			return nil, nil, err
		}
		// p must be odd, and r is an odd prime, so k has to be even.
		k.SetBit(k, 0, 0)
		if k.Sign() == 0 {
			continue
		}
		p = new(big.Int).Mul(k, r)
		p.Add(p, big.NewInt(1))
		if mathutil.IsPrime(p) {
			return p, k, nil
		}
	}
	return nil, nil, fmt.Errorf("benaloh: no prime congruent to 1 modulo %s: %w", r, phe.ErrKeyGeneration)
}

// findGenerator picks y such that x = y^(phi/r) is a non-trivial r-th root of
// unity, which is what makes decryption unambiguous.
func findGenerator(n, phi, r *big.Int, maxTries int) (y, x *big.Int, err error) {
	factors, err := mathutil.PrimeFactors(r)
	if err != nil {
		return nil, nil, err
	}
	one := big.NewInt(1)
	phiOverR := new(big.Int).Div(phi, r)

	for i := 0; i < maxTries; i++ {
		y, err = mathutil.RandRange(big.NewInt(2), n)
		if err != nil {
			return nil, nil, err
		}
		if !mathutil.IsCoprime(y, n) {
			continue
		}

		// y must not be a p-th power for any prime p dividing r, otherwise
		// distinct messages collide during decryption.
		guaranteed := true
		for _, f := range factors {
			e := new(big.Int).Div(phi, f)
			if new(big.Int).Exp(y, e, n).Cmp(one) == 0 {
				guaranteed = false
				break
			}
		}
		if !guaranteed {
			continue
		}

		x = new(big.Int).Exp(y, phiOverR, n)
		if x.Cmp(one) != 0 {
			return y, x, nil
		}
	}
	return nil, nil, fmt.Errorf("benaloh: no suitable generator modulo %s: %w", n, phe.ErrKeyGeneration)
}

// New builds a cryptosystem around an existing key pair.
func New(keys Keys) (*Cryptosystem, error) {
	if err := keys.Validate(); err != nil {
		return nil, err
	}
	if keys.PublicKey.R.Sign() <= 0 {
		return nil, phe.InvalidKeysf("benaloh: r must be positive, got %s", keys.PublicKey.R)
	}

	c := &Cryptosystem{
		Base: phe.Base{Alg: phe.Benaloh},
		keys: keys,
		n:    new(big.Int).Set(keys.PublicKey.N),
		r:    new(big.Int).Set(keys.PublicKey.R),
		y:    new(big.Int).Set(keys.PublicKey.Y),
	}
	if keys.PrivateKey != nil {
		c.phi = new(big.Int).Set(keys.PrivateKey.Phi)
		c.x = new(big.Int).Set(keys.PrivateKey.X)
		c.phiOverR = new(big.Int).Div(c.phi, c.r)
		c.hasSecret = true
	}
	return c, nil
}

// FromJSON rebuilds a cryptosystem from exported key material.
func FromJSON(data []byte) (*Cryptosystem, error) {
	var keys Keys
	if err := json.Unmarshal(data, &keys); err != nil {
		return nil, phe.InvalidKeysf("benaloh: decoding keys: %v", err)
	}
	return New(keys)
}

// Keys returns a copy of the key material.
func (c *Cryptosystem) Keys() Keys { return c.keys }

// PlaintextModulo implements phe.Homomorphic. Benaloh encrypts messages in
// [0, r), which is far smaller than the ciphertext modulus.
func (c *Cryptosystem) PlaintextModulo() *big.Int { return new(big.Int).Set(c.r) }

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
	u, err := mathutil.RandCoprime(c.n)
	if err != nil {
		return nil, fmt.Errorf("benaloh: %w", err)
	}
	return c.EncryptWith(plaintext, u)
}

// EncryptWith encrypts using a caller supplied random key.
func (c *Cryptosystem) EncryptWith(plaintext, random *big.Int) (phe.Value, error) {
	m := new(big.Int).Mod(plaintext, c.r)

	// c = y^m * u^r mod n
	left := new(big.Int).Exp(c.y, m, c.n)
	right := new(big.Int).Exp(random, c.r, c.n)
	return phe.Int{V: left.Mul(left, right).Mod(left, c.n)}, nil
}

// Decrypt implements phe.Homomorphic. It walks the message space until it finds
// the exponent that reproduces the ciphertext, which is why r must stay small.
func (c *Cryptosystem) Decrypt(ciphertext phe.Value) (*big.Int, error) {
	if !c.hasSecret {
		return nil, phe.ErrMissingPrivateKey
	}
	v, err := phe.AsInt(ciphertext)
	if err != nil {
		return nil, err
	}

	target := new(big.Int).Exp(v, c.phiOverR, c.n)

	acc := big.NewInt(1)
	m := new(big.Int)
	one := big.NewInt(1)
	for {
		if acc.Cmp(target) == 0 {
			return m, nil
		}
		m.Add(m, one)
		if m.Cmp(c.r) > 0 {
			return nil, fmt.Errorf("benaloh: cannot restore a message in [0, %s): %w", c.r, phe.ErrDecryptionFailed)
		}
		acc.Mul(acc, c.x).Mod(acc, c.n)
	}
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
	k := new(big.Int).Mod(constant, c.r)
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
