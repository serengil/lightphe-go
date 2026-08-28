// Package naccachestern implements the Naccache-Stern cryptosystem, a
// generalisation of Benaloh that is homomorphic with respect to addition.
//
// The message space sigma is the product of a handful of small primes, and
// decryption recovers the message one prime at a time before reassembling it
// with the Chinese remainder theorem. That keeps each discrete logarithm search
// tiny even though sigma itself can be reasonably large.
//
// Reference: https://sefiks.com/2023/10/26/a-step-by-step-partially-homomorphic-encryption-example-with-naccache-stern-in-python/
package naccachestern

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

// smallPrimes is the pool the message space is drawn from. Keeping the factors
// small is what makes decryption tractable.
var smallPrimes = []int64{3, 5, 7, 11, 13, 17, 19, 23}

// primesPerKey is how many of the small primes go into sigma. Half of them end
// up in p-1 and half in q-1.
const primesPerKey = 4

// PublicKey is the Naccache-Stern public key. Sigma bounds the message space.
type PublicKey struct {
	N     *big.Int `json:"n"`
	G     *big.Int `json:"g"`
	Sigma *big.Int `json:"sigma"`
}

// PrivateKey holds the factorisation of n and the seeds it was built from.
type PrivateKey struct {
	A   *big.Int `json:"a"`
	B   *big.Int `json:"b"`
	P   *big.Int `json:"p"`
	Q   *big.Int `json:"q"`
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
		return phe.RequireSection(phe.NaccacheStern, phe.SectionPublic)
	}
	if err := phe.RequireFields(phe.NaccacheStern, phe.SectionPublic,
		phe.Field("n", k.PublicKey.N != nil),
		phe.Field("g", k.PublicKey.G != nil),
		phe.Field("sigma", k.PublicKey.Sigma != nil),
	); err != nil {
		return err
	}
	if k.PrivateKey != nil {
		if err := phe.RequireFields(phe.NaccacheStern, phe.SectionPrivate,
			phe.Field("a", k.PrivateKey.A != nil),
			phe.Field("b", k.PrivateKey.B != nil),
			phe.Field("p", k.PrivateKey.P != nil),
			phe.Field("q", k.PrivateKey.Q != nil),
			phe.Field("phi", k.PrivateKey.Phi != nil),
		); err != nil {
			return err
		}
	}
	return nil
}

// Cryptosystem is a configured Naccache-Stern instance. It is immutable and
// safe for concurrent use.
type Cryptosystem struct {
	phe.Base

	keys          Keys
	n, g, sigma   *big.Int
	phi           *big.Int
	factors       []*big.Int
	deterministic bool
	hasSecret     bool
}

var _ phe.Homomorphic = (*Cryptosystem)(nil)

// Generate creates a fresh probabilistic key pair.
func Generate(keySize, maxTries int) (*Cryptosystem, error) {
	if keySize <= 0 {
		keySize = DefaultKeySize
	}
	if maxTries <= 0 {
		maxTries = DefaultMaxTries
	}
	primeBits := keySize / 2
	if primeBits < 8 {
		return nil, fmt.Errorf("naccachestern: key size %d is too small: %w", keySize, phe.ErrKeyGeneration)
	}
	one := big.NewInt(1)

	for attempt := 0; attempt < maxTries; attempt++ {
		u, v, sigma, err := pickMessageSpace()
		if err != nil {
			return nil, err
		}

		// p = 2*a*u + 1 and q = 2*b*v + 1 guarantee that sigma divides phi.
		// Searching for a and b independently converges far faster than
		// redrawing both whenever either candidate turns out composite.
		a, p, err := seedPrime(u, primeBits)
		if err != nil {
			continue
		}
		b, q, err := seedPrime(v, primeBits)
		if err != nil {
			continue
		}
		if p.Cmp(q) == 0 {
			continue
		}

		n := new(big.Int).Mul(p, q)
		phi := new(big.Int).Mul(new(big.Int).Sub(p, one), new(big.Int).Sub(q, one))

		if new(big.Int).Mod(phi, sigma).Sign() != 0 {
			continue
		}
		if !mathutil.IsCoprime(sigma, new(big.Int).Div(phi, sigma)) {
			continue
		}

		g, err := findGenerator(n, phi, sigma)
		if err != nil {
			continue
		}

		return New(Keys{
			PublicKey:  &PublicKey{N: n, G: g, Sigma: sigma},
			PrivateKey: &PrivateKey{A: a, B: b, P: p, Q: q, Phi: phi},
		})
	}
	return nil, fmt.Errorf("naccachestern: no valid key pair after %d attempts: %w", maxTries, phe.ErrKeyGeneration)
}

// pickMessageSpace draws the small primes and splits them into the two halves
// that shape p-1 and q-1.
func pickMessageSpace() (u, v, sigma *big.Int, err error) {
	chosen, err := sample(smallPrimes, primesPerKey)
	if err != nil {
		return nil, nil, nil, err
	}

	u = big.NewInt(1)
	v = big.NewInt(1)
	for i, prime := range chosen {
		if i < primesPerKey/2 {
			u.Mul(u, big.NewInt(prime))
		} else {
			v.Mul(v, big.NewInt(prime))
		}
	}
	return u, v, new(big.Int).Mul(u, v), nil
}

// sample draws k distinct entries from pool without replacement.
func sample(pool []int64, k int) ([]int64, error) {
	remaining := make([]int64, len(pool))
	copy(remaining, pool)

	out := make([]int64, 0, k)
	for i := 0; i < k; i++ {
		idx, err := mathutil.RandBelow(big.NewInt(int64(len(remaining))))
		if err != nil {
			return nil, fmt.Errorf("naccachestern: %w", err)
		}
		j := idx.Int64()
		out = append(out, remaining[j])
		remaining = append(remaining[:j], remaining[j+1:]...)
	}
	// Keep the halves deterministic for a given draw.
	for i := 0; i < len(out); i++ {
		for j := i + 1; j < len(out); j++ {
			if out[j] < out[i] {
				out[i], out[j] = out[j], out[i]
			}
		}
	}
	return out, nil
}

// seedPrime finds a prime a of the requested size such that 2*a*half + 1 is
// also prime, and returns both.
func seedPrime(half *big.Int, bits int) (seed, prime *big.Int, err error) {
	twoHalf := new(big.Int).Lsh(half, 1)
	one := big.NewInt(1)

	for i := 0; i < 2000; i++ {
		seed, err = mathutil.RandPrime(bits)
		if err != nil {
			return nil, nil, fmt.Errorf("naccachestern: %w", err)
		}
		prime = new(big.Int).Mul(twoHalf, seed)
		prime.Add(prime, one)
		if mathutil.IsPrime(prime) {
			return seed, prime, nil
		}
	}
	return nil, nil, fmt.Errorf("naccachestern: no seed prime for half %s: %w", half, phe.ErrKeyGeneration)
}

// findGenerator picks g coprime to n that is not a p-th power for any prime p
// dividing sigma.
func findGenerator(n, phi, sigma *big.Int) (*big.Int, error) {
	factors, err := mathutil.PrimeFactors(sigma)
	if err != nil {
		return nil, err
	}
	one := big.NewInt(1)

	for i := 0; i < 1000; i++ {
		g, err := mathutil.RandRange(big.NewInt(2), new(big.Int).Sub(n, one))
		if err != nil {
			return nil, fmt.Errorf("naccachestern: %w", err)
		}
		if !mathutil.IsCoprime(g, n) {
			continue
		}
		usable := true
		for _, f := range factors {
			e := new(big.Int).Div(phi, f)
			if new(big.Int).Exp(g, e, n).Cmp(one) == 0 {
				usable = false
				break
			}
		}
		if usable {
			return g, nil
		}
	}
	return nil, fmt.Errorf("naccachestern: no suitable generator modulo %s: %w", n, phe.ErrKeyGeneration)
}

// New builds a probabilistic cryptosystem around an existing key pair.
func New(keys Keys) (*Cryptosystem, error) { return NewWithMode(keys, false) }

// NewWithMode builds a cryptosystem and selects the deterministic variant, in
// which encryption drops the random blinding factor. The deterministic variant
// leaks equality of plaintexts and cannot re-randomise ciphertexts; prefer the
// probabilistic one unless you have a specific reason not to.
func NewWithMode(keys Keys, deterministic bool) (*Cryptosystem, error) {
	if err := keys.Validate(); err != nil {
		return nil, err
	}
	if keys.PublicKey.Sigma.Sign() <= 0 {
		return nil, phe.InvalidKeysf("naccachestern: sigma must be positive, got %s", keys.PublicKey.Sigma)
	}
	factors, err := mathutil.PrimeFactors(keys.PublicKey.Sigma)
	if err != nil {
		return nil, phe.InvalidKeysf("naccachestern: sigma is not smooth: %v", err)
	}

	c := &Cryptosystem{
		Base:          phe.Base{Alg: phe.NaccacheStern},
		keys:          keys,
		n:             new(big.Int).Set(keys.PublicKey.N),
		g:             new(big.Int).Set(keys.PublicKey.G),
		sigma:         new(big.Int).Set(keys.PublicKey.Sigma),
		factors:       factors,
		deterministic: deterministic,
	}
	if keys.PrivateKey != nil {
		c.phi = new(big.Int).Set(keys.PrivateKey.Phi)
		c.hasSecret = true
	}
	return c, nil
}

// FromJSON rebuilds a cryptosystem from exported key material.
func FromJSON(data []byte) (*Cryptosystem, error) {
	var keys Keys
	if err := json.Unmarshal(data, &keys); err != nil {
		return nil, phe.InvalidKeysf("naccachestern: decoding keys: %v", err)
	}
	return New(keys)
}

// Keys returns a copy of the key material.
func (c *Cryptosystem) Keys() Keys { return c.keys }

// PlaintextModulo implements phe.Homomorphic.
func (c *Cryptosystem) PlaintextModulo() *big.Int { return new(big.Int).Set(c.sigma) }

// CiphertextModulo implements phe.Homomorphic.
func (c *Cryptosystem) CiphertextModulo() *big.Int { return new(big.Int).Set(c.n) }

// HasPrivateKey implements phe.Homomorphic.
func (c *Cryptosystem) HasPrivateKey() bool { return c.hasSecret }

// PublicOnly implements phe.Homomorphic.
func (c *Cryptosystem) PublicOnly() (phe.Homomorphic, error) {
	return NewWithMode(Keys{PublicKey: c.keys.PublicKey}, c.deterministic)
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
		return nil, fmt.Errorf("naccachestern: %w", err)
	}
	return c.EncryptWith(plaintext, r)
}

// EncryptWith encrypts using a caller supplied random key.
func (c *Cryptosystem) EncryptWith(plaintext, random *big.Int) (phe.Value, error) {
	m := new(big.Int).Mod(plaintext, c.sigma)

	powered := new(big.Int).Exp(c.g, m, c.n)
	if c.deterministic {
		return phe.Int{V: powered}, nil
	}
	blind := new(big.Int).Exp(random, c.sigma, c.n)
	return phe.Int{V: powered.Mul(powered, blind).Mod(powered, c.n)}, nil
}

// Decrypt implements phe.Homomorphic. The message is recovered modulo each
// small prime factor of sigma and reassembled with the Chinese remainder
// theorem.
func (c *Cryptosystem) Decrypt(ciphertext phe.Value) (*big.Int, error) {
	if !c.hasSecret {
		return nil, phe.ErrMissingPrivateKey
	}
	v, err := phe.AsInt(ciphertext)
	if err != nil {
		return nil, err
	}

	residues := make([]*big.Int, len(c.factors))
	moduli := make([]*big.Int, len(c.factors))

	for i, prime := range c.factors {
		exponent := new(big.Int).Div(c.phi, prime)
		target := new(big.Int).Exp(v, exponent, c.n)
		base := new(big.Int).Exp(c.g, exponent, c.n)

		residue, err := c.discreteLog(target, base, prime)
		if err != nil {
			return nil, err
		}
		residues[i] = residue
		moduli[i] = prime
	}

	m, _, err := mathutil.CRT(residues, moduli)
	if err != nil {
		return nil, fmt.Errorf("naccachestern: %v: %w", err, phe.ErrDecryptionFailed)
	}
	return m, nil
}

// discreteLog finds j in [0, prime) with base^j == target modulo n.
func (c *Cryptosystem) discreteLog(target, base, prime *big.Int) (*big.Int, error) {
	acc := big.NewInt(1)
	j := new(big.Int)
	one := big.NewInt(1)
	for {
		if acc.Cmp(target) == 0 {
			return new(big.Int).Set(j), nil
		}
		j.Add(j, one)
		if j.Cmp(prime) >= 0 {
			return nil, fmt.Errorf("naccachestern: cannot recover the residue modulo %s: %w", prime, phe.ErrDecryptionFailed)
		}
		acc.Mul(acc, base).Mod(acc, c.n)
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
	k := new(big.Int).Mod(constant, c.sigma)
	return phe.Int{V: new(big.Int).Exp(v, k, c.n)}, nil
}

// Reencrypt implements phe.Homomorphic. The deterministic variant has no
// randomness to refresh, so it reports the operation as unsupported.
func (c *Cryptosystem) Reencrypt(ciphertext phe.Value) (phe.Value, error) {
	if c.deterministic {
		return nil, fmt.Errorf("naccachestern: the deterministic variant cannot re-encrypt; build the probabilistic one instead: %w",
			phe.ErrUnsupportedOperation)
	}
	zero, err := c.Encrypt(new(big.Int))
	if err != nil {
		return nil, err
	}
	return c.Add(ciphertext, zero)
}
