// Package goldwassermicali implements the Goldwasser-Micali cryptosystem, which
// is homomorphic with respect to exclusive or.
//
// Messages are encrypted one bit at a time: a zero bit becomes a quadratic
// residue modulo n and a one bit becomes a non-residue with Jacobi symbol 1.
// Deciding which is which is exactly the quadratic residuosity problem, and it
// is easy once the factorisation of n is known.
//
// Reference: https://sefiks.com/2023/10/27/a-step-by-step-partially-homomorphic-encryption-example-with-goldwasser-micali-in-python/
package goldwassermicali

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

// PublicKey is the Goldwasser-Micali public key. X is a quadratic non-residue
// modulo n with Jacobi symbol 1.
type PublicKey struct {
	N *big.Int `json:"n"`
	X *big.Int `json:"x"`
}

// PrivateKey holds the factorisation of n.
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
		return phe.RequireSection(phe.GoldwasserMicali, phe.SectionPublic)
	}
	if err := phe.RequireFields(phe.GoldwasserMicali, phe.SectionPublic,
		phe.Field("n", k.PublicKey.N != nil),
		phe.Field("x", k.PublicKey.X != nil),
	); err != nil {
		return err
	}
	if k.PrivateKey != nil {
		if err := phe.RequireFields(phe.GoldwasserMicali, phe.SectionPrivate,
			phe.Field("p", k.PrivateKey.P != nil),
			phe.Field("q", k.PrivateKey.Q != nil),
		); err != nil {
			return err
		}
	}
	return nil
}

// Cryptosystem is a configured Goldwasser-Micali instance. It is immutable and
// safe for concurrent use.
type Cryptosystem struct {
	phe.Base

	keys      Keys
	n, x      *big.Int
	p, q      *big.Int
	hasSecret bool
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

	for attempt := 0; attempt < maxTries; attempt++ {
		p, q, err := mathutil.RandDistinctPrimes(keySize / 2)
		if err != nil {
			return nil, fmt.Errorf("goldwassermicali: %w", err)
		}
		n := new(big.Int).Mul(p, q)

		x, err := findNonResidue(n, p, q)
		if err != nil {
			continue
		}
		return New(Keys{
			PublicKey:  &PublicKey{N: n, X: x},
			PrivateKey: &PrivateKey{P: p, Q: q},
		})
	}
	return nil, fmt.Errorf("goldwassermicali: no valid key pair after %d attempts: %w", maxTries, phe.ErrKeyGeneration)
}

// findNonResidue picks x that is a non-residue modulo both primes, so that its
// Jacobi symbol modulo n is 1 while it is not a square.
func findNonResidue(n, p, q *big.Int) (*big.Int, error) {
	for i := 0; i < 1000; i++ {
		x, err := mathutil.RandRange(big.NewInt(2), new(big.Int).Sub(n, big.NewInt(1)))
		if err != nil {
			return nil, fmt.Errorf("goldwassermicali: %w", err)
		}
		if !mathutil.IsCoprime(x, n) {
			continue
		}
		if mathutil.Jacobi(x, p) == -1 && mathutil.Jacobi(x, q) == -1 {
			return x, nil
		}
	}
	return nil, fmt.Errorf("goldwassermicali: no quadratic non-residue modulo %s: %w", n, phe.ErrKeyGeneration)
}

// New builds a cryptosystem around an existing key pair.
func New(keys Keys) (*Cryptosystem, error) {
	if err := keys.Validate(); err != nil {
		return nil, err
	}
	c := &Cryptosystem{
		Base: phe.Base{Alg: phe.GoldwasserMicali},
		keys: keys,
		n:    new(big.Int).Set(keys.PublicKey.N),
		x:    new(big.Int).Set(keys.PublicKey.X),
	}
	if keys.PrivateKey != nil {
		c.p = new(big.Int).Set(keys.PrivateKey.P)
		c.q = new(big.Int).Set(keys.PrivateKey.Q)
		c.hasSecret = true
	}
	return c, nil
}

// FromJSON rebuilds a cryptosystem from exported key material.
func FromJSON(data []byte) (*Cryptosystem, error) {
	var keys Keys
	if err := json.Unmarshal(data, &keys); err != nil {
		return nil, phe.InvalidKeysf("goldwassermicali: decoding keys: %v", err)
	}
	return New(keys)
}

// Keys returns a copy of the key material.
func (c *Cryptosystem) Keys() Keys { return c.keys }

// PlaintextModulo implements phe.Homomorphic. Because messages are encrypted
// bit by bit, integers larger than n survive a round trip; the modulus is
// reported for consistency with the other schemes.
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

// Encrypt implements phe.Homomorphic, producing one ciphertext component per
// bit of the plaintext, most significant bit first.
func (c *Cryptosystem) Encrypt(plaintext *big.Int) (phe.Value, error) {
	bits := new(big.Int).Mod(plaintext, c.n).Text(2)

	items := make([]phe.Value, len(bits))
	for i, bit := range bits {
		component, err := c.encryptBit(bit == '1')
		if err != nil {
			return nil, err
		}
		items[i] = component
	}
	return phe.Tuple{Items: items}, nil
}

// encryptBit encrypts a single bit as r^2 * x^bit mod n.
func (c *Cryptosystem) encryptBit(set bool) (phe.Int, error) {
	r, err := mathutil.RandCoprime(c.n)
	if err != nil {
		return phe.Int{}, fmt.Errorf("goldwassermicali: %w", err)
	}
	v := new(big.Int).Exp(r, big.NewInt(2), c.n)
	if set {
		v.Mul(v, c.x).Mod(v, c.n)
	}
	return phe.Int{V: v}, nil
}

// Decrypt implements phe.Homomorphic.
func (c *Cryptosystem) Decrypt(ciphertext phe.Value) (*big.Int, error) {
	if !c.hasSecret {
		return nil, phe.ErrMissingPrivateKey
	}
	t, err := phe.AsTuple(ciphertext)
	if err != nil {
		return nil, err
	}
	if len(t.Items) == 0 {
		return nil, phe.InvalidCiphertextf("goldwassermicali: empty ciphertext")
	}

	components, err := t.Ints()
	if err != nil {
		return nil, err
	}

	pExp := new(big.Int).Rsh(new(big.Int).Sub(c.p, big.NewInt(1)), 1)
	qExp := new(big.Int).Rsh(new(big.Int).Sub(c.q, big.NewInt(1)), 1)
	one := big.NewInt(1)

	m := new(big.Int)
	for _, component := range components {
		m.Lsh(m, 1)

		// A component is a square modulo n exactly when it is a square modulo
		// both primes, which Euler's criterion decides.
		residueP := new(big.Int).Exp(new(big.Int).Mod(component, c.p), pExp, c.p)
		residueQ := new(big.Int).Exp(new(big.Int).Mod(component, c.q), qExp, c.q)
		if residueP.Cmp(one) != 0 || residueQ.Cmp(one) != 0 {
			m.SetBit(m, 0, 1)
		}
	}
	return m, nil
}

// Xor implements phe.Homomorphic. Ciphertexts of different bit lengths are
// left-padded with encryptions of a zero bit before being combined.
func (c *Cryptosystem) Xor(a, b phe.Value) (phe.Value, error) {
	left, err := phe.AsTuple(a)
	if err != nil {
		return nil, err
	}
	right, err := phe.AsTuple(b)
	if err != nil {
		return nil, err
	}

	if left, right, err = c.align(left, right); err != nil {
		return nil, err
	}

	items := make([]phe.Value, len(left.Items))
	for i := range left.Items {
		x, err := phe.AsInt(left.Items[i])
		if err != nil {
			return nil, err
		}
		y, err := phe.AsInt(right.Items[i])
		if err != nil {
			return nil, err
		}
		product := new(big.Int).Mul(x, y)
		items[i] = phe.Int{V: product.Mod(product, c.n)}
	}
	return phe.Tuple{Items: items}, nil
}

// align left-pads the shorter of two ciphertexts with encrypted zero bits.
func (c *Cryptosystem) align(a, b phe.Tuple) (phe.Tuple, phe.Tuple, error) {
	pad := func(t phe.Tuple, count int) (phe.Tuple, error) {
		items := make([]phe.Value, 0, count+len(t.Items))
		for i := 0; i < count; i++ {
			zero, err := c.encryptBit(false)
			if err != nil {
				return phe.Tuple{}, err
			}
			items = append(items, zero)
		}
		return phe.Tuple{Items: append(items, t.Items...)}, nil
	}

	switch {
	case len(a.Items) > len(b.Items):
		padded, err := pad(b, len(a.Items)-len(b.Items))
		return a, padded, err
	case len(b.Items) > len(a.Items):
		padded, err := pad(a, len(b.Items)-len(a.Items))
		return padded, b, err
	default:
		return a, b, nil
	}
}

// Reencrypt implements phe.Homomorphic by multiplying every component with a
// fresh quadratic residue, which changes the ciphertext but not the bit it
// encodes.
func (c *Cryptosystem) Reencrypt(ciphertext phe.Value) (phe.Value, error) {
	t, err := phe.AsTuple(ciphertext)
	if err != nil {
		return nil, err
	}
	items := make([]phe.Value, len(t.Items))
	for i, item := range t.Items {
		v, err := phe.AsInt(item)
		if err != nil {
			return nil, err
		}
		r, err := mathutil.RandCoprime(c.n)
		if err != nil {
			return nil, fmt.Errorf("goldwassermicali: %w", err)
		}
		refreshed := new(big.Int).Exp(r, big.NewInt(2), c.n)
		refreshed.Mul(refreshed, v).Mod(refreshed, c.n)
		items[i] = phe.Int{V: refreshed}
	}
	return phe.Tuple{Items: items}, nil
}
