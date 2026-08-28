// Package sanderyoungyung implements the Sander-Young-Yung cryptosystem, which
// is homomorphic with respect to bitwise AND.
//
// Every plaintext bit expands into a vector of l components over the quadratic
// residues modulo n. A one bit is encoded as the all-zero vector and a zero bit
// as a random non-zero vector, so multiplying two vectors componentwise yields
// the all-zero vector only when both inputs were one - exactly the AND truth
// table. The expansion is why ciphertexts are large and l stays small.
//
// Reference: https://sefiks.com/2026/04/02/a-step-by-step-partially-homomorphic-sander-young-yung-example-in-python/
package sanderyoungyung

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

// PublicKey is the Sander-Young-Yung public key. L is the expansion factor.
type PublicKey struct {
	N *big.Int `json:"n"`
	X *big.Int `json:"x"`
	L *big.Int `json:"l"`
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
		return phe.RequireSection(phe.SanderYoungYung, phe.SectionPublic)
	}
	if err := phe.RequireFields(phe.SanderYoungYung, phe.SectionPublic,
		phe.Field("n", k.PublicKey.N != nil),
		phe.Field("x", k.PublicKey.X != nil),
		phe.Field("l", k.PublicKey.L != nil),
	); err != nil {
		return err
	}
	if k.PrivateKey != nil {
		if err := phe.RequireFields(phe.SanderYoungYung, phe.SectionPrivate,
			phe.Field("p", k.PrivateKey.P != nil),
			phe.Field("q", k.PrivateKey.Q != nil),
		); err != nil {
			return err
		}
	}
	return nil
}

// Cryptosystem is a configured Sander-Young-Yung instance. It is immutable and
// safe for concurrent use.
type Cryptosystem struct {
	phe.Base

	keys      Keys
	n, x      *big.Int
	l         int
	lBig      *big.Int
	p, q      *big.Int
	hasSecret bool
}

var _ phe.Homomorphic = (*Cryptosystem)(nil)

// Generate creates a fresh key pair. When plaintextLimit is non-nil the
// expansion factor is sized to cover it.
func Generate(keySize int, plaintextLimit *big.Int, maxTries int) (*Cryptosystem, error) {
	if keySize <= 0 {
		keySize = DefaultKeySize
	}
	if maxTries <= 0 {
		maxTries = DefaultMaxTries
	}

	for attempt := 0; attempt < maxTries; attempt++ {
		p, q, err := mathutil.RandDistinctPrimes(keySize / 2)
		if err != nil {
			return nil, fmt.Errorf("sanderyoungyung: %w", err)
		}
		n := new(big.Int).Mul(p, q)

		l, err := expansionFactor(plaintextLimit)
		if err != nil {
			return nil, err
		}

		x, err := findNonResidue(n, p, q, maxTries/10)
		if err != nil {
			continue
		}
		return New(Keys{
			PublicKey:  &PublicKey{N: n, X: x, L: l},
			PrivateKey: &PrivateKey{P: p, Q: q},
		})
	}
	return nil, fmt.Errorf("sanderyoungyung: no valid key pair after %d attempts: %w", maxTries, phe.ErrKeyGeneration)
}

// expansionFactor picks l, the number of components each plaintext bit expands
// into.
func expansionFactor(plaintextLimit *big.Int) (*big.Int, error) {
	lo, hi := big.NewInt(100), big.NewInt(200)
	if plaintextLimit != nil {
		if plaintextLimit.Sign() < 0 {
			return nil, fmt.Errorf("sanderyoungyung: the plaintext limit must not be negative")
		}
		lo = new(big.Int).Set(plaintextLimit)
		hi = new(big.Int).Add(plaintextLimit, big.NewInt(100))
	}
	return mathutil.RandRange(lo, hi)
}

// findNonResidue picks x that is a non-residue modulo both primes.
func findNonResidue(n, p, q *big.Int, tries int) (*big.Int, error) {
	if tries <= 0 {
		tries = 1000
	}
	for i := 0; i < tries; i++ {
		x, err := mathutil.RandRange(big.NewInt(1), new(big.Int).Sub(n, big.NewInt(1)))
		if err != nil {
			return nil, fmt.Errorf("sanderyoungyung: %w", err)
		}
		if !mathutil.IsCoprime(x, n) {
			continue
		}
		if mathutil.Jacobi(x, p) == -1 && mathutil.Jacobi(x, q) == -1 {
			return x, nil
		}
	}
	return nil, fmt.Errorf("sanderyoungyung: no quadratic non-residue modulo %s: %w", n, phe.ErrKeyGeneration)
}

// New builds a cryptosystem around an existing key pair.
func New(keys Keys) (*Cryptosystem, error) {
	if err := keys.Validate(); err != nil {
		return nil, err
	}
	if !keys.PublicKey.L.IsInt64() || keys.PublicKey.L.Int64() <= 0 {
		return nil, phe.InvalidKeysf("sanderyoungyung: l must be a small positive integer, got %s", keys.PublicKey.L)
	}

	c := &Cryptosystem{
		Base: phe.Base{Alg: phe.SanderYoungYung},
		keys: keys,
		n:    new(big.Int).Set(keys.PublicKey.N),
		x:    new(big.Int).Set(keys.PublicKey.X),
		l:    int(keys.PublicKey.L.Int64()),
		lBig: new(big.Int).Set(keys.PublicKey.L),
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
		return nil, phe.InvalidKeysf("sanderyoungyung: decoding keys: %v", err)
	}
	return New(keys)
}

// Keys returns a copy of the key material.
func (c *Cryptosystem) Keys() Keys { return c.keys }

// PlaintextModulo implements phe.Homomorphic. The reference implementation ties
// the message space to the expansion factor l, so plaintexts are reduced modulo
// l before encryption.
func (c *Cryptosystem) PlaintextModulo() *big.Int { return new(big.Int).Set(c.lBig) }

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

// Encrypt implements phe.Homomorphic. The result is a tuple of per-bit tuples,
// each holding l components.
func (c *Cryptosystem) Encrypt(plaintext *big.Int) (phe.Value, error) {
	bits := new(big.Int).Mod(plaintext, c.lBig).Text(2)

	rows := make([]phe.Value, len(bits))
	for i, bit := range bits {
		row, err := c.encryptBit(bit == '1')
		if err != nil {
			return nil, err
		}
		rows[i] = row
	}
	return phe.Tuple{Items: rows}, nil
}

// encryptBit expands a single bit into its l component vector.
func (c *Cryptosystem) encryptBit(set bool) (phe.Tuple, error) {
	exponents := make([]uint, c.l)
	if !set {
		// A zero bit needs a non-zero vector over Z_2^l.
		for {
			nonZero := false
			for i := range exponents {
				bit, err := mathutil.RandBelow(big.NewInt(2))
				if err != nil {
					return phe.Tuple{}, fmt.Errorf("sanderyoungyung: %w", err)
				}
				exponents[i] = uint(bit.Uint64())
				if exponents[i] == 1 {
					nonZero = true
				}
			}
			if nonZero {
				break
			}
		}
	}

	items := make([]phe.Value, c.l)
	for i := range items {
		y, err := mathutil.RandCoprime(c.n)
		if err != nil {
			return phe.Tuple{}, fmt.Errorf("sanderyoungyung: %w", err)
		}
		component := new(big.Int).Mul(y, y)
		if exponents[i] == 1 {
			component.Mul(component, c.x)
		}
		items[i] = phe.Int{V: component.Mod(component, c.n)}
	}
	return phe.Tuple{Items: items}, nil
}

// Decrypt implements phe.Homomorphic.
func (c *Cryptosystem) Decrypt(ciphertext phe.Value) (*big.Int, error) {
	if !c.hasSecret {
		return nil, phe.ErrMissingPrivateKey
	}
	rows, err := phe.AsTuple(ciphertext)
	if err != nil {
		return nil, err
	}
	if len(rows.Items) == 0 {
		return nil, phe.InvalidCiphertextf("sanderyoungyung: empty ciphertext")
	}

	m := new(big.Int)
	for _, row := range rows.Items {
		components, err := phe.AsTuple(row)
		if err != nil {
			return nil, err
		}
		values, err := components.Ints()
		if err != nil {
			return nil, err
		}
		if len(values) != c.l {
			return nil, phe.InvalidCiphertextf("sanderyoungyung: expected %d components per bit, got %d", c.l, len(values))
		}

		// The bit is one exactly when every component is a quadratic residue,
		// which is what encodes the all-zero vector.
		allResidues := true
		for _, v := range values {
			if mathutil.Jacobi(v, c.p) != 1 || mathutil.Jacobi(v, c.q) != 1 {
				allResidues = false
				break
			}
		}

		m.Lsh(m, 1)
		if allResidues {
			m.SetBit(m, 0, 1)
		}
	}
	return m, nil
}

// And implements phe.Homomorphic. Ciphertexts of different bit lengths are
// left-padded with encryptions of a zero bit.
func (c *Cryptosystem) And(a, b phe.Value) (phe.Value, error) {
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

	rows := make([]phe.Value, len(left.Items))
	for i := range left.Items {
		lhs, err := phe.AsTuple(left.Items[i])
		if err != nil {
			return nil, err
		}
		rhs, err := phe.AsTuple(right.Items[i])
		if err != nil {
			return nil, err
		}
		if len(lhs.Items) != len(rhs.Items) {
			return nil, phe.InvalidCiphertextf("sanderyoungyung: mismatched component counts %d and %d",
				len(lhs.Items), len(rhs.Items))
		}

		items := make([]phe.Value, len(lhs.Items))
		for j := range lhs.Items {
			x, err := phe.AsInt(lhs.Items[j])
			if err != nil {
				return nil, err
			}
			y, err := phe.AsInt(rhs.Items[j])
			if err != nil {
				return nil, err
			}
			product := new(big.Int).Mul(x, y)
			items[j] = phe.Int{V: product.Mod(product, c.n)}
		}
		rows[i] = phe.Tuple{Items: items}
	}
	return phe.Tuple{Items: rows}, nil
}

// align left-pads the shorter ciphertext with encrypted zero bits.
func (c *Cryptosystem) align(a, b phe.Tuple) (phe.Tuple, phe.Tuple, error) {
	pad := func(t phe.Tuple, count int) (phe.Tuple, error) {
		rows := make([]phe.Value, 0, count+len(t.Items))
		for i := 0; i < count; i++ {
			zero, err := c.encryptBit(false)
			if err != nil {
				return phe.Tuple{}, err
			}
			rows = append(rows, zero)
		}
		return phe.Tuple{Items: append(rows, t.Items...)}, nil
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
// fresh quadratic residue.
func (c *Cryptosystem) Reencrypt(ciphertext phe.Value) (phe.Value, error) {
	rows, err := phe.AsTuple(ciphertext)
	if err != nil {
		return nil, err
	}
	out := make([]phe.Value, len(rows.Items))
	for i, row := range rows.Items {
		components, err := phe.AsTuple(row)
		if err != nil {
			return nil, err
		}
		items := make([]phe.Value, len(components.Items))
		for j, item := range components.Items {
			v, err := phe.AsInt(item)
			if err != nil {
				return nil, err
			}
			r, err := mathutil.RandCoprime(c.n)
			if err != nil {
				return nil, fmt.Errorf("sanderyoungyung: %w", err)
			}
			refreshed := new(big.Int).Mul(r, r)
			refreshed.Mul(refreshed, v).Mod(refreshed, c.n)
			items[j] = phe.Int{V: refreshed}
		}
		out[i] = phe.Tuple{Items: items}
	}
	return phe.Tuple{Items: out}, nil
}
