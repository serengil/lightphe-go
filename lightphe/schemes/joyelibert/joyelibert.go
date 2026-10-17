// Package joyelibert implements the Joye-Libert cryptosystem, which is
// homomorphic with respect to addition and supports multiplying a ciphertext
// by a known plain constant.
//
// It generalises Goldwasser-Micali from 1 bit to k bit messages by using
// 2^k-th power residue symbols, so messages live in Z_{2^k}. Decryption
// restores the message bit by bit without any brute force.
//
// Reference: Joye, M., Libert, B. (2013). Efficient Cryptosystems from 2^k-th
// Power Residue Symbols. EUROCRYPT 2013. https://eprint.iacr.org/2013/435
package joyelibert

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

// ErrFloatNotSupported reports a float plaintext or constant. Floats are
// represented as dividend * divisor^-1 where the divisor is a power of 10, but
// powers of 10 are not invertible in the plaintext space Z_{2^k}.
var ErrFloatNotSupported = phe.FloatNotSupported("lightphe: Joye-Libert does not support float values because its " +
	"plaintext space is Z_{2^k} where powers of 10 have no modular inverse. Use integers instead")

// PublicKey is the Joye-Libert public key. Y is a quadratic non-residue modulo
// both primes and K fixes the message space Z_{2^k}.
type PublicKey struct {
	N *big.Int `json:"n"`
	Y *big.Int `json:"y"`
	K *big.Int `json:"k"`
}

// PrivateKey is the prime p with p = 1 mod 2^k.
type PrivateKey struct {
	P *big.Int `json:"p"`
}

// Keys bundles the key pair. PrivateKey is nil for encryption-only setups.
type Keys struct {
	PublicKey  *PublicKey  `json:"public_key,omitempty"`
	PrivateKey *PrivateKey `json:"private_key,omitempty"`
}

// Validate reports missing or malformed key material.
func (k Keys) Validate() error {
	if k.PublicKey == nil {
		return phe.RequireSection(phe.JoyeLibert, phe.SectionPublic)
	}
	if err := phe.RequireFields(phe.JoyeLibert, phe.SectionPublic,
		phe.Field("n", k.PublicKey.N != nil),
		phe.Field("y", k.PublicKey.Y != nil),
		phe.Field("k", k.PublicKey.K != nil),
	); err != nil {
		return err
	}
	if k.PrivateKey != nil {
		if err := phe.RequireFields(phe.JoyeLibert, phe.SectionPrivate,
			phe.Field("p", k.PrivateKey.P != nil),
		); err != nil {
			return err
		}
	}
	return nil
}

// Cryptosystem is a configured Joye-Libert instance. It is immutable and safe
// for concurrent use.
type Cryptosystem struct {
	phe.Base

	keys      Keys
	n, y      *big.Int
	k         int
	twoK      *big.Int // 2^k, the plaintext modulus
	p         *big.Int
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
	one := big.NewInt(1)
	primeSize := keySize / 2

	// message space is Z_{2^k}. p - 1 must be divisible by 2^k, and the
	// remaining part of p must be large enough to keep factoring n hard.
	k := keySize / 4
	if k < 1 {
		k = 1
	}
	twoK := new(big.Int).Lsh(one, uint(k))

	// picking a prime p such that p = 1 mod 2^k
	var p *big.Int
	lo := new(big.Int).Lsh(one, uint(primeSize-k-1))
	hi := new(big.Int).Sub(new(big.Int).Lsh(one, uint(primeSize-k)), one)
	for i := 0; i < maxTries; i++ {
		t, err := mathutil.RandRange(lo, hi)
		if err != nil {
			return nil, fmt.Errorf("joyelibert: %w", err)
		}
		candidate := new(big.Int).Mul(t, twoK)
		candidate.Add(candidate, one)
		if mathutil.IsPrime(candidate) {
			p = candidate
			break
		}
	}
	if p == nil {
		return nil, fmt.Errorf("joyelibert: no prime p = 1 mod 2^%d after %d attempts: %w", k, maxTries, phe.ErrKeyGeneration)
	}

	// picking a prime modulus q
	var q *big.Int
	for {
		candidate, err := mathutil.RandPrime(primeSize)
		if err != nil {
			return nil, fmt.Errorf("joyelibert: %w", err)
		}
		if candidate.Cmp(p) != 0 {
			q = candidate
			break
		}
	}

	n := new(big.Int).Mul(p, q)

	// y must be a quadratic non-residue modulo both p and q,
	// so y is in J_n \ QR_n (jacobi symbol 1 but not a square)
	for i := 0; i < maxTries; i++ {
		y, err := mathutil.RandRange(big.NewInt(2), new(big.Int).Sub(n, one))
		if err != nil {
			return nil, fmt.Errorf("joyelibert: %w", err)
		}
		if !mathutil.IsCoprime(y, n) {
			continue
		}
		if mathutil.Jacobi(y, p) == -1 && mathutil.Jacobi(y, q) == -1 {
			return New(Keys{
				PublicKey:  &PublicKey{N: n, Y: y, K: big.NewInt(int64(k))},
				PrivateKey: &PrivateKey{P: p},
			})
		}
	}
	return nil, fmt.Errorf("joyelibert: no suitable y after %d attempts: %w", maxTries, phe.ErrKeyGeneration)
}

// New builds a cryptosystem around an existing key pair.
func New(keys Keys) (*Cryptosystem, error) {
	if err := keys.Validate(); err != nil {
		return nil, err
	}
	if keys.PublicKey.K.Sign() <= 0 || !keys.PublicKey.K.IsInt64() {
		return nil, phe.InvalidKeysf("joyelibert: k must be a positive integer, got %s", keys.PublicKey.K)
	}
	k := int(keys.PublicKey.K.Int64())

	c := &Cryptosystem{
		Base: phe.Base{Alg: phe.JoyeLibert},
		keys: keys,
		n:    new(big.Int).Set(keys.PublicKey.N),
		y:    new(big.Int).Set(keys.PublicKey.Y),
		k:    k,
		twoK: new(big.Int).Lsh(big.NewInt(1), uint(k)),
	}
	if keys.PrivateKey != nil {
		c.p = new(big.Int).Set(keys.PrivateKey.P)
		c.hasSecret = true
	}
	return c, nil
}

// FromJSON rebuilds a cryptosystem from exported key material.
func FromJSON(data []byte) (*Cryptosystem, error) {
	var keys Keys
	if err := json.Unmarshal(data, &keys); err != nil {
		return nil, phe.InvalidKeysf("joyelibert: decoding keys: %v", err)
	}
	return New(keys)
}

// Keys returns a copy of the key material.
func (c *Cryptosystem) Keys() Keys { return c.keys }

// PlaintextModulo implements phe.Homomorphic.
func (c *Cryptosystem) PlaintextModulo() *big.Int { return new(big.Int).Set(c.twoK) }

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
	x, err := mathutil.RandCoprime(c.n)
	if err != nil {
		return nil, fmt.Errorf("joyelibert: %w", err)
	}
	return c.EncryptWith(plaintext, x)
}

// EncryptWith encrypts using a caller supplied random key coprime to n.
func (c *Cryptosystem) EncryptWith(plaintext, random *big.Int) (phe.Value, error) {
	m := new(big.Int).Mod(plaintext, c.twoK)

	// c = y^m * x^(2^k) mod n
	left := new(big.Int).Exp(c.y, m, c.n)
	right := new(big.Int).Exp(random, c.twoK, c.n)
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
	one := big.NewInt(1)
	exponent := new(big.Int).Sub(c.p, one)
	exponent.Rsh(exponent, uint(c.k))

	// z = D^m mod p where D = y^((p-1)/2^k) has order exactly 2^k,
	// so m can be restored bit by bit
	z := new(big.Int).Exp(v, exponent, c.p)
	dInv, err := mathutil.ModInverse(new(big.Int).Exp(c.y, exponent, c.p), c.p)
	if err != nil {
		return nil, fmt.Errorf("joyelibert: %v: %w", err, phe.ErrDecryptionFailed)
	}

	m := new(big.Int)
	b := big.NewInt(1)
	for j := 1; j < c.k; j++ {
		power := new(big.Int).Lsh(one, uint(c.k-j))
		if new(big.Int).Exp(z, power, c.p).Cmp(one) != 0 {
			m.Add(m, b)
			z.Mul(z, dInv).Mod(z, c.p)
		}
		b.Lsh(b, 1)
		dInv.Mul(dInv, dInv).Mod(dInv, c.p)
	}

	if z.Cmp(one) != 0 {
		m.Add(m, b)
	}
	return m, nil
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
	k := new(big.Int).Mod(constant, c.twoK)
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
