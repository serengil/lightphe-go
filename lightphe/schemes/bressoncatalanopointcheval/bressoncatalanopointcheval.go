// Package bressoncatalanopointcheval implements the Bresson-Catalano-
// Pointcheval cryptosystem, which is homomorphic with respect to addition and
// supports multiplying a ciphertext by a known plain constant.
//
// It is an ElGamal-like scheme in Z_{n^2}* with a double trapdoor decryption
// mechanism. A ciphertext can be decrypted either with the secret exponent a
// (local trapdoor), or with the factorization of n (master trapdoor) without
// knowing a. An authority holding the master key publishes n and g, then every
// user generates its own key pair on top of them. The authority can decrypt
// ciphertexts of all those users, so this is a key escrow mechanism by design.
//
// Reference: Bresson, E., Catalano, D., Pointcheval, D. (2003). A Simple
// Public-Key Cryptosystem with a Double Trapdoor Decryption Mechanism and Its
// Applications. ASIACRYPT 2003.
package bressoncatalanopointcheval

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

// PublicKey is the Bresson-Catalano-Pointcheval public key. N and G are shared
// by all users of a master key, and H = g^a is specific to a user.
type PublicKey struct {
	N *big.Int `json:"n"`
	G *big.Int `json:"g"`
	H *big.Int `json:"h"`
}

// PrivateKey holds the local trapdoor a and the master trapdoor p, q. A user
// has the local trapdoor only, and an authority may keep the master trapdoor
// only.
type PrivateKey struct {
	A *big.Int `json:"a,omitempty"`
	P *big.Int `json:"p,omitempty"`
	Q *big.Int `json:"q,omitempty"`
}

// Keys bundles the key pair. PrivateKey is nil for encryption-only setups.
type Keys struct {
	PublicKey  *PublicKey  `json:"public_key,omitempty"`
	PrivateKey *PrivateKey `json:"private_key,omitempty"`
}

// Validate reports missing or malformed key material.
func (k Keys) Validate() error {
	if k.PublicKey == nil {
		return phe.RequireSection(phe.BressonCatalanoPointcheval, phe.SectionPublic)
	}
	if err := phe.RequireFields(phe.BressonCatalanoPointcheval, phe.SectionPublic,
		phe.Field("n", k.PublicKey.N != nil),
		phe.Field("g", k.PublicKey.G != nil),
		phe.Field("h", k.PublicKey.H != nil),
	); err != nil {
		return err
	}
	if k.PrivateKey != nil {
		// authority may keep the master trapdoor only
		return phe.RequireFieldsOrAlternative(phe.BressonCatalanoPointcheval, phe.SectionPrivate,
			[]phe.FieldPresence{phe.Field("a", k.PrivateKey.A != nil)},
			[]phe.FieldPresence{phe.Field("p", k.PrivateKey.P != nil), phe.Field("q", k.PrivateKey.Q != nil)},
		)
	}
	return nil
}

// Cryptosystem is a configured Bresson-Catalano-Pointcheval instance. It is
// immutable and safe for concurrent use.
type Cryptosystem struct {
	phe.Base

	keys        Keys
	n, nSquared *big.Int
	g, h        *big.Int
	a           *big.Int
	p, q        *big.Int
	hasSecret   bool
}

var (
	_ phe.Homomorphic        = (*Cryptosystem)(nil)
	_ phe.MasterKeyDecrypter = (*Cryptosystem)(nil)
)

// Generate creates a fresh key pair with a modulus of keySize bits. The
// private key has both the local and the master trapdoor.
func Generate(keySize, maxTries int) (*Cryptosystem, error) {
	if keySize <= 0 {
		keySize = DefaultKeySize
	}
	if maxTries <= 0 {
		maxTries = DefaultMaxTries
	}
	if keySize < 16 {
		return nil, fmt.Errorf("bressoncatalanopointcheval: key size %d is too small: %w", keySize, phe.ErrKeyGeneration)
	}

	// p = 2p' + 1 and q = 2q' + 1 are safe primes
	p, q, err := mathutil.RandDistinctSafePrimes(keySize/2, maxTries)
	if err != nil {
		return nil, fmt.Errorf("bressoncatalanopointcheval: %v: %w", err, phe.ErrKeyGeneration)
	}
	one := big.NewInt(1)
	n := new(big.Int).Mul(p, q)
	nSquared := new(big.Int).Mul(n, n)
	pPrime := new(big.Int).Rsh(p, 1)
	qPrime := new(big.Int).Rsh(q, 1)
	order := new(big.Int).Mul(pPrime, qPrime)

	// g is a square in Z_{n^2}* of maximal order, so that g^(p'q') = 1 + kn mod
	// n^2 for some k co-prime to n. k is required by the master trapdoor.
	var g *big.Int
	for i := 0; i < maxTries; i++ {
		alpha, err := mathutil.RandRange(big.NewInt(2), new(big.Int).Sub(nSquared, one))
		if err != nil {
			return nil, err
		}
		if !mathutil.IsCoprime(alpha, n) {
			continue
		}
		candidate := new(big.Int).Exp(alpha, big.NewInt(2), nSquared)
		k := new(big.Int).Exp(candidate, order, nSquared)
		k.Sub(k, one).Quo(k, n)
		if mathutil.IsCoprime(k, n) &&
			new(big.Int).Exp(candidate, pPrime, n).Cmp(one) != 0 &&
			new(big.Int).Exp(candidate, qPrime, n).Cmp(one) != 0 {
			g = candidate
			break
		}
	}
	if g == nil {
		return nil, fmt.Errorf("bressoncatalanopointcheval: no suitable generator in %d tries: %w", maxTries, phe.ErrKeyGeneration)
	}

	// local trapdoor
	a, h, err := localTrapdoor(nSquared, g)
	if err != nil {
		return nil, err
	}

	return New(Keys{
		PublicKey:  &PublicKey{N: n, G: g, H: h},
		PrivateKey: &PrivateKey{A: a, P: p, Q: q},
	})
}

// localTrapdoor draws a in [1, n^2 / 2] and returns it together with h = g^a.
func localTrapdoor(nSquared, g *big.Int) (*big.Int, *big.Int, error) {
	a, err := mathutil.RandRange(big.NewInt(1), new(big.Int).Rsh(nSquared, 1))
	if err != nil {
		return nil, nil, err
	}
	return a, new(big.Int).Exp(g, a, nSquared), nil
}

// New builds a cryptosystem around an existing key pair.
func New(keys Keys) (*Cryptosystem, error) {
	if err := keys.Validate(); err != nil {
		return nil, err
	}
	n := new(big.Int).Set(keys.PublicKey.N)
	c := &Cryptosystem{
		Base:     phe.Base{Alg: phe.BressonCatalanoPointcheval},
		keys:     keys,
		n:        n,
		nSquared: new(big.Int).Mul(n, n),
		g:        new(big.Int).Set(keys.PublicKey.G),
		h:        new(big.Int).Set(keys.PublicKey.H),
	}
	if sk := keys.PrivateKey; sk != nil {
		if sk.A != nil {
			c.a = new(big.Int).Set(sk.A)
		}
		if sk.P != nil && sk.Q != nil {
			c.p = new(big.Int).Set(sk.P)
			c.q = new(big.Int).Set(sk.Q)
		}
		c.hasSecret = true
	}
	return c, nil
}

// FromJSON rebuilds a cryptosystem from exported key material.
func FromJSON(data []byte) (*Cryptosystem, error) {
	var keys Keys
	if err := json.Unmarshal(data, &keys); err != nil {
		return nil, phe.InvalidKeysf("bressoncatalanopointcheval: decoding keys: %v", err)
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

// GenerateUserKeys implements phe.MasterKeyDecrypter. It generates a key pair
// for a new user sharing n and g of this cryptosystem, and requires the public
// key only. The private key of the new user has its local trapdoor only.
func (c *Cryptosystem) GenerateUserKeys() ([]byte, error) {
	a, h, err := localTrapdoor(c.nSquared, c.g)
	if err != nil {
		return nil, err
	}
	return json.Marshal(Keys{
		PublicKey:  &PublicKey{N: c.n, G: c.g, H: h},
		PrivateKey: &PrivateKey{A: a},
	})
}

// Encrypt implements phe.Homomorphic, producing A = g^r mod n^2 and
// B = h^r (1 + mn) mod n^2.
func (c *Cryptosystem) Encrypt(plaintext *big.Int) (phe.Value, error) {
	r, err := mathutil.RandRange(big.NewInt(1), new(big.Int).Sub(c.nSquared, big.NewInt(1)))
	if err != nil {
		return nil, fmt.Errorf("bressoncatalanopointcheval: %w", err)
	}
	return c.EncryptWith(plaintext, r), nil
}

// EncryptWith encrypts using a caller supplied random key.
func (c *Cryptosystem) EncryptWith(plaintext, random *big.Int) phe.Value {
	m := new(big.Int).Mod(plaintext, c.n)
	aPart := new(big.Int).Exp(c.g, random, c.nSquared)
	bPart := new(big.Int).Exp(c.h, random, c.nSquared)
	m.Mul(m, c.n).Add(m, big.NewInt(1))
	bPart.Mul(bPart, m).Mod(bPart, c.nSquared)
	return phe.NewTuple(phe.Int{V: aPart}, phe.Int{V: bPart})
}

// Decrypt implements phe.Homomorphic with the local trapdoor a.
func (c *Cryptosystem) Decrypt(ciphertext phe.Value) (*big.Int, error) {
	if !c.hasSecret {
		return nil, phe.ErrMissingPrivateKey
	}
	if c.a == nil {
		return nil, fmt.Errorf("bressoncatalanopointcheval: private key does not have the local trapdoor a, "+
			"use DecryptWithMasterKey if you have the master key: %w", phe.ErrMissingPrivateKey)
	}
	aPart, bPart, err := c.parse(ciphertext)
	if err != nil {
		return nil, err
	}

	// B / A^a = (1 + mn) mod n^2
	mask, err := mathutil.ModInverse(new(big.Int).Exp(aPart, c.a, c.nSquared), c.nSquared)
	if err != nil {
		return nil, fmt.Errorf("bressoncatalanopointcheval: %v: %w", err, phe.ErrDecryptionFailed)
	}
	restored := mask.Mul(mask, bPart).Mod(mask, c.nSquared)
	return c.l(restored), nil
}

// DecryptWithMasterKey implements phe.MasterKeyDecrypter with the master
// trapdoor, which is the factorization of n. It does not require the local
// trapdoor a, so it decrypts ciphertexts of any key pair sharing n and g.
func (c *Cryptosystem) DecryptWithMasterKey(ciphertext phe.Value, owner phe.Homomorphic) (*big.Int, error) {
	if c.p == nil || c.q == nil {
		return nil, fmt.Errorf("bressoncatalanopointcheval: private key does not have the master trapdoor p and q: %w",
			phe.ErrMissingPrivateKey)
	}

	h := c.h
	if owner != nil {
		user, ok := owner.(*Cryptosystem)
		if !ok {
			return nil, phe.InvalidCiphertextf("bressoncatalanopointcheval: ciphertext of %s cannot be decrypted with a master key",
				owner.Algorithm())
		}
		if user.n.Cmp(c.n) != 0 || user.g.Cmp(c.g) != 0 {
			return nil, phe.InvalidCiphertextf("bressoncatalanopointcheval: ciphertext was not encrypted for a user of this " +
				"master key as it does not share the same n and g")
		}
		h = user.h
	}

	aPart, bPart, err := c.parse(ciphertext)
	if err != nil {
		return nil, err
	}

	order := new(big.Int).Mul(new(big.Int).Rsh(c.p, 1), new(big.Int).Rsh(c.q, 1))
	pow := func(x *big.Int) *big.Int { return new(big.Int).Exp(x, order, c.nSquared) }

	// g^(p'q') = 1 + kn, so x^(p'q') = 1 + (log_g x) k n for any power x of g
	kInv, err := mathutil.ModInverse(c.l(pow(c.g)), c.n)
	if err != nil {
		return nil, fmt.Errorf("bressoncatalanopointcheval: %v: %w", err, phe.ErrDecryptionFailed)
	}
	aModN := new(big.Int).Mul(c.l(pow(h)), kInv)
	aModN.Mod(aModN, c.n)
	rModN := new(big.Int).Mul(c.l(pow(aPart)), kInv)
	rModN.Mod(rModN, c.n)
	gamma := aModN.Mul(aModN, rModN).Mod(aModN, c.n)

	// B / g^gamma = g^(n t) (1 + mn) for some t, and g^(n t p'q') = 1 mod n^2
	mask, err := mathutil.ModInverse(new(big.Int).Exp(c.g, gamma, c.nSquared), c.nSquared)
	if err != nil {
		return nil, fmt.Errorf("bressoncatalanopointcheval: %v: %w", err, phe.ErrDecryptionFailed)
	}
	masked := mask.Mul(mask, bPart).Mod(mask, c.nSquared)
	orderInv, err := mathutil.ModInverse(order, c.n)
	if err != nil {
		return nil, fmt.Errorf("bressoncatalanopointcheval: %v: %w", err, phe.ErrDecryptionFailed)
	}
	m := c.l(pow(masked))
	return m.Mul(m, orderInv).Mod(m, c.n), nil
}

// Add implements phe.Homomorphic.
func (c *Cryptosystem) Add(a, b phe.Value) (phe.Value, error) {
	a1, b1, err := c.parse(a)
	if err != nil {
		return nil, err
	}
	a2, b2, err := c.parse(b)
	if err != nil {
		return nil, err
	}
	aPart := new(big.Int).Mul(a1, a2)
	bPart := new(big.Int).Mul(b1, b2)
	return phe.NewTuple(phe.Int{V: aPart.Mod(aPart, c.nSquared)}, phe.Int{V: bPart.Mod(bPart, c.nSquared)}), nil
}

// MultiplyByConstant implements phe.Homomorphic.
func (c *Cryptosystem) MultiplyByConstant(ciphertext phe.Value, constant *big.Int) (phe.Value, error) {
	aPart, bPart, err := c.parse(ciphertext)
	if err != nil {
		return nil, err
	}
	k := new(big.Int).Mod(constant, c.n)
	return phe.NewTuple(
		phe.Int{V: new(big.Int).Exp(aPart, k, c.nSquared)},
		phe.Int{V: new(big.Int).Exp(bPart, k, c.nSquared)},
	), nil
}

// Reencrypt implements phe.Homomorphic by adding an encryption of zero.
func (c *Cryptosystem) Reencrypt(ciphertext phe.Value) (phe.Value, error) {
	zero, err := c.Encrypt(new(big.Int))
	if err != nil {
		return nil, err
	}
	return c.Add(ciphertext, zero)
}

// l is the L function of Paillier-like schemes: (x - 1) / n.
func (c *Cryptosystem) l(x *big.Int) *big.Int {
	r := new(big.Int).Sub(x, big.NewInt(1))
	return r.Quo(r, c.n)
}

func (c *Cryptosystem) parse(v phe.Value) (*big.Int, *big.Int, error) {
	first, second, err := phe.AsPair(v)
	if err != nil {
		return nil, nil, err
	}
	aPart, err := phe.AsInt(first)
	if err != nil {
		return nil, nil, err
	}
	bPart, err := phe.AsInt(second)
	if err != nil {
		return nil, nil, err
	}
	return aPart, bPart, nil
}
