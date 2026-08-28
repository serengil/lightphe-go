// Package ecelgamal implements elliptic curve ElGamal, which is homomorphic
// with respect to addition.
//
// A message m is embedded as the curve point m*G, so decryption ends in an
// elliptic curve discrete logarithm. That is only tractable for small
// plaintexts, which is the usual trade-off for additively homomorphic ECC
// schemes.
//
// Reference: https://sefiks.com/2018/08/21/elliptic-curve-elgamal-encryption/
package ecelgamal

import (
	"encoding/json"
	"fmt"
	"math/big"

	"github.com/serengil/lightphe-go/lightphe/ecc"
	"github.com/serengil/lightphe-go/lightphe/ecc/curves"
	"github.com/serengil/lightphe-go/lightphe/internal/mathutil"
	"github.com/serengil/lightphe-go/lightphe/phe"
)

// PublicKey is the elliptic curve ElGamal public key: the point Qa = ka*G.
type PublicKey struct {
	Qa *phe.Point `json:"Qa"`
}

// PrivateKey is the secret scalar ka.
type PrivateKey struct {
	Ka *big.Int `json:"ka"`
}

// Keys bundles the key pair together with the curve the keys live on. Form and
// Curve are carried alongside the key material so that an exported key file is
// self-describing.
type Keys struct {
	PublicKey  *PublicKey  `json:"public_key,omitempty"`
	PrivateKey *PrivateKey `json:"private_key,omitempty"`
	Form       string      `json:"form,omitempty"`
	Curve      string      `json:"curve,omitempty"`
}

// Validate reports missing or malformed key material.
func (k Keys) Validate() error {
	if k.PublicKey == nil {
		return phe.RequireSection(phe.EllipticCurveElGamal, phe.SectionPublic)
	}
	if err := phe.RequireFields(phe.EllipticCurveElGamal, phe.SectionPublic,
		phe.Field("Qa", k.PublicKey.Qa != nil),
	); err != nil {
		return err
	}
	if k.PrivateKey != nil {
		if err := phe.RequireFields(phe.EllipticCurveElGamal, phe.SectionPrivate,
			phe.Field("ka", k.PrivateKey.Ka != nil),
		); err != nil {
			return err
		}
	}
	return nil
}

// Cryptosystem is a configured elliptic curve ElGamal instance. It is immutable
// and safe for concurrent use.
type Cryptosystem struct {
	phe.Base

	keys      Keys
	ec        *ecc.ECC
	qa        ecc.Point
	ka        *big.Int
	hasSecret bool
}

var _ phe.Homomorphic = (*Cryptosystem)(nil)

// Generate creates a fresh key pair on the given curve. An empty form defaults
// to Weierstrass and an empty curve name to that form's standard curve; a
// keySize of zero sizes the private scalar to the curve order.
func Generate(keySize int, form, curve string) (*Cryptosystem, error) {
	ec, err := ecc.New(curves.Form(form), curve)
	if err != nil {
		return nil, fmt.Errorf("ecelgamal: %w", err)
	}
	if keySize <= 0 {
		keySize = ec.N().BitLen()
	}

	ka, err := mathutil.RandBits(keySize)
	if err != nil {
		return nil, fmt.Errorf("ecelgamal: %w", err)
	}
	qa, err := ec.G().ScalarMul(ka)
	if err != nil {
		return nil, fmt.Errorf("ecelgamal: deriving the public key: %w", err)
	}
	x, y := qa.Coordinates()

	return New(Keys{
		PublicKey:  &PublicKey{Qa: &phe.Point{X: x, Y: y}},
		PrivateKey: &PrivateKey{Ka: ka},
		Form:       form,
		Curve:      curve,
	})
}

// New builds a cryptosystem around an existing key pair. The curve is taken
// from the keys themselves.
func New(keys Keys) (*Cryptosystem, error) {
	if err := keys.Validate(); err != nil {
		return nil, err
	}
	ec, err := ecc.New(curves.Form(keys.Form), keys.Curve)
	if err != nil {
		return nil, fmt.Errorf("ecelgamal: %w", err)
	}
	qa, err := ec.Point(keys.PublicKey.Qa.X, keys.PublicKey.Qa.Y)
	if err != nil {
		return nil, phe.InvalidKeysf("ecelgamal: public key point is not on curve %s", ec.Name())
	}

	c := &Cryptosystem{
		Base: phe.Base{Alg: phe.EllipticCurveElGamal},
		keys: keys,
		ec:   ec,
		qa:   qa,
	}
	if keys.PrivateKey != nil {
		c.ka = new(big.Int).Set(keys.PrivateKey.Ka)
		c.hasSecret = true
	}
	return c, nil
}

// FromJSON rebuilds a cryptosystem from exported key material.
func FromJSON(data []byte) (*Cryptosystem, error) {
	var keys Keys
	if err := json.Unmarshal(data, &keys); err != nil {
		return nil, phe.InvalidKeysf("ecelgamal: decoding keys: %v", err)
	}
	return New(keys)
}

// Keys returns a copy of the key material.
func (c *Cryptosystem) Keys() Keys { return c.keys }

// ECC exposes the underlying curve.
func (c *Cryptosystem) ECC() *ecc.ECC { return c.ec }

// PlaintextModulo implements phe.Homomorphic.
func (c *Cryptosystem) PlaintextModulo() *big.Int { return c.ec.Modulo() }

// CiphertextModulo implements phe.Homomorphic.
func (c *Cryptosystem) CiphertextModulo() *big.Int { return c.ec.Modulo() }

// HasPrivateKey implements phe.Homomorphic.
func (c *Cryptosystem) HasPrivateKey() bool { return c.hasSecret }

// PublicOnly implements phe.Homomorphic.
func (c *Cryptosystem) PublicOnly() (phe.Homomorphic, error) {
	return New(Keys{PublicKey: c.keys.PublicKey, Form: c.keys.Form, Curve: c.keys.Curve})
}

// ExportKeys implements phe.Homomorphic.
func (c *Cryptosystem) ExportKeys(includePrivate bool) ([]byte, error) {
	keys := Keys{PublicKey: c.keys.PublicKey, Form: c.keys.Form, Curve: c.keys.Curve}
	if includePrivate {
		keys.PrivateKey = c.keys.PrivateKey
	}
	return json.Marshal(keys)
}

// Encrypt implements phe.Homomorphic.
func (c *Cryptosystem) Encrypt(plaintext *big.Int) (phe.Value, error) {
	r, err := mathutil.RandBits(c.ec.N().BitLen())
	if err != nil {
		return nil, fmt.Errorf("ecelgamal: %w", err)
	}
	return c.EncryptWith(plaintext, r)
}

// EncryptWith encrypts using a caller supplied random key.
func (c *Cryptosystem) EncryptWith(plaintext, random *big.Int) (phe.Value, error) {
	// s = m*G is the curve point standing in for the message.
	s, err := c.ec.G().ScalarMul(plaintext)
	if err != nil {
		return nil, fmt.Errorf("ecelgamal: encoding the plaintext: %w", err)
	}
	c1, err := c.ec.G().ScalarMul(random)
	if err != nil {
		return nil, fmt.Errorf("ecelgamal: %w", err)
	}
	masked, err := c.qa.ScalarMul(random)
	if err != nil {
		return nil, fmt.Errorf("ecelgamal: %w", err)
	}
	c2, err := masked.Add(s)
	if err != nil {
		return nil, fmt.Errorf("ecelgamal: %w", err)
	}
	return pair(c1, c2), nil
}

// Decrypt implements phe.Homomorphic. Recovering m from m*G is an elliptic
// curve discrete logarithm, solved here by exhaustive search.
func (c *Cryptosystem) Decrypt(ciphertext phe.Value) (*big.Int, error) {
	if !c.hasSecret {
		return nil, phe.ErrMissingPrivateKey
	}
	c1, c2, err := c.points(ciphertext)
	if err != nil {
		return nil, err
	}

	shared, err := c1.ScalarMul(c.ka)
	if err != nil {
		return nil, fmt.Errorf("ecelgamal: %w", err)
	}
	s, err := c2.Sub(shared)
	if err != nil {
		return nil, fmt.Errorf("ecelgamal: %w", err)
	}

	m, err := ecc.DiscreteLog(s, c.ec.G(), c.ec.N())
	if err != nil {
		return nil, fmt.Errorf("ecelgamal: %v: %w", err, phe.ErrDecryptionFailed)
	}
	return m, nil
}

// Add implements phe.Homomorphic: adding both halves of two ciphertexts adds
// the plaintexts they carry.
func (c *Cryptosystem) Add(a, b phe.Value) (phe.Value, error) {
	a1, a2, err := c.points(a)
	if err != nil {
		return nil, err
	}
	b1, b2, err := c.points(b)
	if err != nil {
		return nil, err
	}
	sum1, err := a1.Add(b1)
	if err != nil {
		return nil, fmt.Errorf("ecelgamal: %w", err)
	}
	sum2, err := a2.Add(b2)
	if err != nil {
		return nil, fmt.Errorf("ecelgamal: %w", err)
	}
	return pair(sum1, sum2), nil
}

// MultiplyByConstant implements phe.Homomorphic.
func (c *Cryptosystem) MultiplyByConstant(ciphertext phe.Value, constant *big.Int) (phe.Value, error) {
	c1, c2, err := c.points(ciphertext)
	if err != nil {
		return nil, err
	}
	scaled1, err := c1.ScalarMul(constant)
	if err != nil {
		return nil, fmt.Errorf("ecelgamal: %w", err)
	}
	scaled2, err := c2.ScalarMul(constant)
	if err != nil {
		return nil, fmt.Errorf("ecelgamal: %w", err)
	}
	return pair(scaled1, scaled2), nil
}

// Reencrypt implements phe.Homomorphic by re-blinding both halves with a fresh
// random scalar.
func (c *Cryptosystem) Reencrypt(ciphertext phe.Value) (phe.Value, error) {
	c1, c2, err := c.points(ciphertext)
	if err != nil {
		return nil, err
	}
	r, err := mathutil.RandBits(c.ec.N().BitLen())
	if err != nil {
		return nil, fmt.Errorf("ecelgamal: %w", err)
	}

	rG, err := c.ec.G().ScalarMul(r)
	if err != nil {
		return nil, fmt.Errorf("ecelgamal: %w", err)
	}
	rQa, err := c.qa.ScalarMul(r)
	if err != nil {
		return nil, fmt.Errorf("ecelgamal: %w", err)
	}
	new1, err := c1.Add(rG)
	if err != nil {
		return nil, fmt.Errorf("ecelgamal: %w", err)
	}
	new2, err := c2.Add(rQa)
	if err != nil {
		return nil, fmt.Errorf("ecelgamal: %w", err)
	}
	return pair(new1, new2), nil
}

// pair packs two curve points into a ciphertext value.
func pair(c1, c2 ecc.Point) phe.Value {
	return phe.NewTuple(toValue(c1), toValue(c2))
}

// toValue converts a curve point into a ciphertext payload. Edwards curves
// have an on-curve neutral element, so only the point at infinity collapses
// into the Infinity flag.
func toValue(p ecc.Point) phe.Point {
	if p.Infinity {
		return phe.InfinityPoint()
	}
	return phe.NewPoint(p.X, p.Y)
}

// points splits a ciphertext into its two curve points.
func (c *Cryptosystem) points(v phe.Value) (c1, c2 ecc.Point, err error) {
	first, second, err := phe.AsPair(v)
	if err != nil {
		return ecc.Point{}, ecc.Point{}, err
	}
	if c1, err = c.toPoint(first); err != nil {
		return ecc.Point{}, ecc.Point{}, err
	}
	if c2, err = c.toPoint(second); err != nil {
		return ecc.Point{}, ecc.Point{}, err
	}
	return c1, c2, nil
}

func (c *Cryptosystem) toPoint(v phe.Value) (ecc.Point, error) {
	p, err := phe.AsPoint(v)
	if err != nil {
		return ecc.Point{}, err
	}
	if p.Infinity {
		return c.ec.O(), nil
	}
	point, err := c.ec.Point(p.X, p.Y)
	if err != nil {
		return ecc.Point{}, phe.InvalidCiphertextf("ecelgamal: %v", err)
	}
	return point, nil
}
