// Package bonehgohnissim implements the Boneh-Goh-Nissim cryptosystem, which is
// somewhat homomorphic: it supports arbitrarily many additions and exactly one
// multiplication per ciphertext.
//
// Ciphertexts start out as points on a supersingular curve of order n = q1*q2.
// A multiplication runs the bilinear pairing, which moves the result out of the
// curve group and into the target group F_{p^2}; further additions still work
// there, but a second multiplication does not.
//
// Reference: https://sefiks.com/2026/04/02/a-step-by-step-somewhat-homomorphic-encryption-example-with-boneh-goh-nissim-in-python/
package bonehgohnissim

import (
	"encoding/json"
	"fmt"
	"math/big"

	"github.com/serengil/lightphe-go/lightphe/ecc"
	"github.com/serengil/lightphe-go/lightphe/internal/mathutil"
	"github.com/serengil/lightphe-go/lightphe/phe"
)

// Defaults used when the caller does not specify them.
const (
	DefaultKeySize  = 1024
	DefaultMaxTries = 10000
)

// CurveParams describes the supersingular curve generated along with the keys.
type CurveParams struct {
	A *big.Int   `json:"a"`
	B *big.Int   `json:"b"`
	P *big.Int   `json:"p"`
	G *phe.Point `json:"G"`
	N *big.Int   `json:"n"`
}

// PublicKey is the Boneh-Goh-Nissim public key.
type PublicKey struct {
	Curve *CurveParams `json:"curve"`
	G     *phe.Point   `json:"G"`
	U     *phe.Point   `json:"u"`
	H     *phe.Point   `json:"h"`
	L     *big.Int     `json:"l"`
}

// PrivateKey holds the two primes whose product is the group order.
type PrivateKey struct {
	Q1 *big.Int `json:"q1"`
	Q2 *big.Int `json:"q2"`
}

// Keys bundles the key pair. PrivateKey is nil for encryption-only setups.
type Keys struct {
	PublicKey  *PublicKey  `json:"public_key,omitempty"`
	PrivateKey *PrivateKey `json:"private_key,omitempty"`
}

// Validate reports missing or malformed key material.
func (k Keys) Validate() error {
	if k.PublicKey == nil {
		return phe.RequireSection(phe.BonehGohNissim, phe.SectionPublic)
	}
	if err := phe.RequireFields(phe.BonehGohNissim, phe.SectionPublic,
		phe.Field("curve", k.PublicKey.Curve != nil),
		phe.Field("G", k.PublicKey.G != nil),
		phe.Field("u", k.PublicKey.U != nil),
		phe.Field("h", k.PublicKey.H != nil),
		phe.Field("l", k.PublicKey.L != nil),
	); err != nil {
		return err
	}
	if c := k.PublicKey.Curve; c != nil {
		if err := phe.RequireFields(phe.BonehGohNissim, "public_key.curve",
			phe.Field("a", c.A != nil),
			phe.Field("b", c.B != nil),
			phe.Field("p", c.P != nil),
			phe.Field("G", c.G != nil),
			phe.Field("n", c.N != nil),
		); err != nil {
			return err
		}
	}
	if k.PrivateKey != nil {
		if err := phe.RequireFields(phe.BonehGohNissim, phe.SectionPrivate,
			phe.Field("q1", k.PrivateKey.Q1 != nil),
			phe.Field("q2", k.PrivateKey.Q2 != nil),
		); err != nil {
			return err
		}
	}
	return nil
}

// Cryptosystem is a configured Boneh-Goh-Nissim instance. It is immutable and
// safe for concurrent use.
type Cryptosystem struct {
	phe.Base

	keys      Keys
	ec        *ecc.ECC
	h         ecc.Point
	q1, q2    *big.Int
	plaintext *big.Int
	hasSecret bool
}

var _ phe.Homomorphic = (*Cryptosystem)(nil)

// Generate creates a fresh key pair together with the supersingular curve it
// lives on.
func Generate(keySize, maxTries int) (*Cryptosystem, error) {
	if keySize <= 0 {
		keySize = DefaultKeySize
	}
	if maxTries <= 0 {
		maxTries = DefaultMaxTries
	}
	primeBits := keySize/2 + 1

	for attempt := 0; attempt < maxTries; attempt++ {
		q1, q2, err := mathutil.RandDistinctPrimes(primeBits)
		if err != nil {
			return nil, fmt.Errorf("bonehgohnissim: %w", err)
		}
		n := new(big.Int).Mul(q1, q2)

		// The curve y^2 = x^3 + x over F_p is supersingular with embedding
		// degree 2 when p = 3 (mod 4), and has exactly p+1 = n*l points. Since
		// n is odd, n*l = 0 (mod 4) forces l = 0 (mod 4), so only multiples of
		// four are worth testing.
		l, p := findCofactor(n, maxTries)
		if l == nil {
			continue
		}

		a := big.NewInt(1)
		b := new(big.Int)

		g, err := findGenerator(p, l, n)
		if err != nil {
			continue
		}

		ec, err := ecc.NewCustomWeierstrassECC(a, b, p, g.X, g.Y, n)
		if err != nil {
			// The declared order did not annihilate the generator; start over.
			continue
		}

		// u = r*G for a random unit r, and h = q2*u has order q1, which is what
		// blinds ciphertexts without disturbing decryption.
		r, err := randomUnit(n)
		if err != nil {
			return nil, fmt.Errorf("bonehgohnissim: %w", err)
		}
		u, err := ec.G().ScalarMul(r)
		if err != nil {
			continue
		}
		h, err := u.ScalarMul(q2)
		if err != nil {
			continue
		}

		gx, gy := ec.G().Coordinates()
		ux, uy := u.Coordinates()
		hx, hy := h.Coordinates()

		return New(Keys{
			PublicKey: &PublicKey{
				Curve: &CurveParams{A: a, B: b, P: p, G: &phe.Point{X: gx, Y: gy}, N: n},
				G:     &phe.Point{X: gx, Y: gy},
				U:     &phe.Point{X: ux, Y: uy},
				H:     &phe.Point{X: hx, Y: hy},
				L:     l,
			},
			PrivateKey: &PrivateKey{Q1: q1, Q2: q2},
		})
	}
	return nil, fmt.Errorf("bonehgohnissim: no valid key pair after %d attempts: %w", maxTries, phe.ErrKeyGeneration)
}

// findCofactor searches for l = 0 (mod 4) such that p = n*l - 1 is prime.
func findCofactor(n *big.Int, maxTries int) (l, p *big.Int) {
	candidate := new(big.Int)
	for i := 4; i <= maxTries*4+4; i += 4 {
		candidate.Mul(n, big.NewInt(int64(i)))
		candidate.Sub(candidate, big.NewInt(1))
		if mathutil.IsPrime(candidate) {
			return big.NewInt(int64(i)), new(big.Int).Set(candidate)
		}
	}
	return nil, nil
}

// findGenerator picks a random point on y^2 = x^3 + x and clears the cofactor
// so that the result generates the subgroup of order n.
func findGenerator(p, l, n *big.Int) (*phe.Point, error) {
	curve, err := ecc.NewCustomWeierstrass(big.NewInt(1), new(big.Int), p, big.NewInt(0), big.NewInt(0), n)
	if err != nil {
		return nil, err
	}

	for i := 0; i < 1000; i++ {
		x, err := mathutil.RandBelow(p)
		if err != nil {
			return nil, err
		}
		// rhs = x^3 + x mod p
		rhs := new(big.Int).Exp(x, big.NewInt(3), p)
		rhs.Add(rhs, x)
		rhs.Mod(rhs, p)

		y, err := mathutil.SqrtMod(rhs, p)
		if err != nil {
			continue
		}

		point, err := ecc.NewPoint(curve, x, y)
		if err != nil {
			continue
		}
		// Multiplying by the cofactor l lands in the order-n subgroup.
		cleared, err := point.ScalarMul(l)
		if err != nil || cleared.IsIdentity() {
			continue
		}
		gx, gy := cleared.Coordinates()
		return &phe.Point{X: gx, Y: gy}, nil
	}
	return nil, fmt.Errorf("bonehgohnissim: no generator found on the curve: %w", phe.ErrKeyGeneration)
}

func randomUnit(n *big.Int) (*big.Int, error) {
	for i := 0; i < 10000; i++ {
		r, err := mathutil.RandRange(big.NewInt(2), new(big.Int).Sub(n, big.NewInt(1)))
		if err != nil {
			return nil, err
		}
		if mathutil.IsCoprime(r, n) {
			return r, nil
		}
	}
	return nil, fmt.Errorf("bonehgohnissim: no unit found modulo %s: %w", n, phe.ErrKeyGeneration)
}

// New builds a cryptosystem around an existing key pair.
func New(keys Keys) (*Cryptosystem, error) {
	if err := keys.Validate(); err != nil {
		return nil, err
	}
	params := keys.PublicKey.Curve

	ec, err := ecc.NewCustomWeierstrassECC(params.A, params.B, params.P, params.G.X, params.G.Y, params.N)
	if err != nil {
		return nil, phe.InvalidKeysf("bonehgohnissim: rebuilding the curve: %v", err)
	}
	h, err := ec.Point(keys.PublicKey.H.X, keys.PublicKey.H.Y)
	if err != nil {
		return nil, phe.InvalidKeysf("bonehgohnissim: h is not on the curve: %v", err)
	}

	c := &Cryptosystem{
		Base: phe.Base{Alg: phe.BonehGohNissim},
		keys: keys,
		ec:   ec,
		h:    h,
	}

	if keys.PrivateKey != nil {
		c.q1 = new(big.Int).Set(keys.PrivateKey.Q1)
		c.q2 = new(big.Int).Set(keys.PrivateKey.Q2)
		c.plaintext = new(big.Int).Set(c.q2)
		c.hasSecret = true
	} else {
		// Without q2 the best public bound on the message space is n.
		c.plaintext = ec.N()
	}
	return c, nil
}

// FromJSON rebuilds a cryptosystem from exported key material.
func FromJSON(data []byte) (*Cryptosystem, error) {
	var keys Keys
	if err := json.Unmarshal(data, &keys); err != nil {
		return nil, phe.InvalidKeysf("bonehgohnissim: decoding keys: %v", err)
	}
	return New(keys)
}

// Keys returns a copy of the key material.
func (c *Cryptosystem) Keys() Keys { return c.keys }

// ECC exposes the generated curve.
func (c *Cryptosystem) ECC() *ecc.ECC { return c.ec }

// PlaintextModulo implements phe.Homomorphic.
func (c *Cryptosystem) PlaintextModulo() *big.Int { return new(big.Int).Set(c.plaintext) }

// CiphertextModulo implements phe.Homomorphic.
func (c *Cryptosystem) CiphertextModulo() *big.Int { return c.ec.Modulo() }

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

// Encrypt implements phe.Homomorphic, producing c = m*G + r*h.
func (c *Cryptosystem) Encrypt(plaintext *big.Int) (phe.Value, error) {
	r, err := c.randomBlind()
	if err != nil {
		return nil, err
	}
	return c.EncryptWith(plaintext, r)
}

// EncryptWith encrypts using a caller supplied random key.
func (c *Cryptosystem) EncryptWith(plaintext, random *big.Int) (phe.Value, error) {
	mG, err := c.ec.G().ScalarMul(plaintext)
	if err != nil {
		return nil, fmt.Errorf("bonehgohnissim: %w", err)
	}
	rh, err := c.h.ScalarMul(random)
	if err != nil {
		return nil, fmt.Errorf("bonehgohnissim: %w", err)
	}
	sum, err := mG.Add(rh)
	if err != nil {
		return nil, fmt.Errorf("bonehgohnissim: %w", err)
	}
	return toValue(sum), nil
}

// randomBlind draws the per-encryption randomness. It is bounded by q2 when the
// private key is available and by the curve order otherwise.
func (c *Cryptosystem) randomBlind() (*big.Int, error) {
	upper := c.ec.N()
	if c.hasSecret {
		upper = new(big.Int).Set(c.q2)
	}
	r, err := mathutil.RandRange(big.NewInt(1), new(big.Int).Sub(upper, big.NewInt(1)))
	if err != nil {
		return nil, fmt.Errorf("bonehgohnissim: %w", err)
	}
	return r, nil
}

// Decrypt implements phe.Homomorphic. It handles both curve ciphertexts and the
// F_{p^2} elements that a homomorphic multiplication produces.
func (c *Cryptosystem) Decrypt(ciphertext phe.Value) (*big.Int, error) {
	if !c.hasSecret {
		return nil, phe.ErrMissingPrivateKey
	}
	if gt, ok := ciphertext.(phe.FP2); ok {
		return c.decryptTarget(gt)
	}

	point, err := c.toPoint(ciphertext)
	if err != nil {
		return nil, err
	}

	// Multiplying by q1 kills the blinding term, leaving m*(q1*G) where q1*G
	// has order q2, so the discrete log lands in [0, q2).
	target, err := point.ScalarMul(c.q1)
	if err != nil {
		return nil, fmt.Errorf("bonehgohnissim: %w", err)
	}
	if target.IsIdentity() {
		return new(big.Int), nil
	}
	base, err := c.ec.G().ScalarMul(c.q1)
	if err != nil {
		return nil, fmt.Errorf("bonehgohnissim: %w", err)
	}

	m, err := ecc.DiscreteLog(target, base, c.q2)
	if err != nil {
		return nil, fmt.Errorf("bonehgohnissim: %v: %w", err, phe.ErrDecryptionFailed)
	}
	return m, nil
}

// decryptTarget recovers a product from a pairing value by solving a discrete
// logarithm in the target group.
func (c *Cryptosystem) decryptTarget(gt phe.FP2) (*big.Int, error) {
	modulus := c.ec.Modulo()

	pairing, err := c.ec.Pairing(c.ec.G(), c.ec.G())
	if err != nil {
		return nil, fmt.Errorf("bonehgohnissim: pairing the generator with itself: %w", err)
	}
	if !pairing.Extended {
		return nil, fmt.Errorf("bonehgohnissim: the curve is not supersingular with embedding degree 2: %w", phe.ErrDecryptionFailed)
	}

	base, err := pairing.Value.Exp(c.q1, modulus)
	if err != nil {
		return nil, fmt.Errorf("bonehgohnissim: %w", err)
	}
	target, err := ecc.NewFP2(gt.A, gt.B).Exp(c.q1, modulus)
	if err != nil {
		return nil, fmt.Errorf("bonehgohnissim: %w", err)
	}
	if target.IsOne() {
		return new(big.Int), nil
	}

	acc := ecc.FP2One()
	m := new(big.Int)
	one := big.NewInt(1)
	for {
		m.Add(m, one)
		if m.Cmp(c.q2) >= 0 {
			return nil, fmt.Errorf("bonehgohnissim: cannot restore a product in [0, %s): %w", c.q2, phe.ErrDecryptionFailed)
		}
		acc = acc.Mul(base, modulus)
		if acc.Equal(target) {
			return new(big.Int).Set(m), nil
		}
	}
}

// Add implements phe.Homomorphic. Both operands must live in the same group:
// two curve points, or two pairing values.
func (c *Cryptosystem) Add(a, b phe.Value) (phe.Value, error) {
	aGT, aIsGT := a.(phe.FP2)
	bGT, bIsGT := b.(phe.FP2)

	switch {
	case aIsGT && bIsGT:
		product := ecc.NewFP2(aGT.A, aGT.B).Mul(ecc.NewFP2(bGT.A, bGT.B), c.ec.Modulo())
		return phe.FP2{A: product.A, B: product.B}, nil
	case aIsGT != bIsGT:
		return nil, phe.InvalidCiphertextf("bonehgohnissim: cannot add a curve ciphertext to a pairing result")
	}

	pa, err := c.toPoint(a)
	if err != nil {
		return nil, err
	}
	pb, err := c.toPoint(b)
	if err != nil {
		return nil, err
	}
	sum, err := pa.Add(pb)
	if err != nil {
		return nil, fmt.Errorf("bonehgohnissim: %w", err)
	}
	return toValue(sum), nil
}

// Multiply implements phe.Homomorphic through the bilinear pairing. The result
// lives in F_{p^2} and cannot be multiplied again.
func (c *Cryptosystem) Multiply(a, b phe.Value) (phe.Value, error) {
	if _, ok := a.(phe.FP2); ok {
		return nil, fmt.Errorf("bonehgohnissim: only supports multiplying ciphertexts once: %w", phe.ErrUnsupportedOperation)
	}
	if _, ok := b.(phe.FP2); ok {
		return nil, fmt.Errorf("bonehgohnissim: only supports multiplying ciphertexts once: %w", phe.ErrUnsupportedOperation)
	}

	pa, err := c.toPoint(a)
	if err != nil {
		return nil, err
	}
	pb, err := c.toPoint(b)
	if err != nil {
		return nil, err
	}

	result, err := c.ec.Pairing(pa, pb)
	if err != nil {
		return nil, fmt.Errorf("bonehgohnissim: %w", err)
	}
	if !result.Extended {
		return nil, fmt.Errorf("bonehgohnissim: the pairing returned a base field element, so the curve is not a valid BGN parameter set: %w",
			phe.ErrInvalidKeys)
	}
	return phe.FP2{A: result.Value.A, B: result.Value.B}, nil
}

// MultiplyByConstant implements phe.Homomorphic in both groups.
func (c *Cryptosystem) MultiplyByConstant(ciphertext phe.Value, constant *big.Int) (phe.Value, error) {
	if gt, ok := ciphertext.(phe.FP2); ok {
		scaled, err := ecc.NewFP2(gt.A, gt.B).Exp(constant, c.ec.Modulo())
		if err != nil {
			return nil, fmt.Errorf("bonehgohnissim: %w", err)
		}
		return phe.FP2{A: scaled.A, B: scaled.B}, nil
	}

	point, err := c.toPoint(ciphertext)
	if err != nil {
		return nil, err
	}
	scaled, err := point.ScalarMul(constant)
	if err != nil {
		return nil, fmt.Errorf("bonehgohnissim: %w", err)
	}
	return toValue(scaled), nil
}

// Reencrypt implements phe.Homomorphic by adding a fresh blinding term.
func (c *Cryptosystem) Reencrypt(ciphertext phe.Value) (phe.Value, error) {
	point, err := c.toPoint(ciphertext)
	if err != nil {
		return nil, err
	}
	r, err := c.randomBlind()
	if err != nil {
		return nil, err
	}
	rh, err := c.h.ScalarMul(r)
	if err != nil {
		return nil, fmt.Errorf("bonehgohnissim: %w", err)
	}
	sum, err := point.Add(rh)
	if err != nil {
		return nil, fmt.Errorf("bonehgohnissim: %w", err)
	}
	return toValue(sum), nil
}

func toValue(p ecc.Point) phe.Value {
	if p.Infinity {
		return phe.InfinityPoint()
	}
	return phe.NewPoint(p.X, p.Y)
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
		return ecc.Point{}, phe.InvalidCiphertextf("bonehgohnissim: %v", err)
	}
	return point, nil
}
