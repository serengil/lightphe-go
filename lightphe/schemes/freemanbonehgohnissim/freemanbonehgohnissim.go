// Package freemanbonehgohnissim implements the Freeman-Boneh-Goh-Nissim
// cryptosystem, the prime-order version of Boneh-Goh-Nissim. It is
// homomorphic with respect to addition, and supports one multiplication of
// ciphertexts. Boneh-Goh-Nissim works in a group of composite order n = q1 q2,
// and its security relies on hardness of factoring n, which requires a large
// group. This works in a group of prime order r, and its security relies on
// the decision linear assumption.
//
// Groups are vectors of 3 points on the supersingular curve y^2 = x^3 + x over
// F_p, whose points of order r have a symmetric pairing into F_{p^2}.
//   - private key: secret vector v in Z_r^3
//   - public key: h1 and h2 spanning the subgroup H of vectors orthogonal to v,
//     and g out of H. Vectors are multiplied with the generator point P.
//   - encryption: C = m g + a1 h1 + a2 h2 for random a1 and a2
//   - decryption: projection pi(C) = v1 C1 + v2 C2 + v3 C3 = m pi(g) as
//     pi(H) = 0, then discrete logarithm of it with base pi(g)
//   - multiplication: 3 x 3 pairings e(C_i, C'_j). Its projection, product of
//     e(C_i, C'_j)^(v_i v_j), is e(pi(C), pi(C')) = e(pi(g), pi(g))^(m m').
//
// Freeman's symmetric instantiation needs vectors of 3 points, because
// decisional Diffie-Hellman is easy in groups having a symmetric pairing.
//
// Decryption solves discrete logarithm as in Boneh-Goh-Nissim, so decrypted
// values must be small: in [-limit, limit] where limit is 2^20 by default, and
// can be set with a plaintext limit. Floats and tensors are not supported.
// Ciphertexts are 3 points, and multiplied ciphertexts are 9 elements of
// F_{p^2}. Multiplied ciphertexts can be added with each other and multiplied
// with constants. Adding a fresh ciphertext to a multiplied one pairs it with g
// first, which costs 9 pairings.
//
// The key size is the bit length of the field size p. Default is 1024. The
// group order r is 256 bits, and security is bounded by discrete logarithm in
// F_{p^2}: about 112 bits for p of 1024 bits, and 128 bits for p of 1536 bits.
// It is not quantum resistant.
//
// Reference: Freeman, D. M. (2010). Converting Pairing-Based Cryptosystems
// from Composite-Order Groups to Prime-Order Groups. EUROCRYPT 2010.
//
// Reference: Boneh, D., Goh, E.-J., Nissim, K. (2005). Evaluating 2-DNF
// Formulas on Ciphertexts. TCC 2005.
package freemanbonehgohnissim

import (
	"encoding/json"
	"fmt"
	"math/big"
	"sync"

	"github.com/serengil/lightphe-go/lightphe/ecc"
	"github.com/serengil/lightphe-go/lightphe/internal/mathutil"
	"github.com/serengil/lightphe-go/lightphe/phe"
)

// DefaultKeySize is the bit length of the field size used when none is
// requested.
const DefaultKeySize = 1024

// DefaultPlaintextLimit bounds decrypted values to [-limit, limit] by default,
// as decryption solves discrete logarithm with baby-step giant-step.
const DefaultPlaintextLimit = 1 << 20

// maxOrderBits is the bit length of the prime group order r.
const maxOrderBits = 256

// dimension is the number of points in a ciphertext. A multiplied one has
// dimension^2 elements.
const dimension = 3

// ErrFloatNotSupported reports a float plaintext, constant or tensor.
var ErrFloatNotSupported = phe.FloatNotSupported("lightphe: Freeman-Boneh-Goh-Nissim does not support float values " +
	"or tensors, because they are scaled by powers of 10, which exceed the range that decryption can restore. " +
	"Use integers instead")

// ErrMultipliedTwice reports a multiplication involving an already multiplied
// ciphertext.
var ErrMultipliedTwice = fmt.Errorf("lightphe: Freeman-Boneh-Goh-Nissim supports only one multiplication, "+
	"multiplied ciphertexts cannot be multiplied with ciphertexts again: %w", phe.ErrUnsupportedOperation)

// PublicKey is the Freeman-Boneh-Goh-Nissim public key.
type PublicKey struct {
	P     *big.Int    `json:"p"`
	R     *big.Int    `json:"r"`
	G     *phe.Point  `json:"P"`
	Gs    []phe.Point `json:"g"`
	H1    []phe.Point `json:"h1"`
	H2    []phe.Point `json:"h2"`
	Limit *big.Int    `json:"limit"`
}

// PrivateKey is the secret projection vector v.
type PrivateKey struct {
	V []*big.Int `json:"v"`
}

// Keys bundles the key pair. PrivateKey is nil for encryption-only setups.
type Keys struct {
	PublicKey  *PublicKey  `json:"public_key,omitempty"`
	PrivateKey *PrivateKey `json:"private_key,omitempty"`
}

// Validate reports missing or malformed key material.
func (k Keys) Validate() error {
	if k.PublicKey == nil {
		return phe.RequireSection(phe.FreemanBonehGohNissim, phe.SectionPublic)
	}
	pk := k.PublicKey
	if err := phe.RequireFields(phe.FreemanBonehGohNissim, phe.SectionPublic,
		phe.Field("p", pk.P != nil),
		phe.Field("r", pk.R != nil),
		phe.Field("P", pk.G != nil),
		phe.Field("g", pk.Gs != nil),
		phe.Field("h1", pk.H1 != nil),
		phe.Field("h2", pk.H2 != nil),
		phe.Field("limit", pk.Limit != nil),
	); err != nil {
		return err
	}
	if k.PrivateKey != nil {
		if err := phe.RequireFields(phe.FreemanBonehGohNissim, phe.SectionPrivate,
			phe.Field("v", k.PrivateKey.V != nil),
		); err != nil {
			return err
		}
		if len(k.PrivateKey.V) != dimension {
			return phe.InvalidKeysf("freemanbonehgohnissim: v must have %d entries", dimension)
		}
	}
	if len(pk.Gs) != dimension || len(pk.H1) != dimension || len(pk.H2) != dimension {
		return phe.InvalidKeysf("freemanbonehgohnissim: g, h1 and h2 must have %d points", dimension)
	}
	if !pk.Limit.IsInt64() || pk.Limit.Sign() <= 0 || pk.Limit.Int64() > 1<<40 {
		return phe.InvalidKeysf("freemanbonehgohnissim: limit must be in [1, 2^40]")
	}
	return nil
}

// Cryptosystem is a configured Freeman-Boneh-Goh-Nissim instance. It is
// immutable and safe for concurrent use.
type Cryptosystem struct {
	phe.Base

	keys       Keys
	ec         *ecc.ECC
	r, p       *big.Int
	g, h1, h2  []ecc.Point
	limit      int64
	hasSecret  bool
	curveTable bsgsTable
	gtTable    bsgsTable
}

// bsgsTable is a baby-step giant-step table built once on first use.
type bsgsTable struct {
	once  sync.Once
	err   error
	size  int64
	steps map[string]int64
	base  interface{}
	giant interface{}
}

var (
	_ phe.Homomorphic   = (*Cryptosystem)(nil)
	_ phe.FloatRejecter = (*Cryptosystem)(nil)
)

// Generate creates a fresh key pair with a field size of keySize bits.
// Decrypted values must be in [-plaintextLimit, plaintextLimit]; a nil limit
// selects 2^20.
func Generate(keySize int, plaintextLimit *big.Int) (*Cryptosystem, error) {
	if keySize <= 0 {
		keySize = DefaultKeySize
	}
	if keySize < 32 {
		return nil, fmt.Errorf("freemanbonehgohnissim: key size %d is too small: %w", keySize, phe.ErrKeyGeneration)
	}
	limit := big.NewInt(DefaultPlaintextLimit)
	if plaintextLimit != nil && plaintextLimit.Sign() > 0 {
		limit = new(big.Int).Set(plaintextLimit)
	}
	one := big.NewInt(1)

	rBits := keySize / 2
	if rBits > maxOrderBits {
		rBits = maxOrderBits
	}
	r, err := mathutil.RandRangePrime(new(big.Int).Lsh(one, uint(rBits-1)), new(big.Int).Sub(new(big.Int).Lsh(one, uint(rBits)), one))
	if err != nil {
		return nil, fmt.Errorf("freemanbonehgohnissim: %v: %w", err, phe.ErrKeyGeneration)
	}
	if new(big.Int).Add(new(big.Int).Lsh(limit, 1), one).Cmp(r) >= 0 {
		return nil, fmt.Errorf("freemanbonehgohnissim: plaintext limit %s is too large for the group order of key size %d: %w",
			limit, keySize, phe.ErrKeyGeneration)
	}

	// p = r l - 1 with 4 | l, so that p = 3 mod 4 and y^2 = x^3 + x has
	// p + 1 = r l points
	l := new(big.Int).Lsh(one, uint(keySize-rBits))
	l.Rsh(l, 2).Lsh(l, 2)
	if l.Cmp(big.NewInt(4)) < 0 {
		l.SetInt64(4)
	}
	p := new(big.Int)
	for {
		p.Mul(r, l).Sub(p, one)
		if mathutil.IsPrime(p) {
			break
		}
		l.Add(l, big.NewInt(4))
	}

	// generator P of the subgroup of order r
	generator, err := findGenerator(p, l, r)
	if err != nil {
		return nil, err
	}
	ec, err := ecc.NewCustomWeierstrassECC(big.NewInt(1), new(big.Int), p, generator.X, generator.Y, r)
	if err != nil {
		return nil, fmt.Errorf("freemanbonehgohnissim: %v: %w", err, phe.ErrKeyGeneration)
	}

	// secret projection v, and H = vectors orthogonal to v
	v := make([]*big.Int, dimension)
	for i := range v {
		if v[i], err = mathutil.RandRange(one, new(big.Int).Sub(r, one)); err != nil {
			return nil, err
		}
	}
	var h1, h2 []*big.Int
	for {
		if h1, err = randomOrthogonal(v, r); err != nil {
			return nil, err
		}
		if h2, err = randomOrthogonal(v, r); err != nil {
			return nil, err
		}
		// h1 and h2 must be linearly independent
		if linearlyIndependent(h1, h2, r) {
			break
		}
	}
	var g []*big.Int
	for {
		g = make([]*big.Int, dimension)
		for i := range g {
			if g[i], err = mathutil.RandBelow(r); err != nil {
				return nil, err
			}
		}
		if dot(v, g, r).Sign() != 0 {
			break
		}
	}

	points := func(scalars []*big.Int) ([]phe.Point, error) {
		out := make([]phe.Point, len(scalars))
		for i, s := range scalars {
			pt, err := ec.G().ScalarMul(s)
			if err != nil {
				return nil, err
			}
			out[i] = toPhePoint(pt)
		}
		return out, nil
	}
	gPoints, err := points(g)
	if err != nil {
		return nil, err
	}
	h1Points, err := points(h1)
	if err != nil {
		return nil, err
	}
	h2Points, err := points(h2)
	if err != nil {
		return nil, err
	}
	base := toPhePoint(ec.G())

	return New(Keys{
		PublicKey: &PublicKey{
			P:     p,
			R:     r,
			G:     &base,
			Gs:    gPoints,
			H1:    h1Points,
			H2:    h2Points,
			Limit: limit,
		},
		PrivateKey: &PrivateKey{V: v},
	})
}

// findGenerator picks a random point on y^2 = x^3 + x and clears the cofactor
// l so that the result generates the subgroup of order r.
func findGenerator(p, l, r *big.Int) (ecc.Point, error) {
	// the curve has p + 1 = r l points
	order := new(big.Int).Add(p, big.NewInt(1))
	curve, err := ecc.NewCustomWeierstrass(big.NewInt(1), new(big.Int), p, big.NewInt(0), big.NewInt(0), order)
	if err != nil {
		return ecc.Point{}, err
	}
	for i := 0; i < 10000; i++ {
		x, err := mathutil.RandBelow(p)
		if err != nil {
			return ecc.Point{}, err
		}
		rhs := new(big.Int).Exp(x, big.NewInt(3), p)
		rhs.Add(rhs, x).Mod(rhs, p)
		y, err := mathutil.SqrtMod(rhs, p)
		if err != nil {
			continue
		}
		point, err := ecc.NewPoint(curve, x, y)
		if err != nil {
			continue
		}
		cleared, err := point.ScalarMul(l)
		if err != nil || cleared.IsIdentity() {
			continue
		}
		return cleared, nil
	}
	return ecc.Point{}, fmt.Errorf("freemanbonehgohnissim: no generator found on the curve: %w", phe.ErrKeyGeneration)
}

// randomOrthogonal returns a random vector x in Z_r^3 such that v . x = 0 mod r.
func randomOrthogonal(v []*big.Int, r *big.Int) ([]*big.Int, error) {
	x1, err := mathutil.RandBelow(r)
	if err != nil {
		return nil, err
	}
	x2, err := mathutil.RandBelow(r)
	if err != nil {
		return nil, err
	}
	inv, err := mathutil.ModInverse(v[2], r)
	if err != nil {
		return nil, err
	}
	x3 := new(big.Int).Mul(v[0], x1)
	x3.Add(x3, new(big.Int).Mul(v[1], x2)).Neg(x3).Mul(x3, inv).Mod(x3, r)
	return []*big.Int{x1, x2, x3}, nil
}

func linearlyIndependent(a, b []*big.Int, r *big.Int) bool {
	for i := 0; i < dimension; i++ {
		for j := i + 1; j < dimension; j++ {
			minor := new(big.Int).Mul(a[i], b[j])
			minor.Sub(minor, new(big.Int).Mul(a[j], b[i])).Mod(minor, r)
			if minor.Sign() != 0 {
				return true
			}
		}
	}
	return false
}

func dot(a, b []*big.Int, r *big.Int) *big.Int {
	sum := new(big.Int)
	for i := range a {
		sum.Add(sum, new(big.Int).Mul(a[i], b[i]))
	}
	return sum.Mod(sum, r)
}

// New builds a cryptosystem around an existing key pair.
func New(keys Keys) (*Cryptosystem, error) {
	if err := keys.Validate(); err != nil {
		return nil, err
	}
	pk := keys.PublicKey
	if pk.G.Infinity {
		return nil, phe.InvalidKeysf("freemanbonehgohnissim: P must not be the point at infinity")
	}
	ec, err := ecc.NewCustomWeierstrassECC(big.NewInt(1), new(big.Int), pk.P, pk.G.X, pk.G.Y, pk.R)
	if err != nil {
		return nil, phe.InvalidKeysf("freemanbonehgohnissim: rebuilding the curve: %v", err)
	}
	c := &Cryptosystem{
		Base:      phe.Base{Alg: phe.FreemanBonehGohNissim},
		keys:      keys,
		ec:        ec,
		r:         new(big.Int).Set(pk.R),
		p:         new(big.Int).Set(pk.P),
		limit:     pk.Limit.Int64(),
		hasSecret: keys.PrivateKey != nil,
	}
	for _, field := range []struct {
		name   string
		points []phe.Point
		out    *[]ecc.Point
	}{{"g", pk.Gs, &c.g}, {"h1", pk.H1, &c.h1}, {"h2", pk.H2, &c.h2}} {
		converted, err := c.points(field.points)
		if err != nil {
			return nil, phe.InvalidKeysf("freemanbonehgohnissim: %s: %v", field.name, err)
		}
		*field.out = converted
	}
	return c, nil
}

// FromJSON rebuilds a cryptosystem from exported key material.
func FromJSON(data []byte) (*Cryptosystem, error) {
	var keys Keys
	if err := json.Unmarshal(data, &keys); err != nil {
		return nil, phe.InvalidKeysf("freemanbonehgohnissim: decoding keys: %v", err)
	}
	return New(keys)
}

// Keys returns a copy of the key material.
func (c *Cryptosystem) Keys() Keys { return c.keys }

// ECC exposes the generated curve.
func (c *Cryptosystem) ECC() *ecc.ECC { return c.ec }

// PlaintextModulo implements phe.Homomorphic.
func (c *Cryptosystem) PlaintextModulo() *big.Int { return new(big.Int).Set(c.r) }

// CiphertextModulo implements phe.Homomorphic.
func (c *Cryptosystem) CiphertextModulo() *big.Int { return new(big.Int).Set(c.p) }

// HasPrivateKey implements phe.Homomorphic.
func (c *Cryptosystem) HasPrivateKey() bool { return c.hasSecret }

// FloatsUnsupported implements phe.FloatRejecter.
func (c *Cryptosystem) FloatsUnsupported() error { return ErrFloatNotSupported }

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

// Encrypt implements phe.Homomorphic, producing m g + a1 h1 + a2 h2.
func (c *Cryptosystem) Encrypt(plaintext *big.Int) (phe.Value, error) {
	a1, err := mathutil.RandBelow(c.r)
	if err != nil {
		return nil, err
	}
	a2, err := mathutil.RandBelow(c.r)
	if err != nil {
		return nil, err
	}
	return c.EncryptWith(plaintext, a1, a2)
}

// EncryptWith encrypts using caller supplied random scalars a1 and a2.
func (c *Cryptosystem) EncryptWith(plaintext, a1, a2 *big.Int) (phe.Value, error) {
	m := new(big.Int).Mod(plaintext, c.r)
	items := make([]phe.Value, dimension)
	for i := 0; i < dimension; i++ {
		sum := c.ec.O()
		for _, term := range []struct {
			point  ecc.Point
			scalar *big.Int
		}{{c.g[i], m}, {c.h1[i], a1}, {c.h2[i], a2}} {
			scaled, err := c.scale(term.point, term.scalar)
			if err != nil {
				return nil, err
			}
			if sum, err = sum.Add(scaled); err != nil {
				return nil, fmt.Errorf("freemanbonehgohnissim: %w", err)
			}
		}
		items[i] = toPhePoint(sum)
	}
	return phe.Tuple{Items: items}, nil
}

// Decrypt implements phe.Homomorphic. It handles both fresh ciphertexts of 3
// points and multiplied ones of 9 elements of F_{p^2}.
func (c *Cryptosystem) Decrypt(ciphertext phe.Value) (*big.Int, error) {
	if !c.hasSecret {
		return nil, phe.ErrMissingPrivateKey
	}
	v := c.keys.PrivateKey.V

	if multiplied, ok := c.multiplied(ciphertext); ok {
		elements, err := multiplied()
		if err != nil {
			return nil, err
		}
		// product of e(C_i, C'_j)^(v_i v_j) = e(pi(C), pi(C'))
		projected := ecc.FP2One()
		for index, element := range elements {
			i, j := index/dimension, index%dimension
			exponent := new(big.Int).Mul(v[i], v[j])
			exponent.Mod(exponent, c.r)
			powered, err := element.Exp(exponent, c.p)
			if err != nil {
				return nil, fmt.Errorf("freemanbonehgohnissim: %w", err)
			}
			projected = projected.Mul(powered, c.p)
		}
		m, err := c.discreteLogGT(projected)
		if err != nil {
			return nil, err
		}
		return m.Mod(m, c.r), nil
	}

	pts, err := c.fresh(ciphertext)
	if err != nil {
		return nil, err
	}
	projected, err := c.project(pts)
	if err != nil {
		return nil, err
	}
	m, err := c.discreteLogCurve(projected)
	if err != nil {
		return nil, err
	}
	return m.Mod(m, c.r), nil
}

// Add implements phe.Homomorphic. A fresh ciphertext is paired with g before
// it is added to a multiplied one.
func (c *Cryptosystem) Add(a, b phe.Value) (phe.Value, error) {
	_, multiplied1 := c.multiplied(a)
	_, multiplied2 := c.multiplied(b)

	if !multiplied1 && !multiplied2 {
		p1, err := c.fresh(a)
		if err != nil {
			return nil, err
		}
		p2, err := c.fresh(b)
		if err != nil {
			return nil, err
		}
		items := make([]phe.Value, dimension)
		for i := range items {
			sum, err := p1[i].Add(p2[i])
			if err != nil {
				return nil, fmt.Errorf("freemanbonehgohnissim: %w", err)
			}
			items[i] = toPhePoint(sum)
		}
		return phe.Tuple{Items: items}, nil
	}

	// E(m g + h, g) is an encryption of m as a multiplied ciphertext
	e1, err := c.asMultiplied(a)
	if err != nil {
		return nil, err
	}
	e2, err := c.asMultiplied(b)
	if err != nil {
		return nil, err
	}
	out := make([]ecc.FP2, len(e1))
	for i := range e1 {
		out[i] = e1[i].Mul(e2[i], c.p)
	}
	return fp2Value(out), nil
}

// Multiply implements phe.Homomorphic. It costs 9 pairings.
func (c *Cryptosystem) Multiply(a, b phe.Value) (phe.Value, error) {
	_, multiplied1 := c.multiplied(a)
	_, multiplied2 := c.multiplied(b)
	if multiplied1 || multiplied2 {
		return nil, ErrMultipliedTwice
	}
	p1, err := c.fresh(a)
	if err != nil {
		return nil, err
	}
	p2, err := c.fresh(b)
	if err != nil {
		return nil, err
	}
	elements, err := c.pair(p1, p2)
	if err != nil {
		return nil, err
	}
	return fp2Value(elements), nil
}

// MultiplyByConstant implements phe.Homomorphic for fresh and multiplied
// ciphertexts.
func (c *Cryptosystem) MultiplyByConstant(ciphertext phe.Value, constant *big.Int) (phe.Value, error) {
	k := new(big.Int).Mod(constant, c.r)
	if multiplied, ok := c.multiplied(ciphertext); ok {
		elements, err := multiplied()
		if err != nil {
			return nil, err
		}
		out := make([]ecc.FP2, len(elements))
		for i, element := range elements {
			if out[i], err = element.Exp(k, c.p); err != nil {
				return nil, fmt.Errorf("freemanbonehgohnissim: %w", err)
			}
		}
		return fp2Value(out), nil
	}
	pts, err := c.fresh(ciphertext)
	if err != nil {
		return nil, err
	}
	items := make([]phe.Value, dimension)
	for i, pt := range pts {
		scaled, err := c.scale(pt, k)
		if err != nil {
			return nil, err
		}
		items[i] = toPhePoint(scaled)
	}
	return phe.Tuple{Items: items}, nil
}

// Reencrypt implements phe.Homomorphic for fresh ciphertexts.
func (c *Cryptosystem) Reencrypt(ciphertext phe.Value) (phe.Value, error) {
	if _, ok := c.multiplied(ciphertext); ok {
		return nil, fmt.Errorf("lightphe: Freeman-Boneh-Goh-Nissim can re-encrypt non-multiplied ciphertexts only: %w",
			phe.ErrUnsupportedOperation)
	}
	zero, err := c.Encrypt(new(big.Int))
	if err != nil {
		return nil, err
	}
	return c.Add(ciphertext, zero)
}

// asMultiplied returns the elements of a multiplied ciphertext, pairing a
// fresh one with g first.
func (c *Cryptosystem) asMultiplied(v phe.Value) ([]ecc.FP2, error) {
	if multiplied, ok := c.multiplied(v); ok {
		return multiplied()
	}
	pts, err := c.fresh(v)
	if err != nil {
		return nil, err
	}
	return c.pair(pts, c.g)
}

// pair is the tensor product of two vectors of points with the pairing:
// e(C_i, C'_j) for all i, j.
func (c *Cryptosystem) pair(p1, p2 []ecc.Point) ([]ecc.FP2, error) {
	out := make([]ecc.FP2, 0, dimension*dimension)
	for _, x := range p1 {
		for _, y := range p2 {
			if x.IsIdentity() || y.IsIdentity() {
				out = append(out, ecc.FP2One())
				continue
			}
			result, err := c.ec.Pairing(x, y)
			if err != nil {
				return nil, fmt.Errorf("freemanbonehgohnissim: %w", err)
			}
			if !result.Extended {
				return nil, fmt.Errorf("freemanbonehgohnissim: the pairing returned a base field element: %w", phe.ErrInvalidKeys)
			}
			out = append(out, result.Value)
		}
	}
	return out, nil
}

// project is the secret projection pi(C) = v1 C1 + v2 C2 + v3 C3, which
// vanishes on H.
func (c *Cryptosystem) project(pts []ecc.Point) (ecc.Point, error) {
	result := c.ec.O()
	for i, pt := range pts {
		scaled, err := c.scale(pt, c.keys.PrivateKey.V[i])
		if err != nil {
			return ecc.Point{}, err
		}
		if result, err = result.Add(scaled); err != nil {
			return ecc.Point{}, fmt.Errorf("freemanbonehgohnissim: %w", err)
		}
	}
	return result, nil
}

// scale multiplies a point with a scalar reduced modulo r.
func (c *Cryptosystem) scale(pt ecc.Point, scalar *big.Int) (ecc.Point, error) {
	k := new(big.Int).Mod(scalar, c.r)
	if k.Sign() == 0 || pt.IsIdentity() {
		return c.ec.O(), nil
	}
	scaled, err := pt.ScalarMul(k)
	if err != nil {
		return ecc.Point{}, fmt.Errorf("freemanbonehgohnissim: %w", err)
	}
	return scaled, nil
}

// discreteLogCurve finds m in [-limit, limit] such that target = m pi(g) with
// baby-step giant-step.
func (c *Cryptosystem) discreteLogCurve(target ecc.Point) (*big.Int, error) {
	table := &c.curveTable
	table.once.Do(func() {
		base, err := c.project(c.g)
		if err != nil {
			table.err = err
			return
		}
		table.size = new(big.Int).Sqrt(big.NewInt(2*c.limit)).Int64() + 1
		table.steps = make(map[string]int64, table.size)
		current := c.ec.O()
		for j := int64(0); j < table.size; j++ {
			key := pointKey(current)
			if _, ok := table.steps[key]; !ok {
				table.steps[key] = j
			}
			if current, err = current.Add(base); err != nil {
				table.err = err
				return
			}
		}
		// giant step is -size * base, and the search starts from
		// target + limit * base
		giant, err := c.scale(base, big.NewInt(-table.size))
		if err != nil {
			table.err = err
			return
		}
		table.base, table.giant = base, giant
	})
	if table.err != nil {
		return nil, fmt.Errorf("freemanbonehgohnissim: %w", table.err)
	}
	base, giant := table.base.(ecc.Point), table.giant.(ecc.Point)

	shift, err := c.scale(base, big.NewInt(c.limit))
	if err != nil {
		return nil, err
	}
	current, err := target.Add(shift)
	if err != nil {
		return nil, fmt.Errorf("freemanbonehgohnissim: %w", err)
	}
	for i := int64(0); i <= table.size; i++ {
		if j, ok := table.steps[pointKey(current)]; ok {
			if m := i*table.size + j - c.limit; abs(m) <= c.limit {
				return big.NewInt(m), nil
			}
		}
		if current, err = current.Add(giant); err != nil {
			return nil, fmt.Errorf("freemanbonehgohnissim: %w", err)
		}
	}
	return nil, c.outOfRange()
}

// discreteLogGT finds m in [-limit, limit] such that
// target = e(pi(g), pi(g))^m with baby-step giant-step.
func (c *Cryptosystem) discreteLogGT(target ecc.FP2) (*big.Int, error) {
	table := &c.gtTable
	table.once.Do(func() {
		projected, err := c.project(c.g)
		if err != nil {
			table.err = err
			return
		}
		pairing, err := c.ec.Pairing(projected, projected)
		if err != nil {
			table.err = err
			return
		}
		base := pairing.Value
		table.size = new(big.Int).Sqrt(big.NewInt(2*c.limit)).Int64() + 1
		table.steps = make(map[string]int64, table.size)
		current := ecc.FP2One()
		for j := int64(0); j < table.size; j++ {
			key := current.String()
			if _, ok := table.steps[key]; !ok {
				table.steps[key] = j
			}
			current = current.Mul(base, c.p)
		}
		powered, err := base.Exp(big.NewInt(table.size), c.p)
		if err != nil {
			table.err = err
			return
		}
		giant, err := powered.Inverse(c.p)
		if err != nil {
			table.err = err
			return
		}
		table.base, table.giant = base, giant
	})
	if table.err != nil {
		return nil, fmt.Errorf("freemanbonehgohnissim: %w", table.err)
	}
	base, giant := table.base.(ecc.FP2), table.giant.(ecc.FP2)

	shift, err := base.Exp(big.NewInt(c.limit), c.p)
	if err != nil {
		return nil, fmt.Errorf("freemanbonehgohnissim: %w", err)
	}
	current := target.Mul(shift, c.p)
	for i := int64(0); i <= table.size; i++ {
		if j, ok := table.steps[current.String()]; ok {
			if m := i*table.size + j - c.limit; abs(m) <= c.limit {
				return big.NewInt(m), nil
			}
		}
		current = current.Mul(giant, c.p)
	}
	return nil, c.outOfRange()
}

func (c *Cryptosystem) outOfRange() error {
	return fmt.Errorf("freemanbonehgohnissim: decryption failed, because result is out of [-%d, %d], "+
		"set a greater plaintext limit while building the cryptosystem: %w", c.limit, c.limit, phe.ErrDecryptionFailed)
}

// multiplied reports whether a ciphertext is multiplied, together with a
// function converting it into its elements.
func (c *Cryptosystem) multiplied(v phe.Value) (func() ([]ecc.FP2, error), bool) {
	t, ok := v.(phe.Tuple)
	if !ok || t.Len() != dimension*dimension {
		return nil, false
	}
	return func() ([]ecc.FP2, error) {
		out := make([]ecc.FP2, t.Len())
		for i, item := range t.Items {
			f, ok := item.(phe.FP2)
			if !ok {
				return nil, phe.InvalidCiphertextf("freemanbonehgohnissim: multiplied ciphertext element %d is %T", i, item)
			}
			out[i] = ecc.NewFP2(f.A, f.B)
		}
		return out, nil
	}, true
}

// fresh converts a fresh ciphertext into its points.
func (c *Cryptosystem) fresh(v phe.Value) ([]ecc.Point, error) {
	t, err := phe.AsTuple(v)
	if err != nil {
		return nil, err
	}
	if t.Len() != dimension {
		return nil, phe.InvalidCiphertextf("freemanbonehgohnissim: ciphertext must have %d points, got %d", dimension, t.Len())
	}
	pts := make([]phe.Point, dimension)
	for i, item := range t.Items {
		pt, err := phe.AsPoint(item)
		if err != nil {
			return nil, err
		}
		pts[i] = pt
	}
	out, err := c.points(pts)
	if err != nil {
		return nil, phe.InvalidCiphertextf("freemanbonehgohnissim: %v", err)
	}
	return out, nil
}

// points converts stored coordinates into points on the curve.
func (c *Cryptosystem) points(pts []phe.Point) ([]ecc.Point, error) {
	out := make([]ecc.Point, len(pts))
	for i, pt := range pts {
		if pt.Infinity {
			out[i] = c.ec.O()
			continue
		}
		point, err := c.ec.Point(pt.X, pt.Y)
		if err != nil {
			return nil, err
		}
		out[i] = point
	}
	return out, nil
}

func fp2Value(elements []ecc.FP2) phe.Value {
	items := make([]phe.Value, len(elements))
	for i, e := range elements {
		items[i] = phe.NewFP2(e.A, e.B)
	}
	return phe.Tuple{Items: items}
}

func toPhePoint(p ecc.Point) phe.Point {
	if p.IsIdentity() {
		return phe.InfinityPoint()
	}
	return phe.NewPoint(p.X, p.Y)
}

func pointKey(p ecc.Point) string {
	if p.IsIdentity() {
		return "O"
	}
	return p.X.String() + "," + p.Y.String()
}

func abs(x int64) int64 {
	if x < 0 {
		return -x
	}
	return x
}
