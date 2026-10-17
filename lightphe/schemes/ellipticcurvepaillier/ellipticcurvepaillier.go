// Package ellipticcurvepaillier implements the elliptic curve analogue of
// Paillier, which is homomorphic with respect to addition and supports
// multiplying a ciphertext by a known plain constant.
//
// Paillier works in the multiplicative group Z_{n^2}*, whereas this works in
// the group of points on an elliptic curve y^2 = x^3 + b over the ring Z_{n^2}
// where n = pq.
//
// Points reducing to the point at infinity modulo n form a subgroup of order
// n, in which discrete logarithm is easy, similar to 1 + n in Paillier. A
// ciphertext is m * (n : 1 : 0) + r * g, where g is a point whose order is a
// secret factor of the group order. Multiplying a ciphertext by that order
// clears r * g and leaves m.
//
// p and q are 2 mod 3, so the curve has p + 1 points modulo p and q + 1 points
// modulo q as in KMOV cryptosystem, and the group order is known by the private
// key owner only. Points are in projective coordinates as division is not
// always possible in Z_{n^2}. Additions use complete formulas, which work for
// all points including doubling and the point at infinity, as the order of g is
// odd and so it has no point of order 2. Ciphertexts are 3 times larger than
// Paillier's, and operations are slower.
//
// Point arithmetic is implemented here instead of the ecc package, which works
// with affine points and divides in its addition formulas. Z_{n^2} is not a
// field, and messages live in points reducing to the point at infinity modulo
// n, such as (mn : 1 : 0), which cannot be written as affine points.
// Projective coordinates with complete formulas never divide and keep those
// points distinct.
//
// Reference: Galbraith, S. D. (2002). Elliptic Curve Paillier Schemes. Journal
// of Cryptology, 15(2), 129-138.
//
// Reference: Renes, J., Costello, C., Batina, L. (2016). Complete Addition
// Formulas for Prime Order Elliptic Curves. EUROCRYPT 2016.
package ellipticcurvepaillier

import (
	"encoding/json"
	"fmt"
	"math/big"
	"sync"

	"github.com/serengil/lightphe-go/lightphe/internal/mathutil"
	"github.com/serengil/lightphe-go/lightphe/phe"
)

// DefaultKeySize is the modulus size in bits used when none is requested.
const DefaultKeySize = 1024

// randomKeyExtraBits makes the random key statistically uniform modulo the
// order of g.
const randomKeyExtraBits = 128

// PublicKey is the Elliptic Curve Paillier public key: the modulus n, the curve
// coefficient b and the affine point g over Z_{n^2}.
type PublicKey struct {
	N *big.Int   `json:"n"`
	B *big.Int   `json:"b"`
	G *phe.Point `json:"g"`
}

// PrivateKey holds the secret order of g together with the factors of n.
type PrivateKey struct {
	Order *big.Int `json:"order"`
	P     *big.Int `json:"p,omitempty"`
	Q     *big.Int `json:"q,omitempty"`
}

// Keys bundles the key pair. PrivateKey is nil for encryption-only setups.
type Keys struct {
	PublicKey  *PublicKey  `json:"public_key,omitempty"`
	PrivateKey *PrivateKey `json:"private_key,omitempty"`
}

// Validate reports missing or malformed key material.
func (k Keys) Validate() error {
	if k.PublicKey == nil {
		return phe.RequireSection(phe.EllipticCurvePaillier, phe.SectionPublic)
	}
	if err := phe.RequireFields(phe.EllipticCurvePaillier, phe.SectionPublic,
		phe.Field("n", k.PublicKey.N != nil),
		phe.Field("b", k.PublicKey.B != nil),
		phe.Field("g", k.PublicKey.G != nil && !k.PublicKey.G.Infinity),
	); err != nil {
		return err
	}
	if k.PrivateKey != nil {
		return phe.RequireFields(phe.EllipticCurvePaillier, phe.SectionPrivate,
			phe.Field("order", k.PrivateKey.Order != nil),
		)
	}
	return nil
}

// point is a projective point (X : Y : Z) over Z_{n^2}.
type point [3]*big.Int

// Cryptosystem is a configured Elliptic Curve Paillier instance. It is
// immutable and safe for concurrent use.
type Cryptosystem struct {
	phe.Base

	keys      Keys
	n         *big.Int
	nSquared  *big.Int
	b3        *big.Int
	g         point
	order     *big.Int
	hasSecret bool

	gPowersOnce sync.Once
	gPowers     []point
}

var _ phe.Homomorphic = (*Cryptosystem)(nil)

// Generate creates a fresh key pair with a modulus of keySize bits.
func Generate(keySize int) (*Cryptosystem, error) {
	if keySize <= 0 {
		keySize = DefaultKeySize
	}
	if keySize < 16 {
		return nil, fmt.Errorf("ellipticcurvepaillier: key size %d is too small: %w", keySize, phe.ErrKeyGeneration)
	}
	one := big.NewInt(1)

	for {
		p, err := findPrime(keySize / 2)
		if err != nil {
			return nil, err
		}
		q, err := findPrime(keySize / 2)
		if err != nil {
			return nil, err
		}
		if p.Cmp(q) == 0 {
			continue
		}
		n := new(big.Int).Mul(p, q)
		nSquared := new(big.Int).Mul(n, n)

		// exponent of the group modulo n, and its odd part
		p1 := new(big.Int).Add(p, one)
		q1 := new(big.Int).Add(q, one)
		exponent := new(big.Int).Mul(p1, q1)
		exponent.Quo(exponent, mathutil.GCD(p1, q1))
		order := new(big.Int).Set(exponent)
		for order.Bit(0) == 0 {
			order.Rsh(order, 1)
		}
		if !mathutil.IsCoprime(order, n) {
			continue
		}

		// random point P, and the curve passing through it
		x, err := mathutil.RandBelow(nSquared)
		if err != nil {
			return nil, err
		}
		y, err := mathutil.RandBelow(nSquared)
		if err != nil {
			return nil, err
		}
		b := new(big.Int).Mul(y, y)
		b.Sub(b, new(big.Int).Exp(x, big.NewInt(3), nil)).Mod(b, nSquared)
		if !mathutil.IsCoprime(b, n) {
			continue
		}

		// g has odd order dividing the secret order
		b3 := new(big.Int).Mul(b, big.NewInt(3))
		scalar := new(big.Int).Mul(n, new(big.Int).Quo(exponent, order))
		g := multiply(point{x, y, big.NewInt(1)}, scalar, b3, nSquared)
		if !mathutil.IsCoprime(g[2], n) {
			continue
		}
		zInv, err := mathutil.ModInverse(g[2], nSquared)
		if err != nil {
			continue
		}
		gx := new(big.Int).Mul(g[0], zInv)
		gx.Mod(gx, nSquared)
		gy := new(big.Int).Mul(g[1], zInv)
		gy.Mod(gy, nSquared)

		return New(Keys{
			PublicKey:  &PublicKey{N: n, B: b, G: &phe.Point{X: gx, Y: gy}},
			PrivateKey: &PrivateKey{Order: order, P: p, Q: q},
		})
	}
}

// findPrime returns a prime p = 2 mod 3, so that y^2 = x^3 + b has p + 1
// points modulo p.
func findPrime(bits int) (*big.Int, error) {
	three := big.NewInt(3)
	two := big.NewInt(2)
	rem := new(big.Int)
	for {
		candidate, err := mathutil.RandBits(bits)
		if err != nil {
			return nil, err
		}
		candidate.SetBit(candidate, bits-1, 1)
		candidate.SetBit(candidate, 0, 1)
		if rem.Mod(candidate, three).Cmp(two) == 0 && mathutil.IsPrime(candidate) {
			return candidate, nil
		}
	}
}

// New builds a cryptosystem around an existing key pair.
func New(keys Keys) (*Cryptosystem, error) {
	if err := keys.Validate(); err != nil {
		return nil, err
	}
	n := new(big.Int).Set(keys.PublicKey.N)
	c := &Cryptosystem{
		Base:     phe.Base{Alg: phe.EllipticCurvePaillier},
		keys:     keys,
		n:        n,
		nSquared: new(big.Int).Mul(n, n),
		b3:       new(big.Int).Mul(keys.PublicKey.B, big.NewInt(3)),
		g:        point{new(big.Int).Set(keys.PublicKey.G.X), new(big.Int).Set(keys.PublicKey.G.Y), big.NewInt(1)},
	}
	if keys.PrivateKey != nil {
		c.order = new(big.Int).Set(keys.PrivateKey.Order)
		c.hasSecret = true
	}
	return c, nil
}

// FromJSON rebuilds a cryptosystem from exported key material.
func FromJSON(data []byte) (*Cryptosystem, error) {
	var keys Keys
	if err := json.Unmarshal(data, &keys); err != nil {
		return nil, phe.InvalidKeysf("ellipticcurvepaillier: decoding keys: %v", err)
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

// Encrypt implements phe.Homomorphic, producing m * (n : 1 : 0) + r * g.
func (c *Cryptosystem) Encrypt(plaintext *big.Int) (phe.Value, error) {
	upper := new(big.Int).Lsh(c.n, randomKeyExtraBits)
	r, err := mathutil.RandRange(big.NewInt(1), upper)
	if err != nil {
		return nil, fmt.Errorf("ellipticcurvepaillier: %w", err)
	}
	return c.EncryptWith(plaintext, r), nil
}

// EncryptWith encrypts using a caller supplied random key.
func (c *Cryptosystem) EncryptWith(plaintext, random *big.Int) phe.Value {
	m := new(big.Int).Mod(plaintext, c.n)

	// m * (n : 1 : 0) = (mn : 1 : 0), similar to (1 + n)^m = 1 + mn in Paillier
	messagePoint := point{m.Mul(m, c.n).Mod(m, c.nSquared), big.NewInt(1), new(big.Int)}
	return toValue(add(messagePoint, c.multiplyG(random), c.b3, c.nSquared))
}

// Decrypt implements phe.Homomorphic.
func (c *Cryptosystem) Decrypt(ciphertext phe.Value) (*big.Int, error) {
	if !c.hasSecret {
		return nil, phe.ErrMissingPrivateKey
	}
	pt, err := toPoint(ciphertext)
	if err != nil {
		return nil, err
	}

	// order * C = (order * m) * (n : 1 : 0) as order * r * g is the point at infinity
	result := multiply(pt, c.order, c.b3, c.nSquared)
	x, y, z := result[0], result[1], result[2]
	rem := new(big.Int)
	if rem.Mod(x, c.n).Sign() != 0 || rem.Mod(z, c.n).Sign() != 0 || !mathutil.IsCoprime(y, c.n) {
		return nil, phe.InvalidCiphertextf("ellipticcurvepaillier: ciphertext is invalid")
	}

	// (kn : 1 : 0) -> k
	yInv, err := mathutil.ModInverse(y, c.nSquared)
	if err != nil {
		return nil, fmt.Errorf("ellipticcurvepaillier: %v: %w", err, phe.ErrDecryptionFailed)
	}
	scaled := new(big.Int).Mul(x, yInv)
	scaled.Mod(scaled, c.nSquared).Quo(scaled, c.n)
	orderInv, err := mathutil.ModInverse(c.order, c.n)
	if err != nil {
		return nil, fmt.Errorf("ellipticcurvepaillier: %v: %w", err, phe.ErrDecryptionFailed)
	}
	return scaled.Mul(scaled, orderInv).Mod(scaled, c.n), nil
}

// Add implements phe.Homomorphic.
func (c *Cryptosystem) Add(a, b phe.Value) (phe.Value, error) {
	p1, err := toPoint(a)
	if err != nil {
		return nil, err
	}
	p2, err := toPoint(b)
	if err != nil {
		return nil, err
	}
	return toValue(add(p1, p2, c.b3, c.nSquared)), nil
}

// MultiplyByConstant implements phe.Homomorphic.
func (c *Cryptosystem) MultiplyByConstant(ciphertext phe.Value, constant *big.Int) (phe.Value, error) {
	pt, err := toPoint(ciphertext)
	if err != nil {
		return nil, err
	}
	k := new(big.Int).Mod(constant, c.n)
	return toValue(multiply(pt, k, c.b3, c.nSquared)), nil
}

// Reencrypt implements phe.Homomorphic by adding an encryption of zero.
func (c *Cryptosystem) Reencrypt(ciphertext phe.Value) (phe.Value, error) {
	zero, err := c.Encrypt(new(big.Int))
	if err != nil {
		return nil, err
	}
	return c.Add(ciphertext, zero)
}

// multiplyG multiplies g with a scalar using precomputed 2^i * g points, which
// avoids doublings.
func (c *Cryptosystem) multiplyG(scalar *big.Int) point {
	c.gPowersOnce.Do(func() {
		bits := new(big.Int).Lsh(c.n, randomKeyExtraBits).BitLen()
		powers := make([]point, bits)
		powers[0] = c.g
		for i := 1; i < bits; i++ {
			powers[i] = add(powers[i-1], powers[i-1], c.b3, c.nSquared)
		}
		c.gPowers = powers
	})
	if scalar.BitLen() > len(c.gPowers) {
		return multiply(c.g, scalar, c.b3, c.nSquared)
	}

	result := identity()
	for i := 0; i < scalar.BitLen(); i++ {
		if scalar.Bit(i) == 1 {
			result = add(result, c.gPowers[i], c.b3, c.nSquared)
		}
	}
	return result
}

func identity() point { return point{new(big.Int), big.NewInt(1), new(big.Int)} }

// add adds two projective points on y^2 = x^3 + b over Z_{n^2} with complete
// formulas (Algorithm 7 of Renes-Costello-Batina for a = 0). b3 is 3b.
func add(p1, p2 point, b3, mod *big.Int) point {
	x1, y1, z1 := p1[0], p1[1], p1[2]
	x2, y2, z2 := p2[0], p2[1], p2[2]

	mulMod := func(a, b *big.Int) *big.Int {
		r := new(big.Int).Mul(a, b)
		return r.Mod(r, mod)
	}
	sum := func(a, b *big.Int) *big.Int { return new(big.Int).Add(a, b) }

	t0 := mulMod(x1, x2)
	t1 := mulMod(y1, y2)
	t2 := mulMod(z1, z2)
	t3 := mulMod(sum(x1, y1), sum(x2, y2))
	t3.Sub(t3, t0).Sub(t3, t1).Mod(t3, mod)
	t4 := mulMod(sum(y1, z1), sum(y2, z2))
	t4.Sub(t4, t1).Sub(t4, t2).Mod(t4, mod)
	y3 := mulMod(sum(x1, z1), sum(x2, z2))
	y3.Sub(y3, t0).Sub(y3, t2).Mod(y3, mod)
	t0 = mulMod(big.NewInt(3), t0)
	t2 = mulMod(b3, t2)
	z3 := sum(t1, t2)
	z3.Mod(z3, mod)
	t1 = new(big.Int).Sub(t1, t2)
	t1.Mod(t1, mod)
	y3 = mulMod(b3, y3)
	x3 := new(big.Int).Sub(new(big.Int).Mul(t3, t1), new(big.Int).Mul(t4, y3))
	x3.Mod(x3, mod)
	y3 = new(big.Int).Add(new(big.Int).Mul(t1, z3), new(big.Int).Mul(y3, t0))
	y3.Mod(y3, mod)
	z3 = new(big.Int).Add(new(big.Int).Mul(z3, t4), new(big.Int).Mul(t0, t3))
	z3.Mod(z3, mod)
	return point{x3, y3, z3}
}

// multiply multiplies a projective point with a non-negative scalar with the
// double and add method.
func multiply(pt point, scalar, b3, mod *big.Int) point {
	result := identity()
	for i := scalar.BitLen() - 1; i >= 0; i-- {
		result = add(result, result, b3, mod)
		if scalar.Bit(i) == 1 {
			result = add(result, pt, b3, mod)
		}
	}
	return result
}

func toValue(pt point) phe.Value {
	return phe.NewTuple(phe.Int{V: pt[0]}, phe.Int{V: pt[1]}, phe.Int{V: pt[2]})
}

func toPoint(v phe.Value) (point, error) {
	t, err := phe.AsTuple(v)
	if err != nil {
		return point{}, err
	}
	coords, err := t.Ints()
	if err != nil {
		return point{}, err
	}
	if len(coords) != 3 {
		return point{}, phe.InvalidCiphertextf("ellipticcurvepaillier: expected a projective point of 3 coordinates, got %d", len(coords))
	}
	return point{coords[0], coords[1], coords[2]}, nil
}
