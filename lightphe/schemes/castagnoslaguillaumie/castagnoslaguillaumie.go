// Package castagnoslaguillaumie implements the Castagnos-Laguillaumie
// cryptosystem, which is homomorphic with respect to addition and supports
// multiplying a ciphertext by a known plain constant.
//
// It is an ElGamal-like scheme in the class group of an imaginary quadratic
// order of discriminant Δp = -p^3 q, which has a subgroup F of order p with an
// easy discrete logarithm. So, decryption does not require brute force and
// the message space is the large prime p.
//
// Reference: Castagnos, G., Laguillaumie, F. (2015). Linearly Homomorphic
// Encryption from DDH. CT-RSA 2015. https://eprint.iacr.org/2015/047
package castagnoslaguillaumie

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

var (
	one  = big.NewInt(1)
	two  = big.NewInt(2)
	four = big.NewInt(4)
)

// Form is a binary quadratic form ax^2 + bxy + cy^2, stored as [a, b, c].
type Form [3]*big.Int

// PublicKey is the Castagnos-Laguillaumie public key. P is the message space,
// Q the second prime of Δk = -pq, G the generator and H = G^x, both as
// reduced forms [a, b, c].
type PublicKey struct {
	P *big.Int   `json:"p"`
	Q *big.Int   `json:"q"`
	G []*big.Int `json:"g"`
	H []*big.Int `json:"h"`
}

// PrivateKey is the secret exponent x.
type PrivateKey struct {
	X *big.Int `json:"x"`
}

// Keys bundles the key pair. PrivateKey is nil for encryption-only setups.
type Keys struct {
	PublicKey  *PublicKey  `json:"public_key,omitempty"`
	PrivateKey *PrivateKey `json:"private_key,omitempty"`
}

// Validate reports missing or malformed key material.
func (k Keys) Validate() error {
	if k.PublicKey == nil {
		return phe.RequireSection(phe.CastagnosLaguillaumie, phe.SectionPublic)
	}
	if err := phe.RequireFields(phe.CastagnosLaguillaumie, phe.SectionPublic,
		phe.Field("p", k.PublicKey.P != nil),
		phe.Field("q", k.PublicKey.Q != nil),
		phe.Field("g", k.PublicKey.G != nil),
		phe.Field("h", k.PublicKey.H != nil),
	); err != nil {
		return err
	}
	if len(k.PublicKey.G) != 3 || len(k.PublicKey.H) != 3 {
		return phe.InvalidKeysf("castagnoslaguillaumie: g and h must be forms of 3 integers")
	}
	if k.PrivateKey != nil {
		if err := phe.RequireFields(phe.CastagnosLaguillaumie, phe.SectionPrivate,
			phe.Field("x", k.PrivateKey.X != nil),
		); err != nil {
			return err
		}
	}
	return nil
}

// Cryptosystem is a configured Castagnos-Laguillaumie instance. It is
// immutable and safe for concurrent use.
type Cryptosystem struct {
	phe.Base

	keys           Keys
	p              *big.Int
	deltaK, deltaP *big.Int
	bound          *big.Int
	g, h           Form
	x              *big.Int
	hasSecret      bool
}

var _ phe.Homomorphic = (*Cryptosystem)(nil)

// Generate creates a fresh key pair. keySize is the bit length of the
// fundamental discriminant Δk = -pq.
func Generate(keySize, maxTries int) (*Cryptosystem, error) {
	if keySize <= 0 {
		keySize = DefaultKeySize
	}
	if maxTries <= 0 {
		maxTries = DefaultMaxTries
	}

	// p defines the message space Z_p. q must be greater than 4p to keep
	// the forms of the subgroup F reduced.
	pSize := keySize / 4
	if pSize < 4 {
		pSize = 4
	}
	qSize := keySize - pSize

	for attempt := 0; attempt < maxTries; attempt++ {
		p, err := mathutil.RandPrime(pSize)
		if err != nil {
			return nil, fmt.Errorf("castagnoslaguillaumie: %w", err)
		}
		q, err := mathutil.RandPrime(qSize)
		if err != nil {
			return nil, fmt.Errorf("castagnoslaguillaumie: %w", err)
		}

		// pq = 3 mod 4 makes Δk = -pq a fundamental discriminant
		pq := new(big.Int).Mul(p, q)
		if new(big.Int).Mod(pq, four).Int64() != 3 || mathutil.Jacobi(p, q) != -1 {
			continue
		}

		deltaK := new(big.Int).Neg(pq)
		deltaP := new(big.Int).Mul(deltaK, new(big.Int).Mul(p, p))

		g, ok := findGenerator(p, q, deltaK, deltaP)
		if !ok {
			continue
		}

		x, err := mathutil.RandRange(one, findBound(deltaK))
		if err != nil {
			return nil, fmt.Errorf("castagnoslaguillaumie: %w", err)
		}
		h := formPow(g, x, deltaP)

		return New(Keys{
			PublicKey:  &PublicKey{P: p, Q: q, G: g[:], H: h[:]},
			PrivateKey: &PrivateKey{X: x},
		})
	}
	return nil, fmt.Errorf("castagnoslaguillaumie: no valid key pair after %d attempts: %w", maxTries, phe.ErrKeyGeneration)
}

// New builds a cryptosystem around an existing key pair.
func New(keys Keys) (*Cryptosystem, error) {
	if err := keys.Validate(); err != nil {
		return nil, err
	}
	p := new(big.Int).Set(keys.PublicKey.P)
	deltaK := new(big.Int).Neg(new(big.Int).Mul(p, keys.PublicKey.Q))

	c := &Cryptosystem{
		Base:   phe.Base{Alg: phe.CastagnosLaguillaumie},
		keys:   keys,
		p:      p,
		deltaK: deltaK,
		deltaP: new(big.Int).Mul(deltaK, new(big.Int).Mul(p, p)),
		bound:  findBound(deltaK),
		g:      toForm(keys.PublicKey.G),
		h:      toForm(keys.PublicKey.H),
	}
	if keys.PrivateKey != nil {
		c.x = new(big.Int).Set(keys.PrivateKey.X)
		c.hasSecret = true
	}
	return c, nil
}

// FromJSON rebuilds a cryptosystem from exported key material.
func FromJSON(data []byte) (*Cryptosystem, error) {
	var keys Keys
	if err := json.Unmarshal(data, &keys); err != nil {
		return nil, phe.InvalidKeysf("castagnoslaguillaumie: decoding keys: %v", err)
	}
	return New(keys)
}

// Keys returns a copy of the key material.
func (c *Cryptosystem) Keys() Keys { return c.keys }

// PlaintextModulo implements phe.Homomorphic.
func (c *Cryptosystem) PlaintextModulo() *big.Int { return new(big.Int).Set(c.p) }

// CiphertextModulo implements phe.Homomorphic. It reports |Δp|, the
// discriminant of the class group ciphertexts live in.
func (c *Cryptosystem) CiphertextModulo() *big.Int { return new(big.Int).Neg(c.deltaP) }

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

// Encrypt implements phe.Homomorphic. The ciphertext is the pair of forms
// (g^r, f^m h^r).
func (c *Cryptosystem) Encrypt(plaintext *big.Int) (phe.Value, error) {
	r, err := mathutil.RandRange(one, c.bound)
	if err != nil {
		return nil, fmt.Errorf("castagnoslaguillaumie: %w", err)
	}
	return c.EncryptWith(plaintext, r)
}

// EncryptWith encrypts using a caller supplied random exponent.
func (c *Cryptosystem) EncryptWith(plaintext, random *big.Int) (phe.Value, error) {
	c1 := formPow(c.g, random, c.deltaP)
	c2 := compose(c.fPow(plaintext), formPow(c.h, random, c.deltaP), c.deltaP)
	return pairValue(c1, c2), nil
}

// Decrypt implements phe.Homomorphic.
func (c *Cryptosystem) Decrypt(ciphertext phe.Value) (*big.Int, error) {
	if !c.hasSecret {
		return nil, phe.ErrMissingPrivateKey
	}
	c1, c2, err := asPair(ciphertext)
	if err != nil {
		return nil, err
	}

	// f^m = c2 / c1^x
	fm := compose(c2, inverse(formPow(c1, c.x, c.deltaP)), c.deltaP)
	if formsEqual(fm, identity(c.deltaP)) {
		return new(big.Int), nil
	}

	// discrete logarithm in F is easy: f^m = (p^2, L(m) p, *)
	// where L(m) is congruent to m^-1 modulo p
	pSquared := new(big.Int).Mul(c.p, c.p)
	l, rem := new(big.Int).QuoRem(fm[1], c.p, new(big.Int))
	if fm[0].Cmp(pSquared) != 0 || rem.Sign() != 0 {
		return nil, fmt.Errorf("castagnoslaguillaumie: ciphertext does not belong to keys: %w", phe.ErrDecryptionFailed)
	}
	m, err := mathutil.ModInverse(new(big.Int).Mod(l, c.p), c.p)
	if err != nil {
		return nil, fmt.Errorf("castagnoslaguillaumie: %v: %w", err, phe.ErrDecryptionFailed)
	}
	return m, nil
}

// Add implements phe.Homomorphic.
func (c *Cryptosystem) Add(a, b phe.Value) (phe.Value, error) {
	a1, a2, err := asPair(a)
	if err != nil {
		return nil, err
	}
	b1, b2, err := asPair(b)
	if err != nil {
		return nil, err
	}
	return pairValue(compose(a1, b1, c.deltaP), compose(a2, b2, c.deltaP)), nil
}

// MultiplyByConstant implements phe.Homomorphic.
func (c *Cryptosystem) MultiplyByConstant(ciphertext phe.Value, constant *big.Int) (phe.Value, error) {
	c1, c2, err := asPair(ciphertext)
	if err != nil {
		return nil, err
	}
	k := new(big.Int).Mod(constant, c.p)
	return pairValue(formPow(c1, k, c.deltaP), formPow(c2, k, c.deltaP)), nil
}

// Reencrypt implements phe.Homomorphic.
func (c *Cryptosystem) Reencrypt(ciphertext phe.Value) (phe.Value, error) {
	zeroCiphertext, err := c.Encrypt(new(big.Int))
	if err != nil {
		return nil, err
	}
	return c.Add(ciphertext, zeroCiphertext)
}

// fPow computes f^m in closed form, where f = (p^2, p, *) generates the
// subgroup F of order p.
func (c *Cryptosystem) fPow(m *big.Int) Form {
	reduced := new(big.Int).Mod(m, c.p)
	if reduced.Sign() == 0 {
		return identity(c.deltaP)
	}

	// L(m) is the odd integer in [-p, p] congruent to m^-1 modulo p
	l, _ := mathutil.ModInverse(reduced, c.p)
	if l.Bit(0) == 0 {
		l.Sub(l, c.p)
	}

	a := new(big.Int).Mul(c.p, c.p)
	b := new(big.Int).Mul(l, c.p)
	return reduce(Form{a, b, formC(a, b, c.deltaP)})
}

// findBound returns the upper bound for exponents. Class number of Δk is about
// sqrt(|Δk|) log(|Δk|), and an additional 40 bits makes exponents
// statistically close to uniform.
func findBound(deltaK *big.Int) *big.Int {
	magnitude := new(big.Int).Neg(deltaK)
	bound := new(big.Int).Sqrt(magnitude)
	bound.Mul(bound, big.NewInt(int64(magnitude.BitLen())))
	return bound.Lsh(bound, 40)
}

// findGenerator finds g = [φp^-1(r^2)]^p where r is an ideal above a small
// split prime. Then g belongs to the subgroup of p-th powers in Cl(Δp).
func findGenerator(p, q, deltaK, deltaP *big.Int) (Form, bool) {
	for r := big.NewInt(3); r.Cmp(big.NewInt(10000)) < 0; r = new(big.Int).Add(r, two) {
		if !mathutil.IsPrime(r) || r.Cmp(p) == 0 || r.Cmp(q) == 0 {
			continue
		}
		if mathutil.Jacobi(deltaK, r) != 1 {
			continue
		}

		// prime form above r in Cl(Δk). b must be odd and b^2 = Δk mod 4r
		b, err := mathutil.SqrtMod(deltaK, r)
		if err != nil {
			continue
		}
		if b.Bit(0) == 0 {
			b = new(big.Int).Sub(r, b)
		}
		rForm := Form{new(big.Int).Set(r), b, formC(r, b, deltaK)}

		// squaring prevents being in 2-torsion of the class group
		r2 := compose(rForm, rForm, deltaK)
		if new(big.Int).Mod(r2[0], p).Sign() == 0 {
			continue
		}

		// lift from Cl(Δk) to Cl(Δp) via φp^-1(a, b, c) = (a, bp, cp^2)
		lifted := reduce(Form{
			r2[0],
			new(big.Int).Mul(r2[1], p),
			new(big.Int).Mul(r2[2], new(big.Int).Mul(p, p)),
		})
		g := formPow(lifted, p, deltaP)

		if !formsEqual(g, identity(deltaP)) {
			return g, true
		}
	}
	return Form{}, false
}

// ---------------------------------------------------------------------------
// Binary quadratic form arithmetic
// Ref: Cohen, H. (1993). A Course in Computational Algebraic Number Theory.
// ---------------------------------------------------------------------------

// identity returns the principal form of the class group for a discriminant
// delta = 1 mod 4.
func identity(delta *big.Int) Form {
	c := new(big.Int).Sub(one, delta)
	return Form{big.NewInt(1), big.NewInt(1), c.Div(c, four)}
}

// inverse returns the inverse of a reduced form in the class group.
func inverse(f Form) Form {
	return reduce(Form{f[0], new(big.Int).Neg(f[1]), f[2]})
}

// formC returns c = (b^2 - delta) / 4a, completing a form of discriminant
// delta.
func formC(a, b, delta *big.Int) *big.Int {
	c := new(big.Int).Mul(b, b)
	c.Sub(c, delta)
	return c.Quo(c, new(big.Int).Mul(four, a))
}

// normalize finds the equivalent form with -a < b <= a.
func normalize(f Form) Form {
	a, b, c := f[0], f[1], f[2]
	twoA := new(big.Int).Mul(two, a)
	r := floorDiv(new(big.Int).Sub(a, b), twoA)

	newB := new(big.Int).Mul(twoA, r)
	newB.Add(newB, b)

	newC := new(big.Int).Mul(a, r)
	newC.Mul(newC, r)
	newC.Add(newC, new(big.Int).Mul(b, r))
	newC.Add(newC, c)
	return Form{a, newB, newC}
}

// reduce finds the unique reduced form equivalent to f, i.e. |b| <= a <= c,
// and b >= 0 if a = |b| or a = c (Cohen Algorithm 5.4.2).
func reduce(f Form) Form {
	negA := new(big.Int).Neg(f[0])
	if !(negA.Cmp(f[1]) < 0 && f[1].Cmp(f[0]) <= 0) {
		f = normalize(f)
	}

	for f[0].Cmp(f[2]) > 0 {
		f = normalize(Form{f[2], new(big.Int).Neg(f[1]), f[0]})
	}

	if f[0].Cmp(f[2]) == 0 && f[1].Sign() < 0 {
		f = Form{f[0], new(big.Int).Neg(f[1]), f[2]}
	}
	return f
}

// compose returns the composition of two forms with discriminant delta (Cohen
// Algorithm 5.4.7).
func compose(f1, f2 Form, delta *big.Int) Form {
	if f1[0].Cmp(f2[0]) > 0 {
		f1, f2 = f2, f1
	}
	a1, b1 := f1[0], f1[1]
	a2, b2, c2 := f2[0], f2[1], f2[2]

	s := new(big.Int).Add(b1, b2)
	s.Quo(s, two)
	n := new(big.Int).Sub(b2, s)

	var y1, d *big.Int
	if new(big.Int).Mod(a2, a1).Sign() == 0 {
		y1 = new(big.Int)
		d = a1
	} else {
		// y1 * a2 = d mod a1
		d = new(big.Int).GCD(nil, nil, a2, a1)
		y1, _ = mathutil.ModInverse(new(big.Int).Quo(a2, d), new(big.Int).Quo(a1, d))
	}

	var x2, y2, d1 *big.Int
	if new(big.Int).Mod(s, d).Sign() == 0 {
		y2 = big.NewInt(-1)
		x2 = new(big.Int)
		d1 = d
	} else {
		// x2 * s - y2 * d = d1
		d1 = new(big.Int).GCD(nil, nil, s, d)
		x2, _ = mathutil.ModInverse(new(big.Int).Quo(s, d1), new(big.Int).Quo(d, d1))
		y2 = new(big.Int).Mul(x2, s)
		y2.Sub(y2, d1)
		y2.Quo(y2, d)
	}

	v1 := new(big.Int).Quo(a1, d1)
	v2 := new(big.Int).Quo(a2, d1)

	r := new(big.Int).Mul(y1, y2)
	r.Mul(r, n)
	r.Sub(r, new(big.Int).Mul(x2, c2))
	r.Mod(r, v1)

	b3 := new(big.Int).Mul(two, v2)
	b3.Mul(b3, r)
	b3.Add(b3, b2)
	a3 := new(big.Int).Mul(v1, v2)
	return reduce(Form{a3, b3, formC(a3, b3, delta)})
}

// formPow raises a form to a non-negative power with square and multiply.
func formPow(f Form, exponent *big.Int, delta *big.Int) Form {
	result := identity(delta)
	base := f
	for i := exponent.BitLen() - 1; i >= 0; i-- {
		result = compose(result, result, delta)
		if exponent.Bit(i) == 1 {
			result = compose(result, base, delta)
		}
	}
	return result
}

func formsEqual(f1, f2 Form) bool {
	return f1[0].Cmp(f2[0]) == 0 && f1[1].Cmp(f2[1]) == 0 && f1[2].Cmp(f2[2]) == 0
}

// floorDiv divides rounding towards negative infinity, like Python's //.
func floorDiv(a, b *big.Int) *big.Int {
	q, r := new(big.Int).QuoRem(a, b, new(big.Int))
	if r.Sign() != 0 && (r.Sign() < 0) != (b.Sign() < 0) {
		q.Sub(q, one)
	}
	return q
}

func toForm(values []*big.Int) Form {
	return Form{new(big.Int).Set(values[0]), new(big.Int).Set(values[1]), new(big.Int).Set(values[2])}
}

func formValue(f Form) phe.Value {
	return phe.NewTuple(phe.NewInt(f[0]), phe.NewInt(f[1]), phe.NewInt(f[2]))
}

func pairValue(c1, c2 Form) phe.Value {
	return phe.NewTuple(formValue(c1), formValue(c2))
}

func asPair(v phe.Value) (Form, Form, error) {
	first, second, err := phe.AsPair(v)
	if err != nil {
		return Form{}, Form{}, err
	}
	c1, err := asForm(first)
	if err != nil {
		return Form{}, Form{}, err
	}
	c2, err := asForm(second)
	if err != nil {
		return Form{}, Form{}, err
	}
	return c1, c2, nil
}

func asForm(v phe.Value) (Form, error) {
	t, err := phe.AsTuple(v)
	if err != nil {
		return Form{}, err
	}
	ints, err := t.Ints()
	if err != nil {
		return Form{}, err
	}
	if len(ints) != 3 {
		return Form{}, phe.InvalidCiphertextf("castagnoslaguillaumie: a form needs 3 integers, got %d", len(ints))
	}
	return Form{ints[0], ints[1], ints[2]}, nil
}
