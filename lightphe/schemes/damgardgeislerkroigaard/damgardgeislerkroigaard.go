// Package damgardgeislerkroigaard implements the Damgard-Geisler-Kroigaard
// (DGK) cryptosystem, which is homomorphic with respect to addition and
// supports multiplying a ciphertext by a known plain constant.
//
// Messages live in Z_u for a deliberately small prime u (up to 32 bits), which
// keeps ciphertexts short and decryption fast. So, it is a good fit for small
// values such as counters, votes or bits of a secure comparison. Results that
// exceed this space wrap around, so operations producing large values (e.g.
// encrypted dot products on float tensors) are not suitable for it.
//
// It is a building block of secure comparison protocols, which underlie
// privacy-preserving machine learning tasks such as private decision tree
// evaluation and encrypted argmax. All of them are supported here in the
// semi-honest model, between a client holding the private key and a server.
//
// Reference: Damgard, I., Geisler, M., Kroigaard, M. (2007). Efficient and
// Secure Comparison for On-Line Auctions. ACISP 2007. Correction:
// https://eprint.iacr.org/2008/321
//
// Reference: Tai, R. K. H., Ma, J. P. K., Zhao, Y., Chow, S. S. M. (2017).
// Privacy-Preserving Decision Trees Evaluation via Linear Functions. ESORICS
// 2017.
package damgardgeislerkroigaard

import (
	"encoding/json"
	"fmt"
	"math/big"
	"sync"

	"github.com/serengil/lightphe-go/lightphe/internal/mathutil"
	"github.com/serengil/lightphe-go/lightphe/phe"
)

// Defaults used when the caller does not specify them.
const (
	DefaultKeySize  = 1024
	DefaultMaxTries = 10000
)

// PublicKey is the DGK public key. U is the plaintext space and T the bit
// length of the randomizer subgroup orders.
type PublicKey struct {
	N *big.Int `json:"n"`
	G *big.Int `json:"g"`
	H *big.Int `json:"h"`
	U *big.Int `json:"u"`
	T *big.Int `json:"t"`
}

// PrivateKey holds the factors of n and the orders of the randomizer
// subgroups.
type PrivateKey struct {
	P  *big.Int `json:"p"`
	Q  *big.Int `json:"q,omitempty"`
	VP *big.Int `json:"v_p"`
	VQ *big.Int `json:"v_q,omitempty"`
}

// Keys bundles the key pair. PrivateKey is nil for encryption-only setups.
type Keys struct {
	PublicKey  *PublicKey  `json:"public_key,omitempty"`
	PrivateKey *PrivateKey `json:"private_key,omitempty"`
}

// Validate reports missing or malformed key material.
func (k Keys) Validate() error {
	if k.PublicKey == nil {
		return phe.RequireSection(phe.DamgardGeislerKroigaard, phe.SectionPublic)
	}
	pk := k.PublicKey
	if err := phe.RequireFields(phe.DamgardGeislerKroigaard, phe.SectionPublic,
		phe.Field("n", pk.N != nil),
		phe.Field("g", pk.G != nil),
		phe.Field("h", pk.H != nil),
		phe.Field("u", pk.U != nil),
		phe.Field("t", pk.T != nil),
	); err != nil {
		return err
	}
	if sk := k.PrivateKey; sk != nil {
		return phe.RequireFields(phe.DamgardGeislerKroigaard, phe.SectionPrivate,
			phe.Field("p", sk.P != nil),
			phe.Field("v_p", sk.VP != nil),
		)
	}
	return nil
}

// Cryptosystem is a configured DGK instance. It is immutable and safe for
// concurrent use.
type Cryptosystem struct {
	phe.Base

	keys      Keys
	n, g, h   *big.Int
	u         *big.Int
	t         int
	p, vp     *big.Int
	hasSecret bool

	// baby-step giant-step lookup table, built once on first decryption
	babyOnce  sync.Once
	babySteps map[string]int64
	step      int64
	giant     *big.Int
	base      *big.Int
}

var (
	_ phe.Homomorphic                  = (*Cryptosystem)(nil)
	_ phe.SecureComparer               = (*Cryptosystem)(nil)
	_ phe.NumericDecisionTreeEvaluator = (*Cryptosystem)(nil)
	_ phe.ArgmaxEvaluator              = (*Cryptosystem)(nil)
)

// Generate creates a fresh key pair with a modulus of keySize bits.
func Generate(keySize, maxTries int) (*Cryptosystem, error) {
	if keySize <= 0 {
		keySize = DefaultKeySize
	}
	if maxTries <= 0 {
		maxTries = DefaultMaxTries
	}
	primeSize := keySize / 2

	// u is the plaintext space. it is kept small because decryption requires
	// solving a discrete logarithm in a subgroup of order u.
	uSize := clamp(keySize/16, 4, 32)

	// v_p and v_q are the orders of the randomizer subgroup. 160 bits in the
	// paper. at least 6 bits so that there are enough primes to pick distinct
	// u, v_p and v_q
	t := clamp(keySize/6, 6, 160)

	// the rest of p and q is filled with a random part
	rSize := primeSize - uSize - t - 1
	if rSize < 2 {
		return nil, fmt.Errorf("damgardgeislerkroigaard: key size %d is too small: %w", keySize, phe.ErrKeyGeneration)
	}

	u, err := randPrimeBits(uSize)
	if err != nil {
		return nil, err
	}
	vp, err := randPrimeBits(t, u)
	if err != nil {
		return nil, err
	}
	vq, err := randPrimeBits(t, u, vp)
	if err != nil {
		return nil, err
	}

	// picking primes p and q such that u * v_p divides p - 1 and u * v_q
	// divides q - 1
	p, err := findPrime(u, vp, rSize, maxTries)
	if err != nil {
		return nil, err
	}
	var q *big.Int
	for q == nil || q.Cmp(p) == 0 {
		if q, err = findPrime(u, vq, rSize, maxTries); err != nil {
			return nil, err
		}
	}
	n := new(big.Int).Mul(p, q)

	// g has order u * v_p * v_q, and h has order v_p * v_q in Z_n*. they are
	// built in Z_p* and Z_q* separately, and then combined with CRT
	gp, err := elementOfOrder(p, []*big.Int{u, vp}, maxTries)
	if err != nil {
		return nil, err
	}
	gq, err := elementOfOrder(q, []*big.Int{u, vq}, maxTries)
	if err != nil {
		return nil, err
	}
	hp, err := elementOfOrder(p, []*big.Int{vp}, maxTries)
	if err != nil {
		return nil, err
	}
	hq, err := elementOfOrder(q, []*big.Int{vq}, maxTries)
	if err != nil {
		return nil, err
	}
	g, _, err := mathutil.CRT([]*big.Int{gp, gq}, []*big.Int{p, q})
	if err != nil {
		return nil, fmt.Errorf("damgardgeislerkroigaard: %v: %w", err, phe.ErrKeyGeneration)
	}
	h, _, err := mathutil.CRT([]*big.Int{hp, hq}, []*big.Int{p, q})
	if err != nil {
		return nil, fmt.Errorf("damgardgeislerkroigaard: %v: %w", err, phe.ErrKeyGeneration)
	}

	return New(Keys{
		PublicKey:  &PublicKey{N: n, G: g, H: h, U: u, T: big.NewInt(int64(t))},
		PrivateKey: &PrivateKey{P: p, Q: q, VP: vp, VQ: vq},
	})
}

func clamp(v, lo, hi int) int {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

// randPrimeBits returns a random prime in [2^(bits-1), 2^bits) different from
// the excluded ones.
func randPrimeBits(bits int, exclude ...*big.Int) (*big.Int, error) {
	lo := new(big.Int).Lsh(big.NewInt(1), uint(bits-1))
	hi := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), uint(bits)), big.NewInt(1))
	for i := 0; i < 10000; i++ {
		candidate, err := mathutil.RandRangePrime(lo, hi)
		if err != nil {
			return nil, fmt.Errorf("damgardgeislerkroigaard: %v: %w", err, phe.ErrKeyGeneration)
		}
		distinct := true
		for _, e := range exclude {
			if candidate.Cmp(e) == 0 {
				distinct = false
			}
		}
		if distinct {
			return candidate, nil
		}
	}
	return nil, fmt.Errorf("damgardgeislerkroigaard: no distinct %d-bit prime: %w", bits, phe.ErrKeyGeneration)
}

// findPrime finds a prime p in the form of 2 * u * v * r + 1 where r has rSize
// bits.
func findPrime(u, v *big.Int, rSize, maxTries int) (*big.Int, error) {
	lo := new(big.Int).Lsh(big.NewInt(1), uint(rSize-1))
	hi := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), uint(rSize)), big.NewInt(1))
	factor := new(big.Int).Mul(u, v)
	factor.Lsh(factor, 1)
	for i := 0; i < maxTries; i++ {
		r, err := mathutil.RandRange(lo, hi)
		if err != nil {
			return nil, err
		}
		p := r.Mul(r, factor).Add(r, big.NewInt(1))
		if mathutil.IsPrime(p) {
			return p, nil
		}
	}
	return nil, fmt.Errorf("damgardgeislerkroigaard: no prime p = 1 mod 2*%s*%s in %d tries: %w", u, v, maxTries, phe.ErrKeyGeneration)
}

// elementOfOrder finds an element of Z_p* whose order is exactly the product
// of the given distinct primes, each dividing p - 1.
func elementOfOrder(p *big.Int, factors []*big.Int, maxTries int) (*big.Int, error) {
	one := big.NewInt(1)
	order := big.NewInt(1)
	for _, f := range factors {
		order.Mul(order, f)
	}
	cofactor := new(big.Int).Sub(p, one)
	cofactor.Quo(cofactor, order)
	for i := 0; i < maxTries; i++ {
		x, err := mathutil.RandRange(big.NewInt(2), new(big.Int).Sub(p, big.NewInt(2)))
		if err != nil {
			return nil, err
		}
		y := new(big.Int).Exp(x, cofactor, p)
		// order of y divides prod(factors). it is exactly that if removing any
		// prime factor does not send y to 1
		exact := true
		for _, f := range factors {
			if new(big.Int).Exp(y, new(big.Int).Quo(order, f), p).Cmp(one) == 0 {
				exact = false
				break
			}
		}
		if exact {
			return y, nil
		}
	}
	return nil, fmt.Errorf("damgardgeislerkroigaard: no element of order %s in %d tries: %w", order, maxTries, phe.ErrKeyGeneration)
}

// New builds a cryptosystem around an existing key pair.
func New(keys Keys) (*Cryptosystem, error) {
	if err := keys.Validate(); err != nil {
		return nil, err
	}
	pk := keys.PublicKey
	if pk.U.Sign() <= 0 || !pk.T.IsInt64() || pk.T.Sign() <= 0 {
		return nil, phe.InvalidKeysf("damgardgeislerkroigaard: u and t must be positive")
	}
	c := &Cryptosystem{
		Base: phe.Base{Alg: phe.DamgardGeislerKroigaard},
		keys: keys,
		n:    new(big.Int).Set(pk.N),
		g:    new(big.Int).Set(pk.G),
		h:    new(big.Int).Set(pk.H),
		u:    new(big.Int).Set(pk.U),
		t:    int(pk.T.Int64()),
	}
	if sk := keys.PrivateKey; sk != nil {
		c.p = new(big.Int).Set(sk.P)
		c.vp = new(big.Int).Set(sk.VP)
		c.hasSecret = true
	}
	return c, nil
}

// FromJSON rebuilds a cryptosystem from exported key material.
func FromJSON(data []byte) (*Cryptosystem, error) {
	var keys Keys
	if err := json.Unmarshal(data, &keys); err != nil {
		return nil, phe.InvalidKeysf("damgardgeislerkroigaard: decoding keys: %v", err)
	}
	return New(keys)
}

// Keys returns a copy of the key material.
func (c *Cryptosystem) Keys() Keys { return c.keys }

// PlaintextModulo implements phe.Homomorphic.
func (c *Cryptosystem) PlaintextModulo() *big.Int { return new(big.Int).Set(c.u) }

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

// Encrypt implements phe.Homomorphic, producing g^m h^r mod n.
func (c *Cryptosystem) Encrypt(plaintext *big.Int) (phe.Value, error) {
	v, err := c.encrypt(plaintext)
	if err != nil {
		return nil, err
	}
	return phe.Int{V: v}, nil
}

// encrypt draws a 2.5t bit random key as in the paper.
func (c *Cryptosystem) encrypt(plaintext *big.Int) (*big.Int, error) {
	upper := new(big.Int).Lsh(big.NewInt(1), uint(c.t*5/2))
	r, err := mathutil.RandRange(big.NewInt(1), upper)
	if err != nil {
		return nil, fmt.Errorf("damgardgeislerkroigaard: %w", err)
	}
	return c.EncryptWith(plaintext, r), nil
}

func (c *Cryptosystem) encryptInt(plaintext int64) (*big.Int, error) {
	return c.encrypt(big.NewInt(plaintext))
}

// EncryptWith encrypts using a caller supplied random key.
func (c *Cryptosystem) EncryptWith(plaintext, random *big.Int) *big.Int {
	m := new(big.Int).Mod(plaintext, c.u)
	left := new(big.Int).Exp(c.g, m, c.n)
	right := new(big.Int).Exp(c.h, random, c.n)
	return left.Mul(left, right).Mod(left, c.n)
}

// Decrypt implements phe.Homomorphic.
func (c *Cryptosystem) Decrypt(ciphertext phe.Value) (*big.Int, error) {
	v, err := phe.AsInt(ciphertext)
	if err != nil {
		return nil, err
	}
	return c.decrypt(v)
}

func (c *Cryptosystem) decrypt(ciphertext *big.Int) (*big.Int, error) {
	if !c.hasSecret {
		return nil, phe.ErrMissingPrivateKey
	}

	// c^v_p = (g^v_p)^m mod p because h^v_p = 1 mod p. g^v_p has order u in
	// Z_p* so m is the discrete logarithm of c^v_p in a small subgroup of
	// order u.
	c.babyOnce.Do(func() {
		c.base = new(big.Int).Exp(c.g, c.vp, c.p)
		c.step = new(big.Int).Sqrt(c.u).Int64() + 1
		c.babySteps = make(map[string]int64, c.step)
		value := big.NewInt(1)
		for j := int64(0); j < c.step; j++ {
			key := string(value.Bytes())
			if _, ok := c.babySteps[key]; !ok {
				c.babySteps[key] = j
			}
			value.Mul(value, c.base).Mod(value, c.p)
		}
		inv := new(big.Int).ModInverse(c.base, c.p)
		c.giant = inv.Exp(inv, big.NewInt(c.step), c.p)
	})

	z := new(big.Int).Exp(ciphertext, c.vp, c.p)
	for i := int64(0); i < c.step; i++ {
		if j, ok := c.babySteps[string(z.Bytes())]; ok {
			m := big.NewInt(i*c.step + j)
			return m.Mod(m, c.u), nil
		}
		z.Mul(z, c.giant).Mod(z, c.p)
	}
	return nil, fmt.Errorf("damgardgeislerkroigaard: ciphertext cannot be decrypted: %w", phe.ErrDecryptionFailed)
}

// IsZero checks a ciphertext encrypts 0 without solving the discrete
// logarithm. c^v_p = (g^v_p)^m mod p and g^v_p has order u, so it is 1 if and
// only if m = 0.
func (c *Cryptosystem) IsZero(ciphertext *big.Int) (bool, error) {
	if !c.hasSecret {
		return false, phe.ErrMissingPrivateKey
	}
	return new(big.Int).Exp(ciphertext, c.vp, c.p).Cmp(big.NewInt(1)) == 0, nil
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
	return phe.Int{V: c.add(x, y)}, nil
}

func (c *Cryptosystem) add(x, y *big.Int) *big.Int {
	sum := new(big.Int).Mul(x, y)
	return sum.Mod(sum, c.n)
}

// MultiplyByConstant implements phe.Homomorphic.
func (c *Cryptosystem) MultiplyByConstant(ciphertext phe.Value, constant *big.Int) (phe.Value, error) {
	v, err := phe.AsInt(ciphertext)
	if err != nil {
		return nil, err
	}
	return phe.Int{V: c.scale(v, constant)}, nil
}

func (c *Cryptosystem) scale(v, constant *big.Int) *big.Int {
	k := new(big.Int).Mod(constant, c.u)
	return new(big.Int).Exp(v, k, c.n)
}

func (c *Cryptosystem) scaleInt(v *big.Int, constant int64) *big.Int {
	return c.scale(v, big.NewInt(constant))
}

// Reencrypt implements phe.Homomorphic by adding an encryption of zero.
func (c *Cryptosystem) Reencrypt(ciphertext phe.Value) (phe.Value, error) {
	v, err := phe.AsInt(ciphertext)
	if err != nil {
		return nil, err
	}
	out, err := c.reencrypt(v)
	if err != nil {
		return nil, err
	}
	return phe.Int{V: out}, nil
}

func (c *Cryptosystem) reencrypt(v *big.Int) (*big.Int, error) {
	zero, err := c.encryptInt(0)
	if err != nil {
		return nil, err
	}
	return c.add(v, zero), nil
}

// ---------------------------------------------------------------------------
// Secure comparison
// ---------------------------------------------------------------------------

// EncryptComparisonInput implements phe.SecureComparer. It encrypts bits of a
// value to be compared with a value of the server, least significant bit
// first. This is the 1st step of secure comparison and runs on client side.
func (c *Cryptosystem) EncryptComparisonInput(value int64, bitLength int) ([]*big.Int, error) {
	if err := c.validateComparisonInput(value, bitLength); err != nil {
		return nil, err
	}
	bits := make([]*big.Int, bitLength)
	for i := range bits {
		var bit int64
		if i < 63 {
			bit = (value >> uint(i)) & 1
		}
		encrypted, err := c.encryptInt(bit)
		if err != nil {
			return nil, err
		}
		bits[i] = encrypted
	}
	return bits, nil
}

// EvaluateComparison implements phe.SecureComparer. It compares client's
// encrypted value x with server's value y. This is the 2nd step of secure
// comparison and runs on server side. Private key is not required, and server
// learns nothing about x.
func (c *Cryptosystem) EvaluateComparison(encryptedInput []*big.Int, value int64) ([]*big.Int, error) {
	return c.blindComparison(encryptedInput, value, 0)
}

// DecryptComparison implements phe.SecureComparer. It restores the result of
// secure comparison, true if x <= y. This is the 3rd step of secure comparison
// and runs on client side. Client learns only whether x <= y, but not y.
func (c *Cryptosystem) DecryptComparison(encryptedResult []*big.Int) (bool, error) {
	for _, ciphertext := range encryptedResult {
		zero, err := c.IsZero(ciphertext)
		if err != nil {
			return false, err
		}
		if zero {
			return true, nil
		}
	}
	return false, nil
}

// validateComparisonInput checks that a compared value fits into bitLength
// bits, and the comparison fits into the plaintext space.
func (c *Cryptosystem) validateComparisonInput(value int64, bitLength int) error {
	if bitLength < 1 || value < 0 || (bitLength < 63 && value >= int64(1)<<uint(bitLength)) {
		return fmt.Errorf("damgardgeislerkroigaard: compared values must be integers in [0, 2^%d) but got %d", bitLength, value)
	}

	// values are extended by one bit to break ties. intermediate values of the
	// comparison are in [-2, 3 * (bit_length + 1) - 1] and must not wrap
	// around u.
	if big.NewInt(3*int64(bitLength+1)-1).Cmp(c.u) >= 0 {
		return fmt.Errorf("damgardgeislerkroigaard: plaintext space %s is too small to compare %d-bit values, "+
			"use a larger key size or a smaller bit length", c.u, bitLength)
	}
	return nil
}

// negateBit computes E(1 - b) from E(b) for a bit b.
func (c *Cryptosystem) negateBit(ciphertext *big.Int) (*big.Int, error) {
	one, err := c.encryptInt(1)
	if err != nil {
		return nil, err
	}
	return c.add(one, c.negate(ciphertext)), nil
}

// negate computes E(-m) from E(m).
func (c *Cryptosystem) negate(ciphertext *big.Int) *big.Int {
	return c.scale(ciphertext, new(big.Int).Sub(c.u, big.NewInt(1)))
}

// randBelowU draws a uniform value in [lo, u - 1].
func (c *Cryptosystem) randBelowU(lo int64) (*big.Int, error) {
	return mathutil.RandRange(big.NewInt(lo), new(big.Int).Sub(c.u, big.NewInt(1)))
}

// blindComparison is the DGK comparison of client's encrypted x and server's
// plain y. Client finds a zero among the returned ciphertexts if and only if
// x <= y (flip = 0) or x > y (flip = 1). The server keeps flip secret to hide
// the result from the client. The returned ciphertexts are shuffled and
// re-randomized.
func (c *Cryptosystem) blindComparison(encryptedBits []*big.Int, value int64, flip int) ([]*big.Int, error) {
	bitLength := len(encryptedBits)
	if err := c.validateComparisonInput(value, bitLength); err != nil {
		return nil, err
	}

	// compare 2x with 2y + 1 instead, so that x <= y if and only if 2x < 2y + 1.
	// this way, x and y are never equal and flipping the direction is
	// consistent.
	zero, err := c.encryptInt(0)
	if err != nil {
		return nil, err
	}
	xBits := append([]*big.Int{zero}, encryptedBits...)
	y := new(big.Int).Lsh(big.NewInt(value), 1)
	y.Add(y, big.NewInt(1))

	// s = 1 looks for x < y, s = -1 looks for x > y
	s := big.NewInt(1)
	if flip != 0 {
		s.Sub(c.u, s)
	}

	// c_i = s + x_i - y_i + 3 * sum_{j > i} (x_j xor y_j)
	// c_i = 0 only at the most significant differing bit, and only if
	// x_i - y_i = -s
	blinded := make([]*big.Int, 0, bitLength+1)
	xorSum, err := c.encryptInt(0)
	if err != nil {
		return nil, err
	}
	for i := bitLength; i >= 0; i-- {
		yi := int64(y.Bit(i))
		constant, err := c.encrypt(new(big.Int).Sub(s, big.NewInt(yi)))
		if err != nil {
			return nil, err
		}
		ci := c.add(constant, xBits[i])
		ci = c.add(ci, c.scaleInt(xorSum, 3))

		r, err := c.randBelowU(1)
		if err != nil {
			return nil, err
		}
		masked, err := c.reencrypt(c.scale(ci, r))
		if err != nil {
			return nil, err
		}
		blinded = append(blinded, masked)

		xXorY := xBits[i]
		if yi == 1 {
			if xXorY, err = c.negateBit(xBits[i]); err != nil {
				return nil, err
			}
		}
		xorSum = c.add(xorSum, xXorY)
	}

	if err := shuffle(len(blinded), func(i, j int) { blinded[i], blinded[j] = blinded[j], blinded[i] }); err != nil {
		return nil, err
	}
	return blinded, nil
}

// ---------------------------------------------------------------------------
// Private decision tree evaluation
// ---------------------------------------------------------------------------

// EncryptDecisionTreeFeatures implements phe.NumericDecisionTreeEvaluator. It
// encrypts features of a client to be evaluated in server's decision tree.
// This is the 1st step of private decision tree evaluation and runs on client
// side.
func (c *Cryptosystem) EncryptDecisionTreeFeatures(features []int64, bitLength int) ([][]*big.Int, error) {
	out := make([][]*big.Int, len(features))
	for i, feature := range features {
		bits, err := c.EncryptComparisonInput(feature, bitLength)
		if err != nil {
			return nil, err
		}
		out[i] = bits
	}
	return out, nil
}

// EvaluateDecisionTreeComparisons implements phe.NumericDecisionTreeEvaluator.
// It compares encrypted features with thresholds of all decision nodes. This
// is the 2nd step of private decision tree evaluation and runs on server side.
// Each comparison is randomly flipped, so client cannot learn the path. The
// returned state must be kept secret on server side for the 4th step.
func (c *Cryptosystem) EvaluateDecisionTreeComparisons(tree *phe.NumericTree, encryptedFeatures [][]*big.Int) (
	[][]*big.Int, *phe.DecisionTreeState, error) {
	nodes, err := collectNodes(tree)
	if err != nil {
		return nil, nil, err
	}
	flips := make([]int, len(nodes))
	comparisons := make([][]*big.Int, len(nodes))
	for i, node := range nodes {
		flip, err := mathutil.RandBelow(big.NewInt(2))
		if err != nil {
			return nil, nil, err
		}
		flips[i] = int(flip.Int64())
		if node.Feature < 0 || node.Feature >= len(encryptedFeatures) {
			return nil, nil, fmt.Errorf("damgardgeislerkroigaard: feature index %d does not exist", node.Feature)
		}
		if comparisons[i], err = c.blindComparison(encryptedFeatures[node.Feature], node.Threshold, flips[i]); err != nil {
			return nil, nil, err
		}
	}
	return comparisons, &phe.DecisionTreeState{Tree: tree, Flips: flips}, nil
}

// AnswerDecisionTreeComparisons implements phe.NumericDecisionTreeEvaluator.
// It answers the flipped comparisons of the server in encrypted form. This is
// the 3rd step of private decision tree evaluation and runs on client side.
func (c *Cryptosystem) AnswerDecisionTreeComparisons(encryptedComparisons [][]*big.Int) ([]*big.Int, error) {
	answers := make([]*big.Int, len(encryptedComparisons))
	for i, comparison := range encryptedComparisons {
		result, err := c.DecryptComparison(comparison)
		if err != nil {
			return nil, err
		}
		if answers[i], err = c.encryptInt(boolToInt(result)); err != nil {
			return nil, err
		}
	}
	return answers, nil
}

// EvaluateDecisionTreeLeaves implements phe.NumericDecisionTreeEvaluator. It
// finds the reached leaf in encrypted form. Path cost of a leaf is the number
// of wrong decisions on its path, so only the reached leaf has cost 0. This is
// the 4th step of private decision tree evaluation and runs on server side.
func (c *Cryptosystem) EvaluateDecisionTreeLeaves(state *phe.DecisionTreeState, encryptedAnswers []*big.Int) (
	[]phe.EncryptedLeaf, error) {
	if state == nil || state.Tree == nil {
		return nil, fmt.Errorf("damgardgeislerkroigaard: server state must not be nil")
	}
	flips := state.Flips

	// path cost is at most the depth of the tree, so it must not wrap around u
	if big.NewInt(int64(len(flips))).Cmp(c.u) >= 0 {
		return nil, fmt.Errorf("damgardgeislerkroigaard: decision tree must have less than %s decision nodes", c.u)
	}
	if len(encryptedAnswers) != len(flips) {
		return nil, fmt.Errorf("damgardgeislerkroigaard: expected %d answers but got %d", len(flips), len(encryptedAnswers))
	}

	// remove the random flip, so b = 1 if feature <= threshold
	decisions := make([]*big.Int, len(flips))
	for i, answer := range encryptedAnswers {
		decisions[i] = answer
		if flips[i] != 0 {
			negated, err := c.negateBit(answer)
			if err != nil {
				return nil, err
			}
			decisions[i] = negated
		}
	}

	// path cost of each leaf. going left is wrong if b = 0, going right is
	// wrong if b = 1
	type leaf struct {
		cost  *big.Int
		label *big.Int
	}
	var leaves []leaf
	nodeIndex := 0
	var traverse func(subtree *phe.NumericTree, cost *big.Int) error
	traverse = func(subtree *phe.NumericTree, cost *big.Int) error {
		if subtree.IsLeaf() {
			if subtree.Value.Sign() < 0 || subtree.Value.Cmp(c.u) >= 0 {
				return fmt.Errorf("damgardgeislerkroigaard: leaf labels must be in [0, %s) but got %s", c.u, subtree.Value)
			}
			leaves = append(leaves, leaf{cost: cost, label: subtree.Value})
			return nil
		}
		b := decisions[nodeIndex]
		nodeIndex++
		notB, err := c.negateBit(b)
		if err != nil {
			return err
		}
		if err := traverse(subtree.IfLessOrEqual, c.add(cost, notB)); err != nil {
			return err
		}
		return traverse(subtree.IfGreater, c.add(cost, b))
	}
	start, err := c.encryptInt(0)
	if err != nil {
		return nil, err
	}
	if err := traverse(state.Tree, start); err != nil {
		return nil, err
	}

	// for each leaf, client receives (r1 * cost, r2 * cost + label). only the
	// reached leaf has cost 0, others look random to the client.
	encryptedLeaves := make([]phe.EncryptedLeaf, len(leaves))
	for i, l := range leaves {
		r1, err := c.randBelowU(1)
		if err != nil {
			return nil, err
		}
		r2, err := c.randBelowU(1)
		if err != nil {
			return nil, err
		}
		maskedCost, err := c.reencrypt(c.scale(l.cost, r1))
		if err != nil {
			return nil, err
		}
		label, err := c.encrypt(l.label)
		if err != nil {
			return nil, err
		}
		encryptedLeaves[i] = phe.EncryptedLeaf{Cost: maskedCost, Label: c.add(c.scale(l.cost, r2), label)}
	}

	if err := shuffle(len(encryptedLeaves), func(i, j int) {
		encryptedLeaves[i], encryptedLeaves[j] = encryptedLeaves[j], encryptedLeaves[i]
	}); err != nil {
		return nil, err
	}
	return encryptedLeaves, nil
}

// DecryptDecisionTreeOutput implements phe.NumericDecisionTreeEvaluator. It
// restores the label of the reached leaf. This is the last step of private
// decision tree evaluation and runs on client side.
func (c *Cryptosystem) DecryptDecisionTreeOutput(encryptedLeaves []phe.EncryptedLeaf) (*big.Int, error) {
	for _, l := range encryptedLeaves {
		zero, err := c.IsZero(l.Cost)
		if err != nil {
			return nil, err
		}
		if zero {
			return c.decrypt(l.Label)
		}
	}
	return nil, fmt.Errorf("damgardgeislerkroigaard: none of the leaves is reached: %w", phe.ErrDecryptionFailed)
}

// collectNodes collects decision nodes in pre-order.
func collectNodes(tree *phe.NumericTree) ([]*phe.NumericTree, error) {
	if tree == nil {
		return nil, fmt.Errorf("damgardgeislerkroigaard: decision tree must not be nil")
	}
	if tree.IsLeaf() {
		return nil, nil
	}
	if tree.IfLessOrEqual == nil || tree.IfGreater == nil {
		return nil, fmt.Errorf("damgardgeislerkroigaard: decision node must have both sub trees but got %s", tree)
	}
	left, err := collectNodes(tree.IfLessOrEqual)
	if err != nil {
		return nil, err
	}
	right, err := collectNodes(tree.IfGreater)
	if err != nil {
		return nil, err
	}
	return append(append([]*phe.NumericTree{tree}, left...), right...), nil
}

// ---------------------------------------------------------------------------
// Encrypted argmax
// ---------------------------------------------------------------------------

// EvaluateArgmax implements phe.ArgmaxEvaluator. It finds the index of the
// maximum of encrypted values in [0, 2^bitLength) without decrypting them. It
// runs on server side and interacts with the client (private key owner)
// through the client callback. Client learns neither the values nor the
// comparison results, and server learns nothing. Index of the first maximum is
// returned on ties.
func (c *Cryptosystem) EvaluateArgmax(encryptedValues []*big.Int, bitLength int, client phe.ArgmaxClient) (*big.Int, error) {
	if len(encryptedValues) == 0 {
		return nil, fmt.Errorf("damgardgeislerkroigaard: argmax requires at least one value")
	}
	if client == nil {
		return nil, fmt.Errorf("damgardgeislerkroigaard: argmax requires a client")
	}

	// z = b - a + 2^bit_length must be in the plaintext space without wrapping
	// around
	if bitLength < 0 || bitLength+1 > c.u.BitLen() || new(big.Int).Lsh(big.NewInt(1), uint(bitLength+1)).Cmp(c.u) >= 0 {
		return nil, fmt.Errorf("damgardgeislerkroigaard: plaintext space %s is too small for argmax of %d-bit values, "+
			"use a larger key size or a smaller bit length", c.u, bitLength)
	}

	// client's masked values are compared bit by bit, so u's bit length must
	// fit
	if err := c.validateComparisonInput(new(big.Int).Sub(c.u, big.NewInt(1)).Int64(), c.u.BitLen()); err != nil {
		return nil, err
	}

	maxValue := encryptedValues[0]
	maxIndex, err := c.encryptInt(0)
	if err != nil {
		return nil, err
	}
	for index := 1; index < len(encryptedValues); index++ {
		candidate := encryptedValues[index]
		isGreater, err := c.greaterThan(candidate, maxValue, bitLength, client)
		if err != nil {
			return nil, err
		}

		// max_value += is_greater * (candidate - max_value)
		// max_index += is_greater * (index - max_index)
		valueDiff := c.add(candidate, c.negate(maxValue))
		encryptedIndex, err := c.encryptInt(int64(index))
		if err != nil {
			return nil, err
		}
		indexDiff := c.add(encryptedIndex, c.negate(maxIndex))
		updates, err := c.multiply(isGreater, []*big.Int{valueDiff, indexDiff}, client)
		if err != nil {
			return nil, err
		}
		maxValue = c.add(maxValue, updates[0])
		maxIndex = c.add(maxIndex, updates[1])
	}
	return c.reencrypt(maxIndex)
}

// AnswerArgmax implements phe.ArgmaxEvaluator. It answers a message of the
// server during encrypted argmax and runs on client side. Every value the
// client decrypts here is masked with a uniformly random value, so client
// learns nothing.
func (c *Cryptosystem) AnswerArgmax(message phe.ArgmaxMessage) ([]*big.Int, error) {
	if !c.hasSecret {
		return nil, phe.ErrMissingPrivateKey
	}
	switch message.Type {
	case phe.ArgmaxMaskedDifference:
		if len(message.Payload) != 1 {
			return nil, fmt.Errorf("damgardgeislerkroigaard: masked difference message must have 1 ciphertext")
		}
		masked, err := c.decrypt(message.Payload[0])
		if err != nil {
			return nil, err
		}
		return c.EncryptComparisonInput(masked.Int64(), c.u.BitLen())

	case phe.ArgmaxComparisons:
		if len(message.Comparisons) != 2 {
			return nil, fmt.Errorf("damgardgeislerkroigaard: comparisons message must have 2 comparisons")
		}
		bits := make([]int64, 2)
		for i, comparison := range message.Comparisons {
			result, err := c.DecryptComparison(comparison)
			if err != nil {
				return nil, err
			}
			bits[i] = boolToInt(result)
		}
		out := make([]*big.Int, 3)
		for i, bit := range []int64{bits[0], bits[1], bits[0] * bits[1]} {
			encrypted, err := c.encryptInt(bit)
			if err != nil {
				return nil, err
			}
			out[i] = encrypted
		}
		return out, nil

	case phe.ArgmaxProducts:
		if len(message.Payload) < 1 {
			return nil, fmt.Errorf("damgardgeislerkroigaard: products message must have at least 1 ciphertext")
		}
		maskedBit, err := c.decrypt(message.Payload[0])
		if err != nil {
			return nil, err
		}
		out := make([]*big.Int, len(message.Payload)-1)
		for i, factor := range message.Payload[1:] {
			f, err := c.decrypt(factor)
			if err != nil {
				return nil, err
			}
			if out[i], err = c.encrypt(f.Mul(f, maskedBit)); err != nil {
				return nil, err
			}
		}
		return out, nil
	}
	return nil, fmt.Errorf("damgardgeislerkroigaard: unknown argmax message type %q", message.Type)
}

// greaterThan computes E(a > b) for encrypted a and b in [0, 2^bitLength) with
// the client's help.
func (c *Cryptosystem) greaterThan(encryptedA, encryptedB *big.Int, bitLength int, client phe.ArgmaxClient) (*big.Int, error) {
	u := c.u.Int64()
	offset := int64(1) << uint(bitLength)

	// z = a - b + 2^bit_length is in [1, 2^(bit_length + 1)), and a > b iff
	// z > 2^bit_length. client receives d = z + r mod u for a uniformly random
	// r, which reveals nothing.
	rBig, err := c.randBelowU(0)
	if err != nil {
		return nil, err
	}
	r := rBig.Int64()
	shift, err := c.encryptInt((offset + r) % u)
	if err != nil {
		return nil, err
	}
	maskedDifference, err := c.reencrypt(c.add(c.add(encryptedA, c.negate(encryptedB)), shift))
	if err != nil {
		return nil, err
	}
	encryptedDBits, err := client(phe.ArgmaxMessage{Type: phe.ArgmaxMaskedDifference, Payload: []*big.Int{maskedDifference}})
	if err != nil {
		return nil, err
	}

	// a > b iff d is in the arc [start, end] of Z_u. if the arc does not wrap
	// around u, it is (d >= start) and (d <= end). otherwise, it is
	// (d >= start) or (d <= end).
	start := (r + offset + 1) % u
	end := (r + 2*offset - 1) % u
	wraps := start > end

	// each comparison gives client a bit x_i, while server keeps a bit k_i such
	// that c_i = x_i xor k_i. random flips make x_i uniformly random for the
	// client. d >= start is the negation of d <= start - 1, and always true if
	// start = 0.
	flips := make([]int64, 2)
	for i := range flips {
		flip, err := mathutil.RandBelow(big.NewInt(2))
		if err != nil {
			return nil, err
		}
		flips[i] = flip.Int64()
	}
	firstThreshold, firstNegated := start-1, int64(1)
	if start == 0 {
		firstThreshold, firstNegated = u-1, 0
	}

	first, err := c.blindComparison(encryptedDBits, firstThreshold, int(flips[0]))
	if err != nil {
		return nil, err
	}
	second, err := c.blindComparison(encryptedDBits, end, int(flips[1]))
	if err != nil {
		return nil, err
	}
	answers, err := client(phe.ArgmaxMessage{Type: phe.ArgmaxComparisons, Comparisons: [][]*big.Int{first, second}})
	if err != nil {
		return nil, err
	}
	if len(answers) != 3 {
		return nil, fmt.Errorf("damgardgeislerkroigaard: client must answer comparisons with 3 ciphertexts but got %d", len(answers))
	}
	x1, x2, x1x2 := answers[0], answers[1], answers[2]

	k1 := flips[0] ^ firstNegated
	k2 := flips[1]

	// c_i = k_i + (1 - 2 k_i) x_i is linear in x_i, and so is c_1 * c_2 in x_1,
	// x_2, x_1 x_2
	c1, err := c.linear([]term{{x1, 1 - 2*k1}}, k1)
	if err != nil {
		return nil, err
	}
	c2, err := c.linear([]term{{x2, 1 - 2*k2}}, k2)
	if err != nil {
		return nil, err
	}
	c1c2, err := c.linear([]term{
		{x1, k2 * (1 - 2*k1)},
		{x2, k1 * (1 - 2*k2)},
		{x1x2, (1 - 2*k1) * (1 - 2*k2)},
	}, k1*k2)
	if err != nil {
		return nil, err
	}

	if wraps {
		// c1 or c2 = c1 + c2 - c1 * c2
		return c.add(c.add(c1, c2), c.negate(c1c2)), nil
	}
	return c1c2, nil
}

// multiply computes E(b * f) for an encrypted b and each encrypted f with the
// client's help. Client multiplies B = b + rho and F = f + sigma, both
// uniformly random, and server restores b * f = B * F - sigma * b - rho * f -
// rho * sigma.
func (c *Cryptosystem) multiply(encryptedBit *big.Int, encryptedFactors []*big.Int, client phe.ArgmaxClient) ([]*big.Int, error) {
	rhoBig, err := c.randBelowU(0)
	if err != nil {
		return nil, err
	}
	rho := rhoBig.Int64()
	encryptedRho, err := c.encryptInt(rho)
	if err != nil {
		return nil, err
	}
	payload := []*big.Int{c.add(encryptedBit, encryptedRho)}
	sigmas := make([]int64, len(encryptedFactors))
	for i, factor := range encryptedFactors {
		sigma, err := c.randBelowU(0)
		if err != nil {
			return nil, err
		}
		sigmas[i] = sigma.Int64()
		encryptedSigma, err := c.encryptInt(sigmas[i])
		if err != nil {
			return nil, err
		}
		payload = append(payload, c.add(factor, encryptedSigma))
	}
	maskedProducts, err := client(phe.ArgmaxMessage{Type: phe.ArgmaxProducts, Payload: payload})
	if err != nil {
		return nil, err
	}
	if len(maskedProducts) != len(encryptedFactors) {
		return nil, fmt.Errorf("damgardgeislerkroigaard: client must answer products with %d ciphertexts but got %d",
			len(encryptedFactors), len(maskedProducts))
	}

	out := make([]*big.Int, len(encryptedFactors))
	for i, factor := range encryptedFactors {
		// rho * sigma may exceed int64, so the constant is reduced modulo u first
		constant := new(big.Int).Mul(big.NewInt(rho), big.NewInt(sigmas[i]))
		constant.Neg(constant).Mod(constant, c.u)
		if out[i], err = c.linear([]term{
			{maskedProducts[i], 1},
			{encryptedBit, -sigmas[i]},
			{factor, -rho},
		}, constant.Int64()); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// term is a (ciphertext, coefficient) pair of a linear combination.
type term struct {
	ciphertext  *big.Int
	coefficient int64
}

// linear computes E(sum(coefficient * m) + constant) for (E(m), coefficient)
// terms.
func (c *Cryptosystem) linear(terms []term, constant int64) (*big.Int, error) {
	result, err := c.encryptInt(constant)
	if err != nil {
		return nil, err
	}
	for _, t := range terms {
		coefficient := new(big.Int).Mod(big.NewInt(t.coefficient), c.u)
		if coefficient.Sign() != 0 {
			result = c.add(result, c.scale(t.ciphertext, coefficient))
		}
	}
	return result, nil
}

// shuffle permutes n items uniformly with cryptographically secure randomness.
func shuffle(n int, swap func(i, j int)) error {
	for i := n - 1; i > 0; i-- {
		j, err := mathutil.RandBelow(big.NewInt(int64(i + 1)))
		if err != nil {
			return err
		}
		swap(i, int(j.Int64()))
	}
	return nil
}

func boolToInt(b bool) int64 {
	if b {
		return 1
	}
	return 0
}
