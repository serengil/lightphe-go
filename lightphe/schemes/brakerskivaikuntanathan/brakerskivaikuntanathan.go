// Package brakerskivaikuntanathan implements the Brakerski-Vaikuntanathan
// cryptosystem, which is homomorphic with respect to addition and supports one
// multiplication of ciphertexts like Boneh-Goh-Nissim. Unlike Boneh-Goh-Nissim,
// it does not need pairings, and it is quantum resistant. Its security relies
// on the ring learning with errors (Ring-LWE) problem, which is believed to be
// hard for quantum computers.
//
// It works in the polynomial ring R_q = Z_q[x] / (x^d + 1).
//   - private key: polynomial s with small coefficients
//   - public key: a and b = -(a s + t e), where e is a small error polynomial
//   - encryption: c0 = b u + t g + m, c1 = a u + t f where u, f, g are small
//   - decryption: c0 + c1 s = m + t (g + f s - e u) mod q, so m is its
//     constant term mod t
//   - multiplication: (c0, c1) x (c0', c1') = (c0 c0', c0 c1' + c1 c0', c1 c1'),
//     which is decrypted with (1, s, s^2) as
//     (c0 + c1 s)(c0' + c1' s) = m m' + t (...)
//
// Multiplied ciphertexts are triples of polynomials. They can be added with
// each other and with fresh ciphertexts, and multiplied with constants, but
// cannot be multiplied with ciphertexts again. a is expanded from a public
// seed with SHAKE-128.
//
// The key size is the ring degree d, a power of 2. Default is 4096. With q
// around 2^100, degree 4096 gives about 128-bit security against quantum
// attacks according to the tables of Homomorphic Encryption Standard (log q
// must be at most 101 for d = 4096). Smaller degrees are not secure, and are
// for testing only.
//
// Its plaintext space is small, 2^24 by default, and every ciphertext has
// noise growing with homomorphic operations: addition adds the noises,
// multiplying with a constant k multiplies the noise by |k|, and
// multiplication of ciphertexts multiplies their noises. Decryption returns a
// wrong result without any error when the noise exceeds q / 2. With default
// settings, a multiplied ciphertext still has room for millions of times more
// noise, i.e. for many additions and multiplications with constants. A greater
// plaintext space can be set with a plaintext limit in exchange of a smaller
// room. Floats and tensors are not supported, as they are scaled by powers of
// 10. Ciphertexts have 2 polynomials of d coefficients of 100 bits, about
// 100 KB for d = 4096.
//
// Reference: Brakerski, Z., Vaikuntanathan, V. (2011). Fully Homomorphic
// Encryption from Ring-LWE and Security for Key Dependent Messages. CRYPTO
// 2011.
//
// Reference: Albrecht, M. et al. (2018). Homomorphic Encryption Security
// Standard. HomomorphicEncryption.org.
package brakerskivaikuntanathan

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"math"
	"math/big"
	"math/bits"
	"sync"

	"github.com/serengil/lightphe-go/lightphe/internal/shake"
	"github.com/serengil/lightphe-go/lightphe/phe"
)

// DefaultKeySize is the ring degree used when none is requested.
const DefaultKeySize = 4096

// LogQ is the bit length of the ciphertext modulus.
const LogQ = 100

// DefaultLogT fixes the default plaintext modulus t = 2^DefaultLogT.
const DefaultLogT = 24

// eta parametrizes the centered binomial distribution the secret and errors
// are sampled from. Its standard deviation is sqrt(eta / 2) = 3.24, and its
// values are in [-eta, eta].
const eta = 21

// noiseTail bounds noise in standard deviations for correct decryption.
const noiseTail = 12

// a ciphertext is a pair of polynomials, and a multiplied ciphertext is a
// triple
const (
	freshSize      = 2
	multipliedSize = 3
)

// Q is the ciphertext modulus, the greatest prime less than 2^LogQ. It must be
// co-prime to t, otherwise the public key reveals the secret modulo t.
var Q, _ = new(big.Int).SetString("1267650600228229401496703205361", 10)

// ErrFloatNotSupported reports a float plaintext, constant or tensor.
var ErrFloatNotSupported = phe.FloatNotSupported("lightphe: Brakerski-Vaikuntanathan does not support float values " +
	"or tensors, because they are scaled by powers of 10, which exceed its small plaintext space and noise budget. " +
	"Use integers instead")

// ErrMultipliedTwice reports a multiplication involving an already multiplied
// ciphertext.
var ErrMultipliedTwice = fmt.Errorf("lightphe: Brakerski-Vaikuntanathan supports only one multiplication, "+
	"multiplied ciphertexts cannot be multiplied with ciphertexts again: %w", phe.ErrUnsupportedOperation)

// PublicKey is the Brakerski-Vaikuntanathan public key: the ring degree d, the
// moduli q and t, the seed of the polynomial a and the polynomial b.
type PublicKey struct {
	D    *big.Int   `json:"d"`
	Q    *big.Int   `json:"q"`
	T    *big.Int   `json:"t"`
	Seed *big.Int   `json:"seed"`
	B    []*big.Int `json:"b"`
}

// PrivateKey is the secret polynomial s with small coefficients.
type PrivateKey struct {
	S []int64 `json:"s"`
}

// Keys bundles the key pair. PrivateKey is nil for encryption-only setups.
type Keys struct {
	PublicKey  *PublicKey  `json:"public_key,omitempty"`
	PrivateKey *PrivateKey `json:"private_key,omitempty"`
}

// Validate reports missing or malformed key material.
func (k Keys) Validate() error {
	if k.PublicKey == nil {
		return phe.RequireSection(phe.BrakerskiVaikuntanathan, phe.SectionPublic)
	}
	pk := k.PublicKey
	if err := phe.RequireFields(phe.BrakerskiVaikuntanathan, phe.SectionPublic,
		phe.Field("d", pk.D != nil),
		phe.Field("q", pk.Q != nil),
		phe.Field("t", pk.T != nil),
		phe.Field("seed", pk.Seed != nil),
		phe.Field("b", pk.B != nil),
	); err != nil {
		return err
	}
	if k.PrivateKey != nil {
		if err := phe.RequireFields(phe.BrakerskiVaikuntanathan, phe.SectionPrivate,
			phe.Field("s", k.PrivateKey.S != nil),
		); err != nil {
			return err
		}
	}

	if !pk.D.IsInt64() || !isPowerOfTwo(pk.D.Int64()) || pk.D.Int64() < 8 || pk.D.Int64() > 1<<16 {
		return phe.InvalidKeysf("brakerskivaikuntanathan: degree must be a power of 2, got %s", pk.D)
	}
	d := int(pk.D.Int64())
	if pk.Q.Cmp(Q) != 0 {
		return phe.InvalidKeysf("brakerskivaikuntanathan: q must be %s", Q)
	}
	if pk.T.Sign() <= 0 || !pk.T.IsInt64() || !isPowerOfTwo(pk.T.Int64()) {
		return phe.InvalidKeysf("brakerskivaikuntanathan: t must be a power of 2")
	}
	if pk.Seed.Sign() < 0 || pk.Seed.BitLen() > 256 {
		return phe.InvalidKeysf("brakerskivaikuntanathan: seed must be a 256-bit integer")
	}
	if len(pk.B) != d || (k.PrivateKey != nil && len(k.PrivateKey.S) != d) {
		return phe.InvalidKeysf("brakerskivaikuntanathan: b and s must have %d coefficients", d)
	}
	for _, x := range pk.B {
		if x == nil || x.Sign() < 0 || x.Cmp(Q) >= 0 {
			return phe.InvalidKeysf("brakerskivaikuntanathan: coefficients of b must be in [0, q)")
		}
	}
	return nil
}

func isPowerOfTwo(x int64) bool { return x > 0 && x&(x-1) == 0 }

// Cryptosystem is a configured Brakerski-Vaikuntanathan instance. It is
// immutable and safe for concurrent use.
type Cryptosystem struct {
	phe.Base

	keys      Keys
	d         int
	t         *big.Int
	hasSecret bool

	// a expanded from the seed, and s^2 for decryption of multiplied
	// ciphertexts
	aOnce       sync.Once
	a           []*big.Int
	sSquareOnce sync.Once
	sSquare     []*big.Int
}

var (
	_ phe.Homomorphic   = (*Cryptosystem)(nil)
	_ phe.FloatRejecter = (*Cryptosystem)(nil)
)

// Generate creates a fresh key pair for the ring degree keySize. A nil
// plaintextLimit selects the default plaintext space 2^24; otherwise it is
// rounded up to a power of 2.
func Generate(keySize int, plaintextLimit *big.Int) (*Cryptosystem, error) {
	d := keySize
	if d <= 0 {
		d = DefaultKeySize
	}
	if d < 8 || !isPowerOfTwo(int64(d)) {
		return nil, fmt.Errorf("brakerskivaikuntanathan: key size %d must be a power of 2 and at least 8: %w", d, phe.ErrKeyGeneration)
	}

	t := new(big.Int).Lsh(big.NewInt(1), DefaultLogT)
	if plaintextLimit != nil {
		if plaintextLimit.Cmp(big.NewInt(2)) < 0 {
			return nil, fmt.Errorf("brakerskivaikuntanathan: plaintext limit must be at least 2: %w", phe.ErrKeyGeneration)
		}
		logT := new(big.Int).Sub(plaintextLimit, big.NewInt(1)).BitLen()
		if logT > 62 {
			return nil, fmt.Errorf("brakerskivaikuntanathan: plaintext limit %s is too large: %w", plaintextLimit, phe.ErrKeyGeneration)
		}
		t = new(big.Int).Lsh(big.NewInt(1), uint(logT))
	}

	// product of two fresh ciphertexts must be decrypted correctly
	if multipliedNoiseBound(d, t).Cmp(new(big.Int).Rsh(Q, 1)) >= 0 {
		return nil, fmt.Errorf("brakerskivaikuntanathan: plaintext limit %s is too large, because product of two "+
			"ciphertexts cannot be decrypted correctly: %w", plaintextLimit, phe.ErrKeyGeneration)
	}

	seedBytes := make([]byte, 32)
	if _, err := rand.Read(seedBytes); err != nil {
		return nil, fmt.Errorf("brakerskivaikuntanathan: reading randomness: %w", err)
	}
	seed := new(big.Int).SetBytes(seedBytes)
	a := expand(seed, d)
	s, err := sampleSmall(d)
	if err != nil {
		return nil, err
	}
	e, err := sampleSmall(d)
	if err != nil {
		return nil, err
	}

	// b = -(a s + t e)
	aS := polyMul(a, toModQ(s), d)
	b := make([]*big.Int, d)
	for i := range b {
		x := new(big.Int).Mul(t, big.NewInt(e[i]))
		x.Add(x, aS[i]).Neg(x).Mod(x, Q)
		b[i] = x
	}

	c, err := New(Keys{
		PublicKey:  &PublicKey{D: big.NewInt(int64(d)), Q: new(big.Int).Set(Q), T: t, Seed: seed, B: b},
		PrivateKey: &PrivateKey{S: s},
	})
	if err != nil {
		return nil, err
	}
	c.aOnce.Do(func() { c.a = a })
	return c, nil
}

// New builds a cryptosystem around an existing key pair.
func New(keys Keys) (*Cryptosystem, error) {
	if err := keys.Validate(); err != nil {
		return nil, err
	}
	return &Cryptosystem{
		Base:      phe.Base{Alg: phe.BrakerskiVaikuntanathan},
		keys:      keys,
		d:         int(keys.PublicKey.D.Int64()),
		t:         new(big.Int).Set(keys.PublicKey.T),
		hasSecret: keys.PrivateKey != nil,
	}, nil
}

// FromJSON rebuilds a cryptosystem from exported key material.
func FromJSON(data []byte) (*Cryptosystem, error) {
	var keys Keys
	if err := json.Unmarshal(data, &keys); err != nil {
		return nil, phe.InvalidKeysf("brakerskivaikuntanathan: decoding keys: %v", err)
	}
	return New(keys)
}

// Keys returns a copy of the key material.
func (c *Cryptosystem) Keys() Keys { return c.keys }

// PlaintextModulo implements phe.Homomorphic.
func (c *Cryptosystem) PlaintextModulo() *big.Int { return new(big.Int).Set(c.t) }

// CiphertextModulo implements phe.Homomorphic.
func (c *Cryptosystem) CiphertextModulo() *big.Int { return new(big.Int).Set(Q) }

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

// Encrypt implements phe.Homomorphic.
func (c *Cryptosystem) Encrypt(plaintext *big.Int) (phe.Value, error) {
	u, err := sampleSmall(c.d)
	if err != nil {
		return nil, err
	}
	return c.EncryptWith(plaintext, u)
}

// EncryptWith encrypts using a caller supplied small random polynomial u.
func (c *Cryptosystem) EncryptWith(plaintext *big.Int, u []int64) (phe.Value, error) {
	d := c.d
	if len(u) != d {
		return nil, fmt.Errorf("brakerskivaikuntanathan: random key must have %d coefficients", d)
	}
	m := new(big.Int).Mod(plaintext, c.t)
	c.aOnce.Do(func() { c.a = expand(c.keys.PublicKey.Seed, d) })

	f, err := sampleSmall(d)
	if err != nil {
		return nil, err
	}
	g, err := sampleSmall(d)
	if err != nil {
		return nil, err
	}

	uModQ := toModQ(u)
	c0 := polyMul(c.keys.PublicKey.B, uModQ, d)
	c1 := polyMul(c.a, uModQ, d)
	tmp := new(big.Int)
	for i := 0; i < d; i++ {
		c0[i].Add(c0[i], tmp.Mul(c.t, big.NewInt(g[i]))).Mod(c0[i], Q)
		c1[i].Add(c1[i], tmp.Mul(c.t, big.NewInt(f[i]))).Mod(c1[i], Q)
	}
	c0[0].Add(c0[0], m).Mod(c0[0], Q)
	return toValue([][]*big.Int{c0, c1}), nil
}

// Decrypt implements phe.Homomorphic for pairs and triples of polynomials.
func (c *Cryptosystem) Decrypt(ciphertext phe.Value) (*big.Int, error) {
	if !c.hasSecret {
		return nil, phe.ErrMissingPrivateKey
	}
	polys, err := c.polys(ciphertext)
	if err != nil {
		return nil, err
	}
	s := c.keys.PrivateKey.S
	sBig := make([]*big.Int, len(s))
	for i, x := range s {
		sBig[i] = big.NewInt(x)
	}

	// only the constant term carries the message: c0 + c1 s (+ c2 s^2)
	result := new(big.Int).Set(polys[0][0])
	result.Add(result, constantTerm(polys[1], sBig))
	if len(polys) == multipliedSize {
		c.sSquareOnce.Do(func() {
			sModQ := toModQ(s)
			c.sSquare = polyMul(sModQ, sModQ, c.d)
		})
		result.Add(result, constantTerm(polys[2], c.sSquare))
	}

	// centered representative is m + t * noise
	result.Mod(result, Q)
	if result.Cmp(new(big.Int).Rsh(Q, 1)) > 0 {
		result.Sub(result, Q)
	}
	return result.Mod(result, c.t), nil
}

// Add implements phe.Homomorphic. Fresh and multiplied ciphertexts can be
// added.
func (c *Cryptosystem) Add(a, b phe.Value) (phe.Value, error) {
	first, err := c.polys(a)
	if err != nil {
		return nil, err
	}
	second, err := c.polys(b)
	if err != nil {
		return nil, err
	}
	size := len(first)
	if len(second) > size {
		size = len(second)
	}
	out := make([][]*big.Int, size)
	for k := 0; k < size; k++ {
		poly := make([]*big.Int, c.d)
		for i := range poly {
			x := new(big.Int)
			if k < len(first) {
				x.Add(x, first[k][i])
			}
			if k < len(second) {
				x.Add(x, second[k][i])
			}
			poly[i] = x.Mod(x, Q)
		}
		out[k] = poly
	}
	return toValue(out), nil
}

// Multiply implements phe.Homomorphic. Only fresh ciphertexts (or sums of
// them) can be multiplied, and the result is a triple of polynomials.
func (c *Cryptosystem) Multiply(a, b phe.Value) (phe.Value, error) {
	first, err := c.polys(a)
	if err != nil {
		return nil, err
	}
	second, err := c.polys(b)
	if err != nil {
		return nil, err
	}
	if len(first) != freshSize || len(second) != freshSize {
		return nil, ErrMultipliedTwice
	}
	d := c.d
	sum := func(p1, p2 []*big.Int) []*big.Int {
		out := make([]*big.Int, d)
		for i := range out {
			x := new(big.Int).Add(p1[i], p2[i])
			out[i] = x.Mod(x, Q)
		}
		return out
	}

	// Karatsuba: c0 c1' + c1 c0' = (c0 + c1)(c0' + c1') - c0 c0' - c1 c1'
	low := polyMul(first[0], second[0], d)
	high := polyMul(first[1], second[1], d)
	cross := polyMul(sum(first[0], first[1]), sum(second[0], second[1]), d)
	for i := range cross {
		cross[i].Sub(cross[i], low[i]).Sub(cross[i], high[i]).Mod(cross[i], Q)
	}
	return toValue([][]*big.Int{low, cross, high}), nil
}

// MultiplyByConstant implements phe.Homomorphic. Noise of the result is the
// noise of the ciphertext times |constant|.
func (c *Cryptosystem) MultiplyByConstant(ciphertext phe.Value, constant *big.Int) (phe.Value, error) {
	polys, err := c.polys(ciphertext)
	if err != nil {
		return nil, err
	}

	// centered representative keeps the noise small for negative constants.
	// it is congruent to the constant mod t, so the result does not change.
	k := new(big.Int).Mod(constant, c.t)
	if k.Cmp(new(big.Int).Rsh(c.t, 1)) > 0 {
		k.Sub(k, c.t)
	}

	out := make([][]*big.Int, len(polys))
	for j, poly := range polys {
		scaled := make([]*big.Int, len(poly))
		for i, x := range poly {
			y := new(big.Int).Mul(x, k)
			scaled[i] = y.Mod(y, Q)
		}
		out[j] = scaled
	}
	return toValue(out), nil
}

// Reencrypt implements phe.Homomorphic by adding an encryption of zero.
func (c *Cryptosystem) Reencrypt(ciphertext phe.Value) (phe.Value, error) {
	zero, err := c.Encrypt(new(big.Int))
	if err != nil {
		return nil, err
	}
	return c.Add(ciphertext, zero)
}

// polys converts a ciphertext into its polynomials.
func (c *Cryptosystem) polys(v phe.Value) ([][]*big.Int, error) {
	t, err := phe.AsTuple(v)
	if err != nil {
		return nil, err
	}
	if t.Len() != freshSize && t.Len() != multipliedSize {
		return nil, phe.InvalidCiphertextf("brakerskivaikuntanathan: ciphertext must be a pair or triple of polynomials")
	}
	out := make([][]*big.Int, t.Len())
	for i, item := range t.Items {
		poly, err := phe.AsTuple(item)
		if err != nil {
			return nil, err
		}
		coefficients, err := poly.Ints()
		if err != nil {
			return nil, err
		}
		if len(coefficients) != c.d {
			return nil, phe.InvalidCiphertextf("brakerskivaikuntanathan: polynomials must have %d coefficients, got %d",
				c.d, len(coefficients))
		}
		for _, x := range coefficients {
			if x.Sign() < 0 || x.Cmp(Q) >= 0 {
				return nil, phe.InvalidCiphertextf("brakerskivaikuntanathan: coefficients must be in [0, q)")
			}
		}
		out[i] = coefficients
	}
	return out, nil
}

func toValue(polys [][]*big.Int) phe.Value {
	items := make([]phe.Value, len(polys))
	for i, poly := range polys {
		coefficients := make([]phe.Value, len(poly))
		for j, x := range poly {
			coefficients[j] = phe.Int{V: x}
		}
		items[i] = phe.Tuple{Items: coefficients}
	}
	return phe.Tuple{Items: items}
}

func toModQ(small []int64) []*big.Int {
	out := make([]*big.Int, len(small))
	for i, x := range small {
		out[i] = new(big.Int).Mod(big.NewInt(x), Q)
	}
	return out
}

// polyMul multiplies two polynomials in Z_q[x] / (x^d + 1) with Kronecker
// substitution. Coefficients are packed into big integers, so that a single big
// integer multiplication computes all coefficients of the product.
func polyMul(p1, p2 []*big.Int, d int) []*big.Int {
	// each coefficient of the product is a sum of d products less than q^2
	width := (2*LogQ + bits.Len(uint(d)) + 7) / 8
	pack := func(poly []*big.Int) *big.Int {
		buf := make([]byte, d*width)
		for i, x := range poly {
			// coefficient i occupies slot i counted from the least significant end
			x.FillBytes(buf[(d-1-i)*width : (d-i)*width])
		}
		return new(big.Int).SetBytes(buf)
	}
	product := new(big.Int).Mul(pack(p1), pack(p2))
	buf := make([]byte, 2*d*width)
	product.FillBytes(buf)
	coefficient := func(i int) *big.Int {
		return new(big.Int).SetBytes(buf[(2*d-1-i)*width : (2*d-i)*width])
	}

	// x^d = -1
	out := make([]*big.Int, d)
	for i := range out {
		x := coefficient(i)
		x.Sub(x, coefficient(i+d)).Mod(x, Q)
		out[i] = x
	}
	return out
}

// constantTerm is the constant term of the product of two polynomials in
// Z[x] / (x^d + 1), i.e. p1_0 p2_0 - sum of p1_i p2_(d-i) for i in [1, d).
func constantTerm(p1, p2 []*big.Int) *big.Int {
	d := len(p1)
	result := new(big.Int).Mul(p1[0], p2[0])
	tmp := new(big.Int)
	for i := 1; i < d; i++ {
		result.Sub(result, tmp.Mul(p1[i], p2[d-i]))
	}
	return result
}

// sampleSmall samples from the centered binomial distribution with
// cryptographically secure randomness.
func sampleSmall(size int) ([]int64, error) {
	buf := make([]byte, 8*size)
	if _, err := rand.Read(buf); err != nil {
		return nil, fmt.Errorf("brakerskivaikuntanathan: reading randomness: %w", err)
	}
	mask := uint64(1)<<eta - 1
	out := make([]int64, size)
	for i := range out {
		x := binary.LittleEndian.Uint64(buf[8*i:])
		out[i] = int64(bits.OnesCount64(x&mask)) - int64(bits.OnesCount64((x>>eta)&mask))
	}
	return out, nil
}

// expand expands the public polynomial a from its seed with SHAKE-128. Each
// coefficient is reduced from 64 more bits than q, so it is statistically
// uniform in [0, q).
func expand(seed *big.Int, d int) []*big.Int {
	width := (LogQ + 64 + 7) / 8
	seedBytes := make([]byte, 32)
	seed.FillBytes(seedBytes)
	stream := shake.Sum128(seedBytes, d*width)

	out := make([]*big.Int, d)
	chunk := make([]byte, width)
	for i := range out {
		// little endian slot into big endian bytes
		for k := 0; k < width; k++ {
			chunk[width-1-k] = stream[i*width+k]
		}
		x := new(big.Int).SetBytes(chunk)
		out[i] = x.Mod(x, Q)
	}
	return out
}

// multipliedNoiseBound bounds the noise in the product of two fresh
// ciphertexts. A fresh ciphertext decrypts to m + t v where v = g + f s - e u,
// whose coefficients have standard deviation about sigma^2 sqrt(2d). The
// product multiplies two such polynomials, whose constant term sums d products
// of coefficients.
func multipliedNoiseBound(d int, t *big.Int) *big.Int {
	variance := float64(eta) / 2
	tf, _ := new(big.Float).SetInt(t).Float64()
	freshDeviation := tf * (variance*math.Sqrt(2*float64(d)) + 1)
	bound := math.Ceil(noiseTail * math.Sqrt(float64(d)) * freshDeviation * freshDeviation)
	out, _ := big.NewFloat(bound).Int(nil)
	return out
}
