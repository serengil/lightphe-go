// Package lyubashevskypeikertregev implements the Lyubashevsky-Peikert-Regev
// cryptosystem, which is homomorphic with respect to addition and supports
// multiplying a ciphertext by a known plain constant. It is Regev's
// cryptosystem over a polynomial ring, and it is quantum resistant. Its
// security relies on the ring learning with errors (Ring-LWE) problem like
// Brakerski-Vaikuntanathan.
//
// It works in the polynomial ring R_q = Z_q[x] / (x^d + 1).
//   - private key: polynomial s with small coefficients
//   - public key: a and b = a s + e, where e is a small error polynomial
//   - encryption: c1 = a u + e1, and c2 = constant term of (b u) + e2 + m q / t
//   - decryption: c2 - constant term of (c1 s) = m q / t + noise, so m is
//     restored by rounding
//
// a is expanded from a public seed with SHAKE-128, so the public key is the
// seed and b.
//
// Regev uses a random n x n matrix A, whereas this uses the negacyclic matrix
// of a single polynomial a, so the public structure is n times smaller, and
// c1 = a u is a single polynomial multiplication instead of a matrix-vector
// product. Message is encoded into the constant term only, which is the only
// coefficient decryption reads, so other coefficients of c2 are dropped. Thus,
// a ciphertext has d + 1 coefficients like Regev, instead of 2d of the
// original scheme. Dropping parts of a ciphertext does not help an attacker,
// so the security is the same.
//
// The key size is the ring degree d, a power of 2. Default is 2048. With
// q = 2^50, degree 2048 gives about 128-bit security against quantum attacks
// according to the tables of Homomorphic Encryption Standard (log q must be at
// most 51 for d = 2048). Smaller degrees are not secure, and are for testing
// only.
//
// Its plaintext space is small, 2^24 by default, and every ciphertext has
// noise. Noise grows with homomorphic operations: addition adds the noise of
// ciphertexts, and multiplying with a constant k multiplies the noise by |k|.
// Decryption returns a wrong result without any error when the noise exceeds
// q / 2t. Fresh noise is about 2^13 for d = 2048, and the limit is 2^25 by
// default, so there is room for thousands of additions or multiplication with
// constants up to a few thousands. A greater plaintext space can be set with a
// plaintext limit in exchange of a smaller room for noise. Floats and tensors
// are not supported, as they are scaled by powers of 10. Ciphertexts have
// d + 1 entries of 50 bits each, about 12.8 KB for d = 2048.
//
// Reference: Lyubashevsky, V., Peikert, C., Regev, O. (2010). On Ideal
// Lattices and Learning with Errors over Rings. EUROCRYPT 2010.
//
// Reference: Albrecht, M. et al. (2018). Homomorphic Encryption Security
// Standard. HomomorphicEncryption.org.
package lyubashevskypeikertregev

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
const DefaultKeySize = 2048

// LogQ fixes the ciphertext modulus q = 2^LogQ.
const LogQ = 50

// DefaultLogT fixes the default plaintext modulus t = 2^DefaultLogT.
const DefaultLogT = 24

// eta parametrizes the centered binomial distribution the secret and errors
// are sampled from. Its standard deviation is sqrt(eta / 2) = 3.24, and its
// values are in [-eta, eta].
const eta = 21

// noiseTail bounds fresh noise in standard deviations for correct decryption.
const noiseTail = 12

const qMask = uint64(1)<<LogQ - 1

// ErrFloatNotSupported reports a float plaintext, constant or tensor.
var ErrFloatNotSupported = phe.FloatNotSupported("lightphe: Lyubashevsky-Peikert-Regev does not support float values " +
	"or tensors, because they are scaled by powers of 10, which exceed its small plaintext space and noise budget. " +
	"Use integers instead")

// PublicKey is the Lyubashevsky-Peikert-Regev public key: the ring degree d,
// the moduli q and t, the seed of the polynomial a and the polynomial
// b = a s + e.
type PublicKey struct {
	D    *big.Int `json:"d"`
	Q    *big.Int `json:"q"`
	T    *big.Int `json:"t"`
	Seed *big.Int `json:"seed"`
	B    []uint64 `json:"b"`
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
	alg := phe.LyubashevskyPeikertRegev
	if k.PublicKey == nil {
		return phe.RequireSection(alg, phe.SectionPublic)
	}
	pk := k.PublicKey
	if err := phe.RequireFields(alg, phe.SectionPublic,
		phe.Field("d", pk.D != nil),
		phe.Field("q", pk.Q != nil),
		phe.Field("t", pk.T != nil),
		phe.Field("seed", pk.Seed != nil),
		phe.Field("b", pk.B != nil),
	); err != nil {
		return err
	}
	if k.PrivateKey != nil {
		if err := phe.RequireFields(alg, phe.SectionPrivate,
			phe.Field("s", k.PrivateKey.S != nil),
		); err != nil {
			return err
		}
	}

	if !pk.D.IsInt64() || !isPowerOfTwo(pk.D.Int64()) || pk.D.Int64() < 8 || pk.D.Int64() > 1<<16 {
		return phe.InvalidKeysf("lyubashevskypeikertregev: degree must be a power of 2, got %s", pk.D)
	}
	d := int(pk.D.Int64())
	if pk.Q.Cmp(new(big.Int).Lsh(big.NewInt(1), LogQ)) != 0 {
		return phe.InvalidKeysf("lyubashevskypeikertregev: q must be 2^%d", LogQ)
	}
	if pk.T.Sign() <= 0 || pk.T.Cmp(pk.Q) > 0 || new(big.Int).Mod(pk.Q, pk.T).Sign() != 0 {
		return phe.InvalidKeysf("lyubashevskypeikertregev: t must be a power of 2 dividing q")
	}
	if pk.Seed.Sign() < 0 || pk.Seed.BitLen() > 256 {
		return phe.InvalidKeysf("lyubashevskypeikertregev: seed must be a 256-bit integer")
	}
	if len(pk.B) != d || (k.PrivateKey != nil && len(k.PrivateKey.S) != d) {
		return phe.InvalidKeysf("lyubashevskypeikertregev: b and s must have %d coefficients", d)
	}
	return nil
}

func isPowerOfTwo(x int64) bool { return x > 0 && x&(x-1) == 0 }

// Cryptosystem is a configured Lyubashevsky-Peikert-Regev instance. It is
// immutable and safe for concurrent use.
type Cryptosystem struct {
	phe.Base

	keys      Keys
	d         int
	t         uint64
	hasSecret bool

	// a expanded from the seed when needed
	aOnce sync.Once
	a     []uint64
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
		return nil, fmt.Errorf("lyubashevskypeikertregev: key size %d must be a power of 2 and at least 8: %w",
			d, phe.ErrKeyGeneration)
	}

	q := uint64(1) << LogQ
	t := uint64(1) << DefaultLogT
	if plaintextLimit != nil {
		if plaintextLimit.Cmp(big.NewInt(2)) < 0 {
			return nil, fmt.Errorf("lyubashevskypeikertregev: plaintext limit must be at least 2: %w", phe.ErrKeyGeneration)
		}
		logT := new(big.Int).Sub(plaintextLimit, big.NewInt(1)).BitLen()
		if logT > LogQ {
			return nil, fmt.Errorf("lyubashevskypeikertregev: plaintext limit %s is too large: %w",
				plaintextLimit, phe.ErrKeyGeneration)
		}
		t = uint64(1) << uint(logT)
	}

	// fresh ciphertexts must be decrypted correctly
	bound := noiseBound(d)
	if q/t/2 <= bound {
		return nil, fmt.Errorf("lyubashevskypeikertregev: plaintext limit %s is too large, it must be less than %d "+
			"for degree %d: %w", plaintextLimit, q/(2*bound), d, phe.ErrKeyGeneration)
	}

	seedBytes := make([]byte, 32)
	if _, err := rand.Read(seedBytes); err != nil {
		return nil, fmt.Errorf("lyubashevskypeikertregev: reading randomness: %w", err)
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

	// b = a s + e
	b := polyMul(a, s)
	for i := range b {
		b[i] = (b[i] + uint64(e[i])) & qMask
	}

	c, err := New(Keys{
		PublicKey: &PublicKey{
			D:    big.NewInt(int64(d)),
			Q:    new(big.Int).SetUint64(q),
			T:    new(big.Int).SetUint64(t),
			Seed: seed,
			B:    b,
		},
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
		Base:      phe.Base{Alg: phe.LyubashevskyPeikertRegev},
		keys:      keys,
		d:         int(keys.PublicKey.D.Int64()),
		t:         keys.PublicKey.T.Uint64(),
		hasSecret: keys.PrivateKey != nil,
	}, nil
}

// FromJSON rebuilds a cryptosystem from exported key material.
func FromJSON(data []byte) (*Cryptosystem, error) {
	var keys Keys
	if err := json.Unmarshal(data, &keys); err != nil {
		return nil, phe.InvalidKeysf("lyubashevskypeikertregev: decoding keys: %v", err)
	}
	return New(keys)
}

// Keys returns a copy of the key material.
func (c *Cryptosystem) Keys() Keys { return c.keys }

// PlaintextModulo implements phe.Homomorphic.
func (c *Cryptosystem) PlaintextModulo() *big.Int { return new(big.Int).SetUint64(c.t) }

// CiphertextModulo implements phe.Homomorphic.
func (c *Cryptosystem) CiphertextModulo() *big.Int { return new(big.Int).Lsh(big.NewInt(1), LogQ) }

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
		return nil, fmt.Errorf("lyubashevskypeikertregev: random key must have %d coefficients", d)
	}
	m := new(big.Int).Mod(plaintext, new(big.Int).SetUint64(c.t)).Uint64()
	c.aOnce.Do(func() { c.a = expand(c.keys.PublicKey.Seed, d) })

	e1, err := sampleSmall(d)
	if err != nil {
		return nil, err
	}
	e2, err := sampleSmall(1)
	if err != nil {
		return nil, err
	}

	// c1 = a u + e1
	c1 := polyMul(c.a, u)
	items := make([]phe.Value, d+1)
	for i, x := range c1 {
		items[i] = phe.Int{V: new(big.Int).SetUint64((x + uint64(e1[i])) & qMask)}
	}

	// c2 = constant term of (b u) + e2 + m q / t
	delta := (uint64(1) << LogQ) / c.t
	c2 := constantTerm(c.keys.PublicKey.B, u) + uint64(e2[0]) + m*delta
	items[d] = phe.Int{V: new(big.Int).SetUint64(c2 & qMask)}
	return phe.Tuple{Items: items}, nil
}

// Decrypt implements phe.Homomorphic.
func (c *Cryptosystem) Decrypt(ciphertext phe.Value) (*big.Int, error) {
	if !c.hasSecret {
		return nil, phe.ErrMissingPrivateKey
	}
	entries, err := c.entries(ciphertext)
	if err != nil {
		return nil, err
	}
	delta := (uint64(1) << LogQ) / c.t

	// m q / t + noise
	noisy := (entries[c.d] - constantTerm(entries[:c.d], c.keys.PrivateKey.S)) & qMask
	m := ((noisy + delta/2) / delta) % c.t
	return new(big.Int).SetUint64(m), nil
}

// Add implements phe.Homomorphic. Noise of the result is the sum of noises of
// the ciphertexts.
func (c *Cryptosystem) Add(a, b phe.Value) (phe.Value, error) {
	x, err := c.entries(a)
	if err != nil {
		return nil, err
	}
	y, err := c.entries(b)
	if err != nil {
		return nil, err
	}
	items := make([]phe.Value, len(x))
	for i := range x {
		items[i] = phe.Int{V: new(big.Int).SetUint64((x[i] + y[i]) & qMask)}
	}
	return phe.Tuple{Items: items}, nil
}

// MultiplyByConstant implements phe.Homomorphic. Noise of the result is the
// noise of the ciphertext times |constant|.
func (c *Cryptosystem) MultiplyByConstant(ciphertext phe.Value, constant *big.Int) (phe.Value, error) {
	x, err := c.entries(ciphertext)
	if err != nil {
		return nil, err
	}

	// centered representative keeps the noise small for negative constants,
	// e.g. t - 1 is multiplied as -1. as t divides q, this does not change the
	// result.
	k := new(big.Int).Mod(constant, new(big.Int).SetUint64(c.t)).Uint64()
	if k > c.t/2 {
		k -= c.t
	}
	items := make([]phe.Value, len(x))
	for i := range x {
		items[i] = phe.Int{V: new(big.Int).SetUint64((x[i] * k) & qMask)}
	}
	return phe.Tuple{Items: items}, nil
}

// Reencrypt implements phe.Homomorphic by adding an encryption of zero.
func (c *Cryptosystem) Reencrypt(ciphertext phe.Value) (phe.Value, error) {
	zero, err := c.Encrypt(new(big.Int))
	if err != nil {
		return nil, err
	}
	return c.Add(ciphertext, zero)
}

// entries converts a ciphertext into its d + 1 entries.
func (c *Cryptosystem) entries(v phe.Value) ([]uint64, error) {
	t, err := phe.AsTuple(v)
	if err != nil {
		return nil, err
	}
	if t.Len() != c.d+1 {
		return nil, phe.InvalidCiphertextf("lyubashevskypeikertregev: ciphertext must have %d entries, got %d", c.d+1, t.Len())
	}
	out := make([]uint64, len(t.Items))
	for i, item := range t.Items {
		x, err := phe.AsInt(item)
		if err != nil {
			return nil, err
		}
		if x.Sign() < 0 || x.BitLen() > LogQ {
			return nil, phe.InvalidCiphertextf("lyubashevskypeikertregev: ciphertext entry %d is out of [0, q)", i)
		}
		out[i] = x.Uint64()
	}
	return out, nil
}

// polyMul multiplies a polynomial in Z_q[x] / (x^d + 1) with a small one.
// Arithmetic wraps modulo 2^64, which q = 2^LogQ divides, so coefficients are
// reduced by masking at the end.
func polyMul(p []uint64, small []int64) []uint64 {
	d := len(p)
	out := make([]uint64, d)
	for j, y := range small {
		if y == 0 {
			continue
		}
		k := uint64(y)
		// x^d = -1
		for i := 0; i < d-j; i++ {
			out[i+j] += p[i] * k
		}
		for i := d - j; i < d; i++ {
			out[i+j-d] -= p[i] * k
		}
	}
	for i := range out {
		out[i] &= qMask
	}
	return out
}

// constantTerm is the constant term of the product of two polynomials in
// Z[x] / (x^d + 1), i.e. p_0 s_0 - sum of p_i s_(d-i) for i in [1, d), modulo
// 2^64.
func constantTerm(p []uint64, s []int64) uint64 {
	d := len(p)
	result := p[0] * uint64(s[0])
	for i := 1; i < d; i++ {
		result -= p[i] * uint64(s[d-i])
	}
	return result
}

// sampleSmall samples from the centered binomial distribution with
// cryptographically secure randomness.
func sampleSmall(size int) ([]int64, error) {
	buf := make([]byte, 8*size)
	if _, err := rand.Read(buf); err != nil {
		return nil, fmt.Errorf("lyubashevskypeikertregev: reading randomness: %w", err)
	}
	mask := uint64(1)<<eta - 1
	out := make([]int64, size)
	for i := range out {
		x := binary.LittleEndian.Uint64(buf[8*i:])
		out[i] = int64(bits.OnesCount64(x&mask)) - int64(bits.OnesCount64((x>>eta)&mask))
	}
	return out, nil
}

// noiseBound bounds the noise constant term of (e u) + e2 - constant term of
// (e1 s) in fresh ciphertexts. It sums 2d products of small coefficients like
// Regev.
func noiseBound(d int) uint64 {
	variance := float64(eta) / 2
	return uint64(math.Ceil(noiseTail*variance*math.Sqrt(2*float64(d)))) + eta
}

// expand expands the public polynomial a from its seed with SHAKE-128. q is a
// power of 2, so each coefficient is uniform in [0, q) when its bits are
// masked. Coefficient i is the little endian slot of 7 bytes at index i of the
// stream.
func expand(seed *big.Int, d int) []uint64 {
	const width = (LogQ + 7) / 8
	seedBytes := make([]byte, 32)
	seed.FillBytes(seedBytes)
	stream := shake.Sum128(seedBytes, d*width)

	a := make([]uint64, d)
	slot := make([]byte, 8)
	for i := range a {
		copy(slot, stream[i*width:(i+1)*width])
		a[i] = binary.LittleEndian.Uint64(slot) & qMask
	}
	return a
}
