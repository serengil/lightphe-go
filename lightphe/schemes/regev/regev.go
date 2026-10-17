// Package regev implements the Regev cryptosystem, which is homomorphic with
// respect to addition and supports multiplying a ciphertext by a known plain
// constant.
//
// It is quantum resistant. Its security relies on the learning with errors
// (LWE) problem, which is believed to be hard for quantum computers, unlike
// factoring and discrete logarithm problems that most other algorithms rely
// on.
//
// This is the Lindner-Peikert form of Regev's cryptosystem, which is the one
// used in practice, e.g. by FrodoKEM. Original form requires a public key
// matrix with about n log q rows, whereas this needs an n x n matrix A.
//   - private key: secret vector s with small entries
//   - public key: A and b = A s + e mod q, where e is a small error vector
//   - encryption: c1 = A^T r + e1 and c2 = <b, r> + e2 + m * q / t mod q
//   - decryption: c2 - <c1, s> = m * q / t + noise, so m is restored by
//     rounding
//
// A is expanded from a public seed with SHAKE-128, so the public key is the
// seed and b.
//
// The key size is the lattice dimension n. Default is 2048. With q = 2^50,
// dimension 2048 or more gives about 128-bit security against quantum attacks
// according to the tables of Homomorphic Encryption Standard (log q must be at
// most 51 for n = 2048). Smaller dimensions are not secure, and are for testing
// only.
//
// Its plaintext space is small, 2^24 by default, and every ciphertext has
// noise. Noise grows with homomorphic operations: addition adds the noise of
// ciphertexts, and multiplying with a constant k multiplies the noise by |k|.
// Decryption returns a wrong result without any error when the noise exceeds
// q / 2t. Fresh noise is about 2^13 for n = 2048, and the limit is 2^25 by
// default, so there is room for thousands of additions or multiplication with
// constants up to a few thousands. A greater plaintext space can be set with a
// plaintext limit in exchange of a smaller room for noise. Floats and tensors
// are not supported, as they are scaled by powers of 10. Ciphertexts have
// n + 1 entries of 50 bits each, about 12.8 KB for n = 2048.
//
// Reference: Regev, O. (2005). On Lattices, Learning with Errors, Random Linear
// Codes, and Cryptography. STOC 2005.
//
// Reference: Lindner, R., Peikert, C. (2011). Better Key Sizes (and Attacks)
// for LWE-Based Encryption. CT-RSA 2011.
//
// Reference: Albrecht, M. et al. (2018). Homomorphic Encryption Security
// Standard. HomomorphicEncryption.org.
package regev

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

// DefaultKeySize is the lattice dimension used when none is requested.
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
var ErrFloatNotSupported = phe.FloatNotSupported("lightphe: Regev does not support float values or tensors, " +
	"because they are scaled by powers of 10, which exceed its small plaintext space and noise budget. Use integers instead")

// PublicKey is the Regev public key: the dimension n, the moduli q and t, the
// seed of the matrix A and the vector b = A s + e mod q.
type PublicKey struct {
	N    *big.Int `json:"n"`
	Q    *big.Int `json:"q"`
	T    *big.Int `json:"t"`
	Seed *big.Int `json:"seed"`
	B    []uint64 `json:"b"`
}

// PrivateKey is the secret vector s with small entries.
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
		return phe.RequireSection(phe.Regev, phe.SectionPublic)
	}
	pk := k.PublicKey
	if err := phe.RequireFields(phe.Regev, phe.SectionPublic,
		phe.Field("n", pk.N != nil),
		phe.Field("q", pk.Q != nil),
		phe.Field("t", pk.T != nil),
		phe.Field("seed", pk.Seed != nil),
		phe.Field("b", pk.B != nil),
	); err != nil {
		return err
	}
	if k.PrivateKey != nil {
		if err := phe.RequireFields(phe.Regev, phe.SectionPrivate,
			phe.Field("s", k.PrivateKey.S != nil),
		); err != nil {
			return err
		}
	}

	if !pk.N.IsInt64() || pk.N.Int64() < 8 || pk.N.Int64() > 1<<16 {
		return phe.InvalidKeysf("regev: unsupported dimension %s", pk.N)
	}
	n := int(pk.N.Int64())
	if pk.Q.Cmp(new(big.Int).Lsh(big.NewInt(1), LogQ)) != 0 {
		return phe.InvalidKeysf("regev: q must be 2^%d", LogQ)
	}
	if pk.T.Sign() <= 0 || pk.T.Cmp(pk.Q) > 0 || new(big.Int).Mod(pk.Q, pk.T).Sign() != 0 {
		return phe.InvalidKeysf("regev: t must be a power of 2 dividing q")
	}
	if pk.Seed.Sign() < 0 || pk.Seed.BitLen() > 256 {
		return phe.InvalidKeysf("regev: seed must be a 256-bit integer")
	}
	if len(pk.B) != n || (k.PrivateKey != nil && len(k.PrivateKey.S) != n) {
		return phe.InvalidKeysf("regev: b and s must have %d entries", n)
	}
	return nil
}

// Cryptosystem is a configured Regev instance. It is immutable and safe for
// concurrent use.
type Cryptosystem struct {
	phe.Base

	keys      Keys
	n         int
	t         uint64
	hasSecret bool

	// A in row-major order, expanded from the seed when needed
	aOnce sync.Once
	a     []uint64
}

var (
	_ phe.Homomorphic   = (*Cryptosystem)(nil)
	_ phe.FloatRejecter = (*Cryptosystem)(nil)
)

// Generate creates a fresh key pair for the lattice dimension keySize. A nil
// plaintextLimit selects the default plaintext space 2^24; otherwise it is
// rounded up to a power of 2.
func Generate(keySize int, plaintextLimit *big.Int) (*Cryptosystem, error) {
	n := keySize
	if n <= 0 {
		n = DefaultKeySize
	}
	if n < 8 {
		return nil, fmt.Errorf("regev: key size %d is too small: %w", n, phe.ErrKeyGeneration)
	}

	q := uint64(1) << LogQ
	t := uint64(1) << DefaultLogT
	if plaintextLimit != nil {
		if plaintextLimit.Cmp(big.NewInt(2)) < 0 {
			return nil, fmt.Errorf("regev: plaintext limit must be at least 2: %w", phe.ErrKeyGeneration)
		}
		logT := new(big.Int).Sub(plaintextLimit, big.NewInt(1)).BitLen()
		if logT > LogQ {
			return nil, fmt.Errorf("regev: plaintext limit %s is too large: %w", plaintextLimit, phe.ErrKeyGeneration)
		}
		t = uint64(1) << uint(logT)
	}

	// fresh ciphertexts must be decrypted correctly
	bound := noiseBound(n)
	if q/t/2 <= bound {
		return nil, fmt.Errorf("regev: plaintext limit %s is too large, it must be less than %d for dimension %d: %w",
			plaintextLimit, q/(2*bound), n, phe.ErrKeyGeneration)
	}

	seedBytes := make([]byte, 32)
	if _, err := rand.Read(seedBytes); err != nil {
		return nil, fmt.Errorf("regev: reading randomness: %w", err)
	}
	seed := new(big.Int).SetBytes(seedBytes)
	s, err := sampleSmall(n)
	if err != nil {
		return nil, err
	}
	e, err := sampleSmall(n)
	if err != nil {
		return nil, err
	}

	// b = A s + e mod q
	a := expand(seed, n)
	b := make([]uint64, n)
	for j := 0; j < n; j++ {
		row := a[j*n : (j+1)*n]
		var acc uint64
		for i, x := range row {
			acc += x * uint64(s[i])
		}
		b[j] = (acc + uint64(e[j])) & qMask
	}

	c, err := New(Keys{
		PublicKey: &PublicKey{
			N:    big.NewInt(int64(n)),
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
		Base:      phe.Base{Alg: phe.Regev},
		keys:      keys,
		n:         int(keys.PublicKey.N.Int64()),
		t:         keys.PublicKey.T.Uint64(),
		hasSecret: keys.PrivateKey != nil,
	}, nil
}

// FromJSON rebuilds a cryptosystem from exported key material.
func FromJSON(data []byte) (*Cryptosystem, error) {
	var keys Keys
	if err := json.Unmarshal(data, &keys); err != nil {
		return nil, phe.InvalidKeysf("regev: decoding keys: %v", err)
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
	r, err := sampleSmall(c.n)
	if err != nil {
		return nil, err
	}
	return c.EncryptWith(plaintext, r)
}

// EncryptWith encrypts using a caller supplied small random vector r.
func (c *Cryptosystem) EncryptWith(plaintext *big.Int, r []int64) (phe.Value, error) {
	n := c.n
	if len(r) != n {
		return nil, fmt.Errorf("regev: random key must have %d entries", n)
	}
	m := new(big.Int).Mod(plaintext, new(big.Int).SetUint64(c.t)).Uint64()

	c.aOnce.Do(func() { c.a = expand(c.keys.PublicKey.Seed, n) })

	e1, err := sampleSmall(n)
	if err != nil {
		return nil, err
	}
	e2, err := sampleSmall(1)
	if err != nil {
		return nil, err
	}

	// c1 = A^T r + e1, accumulated row by row
	c1 := make([]uint64, n)
	for i := 0; i < n; i++ {
		ri := uint64(r[i])
		if ri == 0 {
			continue
		}
		row := c.a[i*n : (i+1)*n]
		for j, x := range row {
			c1[j] += x * ri
		}
	}

	items := make([]phe.Value, n+1)
	for j := range c1 {
		items[j] = phe.Int{V: new(big.Int).SetUint64((c1[j] + uint64(e1[j])) & qMask)}
	}

	// c2 = <b, r> + e2 + m q / t
	var c2 uint64
	for i, x := range c.keys.PublicKey.B {
		c2 += x * uint64(r[i])
	}
	delta := (uint64(1) << LogQ) / c.t
	c2 += uint64(e2[0]) + m*delta
	items[n] = phe.Int{V: new(big.Int).SetUint64(c2 & qMask)}
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

	// m * q / t + noise
	noisy := entries[c.n]
	for i, s := range c.keys.PrivateKey.S {
		noisy -= entries[i] * uint64(s)
	}
	noisy &= qMask
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
	k := centered(constant, c.t)
	items := make([]phe.Value, len(x))
	for i := range x {
		items[i] = phe.Int{V: new(big.Int).SetUint64((x[i] * uint64(k)) & qMask)}
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

// entries converts a ciphertext into its n + 1 entries.
func (c *Cryptosystem) entries(v phe.Value) ([]uint64, error) {
	t, err := phe.AsTuple(v)
	if err != nil {
		return nil, err
	}
	if t.Len() != c.n+1 {
		return nil, phe.InvalidCiphertextf("regev: ciphertext must have %d entries, got %d", c.n+1, t.Len())
	}
	out := make([]uint64, len(t.Items))
	for i, item := range t.Items {
		x, err := phe.AsInt(item)
		if err != nil {
			return nil, err
		}
		if x.Sign() < 0 || x.BitLen() > LogQ {
			return nil, phe.InvalidCiphertextf("regev: ciphertext entry %d is out of [0, q)", i)
		}
		out[i] = x.Uint64()
	}
	return out, nil
}

// centered returns the representative of constant mod t in (-t/2, t/2].
func centered(constant *big.Int, t uint64) int64 {
	k := new(big.Int).Mod(constant, new(big.Int).SetUint64(t)).Uint64()
	if k > t/2 {
		return int64(k) - int64(t)
	}
	return int64(k)
}

// sampleSmall samples from the centered binomial distribution with
// cryptographically secure randomness.
func sampleSmall(size int) ([]int64, error) {
	buf := make([]byte, 8*size)
	if _, err := rand.Read(buf); err != nil {
		return nil, fmt.Errorf("regev: reading randomness: %w", err)
	}
	mask := uint64(1)<<eta - 1
	out := make([]int64, size)
	for i := range out {
		x := binary.LittleEndian.Uint64(buf[8*i:])
		out[i] = int64(bits.OnesCount64(x&mask)) - int64(bits.OnesCount64((x>>eta)&mask))
	}
	return out, nil
}

// noiseBound bounds the noise <e, r> + e2 - <s, e1> in fresh ciphertexts.
func noiseBound(n int) uint64 {
	variance := float64(eta) / 2
	return uint64(math.Ceil(noiseTail*variance*math.Sqrt(2*float64(n)))) + eta
}

// slotBytes is the size of an entry of A in the SHAKE-128 stream. The Python
// library packs entries into big integers, and each slot must hold a sum of n
// products of an entry of A and a small number without overflow.
func slotBytes(n int) int {
	return (LogQ + bits.Len64(uint64(eta*n)) + 7) / 8
}

// expand expands the public matrix A from its seed with SHAKE-128 and returns
// it in row-major order. Entry (i, j) is the little endian slot at index
// i * n + j of the stream reduced to LogQ bits.
func expand(seed *big.Int, n int) []uint64 {
	width := slotBytes(n)
	seedBytes := make([]byte, 32)
	seed.FillBytes(seedBytes)
	stream := shake.Sum128(seedBytes, n*n*width)

	a := make([]uint64, n*n)
	slot := make([]byte, 8)
	for k := range a {
		chunk := stream[k*width : (k+1)*width]
		if len(chunk) > 8 {
			chunk = chunk[:8]
		}
		for i := range slot {
			slot[i] = 0
		}
		copy(slot, chunk)
		a[k] = binary.LittleEndian.Uint64(slot) & qMask
	}
	return a
}
