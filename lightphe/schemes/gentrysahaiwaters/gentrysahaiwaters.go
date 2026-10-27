// Package gentrysahaiwaters implements the Gentry-Sahai-Waters cryptosystem,
// which encrypts bits and is homomorphic with respect to both the exclusive or
// and the and. Unlike Boneh-Goh-Nissim or Brakerski-Vaikuntanathan, it
// supports more than one multiplication, so boolean circuits of a small depth
// can be evaluated on encrypted bits. It is quantum resistant, and its
// security relies on the ring learning with errors (Ring-LWE) problem.
//
// This is the ring variant of GSW. It works in the polynomial ring
// R_q = Z_q[x] / (x^d + 1).
//   - private key: polynomial s with small coefficients
//   - public key: a and b = -(a s) + e, where e is a small error polynomial
//   - an encryption of zero is (b u + e1, a u + e2), whose phase c0 + c1 s is
//     small
//   - encryption of a bit m: 2 ell encryptions of zero Z, and C = Z + m G,
//     where G is the gadget matrix having powers of B in its first and second
//     columns
//   - decryption: phase of the last row of the first half is m q / 2 + noise,
//     so m is restored by rounding
//   - and: G^-1(C1) C2 where G^-1 decomposes entries of C1 into small digits,
//     so the noise of C2 is multiplied by small digits only
//   - exclusive or: C1 + C2 encrypts m1 + m2, whose parity is restored by
//     decryption
//
// a is expanded from a public seed with SHAKE-128, so the public key is the
// seed and b.
//
// The key size is the ring degree d, a power of 2. Default is 2048. With
// q = 2^50, degree 2048 gives about 128-bit security against quantum attacks
// according to the tables of Homomorphic Encryption Standard (log q must be at
// most 51 for d = 2048). Smaller degrees are not secure, and are for testing
// only.
//
// Every ciphertext has noise. Exclusive or adds the noises of ciphertexts, so
// it is almost free. Noise of C1 & C2 is the noise of C2 times small digits
// plus the noise of C1, so it depends on the order of operands:
//   - chains: acc = acc & c where c is a fresh ciphertext adds a fixed noise
//     of about 2^17 each time, so long chains of ands, e.g. carries of a
//     ripple carry adder, work.
//   - products of products: noise is multiplied by about 2^15 in each level,
//     so circuits of multiplicative depth 2 work, e.g. (a & b) & (c & d), but
//     depth 3 does not. Decryption returns a wrong result without any error
//     when the noise exceeds q / 4 = 2^48. Fresh noise is about 2^10.
//
// Ciphertexts have 2 ell x 2 polynomials of d coefficients of 50 bits, about
// 256 KB for d = 2048. Floats, tensors and integers other than bits are not
// supported.
//
// Reference: Gentry, C., Sahai, A., Waters, B. (2013). Homomorphic Encryption
// from Learning with Errors: Conceptually-Simpler, Asymptotically-Faster,
// Attribute-Based. CRYPTO 2013.
//
// Reference: Ducas, L., Micciancio, D. (2015). FHEW: Bootstrapping
// Homomorphic Encryption in less than a second. EUROCRYPT 2015.
//
// Reference: Albrecht, M. et al. (2018). Homomorphic Encryption Security
// Standard. HomomorphicEncryption.org.
package gentrysahaiwaters

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"fmt"
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

// Gadget decomposition is in base B = 2^logB with ell digits. The gadget is
// approximate: its entries are 2^offset, 2^offset B, ..., 2^offset B^(ell - 1)
// = q / 2, so the lowest offset bits are dropped by rounding, and decryption
// reads the parity of the message.
const (
	logB   = 10
	ell    = 5
	offset = LogQ - 1 - logB*(ell-1)
)

// eta parametrizes the centered binomial distribution the secret and errors
// are sampled from. Its standard deviation is sqrt(eta / 2) = 3.24, and its
// values are in [-eta, eta].
const eta = 21

const (
	q     = uint64(1) << LogQ
	qMask = q - 1
)

// ErrFloatNotSupported reports a float, a tensor or an integer other than a
// bit.
var ErrFloatNotSupported = phe.FloatNotSupported("lightphe: Gentry-Sahai-Waters encrypts bits, i.e. 0 or 1, and it " +
	"does not support float values, tensors or other integers. Encrypt integers bit by bit instead")

// PublicKey is the Gentry-Sahai-Waters public key: the ring degree d, the
// modulus q, the seed of the polynomial a and the polynomial b = -(a s) + e.
type PublicKey struct {
	D    *big.Int `json:"d"`
	Q    *big.Int `json:"q"`
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
	alg := phe.GentrySahaiWaters
	if k.PublicKey == nil {
		return phe.RequireSection(alg, phe.SectionPublic)
	}
	pk := k.PublicKey
	if err := phe.RequireFields(alg, phe.SectionPublic,
		phe.Field("d", pk.D != nil),
		phe.Field("q", pk.Q != nil),
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
		return phe.InvalidKeysf("gentrysahaiwaters: degree must be a power of 2, got %s", pk.D)
	}
	d := int(pk.D.Int64())
	if pk.Q.Cmp(new(big.Int).SetUint64(q)) != 0 {
		return phe.InvalidKeysf("gentrysahaiwaters: q must be 2^%d", LogQ)
	}
	if pk.Seed.Sign() < 0 || pk.Seed.BitLen() > 256 {
		return phe.InvalidKeysf("gentrysahaiwaters: seed must be a 256-bit integer")
	}
	if len(pk.B) != d || (k.PrivateKey != nil && len(k.PrivateKey.S) != d) {
		return phe.InvalidKeysf("gentrysahaiwaters: b and s must have %d coefficients", d)
	}
	return nil
}

func isPowerOfTwo(x int64) bool { return x > 0 && x&(x-1) == 0 }

// Cryptosystem is a configured Gentry-Sahai-Waters instance. It is immutable
// and safe for concurrent use.
type Cryptosystem struct {
	phe.Base

	keys      Keys
	d         int
	hasSecret bool

	// a expanded from the seed when needed
	aOnce sync.Once
	a     []uint64
}

var (
	_ phe.Homomorphic   = (*Cryptosystem)(nil)
	_ phe.FloatRejecter = (*Cryptosystem)(nil)
)

// row is a row of a ciphertext: a pair of polynomials (c0, c1).
type row [2][]uint64

// Generate creates a fresh key pair for the ring degree keySize.
func Generate(keySize int) (*Cryptosystem, error) {
	d := keySize
	if d <= 0 {
		d = DefaultKeySize
	}
	if d < 8 || !isPowerOfTwo(int64(d)) {
		return nil, fmt.Errorf("gentrysahaiwaters: key size %d must be a power of 2 and at least 8: %w", d, phe.ErrKeyGeneration)
	}

	seedBytes := make([]byte, 32)
	if _, err := rand.Read(seedBytes); err != nil {
		return nil, fmt.Errorf("gentrysahaiwaters: reading randomness: %w", err)
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

	// b = -(a s) + e
	b := make([]uint64, d)
	for i, x := range polyMul(a, s) {
		b[i] = (uint64(e[i]) - x) & qMask
	}

	c, err := New(Keys{
		PublicKey:  &PublicKey{D: big.NewInt(int64(d)), Q: new(big.Int).SetUint64(q), Seed: seed, B: b},
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
		Base:      phe.Base{Alg: phe.GentrySahaiWaters},
		keys:      keys,
		d:         int(keys.PublicKey.D.Int64()),
		hasSecret: keys.PrivateKey != nil,
	}, nil
}

// FromJSON rebuilds a cryptosystem from exported key material.
func FromJSON(data []byte) (*Cryptosystem, error) {
	var keys Keys
	if err := json.Unmarshal(data, &keys); err != nil {
		return nil, phe.InvalidKeysf("gentrysahaiwaters: decoding keys: %v", err)
	}
	return New(keys)
}

// Keys returns a copy of the key material.
func (c *Cryptosystem) Keys() Keys { return c.keys }

// PlaintextModulo implements phe.Homomorphic. Plaintexts are bits.
func (c *Cryptosystem) PlaintextModulo() *big.Int { return big.NewInt(2) }

// CiphertextModulo implements phe.Homomorphic.
func (c *Cryptosystem) CiphertextModulo() *big.Int { return new(big.Int).SetUint64(q) }

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

// Encrypt implements phe.Homomorphic. The plaintext is reduced to its parity.
func (c *Cryptosystem) Encrypt(plaintext *big.Int) (phe.Value, error) {
	us := make([][]int64, 2*ell)
	for i := range us {
		u, err := sampleSmall(c.d)
		if err != nil {
			return nil, err
		}
		us[i] = u
	}
	return c.EncryptWith(plaintext, us)
}

// EncryptWith encrypts using caller supplied small random polynomials u, one
// for each of the 2 ell rows.
func (c *Cryptosystem) EncryptWith(plaintext *big.Int, us [][]int64) (phe.Value, error) {
	d := c.d
	if len(us) != 2*ell {
		return nil, fmt.Errorf("gentrysahaiwaters: random key must have %d polynomials", 2*ell)
	}
	m := uint64(plaintext.Bit(0))
	c.aOnce.Do(func() { c.a = expand(c.keys.PublicKey.Seed, d) })

	rows := make([]row, 2*ell)
	for i, u := range us {
		if len(u) != d {
			return nil, fmt.Errorf("gentrysahaiwaters: random polynomials must have %d coefficients", d)
		}
		e1, err := sampleSmall(d)
		if err != nil {
			return nil, err
		}
		e2, err := sampleSmall(d)
		if err != nil {
			return nil, err
		}
		c0 := polyMul(c.keys.PublicKey.B, u)
		c1 := polyMul(c.a, u)
		for k := 0; k < d; k++ {
			c0[k] = (c0[k] + uint64(e1[k])) & qMask
			c1[k] = (c1[k] + uint64(e2[k])) & qMask
		}

		// first ell rows carry m g_i in c0, and last ell rows carry it in c1
		if i < ell {
			c0[0] = (c0[0] + m*gadget(i)) & qMask
		} else {
			c1[0] = (c1[0] + m*gadget(i-ell)) & qMask
		}
		rows[i] = row{c0, c1}
	}
	return toValue(rows), nil
}

// Decrypt implements phe.Homomorphic.
func (c *Cryptosystem) Decrypt(ciphertext phe.Value) (*big.Int, error) {
	if !c.hasSecret {
		return nil, phe.ErrMissingPrivateKey
	}
	rows, err := c.rows(ciphertext)
	if err != nil {
		return nil, err
	}

	// phase of the last row of the first half is m q / 2 + noise
	r := rows[ell-1]
	phase := (r[0][0] + constantTerm(r[1], c.keys.PrivateKey.S)) & qMask
	if q/4 <= phase && phase < q-q/4 {
		return big.NewInt(1), nil
	}
	return new(big.Int), nil
}

// Multiply implements phe.Homomorphic. Multiplication of bits is their and.
func (c *Cryptosystem) Multiply(a, b phe.Value) (phe.Value, error) { return c.And(a, b) }

// And implements phe.Homomorphic. Noise of the result is the noise of b times
// small digits plus the noise of a, so keep b fresh in long chains, e.g.
// acc = acc & fresh.
func (c *Cryptosystem) And(a, b phe.Value) (phe.Value, error) {
	first, err := c.rows(a)
	if err != nil {
		return nil, err
	}
	second, err := c.rows(b)
	if err != nil {
		return nil, err
	}

	// each row of a is decomposed into 2 ell small digit polynomials, and the
	// row of the result is their weighted sum of rows of b. Its phase is
	// G^-1(a) times the noise of b plus m2 times the phase of a, so it
	// encrypts m1 m2.
	out := make([]row, len(first))
	var wg sync.WaitGroup
	wg.Add(len(first))
	for i := range first {
		go func(i int) {
			defer wg.Done()
			digits := append(decompose(first[i][0]), decompose(first[i][1])...)
			var result row
			for column := 0; column < 2; column++ {
				acc := make([]uint64, c.d)
				for k, digit := range digits {
					for j, x := range polyMul(second[k][column], digit) {
						acc[j] += x
					}
				}
				for j := range acc {
					acc[j] &= qMask
				}
				result[column] = acc
			}
			out[i] = result
		}(i)
	}
	wg.Wait()
	return toValue(out), nil
}

// Xor implements phe.Homomorphic. Sum of ciphertexts encrypts m1 + m2, and
// decryption restores its parity. Noise of the result is the sum of noises of
// the ciphertexts.
func (c *Cryptosystem) Xor(a, b phe.Value) (phe.Value, error) {
	first, err := c.rows(a)
	if err != nil {
		return nil, err
	}
	second, err := c.rows(b)
	if err != nil {
		return nil, err
	}
	out := make([]row, len(first))
	for i := range first {
		for column := 0; column < 2; column++ {
			sum := make([]uint64, c.d)
			for j := range sum {
				sum[j] = (first[i][column][j] + second[i][column][j]) & qMask
			}
			out[i][column] = sum
		}
	}
	return toValue(out), nil
}

// Reencrypt implements phe.Homomorphic by combining the ciphertext with an
// encryption of zero.
func (c *Cryptosystem) Reencrypt(ciphertext phe.Value) (phe.Value, error) {
	zero, err := c.Encrypt(new(big.Int))
	if err != nil {
		return nil, err
	}
	return c.Xor(ciphertext, zero)
}

// rows converts a ciphertext into its 2 ell rows.
func (c *Cryptosystem) rows(v phe.Value) ([]row, error) {
	t, err := phe.AsTuple(v)
	if err != nil {
		return nil, err
	}
	if t.Len() != 2*ell {
		return nil, phe.InvalidCiphertextf("gentrysahaiwaters: ciphertext must have %d rows, got %d", 2*ell, t.Len())
	}
	out := make([]row, t.Len())
	for i, item := range t.Items {
		pair, err := phe.AsTuple(item)
		if err != nil {
			return nil, err
		}
		if pair.Len() != 2 {
			return nil, phe.InvalidCiphertextf("gentrysahaiwaters: rows must be pairs of polynomials")
		}
		for column, polyValue := range pair.Items {
			poly, err := phe.AsTuple(polyValue)
			if err != nil {
				return nil, err
			}
			coefficients, err := poly.Ints()
			if err != nil {
				return nil, err
			}
			if len(coefficients) != c.d {
				return nil, phe.InvalidCiphertextf("gentrysahaiwaters: polynomials must have %d coefficients, got %d",
					c.d, len(coefficients))
			}
			out[i][column] = make([]uint64, c.d)
			for j, x := range coefficients {
				if x.Sign() < 0 || x.BitLen() > LogQ {
					return nil, phe.InvalidCiphertextf("gentrysahaiwaters: coefficients must be in [0, q)")
				}
				out[i][column][j] = x.Uint64()
			}
		}
	}
	return out, nil
}

func toValue(rows []row) phe.Value {
	items := make([]phe.Value, len(rows))
	for i, r := range rows {
		pair := make([]phe.Value, 2)
		for column, poly := range r {
			coefficients := make([]phe.Value, len(poly))
			for j, x := range poly {
				coefficients[j] = phe.Int{V: new(big.Int).SetUint64(x)}
			}
			pair[column] = phe.Tuple{Items: coefficients}
		}
		items[i] = phe.Tuple{Items: pair}
	}
	return phe.Tuple{Items: items}
}

// gadget is the entry 2^offset B^index of the approximate gadget.
func gadget(index int) uint64 { return uint64(1) << uint(offset+logB*index) }

// decompose decomposes a polynomial into ell polynomials of signed digits in
// [-B / 2, B / 2), so that the sum of digits_i gadget_i is the polynomial up
// to a rounding error less than 2^offset in each coefficient.
func decompose(poly []uint64) [][]int64 {
	const base = int64(1) << logB
	const halfB = base >> 1
	digits := make([][]int64, ell)
	for j := range digits {
		digits[j] = make([]int64, len(poly))
	}
	for i, coefficient := range poly {
		// centered representative, rounded to a multiple of 2^offset
		x := int64(coefficient)
		if coefficient >= q>>1 {
			x -= int64(q)
		}
		x = (x + 1<<(offset-1)) >> offset
		for j := 0; j < ell; j++ {
			digit := x & (base - 1)
			if digit >= halfB {
				digit -= base
			}
			digits[j][i] = digit
			x = (x - digit) >> logB
		}
	}
	return digits
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
		return nil, fmt.Errorf("gentrysahaiwaters: reading randomness: %w", err)
	}
	mask := uint64(1)<<eta - 1
	out := make([]int64, size)
	for i := range out {
		x := binary.LittleEndian.Uint64(buf[8*i:])
		out[i] = int64(bits.OnesCount64(x&mask)) - int64(bits.OnesCount64((x>>eta)&mask))
	}
	return out, nil
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
