// Package mlkem implements the public key encryption inside ML-KEM, which is
// homomorphic with respect to the exclusive or of 256-bit messages like
// Goldwasser-Micali, but quantum resistant. It uses the parameter sets
// standardized by NIST in FIPS 203: ML-KEM-512, ML-KEM-768 and ML-KEM-1024.
// Its security relies on the module learning with errors (Module-LWE)
// problem.
//
// ML-KEM is a key encapsulation mechanism built on a public key encryption
// scheme K-PKE. This is K-PKE, which works in modules of rank k over the ring
// R_q = Z_q[x] / (x^256 + 1).
//   - private key: vector s of k polynomials with small coefficients
//   - public key: k x k matrix A of polynomials and t = A s + e, where e is
//     small
//   - encryption of 256 message bits m_i: u = A^T r + e1, and
//     v = t^T r + e2 + m q / 2 where m q / 2 is the polynomial whose i-th
//     coefficient is m_i round(q / 2)
//   - decryption: v - s^T u = m q / 2 + noise, so m_i is 1 if the i-th
//     coefficient is closer to q / 2 than to 0
//   - exclusive or: adding ciphertexts adds the bits modulo 2
//
// A is expanded from a public seed with SHAKE-128, so the public key is the
// seed and t.
//
// This is not a FIPS 203 compliant implementation of ML-KEM:
//   - It is the CPA secure K-PKE, without the Fujisaki-Okamoto transform of
//     ML-KEM that makes it CCA secure, because a CCA secure scheme cannot be
//     homomorphic.
//   - Ciphertexts are not compressed, because compression adds rounding noise
//     that leaves no room for homomorphic operations. Security of K-PKE does
//     not depend on compression, which only drops information from
//     ciphertexts.
//   - Byte encodings, the sampling of A and the NTT representation are not the
//     ones in FIPS 203, so its keys and ciphertexts are not interoperable with
//     other ML-KEM libraries.
//   - It is not validated by NIST under FIPS 140-3.
//
// It uses the standardized parameters q, n, k, eta1 and eta2 only.
//
// The key size is the parameter set: 512, 768 or 1024. Default is 768, i.e.
// ML-KEM-768, which NIST categorizes as at least as hard to break as AES-192.
//
// Every ciphertext has noise, and exclusive or adds the noises of ciphertexts.
// Decryption returns a wrong result without any error when the noise exceeds
// q / 4. Fresh ciphertexts practically never fail, but q is small, so only a
// few ciphertexts can be combined. Failure probability of decrypting the
// exclusive or of c ciphertexts of ML-KEM-768 is about 2^-77 for c = 4, 2^-50
// for c = 6, and 2^-36 for c = 8. Regenerating a ciphertext counts as
// combining it with one more ciphertext. Ciphertexts have k + 1 polynomials of
// 256 coefficients of 12 bits, about 1.5 KB for ML-KEM-768. Floats and tensors
// are not supported.
//
// Reference: National Institute of Standards and Technology (2024).
// Module-Lattice-Based Key-Encapsulation Mechanism Standard. FIPS 203.
//
// Reference: Bos, J. et al. (2018). CRYSTALS - Kyber: a CCA-secure
// module-lattice-based KEM. IEEE EuroS&P 2018.
package mlkem

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"math/big"
	"math/bits"
	"sync"

	"github.com/serengil/lightphe-go/lightphe/internal/shake"
	"github.com/serengil/lightphe-go/lightphe/phe"
)

// DefaultKeySize is the parameter set used when none is requested.
const DefaultKeySize = 768

// Q and N are the parameters of FIPS 203: the ring Z_q[x] / (x^N + 1).
const (
	Q = 3329
	N = 256
)

// halfQ is round(q / 2), which bits of a message are encoded as.
const halfQ = (Q + 1) / 2

// parameterSet is a parameter set of FIPS 203: module rank k, and parameters
// of centered binomial distributions for secret and error vectors (eta1) and
// errors of encryption (eta2).
type parameterSet struct {
	k, eta1, eta2 int
}

var parameterSets = map[int64]parameterSet{
	512:  {k: 2, eta1: 3, eta2: 2},
	768:  {k: 3, eta1: 2, eta2: 2},
	1024: {k: 4, eta1: 2, eta2: 2},
}

// ErrFloatNotSupported reports a float plaintext, constant or tensor.
var ErrFloatNotSupported = phe.FloatNotSupported("lightphe: ML-KEM does not support float values or tensors, " +
	"because it is homomorphic with respect to the exclusive or of 256-bit messages. Use integers instead")

// PublicKey is the public key of ML-KEM's K-PKE: the parameter set, the seed
// of the matrix A and the vector t = A s + e of k polynomials.
type PublicKey struct {
	ParameterSet *big.Int  `json:"parameter_set"`
	Seed         *big.Int  `json:"seed"`
	T            [][]int64 `json:"t"`
}

// PrivateKey is the secret vector s of k polynomials with small coefficients.
type PrivateKey struct {
	S [][]int64 `json:"s"`
}

// Keys bundles the key pair. PrivateKey is nil for encryption-only setups.
type Keys struct {
	PublicKey  *PublicKey  `json:"public_key,omitempty"`
	PrivateKey *PrivateKey `json:"private_key,omitempty"`
}

// Validate reports missing or malformed key material.
func (k Keys) Validate() error {
	if k.PublicKey == nil {
		return phe.RequireSection(phe.MLKEM, phe.SectionPublic)
	}
	pk := k.PublicKey
	if err := phe.RequireFields(phe.MLKEM, phe.SectionPublic,
		phe.Field("parameter_set", pk.ParameterSet != nil),
		phe.Field("seed", pk.Seed != nil),
		phe.Field("t", pk.T != nil),
	); err != nil {
		return err
	}
	if k.PrivateKey != nil {
		if err := phe.RequireFields(phe.MLKEM, phe.SectionPrivate,
			phe.Field("s", k.PrivateKey.S != nil),
		); err != nil {
			return err
		}
	}

	params, ok := parameterSets[pk.ParameterSet.Int64()]
	if !pk.ParameterSet.IsInt64() || !ok {
		return phe.InvalidKeysf("mlkem: parameter set must be 512, 768 or 1024, got %s", pk.ParameterSet)
	}
	if pk.Seed.Sign() < 0 || pk.Seed.BitLen() > 256 {
		return phe.InvalidKeysf("mlkem: seed must be a 256-bit integer")
	}
	if !isVector(pk.T, params.k, 0, Q-1) {
		return phe.InvalidKeysf("mlkem: t must have %d polynomials of %d coefficients in [0, q)", params.k, N)
	}
	if k.PrivateKey != nil && !isVector(k.PrivateKey.S, params.k, -int64(params.eta1), int64(params.eta1)) {
		return phe.InvalidKeysf("mlkem: s must have %d polynomials of %d small coefficients", params.k, N)
	}
	return nil
}

// isVector reports whether v has k polynomials of N coefficients in [lo, hi].
func isVector(v [][]int64, k int, lo, hi int64) bool {
	if len(v) != k {
		return false
	}
	for _, poly := range v {
		if len(poly) != N {
			return false
		}
		for _, x := range poly {
			if x < lo || x > hi {
				return false
			}
		}
	}
	return true
}

// Cryptosystem is a configured ML-KEM instance. It is immutable and safe for
// concurrent use.
type Cryptosystem struct {
	phe.Base

	keys      Keys
	params    parameterSet
	hasSecret bool

	// A expanded from the seed when needed, a[i][j] is the entry at row i and
	// column j
	aOnce sync.Once
	a     [][][]int64
}

var (
	_ phe.Homomorphic   = (*Cryptosystem)(nil)
	_ phe.FloatRejecter = (*Cryptosystem)(nil)
)

// Generate creates a fresh key pair for the parameter set keySize: 512, 768
// or 1024.
func Generate(keySize int) (*Cryptosystem, error) {
	if keySize <= 0 {
		keySize = DefaultKeySize
	}
	params, ok := parameterSets[int64(keySize)]
	if !ok {
		return nil, fmt.Errorf("mlkem: key size %d must be one of the parameter sets of ML-KEM: 512, 768 or 1024: %w",
			keySize, phe.ErrKeyGeneration)
	}

	seedBytes := make([]byte, 32)
	if _, err := rand.Read(seedBytes); err != nil {
		return nil, fmt.Errorf("mlkem: reading randomness: %w", err)
	}
	seed := new(big.Int).SetBytes(seedBytes)
	a := expand(seed, params.k)
	s, err := sampleVector(params.k, params.eta1)
	if err != nil {
		return nil, err
	}
	e, err := sampleVector(params.k, params.eta1)
	if err != nil {
		return nil, err
	}

	// t = A s + e
	t := make([][]int64, params.k)
	for i := range t {
		row := make([][]int64, params.k)
		for j := range row {
			row[j] = a[i][j]
		}
		t[i] = addPoly(dot(row, s), e[i])
	}

	c, err := New(Keys{
		PublicKey:  &PublicKey{ParameterSet: big.NewInt(int64(keySize)), Seed: seed, T: t},
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
		Base:      phe.Base{Alg: phe.MLKEM},
		keys:      keys,
		params:    parameterSets[keys.PublicKey.ParameterSet.Int64()],
		hasSecret: keys.PrivateKey != nil,
	}, nil
}

// FromJSON rebuilds a cryptosystem from exported key material.
func FromJSON(data []byte) (*Cryptosystem, error) {
	var keys Keys
	if err := json.Unmarshal(data, &keys); err != nil {
		return nil, phe.InvalidKeysf("mlkem: decoding keys: %v", err)
	}
	return New(keys)
}

// Keys returns a copy of the key material.
func (c *Cryptosystem) Keys() Keys { return c.keys }

// PlaintextModulo implements phe.Homomorphic. Messages are 256-bit integers.
func (c *Cryptosystem) PlaintextModulo() *big.Int { return new(big.Int).Lsh(big.NewInt(1), N) }

// CiphertextModulo implements phe.Homomorphic.
func (c *Cryptosystem) CiphertextModulo() *big.Int { return big.NewInt(Q) }

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
	r, err := sampleVector(c.params.k, c.params.eta1)
	if err != nil {
		return nil, err
	}
	return c.EncryptWith(plaintext, r)
}

// EncryptWith encrypts using a caller supplied random vector r of k
// polynomials with small coefficients.
func (c *Cryptosystem) EncryptWith(plaintext *big.Int, r [][]int64) (phe.Value, error) {
	k := c.params.k
	if !isVector(r, k, -int64(c.params.eta1), int64(c.params.eta1)) {
		return nil, fmt.Errorf("mlkem: random key must have %d polynomials of %d small coefficients", k, N)
	}
	m := new(big.Int).Mod(plaintext, c.PlaintextModulo())
	c.aOnce.Do(func() { c.a = expand(c.keys.PublicKey.Seed, k) })

	e1, err := sampleVector(k, c.params.eta2)
	if err != nil {
		return nil, err
	}
	e2, err := sampleVector(1, c.params.eta2)
	if err != nil {
		return nil, err
	}

	// u = A^T r + e1
	polys := make([][]int64, k+1)
	for i := 0; i < k; i++ {
		column := make([][]int64, k)
		for j := range column {
			column[j] = c.a[j][i]
		}
		polys[i] = addPoly(dot(column, r), e1[i])
	}

	// v = t^T r + e2 + m q / 2
	v := addPoly(dot(c.keys.PublicKey.T, r), e2[0])
	for x := range v {
		if m.Bit(x) == 1 {
			v[x] = (v[x] + halfQ) % Q
		}
	}
	polys[k] = v
	return toValue(polys), nil
}

// Decrypt implements phe.Homomorphic.
func (c *Cryptosystem) Decrypt(ciphertext phe.Value) (*big.Int, error) {
	if !c.hasSecret {
		return nil, phe.ErrMissingPrivateKey
	}
	polys, err := c.polys(ciphertext)
	if err != nil {
		return nil, err
	}
	k := c.params.k

	// v - s^T u = m q / 2 + noise
	su := dot(polys[:k], c.keys.PrivateKey.S)
	plaintext := new(big.Int)
	for x := 0; x < N; x++ {
		w := ((polys[k][x]-su[x])%Q + Q) % Q
		// bit is 1 if w is closer to q / 2 than to 0
		if Q/4 < w && w < Q-Q/4 {
			plaintext.SetBit(plaintext, x, 1)
		}
	}
	return plaintext, nil
}

// Xor implements phe.Homomorphic. Noise of the result is the sum of noises of
// the ciphertexts. Bits are added modulo 2, as 2 round(q / 2) = q + 1 is close
// to 0 modulo q.
func (c *Cryptosystem) Xor(a, b phe.Value) (phe.Value, error) {
	x, err := c.polys(a)
	if err != nil {
		return nil, err
	}
	y, err := c.polys(b)
	if err != nil {
		return nil, err
	}
	out := make([][]int64, len(x))
	for i := range x {
		out[i] = addPoly(x[i], y[i])
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

// polys converts a ciphertext into its k + 1 polynomials.
func (c *Cryptosystem) polys(v phe.Value) ([][]int64, error) {
	t, err := phe.AsTuple(v)
	if err != nil {
		return nil, err
	}
	if t.Len() != c.params.k+1 {
		return nil, phe.InvalidCiphertextf("mlkem: ciphertext must have %d polynomials, got %d", c.params.k+1, t.Len())
	}
	out := make([][]int64, t.Len())
	for i, item := range t.Items {
		poly, err := phe.AsTuple(item)
		if err != nil {
			return nil, err
		}
		coefficients, err := poly.Ints()
		if err != nil {
			return nil, err
		}
		if len(coefficients) != N {
			return nil, phe.InvalidCiphertextf("mlkem: polynomials must have %d coefficients, got %d", N, len(coefficients))
		}
		out[i] = make([]int64, N)
		for j, x := range coefficients {
			if x.Sign() < 0 || x.Cmp(big.NewInt(Q)) >= 0 {
				return nil, phe.InvalidCiphertextf("mlkem: coefficients must be in [0, q)")
			}
			out[i][j] = x.Int64()
		}
	}
	return out, nil
}

func toValue(polys [][]int64) phe.Value {
	items := make([]phe.Value, len(polys))
	for i, poly := range polys {
		coefficients := make([]phe.Value, len(poly))
		for j, x := range poly {
			coefficients[j] = phe.Int{V: big.NewInt(x)}
		}
		items[i] = phe.Tuple{Items: coefficients}
	}
	return phe.Tuple{Items: items}
}

// polyMul multiplies two polynomials in Z_q[x] / (x^256 + 1). Small
// coefficients may be negative, and the product has coefficients in [0, q).
func polyMul(p1, p2 []int64) []int64 {
	var acc [N]int64
	for i, x := range p1 {
		if x == 0 {
			continue
		}
		// x^256 = -1
		for j := 0; j < N-i; j++ {
			acc[i+j] += x * p2[j]
		}
		for j := N - i; j < N; j++ {
			acc[i+j-N] -= x * p2[j]
		}
	}
	out := make([]int64, N)
	for i, x := range acc {
		out[i] = (x%Q + Q) % Q
	}
	return out
}

// dot returns the sum of products of polynomials of two vectors.
func dot(v1, v2 [][]int64) []int64 {
	out := make([]int64, N)
	for i := range v1 {
		out = addPoly(out, polyMul(v1[i], v2[i]))
	}
	return out
}

// addPoly adds two polynomials modulo q.
func addPoly(p1, p2 []int64) []int64 {
	out := make([]int64, N)
	for i := range out {
		out[i] = ((p1[i]+p2[i])%Q + Q) % Q
	}
	return out
}

// sampleVector samples k polynomials from the centered binomial distribution
// with parameter eta with cryptographically secure randomness.
func sampleVector(k, eta int) ([][]int64, error) {
	buf := make([]byte, k*N)
	if _, err := rand.Read(buf); err != nil {
		return nil, fmt.Errorf("mlkem: reading randomness: %w", err)
	}
	mask := uint(1)<<uint(eta) - 1
	out := make([][]int64, k)
	for i := range out {
		out[i] = make([]int64, N)
		for j := range out[i] {
			x := uint(buf[i*N+j])
			out[i][j] = int64(bits.OnesCount(x&mask)) - int64(bits.OnesCount((x>>uint(eta))&mask))
		}
	}
	return out, nil
}

// expand expands the public matrix A from its seed with SHAKE-128. Every 3
// bytes give two 12-bit values, which are accepted if they are less than q,
// so coefficients are uniform in [0, q). Entry (i, j) has its own stream of
// the seed followed by bytes j and i.
func expand(seed *big.Int, k int) [][][]int64 {
	seedBytes := make([]byte, 32)
	seed.FillBytes(seedBytes)

	a := make([][][]int64, k)
	for i := range a {
		a[i] = make([][]int64, k)
		for j := range a[i] {
			input := append(append([]byte{}, seedBytes...), byte(j), byte(i))
			coefficients := make([]int64, 0, N)
			for length := 3 * N; len(coefficients) < N; length *= 2 {
				stream := shake.Sum128(input, length)
				coefficients = coefficients[:0]
				for x := 0; x+2 < length && len(coefficients) < N; x += 3 {
					d1 := int64(stream[x]) | int64(stream[x+1]&0x0F)<<8
					d2 := int64(stream[x+1]>>4) | int64(stream[x+2])<<4
					for _, d := range []int64{d1, d2} {
						if d < Q && len(coefficients) < N {
							coefficients = append(coefficients, d)
						}
					}
				}
			}
			a[i][j] = coefficients
		}
	}
	return a
}
