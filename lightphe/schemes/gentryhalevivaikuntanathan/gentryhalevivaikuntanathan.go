// Package gentryhalevivaikuntanathan implements the Gentry-Halevi-
// Vaikuntanathan cryptosystem, which is homomorphic with respect to addition
// and supports one multiplication of ciphertexts like Boneh-Goh-Nissim,
// without pairings. Its security relies on the learning with errors (LWE)
// problem.
//
// THIS IS FOR LEARNING PURPOSES ONLY, AND IT IS NOT SECURE. Ciphertexts are
// m x m matrices where m grows with n log q, so secure parameters would need
// ciphertexts of terabytes. Here, the lattice dimension n is between 2 and 8,
// which offers no security at all. Use Brakerski-Vaikuntanathan for a
// practical and quantum resistant alternative.
//
// Matrices are over Z_q where q is a power of 2, and plaintexts are in Z_p for
// an odd prime p.
//   - private key: short m x m matrix T, which is full rank and satisfies
//     T A = 0 mod q. It is generated with the gadget trapdoor of
//     Micciancio-Peikert: A^T = [A_bar | G - A_bar R] where G is the gadget
//     matrix of powers of 2.
//   - public key: m x n matrix A
//   - encryption of m: C = A S + p X + m I mod q for uniformly random S and
//     small X
//   - decryption: T C T^T mod q = T (p X + m I) T^T, as T A = 0. When its
//     entries are small enough, it equals T (p X + m I) T^T over integers, so
//     reducing it modulo p and multiplying with T^-1 and T^-T modulo p restores
//     m I.
//   - multiplication: C1 C2^T, which is decrypted in the same way to m1 m2 I,
//     as T (A S1 + Z1)(A S2 + Z2)^T T^T = T Z1 Z2^T T^T
//
// The original scheme encrypts m x m matrices of plaintexts. Here, a single
// plaintext is encrypted as the scalar matrix m I.
//
// Noise grows with homomorphic operations, and decryption returns a wrong
// result without any error when it exceeds q / 2. q is chosen to leave room
// for multiplying a product with constants up to a few thousands, or for
// adding thousands of products.
//
// Reference: Gentry, C., Halevi, S., Vaikuntanathan, V. (2010). A Simple
// BGN-Type Cryptosystem from LWE. EUROCRYPT 2010.
//
// Reference: Micciancio, D., Peikert, C. (2012). Trapdoors for Lattices:
// Simpler, Tighter, Faster, Smaller. EUROCRYPT 2012.
package gentryhalevivaikuntanathan

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"math"
	"math/big"
	"math/bits"

	"github.com/serengil/lightphe-go/lightphe/internal/mathutil"
	"github.com/serengil/lightphe-go/lightphe/phe"
)

// Supported lattice dimensions. Ciphertexts are m x m matrices where m grows
// with n log q, so the dimension is limited.
const (
	MinKeySize     = 2
	MaxKeySize     = 8
	DefaultKeySize = 4
)

// DefaultPlaintextModulo is the default plaintext modulus p.
const DefaultPlaintextModulo = 101

// noiseMarginBits is the room for noise growth after a multiplication, i.e.
// for additions and constants.
const noiseMarginBits = 12

// eta parametrizes the centered binomial distribution errors are sampled from.
const eta = 2

// maxLogQ keeps every entry of a matrix within an uint64.
const maxLogQ = 62

// ciphertext levels
const (
	fresh      = 1
	multiplied = 2
)

// ErrFloatNotSupported reports a float plaintext, constant or tensor.
var ErrFloatNotSupported = phe.FloatNotSupported("lightphe: Gentry-Halevi-Vaikuntanathan does not support float " +
	"values or tensors, because they are scaled by powers of 10, which exceed its small plaintext space. " +
	"Use integers instead")

// ErrMultipliedTwice reports a multiplication involving an already multiplied
// ciphertext.
var ErrMultipliedTwice = fmt.Errorf("lightphe: Gentry-Halevi-Vaikuntanathan supports only one multiplication, "+
	"multiplied ciphertexts cannot be multiplied with ciphertexts again: %w", phe.ErrUnsupportedOperation)

// PublicKey is the Gentry-Halevi-Vaikuntanathan public key: the m x n matrix
// A and the moduli q and p.
type PublicKey struct {
	A [][]uint64 `json:"A"`
	Q *big.Int   `json:"q"`
	P *big.Int   `json:"p"`
}

// PrivateKey is the short trapdoor T, together with the first row of T^-1 mod
// p, which is enough to restore scalar matrices m I.
type PrivateKey struct {
	T [][]int64 `json:"T"`
	U []int64   `json:"u,omitempty"`
}

// Keys bundles the key pair. PrivateKey is nil for encryption-only setups.
type Keys struct {
	PublicKey  *PublicKey  `json:"public_key,omitempty"`
	PrivateKey *PrivateKey `json:"private_key,omitempty"`
}

// Validate reports missing or malformed key material.
func (k Keys) Validate() error {
	if k.PublicKey == nil {
		return phe.RequireSection(phe.GentryHaleviVaikuntanathan, phe.SectionPublic)
	}
	pk := k.PublicKey
	if err := phe.RequireFields(phe.GentryHaleviVaikuntanathan, phe.SectionPublic,
		phe.Field("A", pk.A != nil),
		phe.Field("q", pk.Q != nil),
		phe.Field("p", pk.P != nil),
	); err != nil {
		return err
	}
	if k.PrivateKey != nil {
		if err := phe.RequireFields(phe.GentryHaleviVaikuntanathan, phe.SectionPrivate,
			phe.Field("T", k.PrivateKey.T != nil),
		); err != nil {
			return err
		}
	}

	logQ := pk.Q.BitLen() - 1
	if pk.Q.Sign() <= 0 || new(big.Int).Lsh(big.NewInt(1), uint(logQ)).Cmp(pk.Q) != 0 || logQ > maxLogQ {
		return phe.InvalidKeysf("gentryhalevivaikuntanathan: q must be a power of 2 up to 2^%d", maxLogQ)
	}
	if !pk.P.IsInt64() || pk.P.Int64() < 3 || pk.P.Int64() > 1<<24 {
		return phe.InvalidKeysf("gentryhalevivaikuntanathan: p must be an odd prime up to 2^24")
	}
	m := len(pk.A)
	if m == 0 || len(pk.A[0]) == 0 {
		return phe.InvalidKeysf("gentryhalevivaikuntanathan: A must not be empty")
	}
	for _, row := range pk.A {
		if len(row) != len(pk.A[0]) {
			return phe.InvalidKeysf("gentryhalevivaikuntanathan: rows of A must have the same length")
		}
	}
	if sk := k.PrivateKey; sk != nil {
		if len(sk.T) != m {
			return phe.InvalidKeysf("gentryhalevivaikuntanathan: T must be a %d x %d matrix", m, m)
		}
		for _, row := range sk.T {
			if len(row) != m {
				return phe.InvalidKeysf("gentryhalevivaikuntanathan: T must be a %d x %d matrix", m, m)
			}
		}
		if sk.U != nil && len(sk.U) != m {
			return phe.InvalidKeysf("gentryhalevivaikuntanathan: u must have %d entries", m)
		}
	}
	return nil
}

// Cryptosystem is a configured Gentry-Halevi-Vaikuntanathan instance. It is
// immutable and safe for concurrent use.
type Cryptosystem struct {
	phe.Base

	keys      Keys
	m, n      int
	qMask     uint64
	p         int64
	u         []int64
	hasSecret bool
}

var (
	_ phe.Homomorphic   = (*Cryptosystem)(nil)
	_ phe.FloatRejecter = (*Cryptosystem)(nil)
)

// Generate creates a fresh key pair for the lattice dimension keySize in
// [2, 8]. The plaintext modulus p is the smallest prime greater than or equal
// to plaintextLimit, or 101 if it is nil.
func Generate(keySize int, plaintextLimit *big.Int) (*Cryptosystem, error) {
	n := keySize
	if n <= 0 {
		n = DefaultKeySize
	}
	if n < MinKeySize || n > MaxKeySize {
		return nil, fmt.Errorf("gentryhalevivaikuntanathan: key size %d is not supported, it is for learning purposes only "+
			"and its key size must be in [%d, %d]: %w", n, MinKeySize, MaxKeySize, phe.ErrKeyGeneration)
	}

	// T must be invertible modulo p, and det(T) is a power of 2
	p := int64(DefaultPlaintextModulo)
	if plaintextLimit != nil {
		limit := plaintextLimit.Int64()
		if !plaintextLimit.IsInt64() || limit > 1<<24 {
			return nil, fmt.Errorf("gentryhalevivaikuntanathan: plaintext limit %s is too large: %w", plaintextLimit, phe.ErrKeyGeneration)
		}
		if limit < 3 {
			limit = 3
		}
		p = mathutil.NextPrime(big.NewInt(limit - 1)).Int64()
	}

	mBar := 2 * n
	k := modulusBits(n, mBar, p)
	if k > maxLogQ {
		return nil, fmt.Errorf("gentryhalevivaikuntanathan: plaintext limit %d is too large: %w", p, phe.ErrKeyGeneration)
	}
	qMask := uint64(1)<<uint(k) - 1
	nk := n * k
	m := mBar + nk

	// A^T = [A_bar | G - A_bar R], where G = I_n (x) (1, 2, ..., 2^(k-1))
	aBar, err := randomMatrix(n, mBar, qMask)
	if err != nil {
		return nil, err
	}
	r := make([][]int64, mBar)
	ternary := make([]byte, mBar*nk)
	if _, err := rand.Read(ternary); err != nil {
		return nil, fmt.Errorf("gentryhalevivaikuntanathan: reading randomness: %w", err)
	}
	for i := range r {
		r[i] = make([]int64, nk)
		for j := range r[i] {
			// rejection keeps the ternary distribution uniform
			b := ternary[i*nk+j]
			for b >= 255 {
				one := make([]byte, 1)
				if _, err := rand.Read(one); err != nil {
					return nil, fmt.Errorf("gentryhalevivaikuntanathan: reading randomness: %w", err)
				}
				b = one[0]
			}
			r[i][j] = int64(b%3) - 1
		}
	}
	aTransposed := make([][]uint64, n)
	for i := 0; i < n; i++ {
		row := make([]uint64, m)
		copy(row, aBar[i])
		for col := 0; col < nk; col++ {
			var acc uint64
			for j := 0; j < mBar; j++ {
				acc += aBar[i][j] * uint64(r[j][col])
			}
			var gadget uint64
			if col/k == i {
				gadget = uint64(1) << uint(col%k)
			}
			row[mBar+col] = (gadget - acc) & qMask
		}
		aTransposed[i] = row
	}

	// W is the bit decomposition of -A_bar, so that G W = -A_bar mod q
	w := make([][]int64, nk)
	for i := range w {
		w[i] = make([]int64, mBar)
	}
	for j := 0; j < mBar; j++ {
		for i := 0; i < n; i++ {
			value := (-aBar[i][j]) & qMask
			for bit := 0; bit < k; bit++ {
				w[i*k+bit][j] = int64((value >> uint(bit)) & 1)
			}
		}
	}

	// S_G = I_n (x) S_k, whose columns 2 e_i - e_(i+1) and 2 e_k are
	// orthogonal to the gadget
	sG := make([][]int64, nk)
	for i := range sG {
		sG[i] = make([]int64, nk)
	}
	for block := 0; block < n; block++ {
		for i := 0; i < k; i++ {
			sG[block*k+i][block*k+i] = 2
			if i+1 < k {
				sG[block*k+i+1][block*k+i] = -1
			}
		}
	}

	// S = [[I + R W, R S_G], [W, S_G]] is a short basis with A^T S = 0 mod q
	rW := matmulInt(r, w)
	rSG := matmulInt(r, sG)
	s := make([][]int64, 0, m)
	for i := 0; i < mBar; i++ {
		row := make([]int64, 0, m)
		for j := 0; j < mBar; j++ {
			var identity int64
			if i == j {
				identity = 1
			}
			row = append(row, identity+rW[i][j])
		}
		s = append(s, append(row, rSG[i]...))
	}
	for i := 0; i < nk; i++ {
		s = append(s, append(append([]int64{}, w[i]...), sG[i]...))
	}

	t := make([][]int64, m)
	for i := range t {
		t[i] = make([]int64, m)
		for j := range t[i] {
			t[i][j] = s[j][i]
		}
	}
	a := make([][]uint64, m)
	for i := range a {
		a[i] = make([]uint64, n)
		for j := range a[i] {
			a[i][j] = aTransposed[j][i]
		}
	}
	u, err := firstRowOfInverse(t, p)
	if err != nil {
		return nil, err
	}

	return New(Keys{
		PublicKey: &PublicKey{
			A: a,
			Q: new(big.Int).Lsh(big.NewInt(1), uint(k)),
			P: big.NewInt(p),
		},
		PrivateKey: &PrivateKey{T: t, U: u},
	})
}

// New builds a cryptosystem around an existing key pair.
func New(keys Keys) (*Cryptosystem, error) {
	if err := keys.Validate(); err != nil {
		return nil, err
	}
	pk := keys.PublicKey
	c := &Cryptosystem{
		Base:      phe.Base{Alg: phe.GentryHaleviVaikuntanathan},
		keys:      keys,
		m:         len(pk.A),
		n:         len(pk.A[0]),
		qMask:     new(big.Int).Sub(pk.Q, big.NewInt(1)).Uint64(),
		p:         pk.P.Int64(),
		hasSecret: keys.PrivateKey != nil,
	}
	if sk := keys.PrivateKey; sk != nil {
		c.u = sk.U
		if c.u == nil {
			u, err := firstRowOfInverse(sk.T, c.p)
			if err != nil {
				return nil, err
			}
			c.u = u
		}
	}
	return c, nil
}

// FromJSON rebuilds a cryptosystem from exported key material.
func FromJSON(data []byte) (*Cryptosystem, error) {
	var keys Keys
	if err := json.Unmarshal(data, &keys); err != nil {
		return nil, phe.InvalidKeysf("gentryhalevivaikuntanathan: decoding keys: %v", err)
	}
	return New(keys)
}

// Keys returns a copy of the key material.
func (c *Cryptosystem) Keys() Keys { return c.keys }

// PlaintextModulo implements phe.Homomorphic.
func (c *Cryptosystem) PlaintextModulo() *big.Int { return big.NewInt(c.p) }

// CiphertextModulo implements phe.Homomorphic.
func (c *Cryptosystem) CiphertextModulo() *big.Int { return new(big.Int).Set(c.keys.PublicKey.Q) }

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

// Encrypt implements phe.Homomorphic, producing C = A S + p X + m I mod q.
func (c *Cryptosystem) Encrypt(plaintext *big.Int) (phe.Value, error) {
	s, err := randomMatrix(c.n, c.m, c.qMask)
	if err != nil {
		return nil, err
	}
	return c.EncryptWith(plaintext, s)
}

// EncryptWith encrypts using a caller supplied uniformly random n x m matrix S.
func (c *Cryptosystem) EncryptWith(plaintext *big.Int, s [][]uint64) (phe.Value, error) {
	if len(s) != c.n {
		return nil, fmt.Errorf("gentryhalevivaikuntanathan: random key must be a %d x %d matrix", c.n, c.m)
	}
	m := uint64(new(big.Int).Mod(plaintext, big.NewInt(c.p)).Int64())
	noise, err := sampleSmall(c.m * c.m)
	if err != nil {
		return nil, err
	}
	a := c.keys.PublicKey.A
	matrix := make([][]uint64, c.m)
	for i := range matrix {
		row := make([]uint64, c.m)
		for j := range row {
			var acc uint64
			for l := 0; l < c.n; l++ {
				acc += a[i][l] * s[l][j]
			}
			acc += uint64(c.p) * uint64(noise[i*c.m+j])
			if i == j {
				acc += m
			}
			row[j] = acc & c.qMask
		}
		matrix[i] = row
	}
	return toValue(fresh, matrix), nil
}

// Decrypt implements phe.Homomorphic.
func (c *Cryptosystem) Decrypt(ciphertext phe.Value) (*big.Int, error) {
	if !c.hasSecret {
		return nil, phe.ErrMissingPrivateKey
	}
	_, matrix, err := c.parse(ciphertext)
	if err != nil {
		return nil, err
	}
	t := c.keys.PrivateKey.T

	// E = T C T^T mod q, centered, equals T (p X + B) T^T over integers
	tc := make([][]uint64, c.m)
	for i := range tc {
		row := make([]uint64, c.m)
		for l, tl := range t[i] {
			if tl == 0 {
				continue
			}
			factor := uint64(tl)
			for j, x := range matrix[l] {
				row[j] += factor * x
			}
		}
		tc[i] = row
	}
	half := (c.qMask + 1) / 2
	e := make([][]int64, c.m)
	for i := range e {
		e[i] = make([]int64, c.m)
		for j := range e[i] {
			var acc uint64
			for l, x := range tc[i] {
				acc += x * uint64(t[j][l])
			}
			acc &= c.qMask
			centered := int64(acc)
			if acc > half {
				centered = int64(acc) - int64(c.qMask+1)
			}
			// B = T^-1 E T^-T mod p, so entries are reduced modulo p first
			e[i][j] = mod(centered, c.p)
		}
	}

	// first diagonal entry of B is the message
	var result int64
	for j := 0; j < c.m; j++ {
		var column int64
		for i := 0; i < c.m; i++ {
			column = (column + c.u[i]%c.p*e[i][j]) % c.p
		}
		result = (result + column*(c.u[j]%c.p)) % c.p
	}
	return big.NewInt(mod(result, c.p)), nil
}

// Add implements phe.Homomorphic. Fresh and multiplied ciphertexts can be
// added, as they are decrypted in the same way.
func (c *Cryptosystem) Add(a, b phe.Value) (phe.Value, error) {
	level1, matrix1, err := c.parse(a)
	if err != nil {
		return nil, err
	}
	level2, matrix2, err := c.parse(b)
	if err != nil {
		return nil, err
	}
	out := make([][]uint64, c.m)
	for i := range out {
		out[i] = make([]uint64, c.m)
		for j := range out[i] {
			out[i][j] = (matrix1[i][j] + matrix2[i][j]) & c.qMask
		}
	}
	level := level1
	if level2 > level {
		level = level2
	}
	return toValue(level, out), nil
}

// Multiply implements phe.Homomorphic. It is the matrix product C1 C2^T.
func (c *Cryptosystem) Multiply(a, b phe.Value) (phe.Value, error) {
	level1, matrix1, err := c.parse(a)
	if err != nil {
		return nil, err
	}
	level2, matrix2, err := c.parse(b)
	if err != nil {
		return nil, err
	}
	if level1 != fresh || level2 != fresh {
		return nil, ErrMultipliedTwice
	}
	out := make([][]uint64, c.m)
	for i := range out {
		out[i] = make([]uint64, c.m)
		for j := range out[i] {
			var acc uint64
			for l, x := range matrix1[i] {
				acc += x * matrix2[j][l]
			}
			out[i][j] = acc & c.qMask
		}
	}
	return toValue(multiplied, out), nil
}

// MultiplyByConstant implements phe.Homomorphic. Noise of the result is the
// noise of the ciphertext times |constant|.
func (c *Cryptosystem) MultiplyByConstant(ciphertext phe.Value, constant *big.Int) (phe.Value, error) {
	level, matrix, err := c.parse(ciphertext)
	if err != nil {
		return nil, err
	}

	// centered representative keeps the noise small for negative constants
	k := new(big.Int).Mod(constant, big.NewInt(c.p)).Int64()
	if k > c.p/2 {
		k -= c.p
	}
	out := make([][]uint64, c.m)
	for i := range out {
		out[i] = make([]uint64, c.m)
		for j, x := range matrix[i] {
			out[i][j] = (x * uint64(k)) & c.qMask
		}
	}
	return toValue(level, out), nil
}

// Reencrypt implements phe.Homomorphic by adding an encryption of zero.
func (c *Cryptosystem) Reencrypt(ciphertext phe.Value) (phe.Value, error) {
	zero, err := c.Encrypt(new(big.Int))
	if err != nil {
		return nil, err
	}
	return c.Add(ciphertext, zero)
}

// parse converts a ciphertext into its level and matrix.
func (c *Cryptosystem) parse(v phe.Value) (int, [][]uint64, error) {
	levelValue, matrixValue, err := phe.AsPair(v)
	if err != nil {
		return 0, nil, err
	}
	level, err := phe.AsInt(levelValue)
	if err != nil {
		return 0, nil, err
	}
	if !level.IsInt64() || (level.Int64() != fresh && level.Int64() != multiplied) {
		return 0, nil, phe.InvalidCiphertextf("gentryhalevivaikuntanathan: unknown ciphertext level %s", level)
	}
	rows, err := phe.AsTuple(matrixValue)
	if err != nil {
		return 0, nil, err
	}
	if rows.Len() != c.m {
		return 0, nil, phe.InvalidCiphertextf("gentryhalevivaikuntanathan: ciphertext must be a %d x %d matrix", c.m, c.m)
	}
	matrix := make([][]uint64, c.m)
	for i, item := range rows.Items {
		row, err := phe.AsTuple(item)
		if err != nil {
			return 0, nil, err
		}
		entries, err := row.Ints()
		if err != nil {
			return 0, nil, err
		}
		if len(entries) != c.m {
			return 0, nil, phe.InvalidCiphertextf("gentryhalevivaikuntanathan: ciphertext must be a %d x %d matrix", c.m, c.m)
		}
		matrix[i] = make([]uint64, c.m)
		for j, x := range entries {
			if x.Sign() < 0 || x.BitLen() > maxLogQ {
				return 0, nil, phe.InvalidCiphertextf("gentryhalevivaikuntanathan: ciphertext entries must be in [0, q)")
			}
			matrix[i][j] = x.Uint64() & c.qMask
		}
	}
	return int(level.Int64()), matrix, nil
}

func toValue(level int, matrix [][]uint64) phe.Value {
	rows := make([]phe.Value, len(matrix))
	for i, row := range matrix {
		entries := make([]phe.Value, len(row))
		for j, x := range row {
			entries[j] = phe.Int{V: new(big.Int).SetUint64(x)}
		}
		rows[i] = phe.Tuple{Items: entries}
	}
	return phe.NewTuple(phe.Int{V: big.NewInt(int64(level))}, phe.Tuple{Items: rows})
}

// modulusBits finds the bits of q, so that the noise of a product stays below
// q / 2 with a margin. Noise of a product is about p^2 m^2 times a small
// factor, and m = m_bar + n log q, so it is found iteratively.
func modulusBits(n, mBar int, p int64) int {
	k := 32
	for {
		m := float64(mBar + n*k)
		required := int(math.Ceil(2*math.Log2(float64(p)) + 2*math.Log2(m) + 2 + noiseMarginBits))
		if required <= k {
			return k
		}
		k = required
	}
}

// randomMatrix returns a rows x columns matrix of uniform entries modulo q.
func randomMatrix(rows, columns int, qMask uint64) ([][]uint64, error) {
	buf := make([]byte, 8*rows*columns)
	if _, err := rand.Read(buf); err != nil {
		return nil, fmt.Errorf("gentryhalevivaikuntanathan: reading randomness: %w", err)
	}
	out := make([][]uint64, rows)
	for i := range out {
		out[i] = make([]uint64, columns)
		for j := range out[i] {
			out[i][j] = binary.LittleEndian.Uint64(buf[8*(i*columns+j):]) & qMask
		}
	}
	return out, nil
}

// sampleSmall samples from the centered binomial distribution with
// cryptographically secure randomness.
func sampleSmall(size int) ([]int64, error) {
	buf := make([]byte, size)
	if _, err := rand.Read(buf); err != nil {
		return nil, fmt.Errorf("gentryhalevivaikuntanathan: reading randomness: %w", err)
	}
	mask := byte(1)<<eta - 1
	out := make([]int64, size)
	for i, x := range buf {
		out[i] = int64(bits.OnesCount8(x&mask)) - int64(bits.OnesCount8((x>>eta)&mask))
	}
	return out, nil
}

// matmulInt is the matrix product of small integer matrices.
func matmulInt(left, right [][]int64) [][]int64 {
	out := make([][]int64, len(left))
	for i, row := range left {
		out[i] = make([]int64, len(right[0]))
		for l, x := range row {
			if x == 0 {
				continue
			}
			for j, y := range right[l] {
				out[i][j] += x * y
			}
		}
	}
	return out
}

// firstRowOfInverse returns the first row of the inverse of a matrix modulo
// prime p with Gauss-Jordan elimination.
func firstRowOfInverse(matrix [][]int64, p int64) ([]int64, error) {
	size := len(matrix)
	augmented := make([][]int64, size)
	for i, row := range matrix {
		augmented[i] = make([]int64, 2*size)
		for j, x := range row {
			augmented[i][j] = mod(x, p)
		}
		augmented[i][size+i] = 1
	}
	for column := 0; column < size; column++ {
		pivot := -1
		for row := column; row < size; row++ {
			if augmented[row][column] != 0 {
				pivot = row
				break
			}
		}
		if pivot < 0 {
			return nil, phe.InvalidKeysf("gentryhalevivaikuntanathan: T is not invertible modulo %d", p)
		}
		augmented[column], augmented[pivot] = augmented[pivot], augmented[column]
		inverse := new(big.Int).ModInverse(big.NewInt(augmented[column][column]), big.NewInt(p)).Int64()
		for j := range augmented[column] {
			augmented[column][j] = augmented[column][j] * inverse % p
		}
		for row := 0; row < size; row++ {
			factor := augmented[row][column]
			if row != column && factor != 0 {
				for j := range augmented[row] {
					augmented[row][j] = mod(augmented[row][j]-factor*augmented[column][j], p)
				}
			}
		}
	}
	return augmented[0][size:], nil
}

func mod(x, p int64) int64 {
	r := x % p
	if r < 0 {
		r += p
	}
	return r
}
