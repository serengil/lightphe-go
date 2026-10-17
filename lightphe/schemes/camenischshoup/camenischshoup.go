// Package camenischshoup implements the Camenisch-Shoup cryptosystem, which is
// homomorphic with respect to addition and supports multiplying a ciphertext
// by a known plain constant.
//
// It is designed for verifiable encryption of discrete logarithms. A prover
// encrypts a secret such as the private key of an elliptic curve public key for
// a trusted third party, and proves that the ciphertext really contains it
// without revealing it. Anyone having the public key of the trusted third party
// can verify the proof, and only the trusted third party can decrypt the
// ciphertext.
//
// Verifiable encryption has three steps run by three parties:
//   - EncryptVerifiably: prover (e.g. Alice) encrypts her secret and creates
//     the proof
//   - VerifyEncryption: verifier (e.g. a bank) checks the proof against the
//     public point it already knows, without learning the secret
//   - DecryptVerifiableCiphertext: trusted third party restores the secret
//
// Only the last step requires the private key.
//
// Ciphertexts for homomorphic operations are (u, e) pairs. Verifiable
// ciphertexts additionally have a validity tag v bound to a label, which makes
// them secure against chosen ciphertext attacks. Homomorphic operations drop
// that tag, as non-malleability and homomorphism contradict each other.
//
// The proof follows the paper with Fiat-Shamir heuristic. Its soundness relies
// on the auxiliary RSA modulus n_bar, whose factorization is discarded during
// key generation and must not be known by the prover. Hash inputs are formatted
// exactly as in the Python library, so proofs are interchangeable.
//
// Reference: Camenisch, J., Shoup, V. (2003). Practical Verifiable Encryption
// and Decryption of Discrete Logarithms. CRYPTO 2003.
package camenischshoup

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"math/big"
	"strings"
	"sync"

	"github.com/serengil/lightphe-go/lightphe/ecc"
	"github.com/serengil/lightphe-go/lightphe/ecc/curves"
	"github.com/serengil/lightphe-go/lightphe/internal/mathutil"
	"github.com/serengil/lightphe-go/lightphe/phe"
)

// Defaults used when the caller does not specify them.
const (
	DefaultKeySize  = 1024
	DefaultMaxTries = 10000
)

// ChallengeBits is the challenge length of the proof. Soundness error is
// 2^-ChallengeBits.
const ChallengeBits = 128

// StatisticalBits is the statistical zero-knowledge parameter of the proof.
const StatisticalBits = 80

// PublicKey is the Camenisch-Shoup public key. N_bar, G_bar and H_bar form the
// auxiliary group the proof commits to the secret in.
type PublicKey struct {
	N    *big.Int `json:"n"`
	G    *big.Int `json:"g"`
	Y1   *big.Int `json:"y1"`
	Y2   *big.Int `json:"y2"`
	Y3   *big.Int `json:"y3"`
	NBar *big.Int `json:"n_bar"`
	GBar *big.Int `json:"g_bar"`
	HBar *big.Int `json:"h_bar"`
}

// PrivateKey holds the three secret exponents.
type PrivateKey struct {
	X1 *big.Int `json:"x1"`
	X2 *big.Int `json:"x2"`
	X3 *big.Int `json:"x3"`
}

// Keys bundles the key pair. PrivateKey is nil for encryption-only setups.
type Keys struct {
	PublicKey  *PublicKey  `json:"public_key,omitempty"`
	PrivateKey *PrivateKey `json:"private_key,omitempty"`
}

// Validate reports missing or malformed key material.
func (k Keys) Validate() error {
	if k.PublicKey == nil {
		return phe.RequireSection(phe.CamenischShoup, phe.SectionPublic)
	}
	pk := k.PublicKey
	if err := phe.RequireFields(phe.CamenischShoup, phe.SectionPublic,
		phe.Field("n", pk.N != nil),
		phe.Field("g", pk.G != nil),
		phe.Field("y1", pk.Y1 != nil),
		phe.Field("y2", pk.Y2 != nil),
		phe.Field("y3", pk.Y3 != nil),
		phe.Field("n_bar", pk.NBar != nil),
		phe.Field("g_bar", pk.GBar != nil),
		phe.Field("h_bar", pk.HBar != nil),
	); err != nil {
		return err
	}
	if sk := k.PrivateKey; sk != nil {
		return phe.RequireFields(phe.CamenischShoup, phe.SectionPrivate,
			phe.Field("x1", sk.X1 != nil),
			phe.Field("x2", sk.X2 != nil),
			phe.Field("x3", sk.X3 != nil),
		)
	}
	return nil
}

// Cryptosystem is a configured Camenisch-Shoup instance. It is immutable and
// safe for concurrent use.
type Cryptosystem struct {
	phe.Base

	keys      Keys
	n         *big.Int
	nSquared  *big.Int
	form      string
	curve     string
	hasSecret bool

	// elliptic curve of the secrets, built lazily as homomorphic operations do
	// not need it
	eccOnce sync.Once
	ec      *ecc.ECC
	eccErr  error
}

var (
	_ phe.Homomorphic         = (*Cryptosystem)(nil)
	_ phe.VerifiableEncrypter = (*Cryptosystem)(nil)
)

// Generate creates a fresh key pair with a modulus of keySize bits. form and
// curve select the elliptic curve of the secrets to be encrypted verifiably;
// empty values default to secp256k1 in weierstrass form.
func Generate(keySize, maxTries int, form, curve string) (*Cryptosystem, error) {
	if keySize <= 0 {
		keySize = DefaultKeySize
	}
	if maxTries <= 0 {
		maxTries = DefaultMaxTries
	}
	if keySize < 16 {
		return nil, fmt.Errorf("camenischshoup: key size %d is too small: %w", keySize, phe.ErrKeyGeneration)
	}
	one := big.NewInt(1)
	two := big.NewInt(2)

	// n = pq where p = 2p' + 1 and q = 2q' + 1 are safe primes
	p, q, err := mathutil.RandDistinctSafePrimes(keySize/2, maxTries)
	if err != nil {
		return nil, fmt.Errorf("camenischshoup: %v: %w", err, phe.ErrKeyGeneration)
	}
	n := new(big.Int).Mul(p, q)
	nSquared := new(big.Int).Mul(n, n)
	pPrime := new(big.Int).Rsh(p, 1)
	qPrime := new(big.Int).Rsh(q, 1)

	// g is a 2n-th power in Z_{n^2}*, so its order divides p'q'
	twoN := new(big.Int).Lsh(n, 1)
	var g *big.Int
	for i := 0; i < maxTries; i++ {
		base, err := mathutil.RandRange(two, new(big.Int).Sub(nSquared, one))
		if err != nil {
			return nil, err
		}
		candidate := new(big.Int).Exp(base, twoN, nSquared)
		if new(big.Int).Exp(candidate, pPrime, nSquared).Cmp(one) != 0 &&
			new(big.Int).Exp(candidate, qPrime, nSquared).Cmp(one) != 0 {
			g = candidate
			break
		}
	}
	if g == nil {
		return nil, fmt.Errorf("camenischshoup: no suitable generator in %d tries: %w", maxTries, phe.ErrKeyGeneration)
	}

	quarter := new(big.Int).Rsh(nSquared, 2)
	xs := make([]*big.Int, 3)
	for i := range xs {
		if xs[i], err = mathutil.RandRange(one, quarter); err != nil {
			return nil, err
		}
	}

	// auxiliary RSA modulus for the proof. its factorization is discarded.
	pBar, qBar, err := mathutil.RandDistinctSafePrimes(keySize/2, maxTries)
	if err != nil {
		return nil, fmt.Errorf("camenischshoup: %v: %w", err, phe.ErrKeyGeneration)
	}
	nBar := new(big.Int).Mul(pBar, qBar)
	var hBar *big.Int
	for i := 0; i < maxTries; i++ {
		base, err := mathutil.RandRange(two, new(big.Int).Sub(nBar, one))
		if err != nil {
			return nil, err
		}
		candidate := new(big.Int).Exp(base, two, nBar)
		if new(big.Int).Mod(candidate, pBar).Cmp(one) != 0 && new(big.Int).Mod(candidate, qBar).Cmp(one) != 0 {
			hBar = candidate
			break
		}
	}
	if hBar == nil {
		return nil, fmt.Errorf("camenischshoup: no suitable generator in %d tries: %w", maxTries, phe.ErrKeyGeneration)
	}
	exponent, err := mathutil.RandRange(two, new(big.Int).Rsh(nBar, 2))
	if err != nil {
		return nil, err
	}
	gBar := new(big.Int).Exp(hBar, exponent, nBar)

	return New(Keys{
		PublicKey: &PublicKey{
			N:    n,
			G:    g,
			Y1:   new(big.Int).Exp(g, xs[0], nSquared),
			Y2:   new(big.Int).Exp(g, xs[1], nSquared),
			Y3:   new(big.Int).Exp(g, xs[2], nSquared),
			NBar: nBar,
			GBar: gBar,
			HBar: hBar,
		},
		PrivateKey: &PrivateKey{X1: xs[0], X2: xs[1], X3: xs[2]},
	}, form, curve)
}

// New builds a cryptosystem around an existing key pair. form and curve select
// the elliptic curve of the secrets to be encrypted verifiably.
func New(keys Keys, form, curve string) (*Cryptosystem, error) {
	if err := keys.Validate(); err != nil {
		return nil, err
	}
	n := new(big.Int).Set(keys.PublicKey.N)
	return &Cryptosystem{
		Base:      phe.Base{Alg: phe.CamenischShoup},
		keys:      keys,
		n:         n,
		nSquared:  new(big.Int).Mul(n, n),
		form:      form,
		curve:     curve,
		hasSecret: keys.PrivateKey != nil,
	}, nil
}

// FromJSON rebuilds a cryptosystem from exported key material.
func FromJSON(data []byte, form, curve string) (*Cryptosystem, error) {
	var keys Keys
	if err := json.Unmarshal(data, &keys); err != nil {
		return nil, phe.InvalidKeysf("camenischshoup: decoding keys: %v", err)
	}
	return New(keys, form, curve)
}

// Keys returns a copy of the key material.
func (c *Cryptosystem) Keys() Keys { return c.keys }

// ECC returns the elliptic curve of the secrets to be encrypted verifiably.
func (c *Cryptosystem) ECC() (*ecc.ECC, error) {
	c.eccOnce.Do(func() {
		c.ec, c.eccErr = ecc.New(curves.Form(c.form), c.curve)
	})
	return c.ec, c.eccErr
}

// PlaintextModulo implements phe.Homomorphic.
func (c *Cryptosystem) PlaintextModulo() *big.Int { return new(big.Int).Set(c.n) }

// CiphertextModulo implements phe.Homomorphic.
func (c *Cryptosystem) CiphertextModulo() *big.Int { return new(big.Int).Set(c.nSquared) }

// HasPrivateKey implements phe.Homomorphic.
func (c *Cryptosystem) HasPrivateKey() bool { return c.hasSecret }

// PublicOnly implements phe.Homomorphic.
func (c *Cryptosystem) PublicOnly() (phe.Homomorphic, error) {
	return New(Keys{PublicKey: c.keys.PublicKey}, c.form, c.curve)
}

// ExportKeys implements phe.Homomorphic.
func (c *Cryptosystem) ExportKeys(includePrivate bool) ([]byte, error) {
	keys := Keys{PublicKey: c.keys.PublicKey}
	if includePrivate {
		keys.PrivateKey = c.keys.PrivateKey
	}
	return json.Marshal(keys)
}

// randomKey draws the one-time random key of an encryption in [1, n / 4].
func (c *Cryptosystem) randomKey() (*big.Int, error) {
	upper := new(big.Int).Rsh(c.n, 2)
	if upper.Sign() == 0 {
		upper.SetInt64(1)
	}
	return mathutil.RandRange(big.NewInt(1), upper)
}

// Encrypt implements phe.Homomorphic, producing u = g^r mod n^2 and
// e = y1^r (1 + n)^m mod n^2.
func (c *Cryptosystem) Encrypt(plaintext *big.Int) (phe.Value, error) {
	r, err := c.randomKey()
	if err != nil {
		return nil, fmt.Errorf("camenischshoup: %w", err)
	}
	u, e := c.encrypt(plaintext, r)
	return phe.NewTuple(phe.Int{V: u}, phe.Int{V: e}), nil
}

func (c *Cryptosystem) encrypt(plaintext, r *big.Int) (*big.Int, *big.Int) {
	pk := c.keys.PublicKey
	m := new(big.Int).Mod(plaintext, c.n)
	u := new(big.Int).Exp(pk.G, r, c.nSquared)
	e := new(big.Int).Exp(pk.Y1, r, c.nSquared)
	m.Mul(m, c.n).Add(m, big.NewInt(1))
	e.Mul(e, m).Mod(e, c.nSquared)
	return u, e
}

// Decrypt implements phe.Homomorphic. Verifiable ciphertexts must be decrypted
// with their labels instead.
func (c *Cryptosystem) Decrypt(ciphertext phe.Value) (*big.Int, error) {
	if !c.hasSecret {
		return nil, phe.ErrMissingPrivateKey
	}
	t, err := phe.AsTuple(ciphertext)
	if err != nil {
		return nil, err
	}
	if t.Len() != 2 {
		return nil, phe.InvalidCiphertextf("camenischshoup: ciphertext must be a (u, e) pair, " +
			"decrypt verifiable ciphertexts with their labels")
	}
	items, err := t.Ints()
	if err != nil {
		return nil, err
	}
	return c.recover(items[0], items[1])
}

// EncryptWithLabel encrypts a plaintext secure against chosen ciphertext
// attacks. The ciphertext (u, e, v) can be decrypted with the same label only.
func (c *Cryptosystem) EncryptWithLabel(plaintext *big.Int, label string) ([]*big.Int, error) {
	r, err := c.randomKey()
	if err != nil {
		return nil, err
	}
	u, e, v := c.encryptWithLabel(plaintext, label, r)
	return []*big.Int{u, e, v}, nil
}

func (c *Cryptosystem) encryptWithLabel(plaintext *big.Int, label string, r *big.Int) (u, e, v *big.Int) {
	u, e = c.encrypt(plaintext, r)
	v = c.abs(new(big.Int).Exp(c.tagBase(u, e, label), r, c.nSquared))
	return u, e, v
}

// DecryptWithLabel decrypts a ciphertext created with EncryptWithLabel. It is
// rejected if it was modified or its label is different.
func (c *Cryptosystem) DecryptWithLabel(ciphertext []*big.Int, label string) (*big.Int, error) {
	if !c.hasSecret {
		return nil, phe.ErrMissingPrivateKey
	}
	if len(ciphertext) != 3 {
		return nil, phe.InvalidCiphertextf("camenischshoup: verifiable ciphertext must be a (u, e, v) triple")
	}
	u, e, v := ciphertext[0], ciphertext[1], ciphertext[2]
	if u == nil || e == nil || v == nil {
		return nil, phe.InvalidCiphertextf("camenischshoup: verifiable ciphertext must be a (u, e, v) triple")
	}
	sk := c.keys.PrivateKey

	tagExponent := new(big.Int).Mul(c.hashTag(u, e, label), sk.X3)
	tagExponent.Add(tagExponent, sk.X2).Lsh(tagExponent, 1)
	lhs, err := powMod(u, tagExponent, c.nSquared)
	if err != nil || v.Cmp(c.abs(v)) != 0 || lhs.Cmp(new(big.Int).Exp(v, big.NewInt(2), c.nSquared)) != 0 {
		return nil, phe.InvalidCiphertextf("camenischshoup: ciphertext is invalid or was encrypted with a different label")
	}
	return c.recover(u, e)
}

// EncryptVerifiably implements phe.VerifiableEncrypter. It encrypts the
// discrete logarithm of an elliptic curve point, e.g. a private key, for the
// owner of this cryptosystem and proves that the ciphertext contains it. It
// runs on prover side and requires the public key only.
func (c *Cryptosystem) EncryptVerifiably(secret *big.Int, label string) (*phe.VerifiableCiphertext, error) {
	ec, err := c.validateVerifiableEncryption()
	if err != nil {
		return nil, err
	}
	pk := c.keys.PublicKey
	order := ec.N()
	bound := new(big.Int).Lsh(big.NewInt(1), ChallengeBits+StatisticalBits)

	m := new(big.Int).Mod(secret, order)
	if m.Sign() == 0 {
		return nil, fmt.Errorf("camenischshoup: secret must not be a multiple of the order of the curve")
	}
	publicPoint, err := ec.G().ScalarMul(m)
	if err != nil {
		return nil, fmt.Errorf("camenischshoup: %w", err)
	}

	r, err := c.randomKey()
	if err != nil {
		return nil, err
	}
	u, e, v := c.encryptWithLabel(m, label, r)
	tagBase := c.tagBase(u, e, label)

	// commitment to the secret in auxiliary group
	s, err := mathutil.RandRange(big.NewInt(1), new(big.Int).Rsh(pk.NBar, 2))
	if err != nil {
		return nil, err
	}
	l := new(big.Int).Exp(pk.GBar, m, pk.NBar)
	l.Mul(l, new(big.Int).Exp(pk.HBar, s, pk.NBar)).Mod(l, pk.NBar)

	// random masks statistically hiding the secret, r and s
	rMask, err := randSymmetric(new(big.Int).Mul(new(big.Int).Rsh(c.n, 2), bound))
	if err != nil {
		return nil, err
	}
	sMask, err := randSymmetric(new(big.Int).Mul(new(big.Int).Rsh(pk.NBar, 2), bound))
	if err != nil {
		return nil, err
	}
	mMask, err := randSymmetric(new(big.Int).Mul(order, bound))
	if err != nil {
		return nil, err
	}

	two := big.NewInt(2)
	twoR := new(big.Int).Mul(two, rMask)
	onePlusN := new(big.Int).Add(c.n, big.NewInt(1))
	commitments := make([]string, 5)
	vals, err := c.powProducts([][2]*big.Int{{pk.G, twoR}}, [][2]*big.Int{{pk.Y1, twoR}, {onePlusN, new(big.Int).Mul(two, mMask)}},
		[][2]*big.Int{{tagBase, twoR}})
	if err != nil {
		return nil, fmt.Errorf("camenischshoup: %w", err)
	}
	commitments[0], commitments[1], commitments[2] = vals[0].String(), vals[1].String(), vals[2].String()
	pointCommitment, err := ec.G().ScalarMul(new(big.Int).Mod(mMask, order))
	if err != nil {
		return nil, fmt.Errorf("camenischshoup: %w", err)
	}
	commitments[3] = pointString(pointCommitment)
	auxiliary, err := auxiliaryProduct(pk, [][2]*big.Int{{pk.GBar, mMask}, {pk.HBar, sMask}})
	if err != nil {
		return nil, fmt.Errorf("camenischshoup: %w", err)
	}
	commitments[4] = auxiliary.String()

	challenge := c.challenge(ec, publicPoint, label, []*big.Int{u, e, v}, l, commitments)

	response := func(mask, value *big.Int) *big.Int {
		return new(big.Int).Sub(mask, new(big.Int).Mul(challenge, value))
	}
	return &phe.VerifiableCiphertext{
		Ciphertext: []*big.Int{u, e, v},
		Commitment: l,
		Proof: &phe.Proof{
			Challenge: challenge,
			R:         response(rMask, r),
			S:         response(sMask, s),
			M:         response(mMask, m),
		},
	}, nil
}

// VerifyEncryption implements phe.VerifiableEncrypter. It verifies that a
// verifiable ciphertext contains the discrete logarithm of a public point
// without decrypting it, and requires the public key only.
func (c *Cryptosystem) VerifyEncryption(ciphertext *phe.VerifiableCiphertext, publicPoint ecc.Point, label string) (bool, error) {
	ec, err := c.validateVerifiableEncryption()
	if err != nil {
		return false, err
	}
	pk := c.keys.PublicKey
	order := ec.N()

	if !c.wellFormed(ec, ciphertext) {
		return false, nil
	}
	u, e, v := ciphertext.Ciphertext[0], ciphertext.Ciphertext[1], ciphertext.Ciphertext[2]
	l := ciphertext.Commitment
	proof := ciphertext.Proof

	if publicPoint.Infinity || publicPoint.X == nil || publicPoint.Y == nil {
		return false, nil
	}
	point, err := ec.Point(publicPoint.X, publicPoint.Y)
	if err != nil || point.IsIdentity() {
		return false, nil
	}
	tagBase := c.tagBase(u, e, label)

	two := big.NewInt(2)
	twoC := new(big.Int).Mul(two, proof.Challenge)
	twoR := new(big.Int).Mul(two, proof.R)
	onePlusN := new(big.Int).Add(c.n, big.NewInt(1))
	vals, err := c.powProducts(
		[][2]*big.Int{{u, twoC}, {pk.G, twoR}},
		[][2]*big.Int{{e, twoC}, {pk.Y1, twoR}, {onePlusN, new(big.Int).Mul(two, proof.M)}},
		[][2]*big.Int{{v, twoC}, {tagBase, twoR}},
	)
	if err != nil {
		// not invertible
		return false, nil
	}
	scaled, err := point.ScalarMul(proof.Challenge)
	if err != nil {
		return false, nil
	}
	mG, err := ec.G().ScalarMul(new(big.Int).Mod(proof.M, order))
	if err != nil {
		return false, nil
	}
	pointCommitment, err := scaled.Add(mG)
	if err != nil {
		return false, nil
	}
	auxiliary, err := auxiliaryProduct(pk, [][2]*big.Int{{l, proof.Challenge}, {pk.GBar, proof.M}, {pk.HBar, proof.S}})
	if err != nil {
		return false, nil
	}
	commitments := []string{vals[0].String(), vals[1].String(), vals[2].String(), pointString(pointCommitment), auxiliary.String()}

	expected := c.challenge(ec, point, label, []*big.Int{u, e, v}, l, commitments)
	return expected.Cmp(proof.Challenge) == 0, nil
}

// wellFormed checks types and ranges of a verifiable ciphertext.
func (c *Cryptosystem) wellFormed(ec *ecc.ECC, vc *phe.VerifiableCiphertext) bool {
	if vc == nil || vc.Proof == nil || len(vc.Ciphertext) != 3 || vc.Commitment == nil {
		return false
	}
	p := vc.Proof
	if p.Challenge == nil || p.R == nil || p.S == nil || p.M == nil {
		return false
	}
	for _, x := range vc.Ciphertext {
		if x == nil || x.Sign() <= 0 || x.Cmp(c.nSquared) >= 0 {
			return false
		}
	}
	v := vc.Ciphertext[2]
	if v.Cmp(c.abs(v)) != 0 {
		return false
	}
	if vc.Commitment.Sign() <= 0 || vc.Commitment.Cmp(c.keys.PublicKey.NBar) >= 0 {
		return false
	}
	if p.Challenge.Sign() < 0 || p.Challenge.BitLen() > ChallengeBits {
		return false
	}
	// secret must be small enough to be restored from its encryption mod n
	limit := new(big.Int).Lsh(ec.N(), ChallengeBits+StatisticalBits+1)
	return new(big.Int).Abs(p.M).Cmp(limit) <= 0
}

// DecryptVerifiableCiphertext implements phe.VerifiableEncrypter. It restores
// the secret, and is the only step requiring the private key. It does not
// check the proof, as VerifyEncryption does that.
func (c *Cryptosystem) DecryptVerifiableCiphertext(ciphertext *phe.VerifiableCiphertext, label string) (*big.Int, error) {
	if !c.hasSecret {
		return nil, phe.ErrMissingPrivateKey
	}
	if ciphertext == nil {
		return nil, phe.InvalidCiphertextf("camenischshoup: nil verifiable ciphertext")
	}
	ec, err := c.ECC()
	if err != nil {
		return nil, err
	}
	m, err := c.DecryptWithLabel(ciphertext.Ciphertext, label)
	if err != nil {
		return nil, err
	}
	// proof guarantees that the secret is in (-n/2, n/2)
	if m.Cmp(new(big.Int).Rsh(c.n, 1)) > 0 {
		m.Sub(m, c.n)
	}
	return m.Mod(m, ec.N()), nil
}

// Add implements phe.Homomorphic. Validity tags of verifiable ciphertexts are
// dropped.
func (c *Cryptosystem) Add(a, b phe.Value) (phe.Value, error) {
	u1, e1, err := c.pair(a)
	if err != nil {
		return nil, err
	}
	u2, e2, err := c.pair(b)
	if err != nil {
		return nil, err
	}
	u := new(big.Int).Mul(u1, u2)
	e := new(big.Int).Mul(e1, e2)
	return phe.NewTuple(phe.Int{V: u.Mod(u, c.nSquared)}, phe.Int{V: e.Mod(e, c.nSquared)}), nil
}

// MultiplyByConstant implements phe.Homomorphic. Validity tags of verifiable
// ciphertexts are dropped.
func (c *Cryptosystem) MultiplyByConstant(ciphertext phe.Value, constant *big.Int) (phe.Value, error) {
	u, e, err := c.pair(ciphertext)
	if err != nil {
		return nil, err
	}
	k := new(big.Int).Mod(constant, c.n)
	return phe.NewTuple(
		phe.Int{V: new(big.Int).Exp(u, k, c.nSquared)},
		phe.Int{V: new(big.Int).Exp(e, k, c.nSquared)},
	), nil
}

// Reencrypt implements phe.Homomorphic by adding an encryption of zero.
func (c *Cryptosystem) Reencrypt(ciphertext phe.Value) (phe.Value, error) {
	zero, err := c.Encrypt(new(big.Int))
	if err != nil {
		return nil, err
	}
	return c.Add(ciphertext, zero)
}

// pair returns the first two components of a ciphertext, so that the validity
// tag of a verifiable ciphertext is dropped.
func (c *Cryptosystem) pair(v phe.Value) (*big.Int, *big.Int, error) {
	t, err := phe.AsTuple(v)
	if err != nil {
		return nil, nil, err
	}
	items, err := t.Ints()
	if err != nil {
		return nil, nil, err
	}
	if len(items) < 2 || len(items) > 3 {
		return nil, nil, phe.InvalidCiphertextf("camenischshoup: expected a (u, e) pair, got %d components", len(items))
	}
	return items[0], items[1], nil
}

// recover restores the plaintext from a (u, e) pair.
func (c *Cryptosystem) recover(u, e *big.Int) (*big.Int, error) {
	// (e / u^x1)^(2t) = (1 + n)^m where t = 1/2 mod n
	halfInv, err := mathutil.ModInverse(big.NewInt(2), c.n)
	if err != nil {
		return nil, fmt.Errorf("camenischshoup: %v: %w", err, phe.ErrDecryptionFailed)
	}
	twoT := halfInv.Lsh(halfInv, 1)
	mask, err := mathutil.ModInverse(new(big.Int).Exp(u, c.keys.PrivateKey.X1, c.nSquared), c.nSquared)
	if err != nil {
		return nil, phe.InvalidCiphertextf("camenischshoup: ciphertext is invalid")
	}
	mHat := mask.Mul(mask, e).Mod(mask, c.nSquared)
	mHat.Exp(mHat, twoT, c.nSquared)
	if new(big.Int).Mod(mHat, c.n).Cmp(big.NewInt(1)) != 0 {
		return nil, phe.InvalidCiphertextf("camenischshoup: ciphertext is invalid")
	}
	return mHat.Sub(mHat, big.NewInt(1)).Quo(mHat, c.n), nil
}

// tagBase is the base of the validity tag: y2 * y3^H(u, e, label) mod n^2.
func (c *Cryptosystem) tagBase(u, e *big.Int, label string) *big.Int {
	pk := c.keys.PublicKey
	base := new(big.Int).Exp(pk.Y3, c.hashTag(u, e, label), c.nSquared)
	return base.Mul(base, pk.Y2).Mod(base, c.nSquared)
}

// hashTag hashes a ciphertext and its label for the validity tag. It is
// smaller than p' and q' as required by the scheme.
func (c *Cryptosystem) hashTag(u, e *big.Int, label string) *big.Int {
	bits := c.n.BitLen()/2 - 2
	if bits < 1 {
		bits = 1
	}
	if bits > 256 {
		bits = 256
	}
	digest := sha256.Sum256([]byte(fmt.Sprintf("tag|%s|%s|%s", u, e, label)))
	h := new(big.Int).SetBytes(digest[:])
	return h.Mod(h, new(big.Int).Lsh(big.NewInt(1), uint(bits)))
}

// challenge is the Fiat-Shamir challenge of the proof.
func (c *Cryptosystem) challenge(ec *ecc.ECC, publicPoint ecc.Point, label string, ciphertext []*big.Int, l *big.Int,
	commitments []string) *big.Int {
	pk := c.keys.PublicKey
	items := []string{
		pk.N.String(), pk.G.String(), pk.Y1.String(), pk.Y2.String(), pk.Y3.String(),
		pk.NBar.String(), pk.GBar.String(), pk.HBar.String(),
		pointString(ec.G()), pointString(publicPoint), label,
	}
	for _, x := range ciphertext {
		items = append(items, x.String())
	}
	items = append(items, l.String())
	items = append(items, commitments...)

	digest := sha256.Sum256([]byte("challenge|" + strings.Join(items, "|")))
	h := new(big.Int).SetBytes(digest[:])
	return h.Mod(h, new(big.Int).Lsh(big.NewInt(1), ChallengeBits))
}

// abs is the absolute value of an element of Z_{n^2}, where elements greater
// than n^2 / 2 are considered negative.
func (c *Cryptosystem) abs(a *big.Int) *big.Int {
	if a.Cmp(new(big.Int).Rsh(c.nSquared, 1)) > 0 {
		return new(big.Int).Sub(c.nSquared, a)
	}
	return new(big.Int).Set(a)
}

// validateVerifiableEncryption checks that secrets are restorable from their
// encryption mod n, even if they are extracted from a cheating prover.
func (c *Cryptosystem) validateVerifiableEncryption() (*ecc.ECC, error) {
	ec, err := c.ECC()
	if err != nil {
		return nil, err
	}
	minimum := new(big.Int).Lsh(ec.N(), ChallengeBits+StatisticalBits+3)
	if c.n.Cmp(minimum) <= 0 {
		return nil, fmt.Errorf("camenischshoup: key size %d is too small for verifiable encryption, "+
			"it must be greater than %d bits for this curve", c.n.BitLen(), minimum.BitLen())
	}
	return ec, nil
}

// powProducts computes products of powers modulo n^2 for each group of
// (base, exponent) pairs. Exponents may be negative.
func (c *Cryptosystem) powProducts(groups ...[][2]*big.Int) ([]*big.Int, error) {
	out := make([]*big.Int, len(groups))
	for i, group := range groups {
		product := big.NewInt(1)
		for _, term := range group {
			power, err := powMod(term[0], term[1], c.nSquared)
			if err != nil {
				return nil, err
			}
			product.Mul(product, power).Mod(product, c.nSquared)
		}
		out[i] = product
	}
	return out, nil
}

// auxiliaryProduct computes a product of powers in the auxiliary group.
func auxiliaryProduct(pk *PublicKey, terms [][2]*big.Int) (*big.Int, error) {
	product := big.NewInt(1)
	for _, term := range terms {
		power, err := powMod(term[0], term[1], pk.NBar)
		if err != nil {
			return nil, err
		}
		product.Mul(product, power).Mod(product, pk.NBar)
	}
	return product, nil
}

// powMod computes base^exponent mod modulus for any sign of the exponent, as
// Python's pow does.
func powMod(base, exponent, modulus *big.Int) (*big.Int, error) {
	if exponent.Sign() >= 0 {
		return new(big.Int).Exp(base, exponent, modulus), nil
	}
	inv, err := mathutil.ModInverse(base, modulus)
	if err != nil {
		return nil, err
	}
	return inv.Exp(inv, new(big.Int).Neg(exponent), modulus), nil
}

// randSymmetric draws a uniform integer in [-bound, bound].
func randSymmetric(bound *big.Int) (*big.Int, error) {
	return mathutil.RandRange(new(big.Int).Neg(bound), bound)
}

// pointString formats a point as Python formats its coordinate tuple.
func pointString(p ecc.Point) string {
	if p.Infinity {
		return "(None, None)"
	}
	return fmt.Sprintf("(%s, %s)", p.X, p.Y)
}
