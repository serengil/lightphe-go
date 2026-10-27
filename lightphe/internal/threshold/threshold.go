// Package threshold implements threshold decryption. A private key is split
// into shares with Shamir's secret sharing, and any threshold of parties
// shareholders decrypt a ciphertext together, whereas fewer shareholders learn
// nothing about the plaintext.
//
// Reference: Shamir, A. (1979). How to Share a Secret.
//
// Reference: Shoup, V. (2000). Practical Threshold Signatures.
//
// Reference: Damgard, I., Jurik, M. (2001). A Generalisation, a
// Simplification and Some Applications of Paillier's Probabilistic Public-Key
// System.
package threshold

import (
	"encoding/json"
	"errors"
	"fmt"
	"math/big"

	"github.com/serengil/lightphe-go/lightphe/internal/mathutil"
	"github.com/serengil/lightphe-go/lightphe/internal/zkp"
	"github.com/serengil/lightphe-go/lightphe/phe"
)

// ErrSafePrimesRequired reports a proof of partial decryption requested for
// Paillier or Damgard-Jurik keys not generated with safe primes.
var ErrSafePrimesRequired = errors.New("lightphe: partial decryptions of Paillier and Damgard-Jurik can be proven " +
	"only if keys are generated with safe primes")

// ErrNoThresholdKey reports a partial decryption requested without a share.
var ErrNoThresholdKey = errors.New("lightphe: you must have threshold key to perform partial decryption")

// ErrNoThresholdParameters reports a combination requested with a public key
// lacking threshold parameters.
var ErrNoThresholdParameters = errors.New("lightphe: public key does not have threshold parameters, " +
	"generate threshold keys first")

// ErrNoVerificationKeys reports a verification requested with a public key
// lacking verification keys of shareholders.
var ErrNoVerificationKeys = errors.New("lightphe: public key does not have verification keys of shareholders")

var one = big.NewInt(1)

// Validate checks that a threshold scheme is well defined.
func Validate(threshold, parties int) error {
	if threshold < 1 {
		return fmt.Errorf("lightphe: threshold must be at least 1, got %d", threshold)
	}
	if parties < threshold {
		return fmt.Errorf("lightphe: parties (%d) must be greater than or equal to threshold (%d)", parties, threshold)
	}
	return nil
}

// SplitSecret splits a secret into shares with a random polynomial f of degree
// threshold - 1 where f(0) = secret. Item i is the share f(i + 1) mod modulo
// of the party with index i + 1.
func SplitSecret(secret *big.Int, threshold, parties int, modulo *big.Int) ([]*big.Int, error) {
	if err := Validate(threshold, parties); err != nil {
		return nil, err
	}
	coefficients := []*big.Int{new(big.Int).Mod(secret, modulo)}
	for i := 1; i < threshold; i++ {
		c, err := mathutil.RandBelow(modulo)
		if err != nil {
			return nil, err
		}
		coefficients = append(coefficients, c)
	}

	shares := make([]*big.Int, parties)
	for index := 1; index <= parties; index++ {
		// horner's method
		share := new(big.Int)
		x := big.NewInt(int64(index))
		for i := len(coefficients) - 1; i >= 0; i-- {
			share.Mul(share, x).Add(share, coefficients[i]).Mod(share, modulo)
		}
		shares[index-1] = share
	}
	return shares, nil
}

// LagrangeCoefficient is the lagrange coefficient of a party at 0, i.e. the
// product of j / (j - index) over other indices j, in a modulo where
// differences of indices are invertible, e.g. a prime order of a group.
func LagrangeCoefficient(index int, indices []int, modulo *big.Int) (*big.Int, error) {
	numerator := big.NewInt(1)
	denominator := big.NewInt(1)
	for _, j := range indices {
		if j == index {
			continue
		}
		numerator.Mul(numerator, big.NewInt(int64(j))).Mod(numerator, modulo)
		denominator.Mul(denominator, big.NewInt(int64(j-index))).Mod(denominator, modulo)
	}
	inverse, err := mathutil.ModInverse(denominator, modulo)
	if err != nil {
		return nil, err
	}
	return numerator.Mul(numerator, inverse).Mod(numerator, modulo), nil
}

// ScaledLagrangeCoefficient is the lagrange coefficient of a party at 0
// multiplied by delta = parties!. It is always an integer, so it works in
// groups of unknown order.
func ScaledLagrangeCoefficient(index int, indices []int, delta *big.Int) *big.Int {
	numerator := new(big.Int).Set(delta)
	denominator := big.NewInt(1)
	for _, j := range indices {
		if j == index {
			continue
		}
		numerator.Mul(numerator, big.NewInt(int64(j)))
		denominator.Mul(denominator, big.NewInt(int64(j-index)))
	}
	return numerator.Quo(numerator, denominator)
}

// Factorial returns n!.
func Factorial(n int) *big.Int {
	return new(big.Int).MulRange(1, int64(n))
}

// ShareKeys builds the JSON key of each shareholder from the public key
// having threshold parameters. buildKey returns the key material of the
// shareholder having the given threshold key.
func ShareKeys(shares []*big.Int, buildKey func(key *phe.ThresholdKey) interface{}) ([][]byte, error) {
	out := make([][]byte, len(shares))
	for i, share := range shares {
		data, err := json.Marshal(buildKey(&phe.ThresholdKey{Index: i + 1, Share: share}))
		if err != nil {
			return nil, err
		}
		out[i] = data
	}
	return out, nil
}

// Select validates partial decryptions and picks threshold many of them from
// distinct parties. If verify is set, partial decryptions with invalid proofs
// are discarded.
func Select(threshold, parties int, partials []*phe.PartialDecryption,
	verify func(*phe.PartialDecryption) (bool, error)) ([]*phe.PartialDecryption, error) {
	if threshold == 0 || parties == 0 {
		return nil, ErrNoThresholdParameters
	}

	selected := make([]*phe.PartialDecryption, 0, threshold)
	byIndex := make(map[int]*phe.PartialDecryption)
	for _, partial := range partials {
		if partial == nil || partial.Value == nil {
			continue
		}
		if verify != nil {
			valid, err := verify(partial)
			if err != nil {
				return nil, err
			}
			if !valid {
				// invalid proofs are discarded
				continue
			}
		}
		if partial.Index < 1 || partial.Index > parties {
			return nil, fmt.Errorf("lightphe: index of partial decryption must be in [1, %d], got %d", parties, partial.Index)
		}
		if existing, ok := byIndex[partial.Index]; ok {
			if !existing.Value.Equal(partial.Value) {
				return nil, fmt.Errorf("lightphe: conflicting partial decryptions for index %d", partial.Index)
			}
			continue
		}
		byIndex[partial.Index] = partial
		selected = append(selected, partial)
	}

	if len(selected) < threshold {
		return nil, fmt.Errorf("lightphe: at least %d valid partial decryptions from distinct parties are required, got %d: %w",
			threshold, len(selected), phe.ErrDecryptionFailed)
	}
	return selected[:threshold], nil
}

// Indices returns the indices of partial decryptions.
func Indices(partials []*phe.PartialDecryption) []int {
	out := make([]int, len(partials))
	for i, partial := range partials {
		out[i] = partial.Index
	}
	return out
}

// Paillier is the public key of Paillier or Damgard-Jurik with threshold
// parameters. VerificationBase and VerificationKeys are set if n is a product
// of safe primes.
type Paillier struct {
	N, Modulo        *big.Int
	Threshold        int
	Parties          int
	VerificationBase *big.Int
	VerificationKeys []*big.Int
}

// SharePaillierKey splits the private key of Paillier or Damgard-Jurik. The
// decryption exponent d satisfies d = 0 mod phi and d = 1 mod n^s, so
// c^d = (1 + n)^m, and it is shared modulo n^s phi. If n is a product of safe
// primes, verification keys v^(delta share) are returned to prove partial
// decryptions; otherwise base and verificationKeys are nil.
func SharePaillierKey(n, phi *big.Int, s int, modulo *big.Int, threshold, parties int) (
	shares []*big.Int, base *big.Int, verificationKeys []*big.Int, err error) {
	if err := Validate(threshold, parties); err != nil {
		return nil, nil, nil, err
	}
	delta := Factorial(parties)
	if !mathutil.IsCoprime(delta, n) {
		return nil, nil, nil, fmt.Errorf("lightphe: number of parties %d is too large for the modulus", parties)
	}
	ns := new(big.Int).Exp(n, big.NewInt(int64(s)), nil)
	phiInverse, err := mathutil.ModInverse(phi, ns)
	if err != nil {
		return nil, nil, nil, err
	}
	d := new(big.Int).Mul(phi, phiInverse)

	// order of the multiplicative group of n^(s+1)
	if shares, err = SplitSecret(d, threshold, parties, new(big.Int).Mul(ns, phi)); err != nil {
		return nil, nil, nil, err
	}

	if !IsSafePaillierKey(n, phi) {
		return shares, nil, nil, nil
	}

	// a random square generates the cyclic group of squares with high
	// probability
	r, err := zkp.RandomUnit(n, modulo)
	if err != nil {
		return nil, nil, nil, err
	}
	base = new(big.Int).Exp(r, big.NewInt(2), modulo)
	verificationKeys = make([]*big.Int, parties)
	for i, share := range shares {
		verificationKeys[i] = new(big.Int).Exp(base, new(big.Int).Mul(delta, share), modulo)
	}
	return shares, base, verificationKeys, nil
}

// IsSafePaillierKey checks whether n is a product of two safe primes,
// restoring them from n and phi.
func IsSafePaillierKey(n, phi *big.Int) bool {
	// p + q = n - phi + 1, and p, q are roots of x^2 - (p + q) x + n
	total := new(big.Int).Sub(n, phi)
	total.Add(total, one)
	discriminant := new(big.Int).Mul(total, total)
	discriminant.Sub(discriminant, new(big.Int).Lsh(n, 2))
	if discriminant.Sign() < 0 {
		return false
	}
	root := new(big.Int).Sqrt(discriminant)
	if new(big.Int).Mul(root, root).Cmp(discriminant) != 0 {
		return false
	}
	p := new(big.Int).Add(total, root)
	p.Rsh(p, 1)
	q := new(big.Int).Sub(total, root)
	q.Rsh(q, 1)
	if new(big.Int).Mul(p, q).Cmp(n) != 0 || p.Bit(0) == 0 || q.Bit(0) == 0 {
		return false
	}
	return mathutil.IsPrime(new(big.Int).Rsh(p, 1)) && mathutil.IsPrime(new(big.Int).Rsh(q, 1))
}

// xBits bounds the bit length of delta * share.
func (k Paillier) xBits() int {
	return new(big.Int).Mul(Factorial(k.Parties), k.Modulo).BitLen()
}

// PartialDecrypt decrypts a Paillier or Damgard-Jurik ciphertext partially.
// Keys with verification keys compute c^(2 delta share) as Shoup does, and
// can prove it.
func (k Paillier) PartialDecrypt(key *phe.ThresholdKey, ciphertext *big.Int, prove bool, domain string) (
	*phe.PartialDecryption, error) {
	if key == nil {
		return nil, ErrNoThresholdKey
	}
	if k.VerificationBase == nil {
		if prove {
			return nil, ErrSafePrimesRequired
		}
		return &phe.PartialDecryption{Index: key.Index, Value: phe.Int{V: new(big.Int).Exp(ciphertext, key.Share, k.Modulo)}}, nil
	}

	exponent := new(big.Int).Mul(Factorial(k.Parties), key.Share)
	value := new(big.Int).Exp(ciphertext, new(big.Int).Lsh(exponent, 1), k.Modulo)
	partial := &phe.PartialDecryption{Index: key.Index, Value: phe.Int{V: value}}
	if !prove {
		return partial, nil
	}
	proof, err := zkp.ProveDLEQUnknownOrder(
		k.N, k.Modulo,
		new(big.Int).Exp(ciphertext, big.NewInt(4), k.Modulo),
		new(big.Int).Exp(value, big.NewInt(2), k.Modulo),
		k.VerificationBase,
		k.VerificationKeys[key.Index-1],
		exponent, k.xBits(), domain,
		[]interface{}{key.Index, ciphertext},
	)
	if err != nil {
		return nil, err
	}
	partial.Proof = proof
	return partial, nil
}

// VerifyPartialDecryption verifies that a partial decryption of Paillier or
// Damgard-Jurik is computed with the share of its shareholder.
func (k Paillier) VerifyPartialDecryption(ciphertext *big.Int, partial *phe.PartialDecryption, domain string) (bool, error) {
	if k.VerificationBase == nil {
		return false, ErrSafePrimesRequired
	}
	if partial == nil || partial.Index < 1 || partial.Index > len(k.VerificationKeys) {
		return false, nil
	}
	value, err := phe.AsInt(partial.Value)
	if err != nil || value.Sign() <= 0 || value.Cmp(k.Modulo) >= 0 {
		return false, nil
	}
	return zkp.VerifyDLEQUnknownOrder(
		k.N, k.Modulo,
		new(big.Int).Exp(ciphertext, big.NewInt(4), k.Modulo),
		new(big.Int).Exp(value, big.NewInt(2), k.Modulo),
		k.VerificationBase,
		k.VerificationKeys[partial.Index-1],
		partial.Proof, k.xBits(), domain,
		[]interface{}{partial.Index, ciphertext},
	), nil
}

// Combine restores the plaintext from partial decryptions of Paillier or
// Damgard-Jurik. Order of the group is secret, so lagrange coefficients are
// scaled with delta = parties! to be integers.
func (k Paillier) Combine(ciphertext *big.Int, partials []*phe.PartialDecryption, verify bool, domain string) (*big.Int, error) {
	verifiable := k.VerificationBase != nil
	if verify && !verifiable {
		return nil, ErrSafePrimesRequired
	}
	var verifier func(*phe.PartialDecryption) (bool, error)
	if verify {
		verifier = func(partial *phe.PartialDecryption) (bool, error) {
			return k.VerifyPartialDecryption(ciphertext, partial, domain)
		}
	}
	selected, err := Select(k.Threshold, k.Parties, partials, verifier)
	if err != nil {
		return nil, err
	}

	delta := Factorial(k.Parties)
	indices := Indices(selected)

	// c^(delta d) = (1 + n)^(delta m) for regular partial decryptions, and
	// c^(4 delta^2 d) = (1 + n)^(4 delta^2 m) for c^(2 delta share)
	exponent := big.NewInt(1)
	factor := new(big.Int).Set(delta)
	if verifiable {
		exponent = big.NewInt(2)
		factor.Mul(factor, delta).Lsh(factor, 2)
	}

	combined := big.NewInt(1)
	for _, partial := range selected {
		value, err := phe.AsInt(partial.Value)
		if err != nil {
			return nil, err
		}
		coefficient := ScaledLagrangeCoefficient(partial.Index, indices, delta)
		coefficient.Mul(coefficient, exponent)
		term := new(big.Int)
		if coefficient.Sign() < 0 {
			inverse, err := mathutil.ModInverse(value, k.Modulo)
			if err != nil {
				return nil, fmt.Errorf("lightphe: %v: %w", err, phe.ErrDecryptionFailed)
			}
			term.Exp(inverse, coefficient.Neg(coefficient), k.Modulo)
		} else {
			term.Exp(value, coefficient, k.Modulo)
		}
		combined.Mul(combined, term).Mod(combined, k.Modulo)
	}

	factorM := combined.Sub(combined, one)
	factorM.Quo(factorM, k.N).Mod(factorM, k.N)
	factorInverse, err := mathutil.ModInverse(factor, k.N)
	if err != nil {
		return nil, err
	}
	return factorM.Mul(factorM, factorInverse).Mod(factorM, k.N), nil
}
