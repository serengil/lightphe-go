package ecelgamal

import (
	"encoding/json"
	"fmt"
	"math/big"

	"github.com/serengil/lightphe-go/lightphe/ecc"
	"github.com/serengil/lightphe-go/lightphe/internal/mathutil"
	"github.com/serengil/lightphe-go/lightphe/internal/threshold"
	"github.com/serengil/lightphe-go/lightphe/internal/zkp"
	"github.com/serengil/lightphe-go/lightphe/phe"
)

// Domains separating the proofs of elliptic curve ElGamal from proofs of
// other statements.
const (
	DecryptionDomain        = "lightphe/elliptic-curve-elgamal/decryption"
	PartialDecryptionDomain = "lightphe/elliptic-curve-elgamal/partial-decryption"
	MembershipDomain        = "lightphe/elliptic-curve-elgamal/membership"
	KnowledgeDomain         = "lightphe/elliptic-curve-elgamal/knowledge"
)

var (
	_ phe.ThresholdDecrypter = (*Cryptosystem)(nil)
	_ phe.DecryptionProver   = (*Cryptosystem)(nil)
	_ phe.MembershipProver   = (*Cryptosystem)(nil)
	_ phe.KnowledgeProver    = (*Cryptosystem)(nil)
)

func (c *Cryptosystem) group() zkp.EllipticCurveGroup { return zkp.EllipticCurveGroup{EC: c.ec} }

// GenerateThresholdKeys implements phe.ThresholdDecrypter. Verification keys
// share * G are published to verify partial decryptions.
func (c *Cryptosystem) GenerateThresholdKeys(t, parties int) ([]byte, [][]byte, error) {
	if !c.hasSecret {
		return nil, nil, phe.ErrMissingPrivateKey
	}
	n := c.ec.N()
	if big.NewInt(int64(parties)).Cmp(n) >= 0 {
		return nil, nil, fmt.Errorf("lightphe: number of parties must be less than the curve order %s", n)
	}
	shares, err := threshold.SplitSecret(c.ka, t, parties, n)
	if err != nil {
		return nil, nil, err
	}
	verificationKeys := make([]*phe.Point, parties)
	for i, share := range shares {
		point, err := c.ec.G().ScalarMul(share)
		if err != nil {
			return nil, nil, err
		}
		value := toValue(point)
		verificationKeys[i] = &value
	}

	pk := *c.keys.PublicKey
	pk.Threshold, pk.Parties, pk.VerificationKeys = t, parties, verificationKeys
	publicKey, err := json.Marshal(Keys{PublicKey: &pk, Form: c.keys.Form, Curve: c.keys.Curve})
	if err != nil {
		return nil, nil, err
	}
	shareKeys, err := threshold.ShareKeys(shares, func(key *phe.ThresholdKey) interface{} {
		return Keys{PublicKey: &pk, ThresholdKey: key, Form: c.keys.Form, Curve: c.keys.Curve}
	})
	return publicKey, shareKeys, err
}

// PartialDecrypt implements phe.ThresholdDecrypter. The partial decryption is
// share * c1.
func (c *Cryptosystem) PartialDecrypt(ciphertext phe.Value, prove bool) (*phe.PartialDecryption, error) {
	key := c.keys.ThresholdKey
	if key == nil {
		return nil, threshold.ErrNoThresholdKey
	}
	c1, _, err := c.points(ciphertext)
	if err != nil {
		return nil, err
	}
	value, err := c1.ScalarMul(key.Share)
	if err != nil {
		return nil, err
	}
	partial := &phe.PartialDecryption{Index: key.Index, Value: toValue(value)}
	if !prove {
		return partial, nil
	}
	h1, err := c.ec.G().ScalarMul(key.Share)
	if err != nil {
		return nil, err
	}
	proof, err := zkp.ProveDLEQ(c.group(), c.ec.G(), h1, c1, value, key.Share,
		PartialDecryptionDomain, []interface{}{c.ec.N(), key.Index})
	if err != nil {
		return nil, err
	}
	partial.Proof = proof
	return partial, nil
}

// VerifyPartialDecryption implements phe.ThresholdDecrypter.
func (c *Cryptosystem) VerifyPartialDecryption(ciphertext phe.Value, partial *phe.PartialDecryption) (bool, error) {
	verificationKeys := c.keys.PublicKey.VerificationKeys
	if verificationKeys == nil {
		return false, threshold.ErrNoVerificationKeys
	}
	if partial == nil || partial.Index < 1 || partial.Index > len(verificationKeys) || verificationKeys[partial.Index-1] == nil {
		return false, nil
	}
	c1, _, err := c.points(ciphertext)
	if err != nil {
		return false, nil
	}
	h1, err := c.toPoint(*verificationKeys[partial.Index-1])
	if err != nil {
		return false, nil
	}
	h2, err := c.toPoint(partial.Value)
	if err != nil {
		return false, nil
	}
	return zkp.VerifyDLEQ(c.group(), c.ec.G(), h1, c1, h2, partial.Proof,
		PartialDecryptionDomain, []interface{}{c.ec.N(), partial.Index}), nil
}

// CombinePartialDecryptions implements phe.ThresholdDecrypter. ka * c1 is
// restored with lagrange interpolation.
func (c *Cryptosystem) CombinePartialDecryptions(ciphertext phe.Value, partials []*phe.PartialDecryption, verify bool) (
	*big.Int, error) {
	_, c2, err := c.points(ciphertext)
	if err != nil {
		return nil, err
	}
	var verifier func(*phe.PartialDecryption) (bool, error)
	if verify {
		verifier = func(partial *phe.PartialDecryption) (bool, error) {
			return c.VerifyPartialDecryption(ciphertext, partial)
		}
	}
	pk := c.keys.PublicKey
	selected, err := threshold.Select(pk.Threshold, pk.Parties, partials, verifier)
	if err != nil {
		return nil, err
	}
	indices := threshold.Indices(selected)

	s := c2
	for _, partial := range selected {
		coefficient, err := threshold.LagrangeCoefficient(partial.Index, indices, c.ec.N())
		if err != nil {
			return nil, err
		}
		point, err := c.toPoint(partial.Value)
		if err != nil {
			return nil, err
		}
		scaled, err := point.ScalarMul(coefficient)
		if err != nil {
			return nil, err
		}
		if s, err = s.Sub(scaled); err != nil {
			return nil, err
		}
	}

	// s = m * G, solve ECDLP
	m, err := ecc.DiscreteLog(s, c.ec.G(), c.ec.N())
	if err != nil {
		return nil, fmt.Errorf("ecelgamal: %v: %w", err, phe.ErrDecryptionFailed)
	}
	return m, nil
}

// DecryptWithProof implements phe.DecryptionProver. Chaum-Pedersen proof
// shows that log_G(Qa) = log_c1(ka * c1) without revealing the private key.
func (c *Cryptosystem) DecryptWithProof(ciphertext phe.Value) (*big.Int, *phe.ZKProof, error) {
	if !c.hasSecret {
		return nil, nil, phe.ErrMissingPrivateKey
	}
	c1, c2, err := c.points(ciphertext)
	if err != nil {
		return nil, nil, err
	}
	shared, err := c1.ScalarMul(c.ka)
	if err != nil {
		return nil, nil, err
	}
	proof, err := zkp.ProveDLEQ(c.group(), c.ec.G(), c.qa, c1, shared, c.ka,
		DecryptionDomain, []interface{}{c.ec.N(), c2})
	if err != nil {
		return nil, nil, err
	}
	plaintext, err := c.Decrypt(ciphertext)
	if err != nil {
		return nil, nil, err
	}
	return plaintext, proof, nil
}

// VerifyDecryption implements phe.DecryptionProver. The plaintext is checked
// in modulo of the curve order.
func (c *Cryptosystem) VerifyDecryption(ciphertext phe.Value, plaintext *big.Int, proof *phe.ZKProof) (bool, error) {
	if plaintext == nil {
		return false, nil
	}
	c1, c2, err := c.points(ciphertext)
	if err != nil {
		return false, nil
	}

	// ka * c1 implied by the claimed plaintext
	shared, err := c.subtractMessage(c2, plaintext)
	if err != nil {
		return false, nil
	}
	return zkp.VerifyDLEQ(c.group(), c.ec.G(), c.qa, c1, shared, proof,
		DecryptionDomain, []interface{}{c.ec.N(), c2}), nil
}

// subtractMessage returns c2 - m * G.
func (c *Cryptosystem) subtractMessage(c2 ecc.Point, m *big.Int) (ecc.Point, error) {
	mG, err := c.ec.G().ScalarMul(new(big.Int).Mod(m, c.ec.N()))
	if err != nil {
		return ecc.Point{}, err
	}
	return c2.Sub(mG)
}

// GenerateRandomKey implements phe.MembershipProver.
func (c *Cryptosystem) GenerateRandomKey() (*big.Int, error) {
	return mathutil.RandBits(c.ec.N().BitLen())
}

// EncryptWithProof implements phe.MembershipProver. Disjunctive
// Chaum-Pedersen proof shows that c2 - v * G is r * Qa for one of the values
// v.
func (c *Cryptosystem) EncryptWithProof(plaintext *big.Int, values []*big.Int, context interface{}) (
	phe.Value, *phe.ZKProof, error) {
	r, err := c.GenerateRandomKey()
	if err != nil {
		return nil, nil, err
	}
	ciphertext, err := c.EncryptWith(plaintext, r)
	if err != nil {
		return nil, nil, err
	}
	proof, err := c.ProveMembership(ciphertext, plaintext, r, values, context)
	if err != nil {
		return nil, nil, err
	}
	return ciphertext, proof, nil
}

// ProveMembership implements phe.MembershipProver.
func (c *Cryptosystem) ProveMembership(ciphertext phe.Value, plaintext, randomKey *big.Int, values []*big.Int,
	context interface{}) (*phe.ZKProof, error) {
	c1, c2, err := c.points(ciphertext)
	if err != nil {
		return nil, err
	}
	index, err := zkp.IndexOf(plaintext, values)
	if err != nil {
		return nil, err
	}
	candidates, err := c.membershipCandidates(c2, values)
	if err != nil {
		return nil, err
	}
	return zkp.ProveDLEQOr(c.group(), c.ec.G(), c1, c.qa, candidates, randomKey, index,
		MembershipDomain, []interface{}{c.ec.N(), c2, values, context})
}

// CombineRandomKeys implements phe.MembershipProver. c1 = r * G adds, so
// random keys add.
func (c *Cryptosystem) CombineRandomKeys(randomKeys []*big.Int) *big.Int {
	sum := new(big.Int)
	for _, r := range randomKeys {
		sum.Add(sum, r)
	}
	return sum
}

// VerifyCiphertext implements phe.MembershipProver.
func (c *Cryptosystem) VerifyCiphertext(ciphertext phe.Value, proof *phe.ZKProof, values []*big.Int,
	context interface{}) (bool, error) {
	c1, c2, err := c.points(ciphertext)
	if err != nil {
		return false, nil
	}
	candidates, err := c.membershipCandidates(c2, values)
	if err != nil {
		return false, nil
	}
	return zkp.VerifyDLEQOr(c.group(), c.ec.G(), c1, c.qa, candidates, proof,
		MembershipDomain, []interface{}{c.ec.N(), c2, values, context}), nil
}

// membershipCandidates returns c2 - v * G for each value v. A ciphertext
// encrypts v if and only if its candidate is r * Qa where c1 = r * G.
func (c *Cryptosystem) membershipCandidates(c2 ecc.Point, values []*big.Int) ([]zkp.Element, error) {
	out := make([]zkp.Element, len(values))
	for i, v := range values {
		candidate, err := c.subtractMessage(c2, v)
		if err != nil {
			return nil, err
		}
		out[i] = candidate
	}
	return out, nil
}

// EncryptWithProofOfKnowledge implements phe.KnowledgeProver. Schnorr proof
// shows knowledge of r where c1 = r * G, which reveals the plaintext from c2.
// It is bound to c2, so a copied, re-randomized or modified ciphertext of
// someone else cannot be proven.
func (c *Cryptosystem) EncryptWithProofOfKnowledge(plaintext *big.Int, context interface{}) (phe.Value, *phe.ZKProof, error) {
	r, err := c.GenerateRandomKey()
	if err != nil {
		return nil, nil, err
	}
	ciphertext, err := c.EncryptWith(plaintext, r)
	if err != nil {
		return nil, nil, err
	}
	c1, c2, err := c.points(ciphertext)
	if err != nil {
		return nil, nil, err
	}
	proof, err := zkp.ProveDLog(c.group(), c.ec.G(), c1, r, KnowledgeDomain, []interface{}{c.ec.N(), c2, context})
	if err != nil {
		return nil, nil, err
	}
	return ciphertext, proof, nil
}

// VerifyKnowledge implements phe.KnowledgeProver.
func (c *Cryptosystem) VerifyKnowledge(ciphertext phe.Value, proof *phe.ZKProof, context interface{}) (bool, error) {
	// c2 must be a point on the curve
	c1, c2, err := c.points(ciphertext)
	if err != nil {
		return false, nil
	}
	return zkp.VerifyDLog(c.group(), c.ec.G(), c1, proof, KnowledgeDomain, []interface{}{c.ec.N(), c2, context}), nil
}
