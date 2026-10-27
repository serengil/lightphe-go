package zkp

import (
	"fmt"
	"math/big"

	"github.com/serengil/lightphe-go/lightphe/phe"
)

// PaillierProver proves statements about ciphertexts g^m r^n mod n^(s+1) of
// Paillier (s = 1) and Damgard-Jurik with the public key only. Domains
// separate proofs of different cryptosystems.
type PaillierProver struct {
	N, Modulo        *big.Int
	MembershipDomain string
	KnowledgeDomain  string
}

// IndexOf returns the index of value in values.
func IndexOf(value *big.Int, values []*big.Int) (int, error) {
	for i, v := range values {
		if v.Cmp(value) == 0 {
			return i, nil
		}
	}
	return -1, fmt.Errorf("lightphe: plaintext must be one of the allowed values")
}

// ProveMembership proves that a ciphertext encrypted with the random key r
// encrypts one of values. 1-out-of-k proof of Damgard and Jurik shows that
// c g^-v is an n-th power for one of the values v.
func (p PaillierProver) ProveMembership(ciphertext phe.Value, plaintext, r *big.Int, values []*big.Int,
	context interface{}) (*phe.ZKProof, error) {
	c, err := phe.AsInt(ciphertext)
	if err != nil {
		return nil, err
	}
	index, err := IndexOf(plaintext, values)
	if err != nil {
		return nil, err
	}
	us, err := PaillierMembershipCandidates(c, values, p.N, p.Modulo)
	if err != nil {
		return nil, err
	}
	return ProveNthPowerOr(p.N, p.Modulo, us, r, index, p.MembershipDomain, []interface{}{values, context})
}

// VerifyCiphertext verifies that a ciphertext encrypts one of values.
func (p PaillierProver) VerifyCiphertext(ciphertext phe.Value, proof *phe.ZKProof, values []*big.Int,
	context interface{}) bool {
	c, err := phe.AsInt(ciphertext)
	if err != nil || !isUnit(c, p.N, p.Modulo) {
		return false
	}
	us, err := PaillierMembershipCandidates(c, values, p.N, p.Modulo)
	if err != nil {
		return false
	}
	return VerifyNthPowerOr(p.N, p.Modulo, us, proof, p.MembershipDomain, []interface{}{values, context})
}

// CombineRandomKeys returns the random key of the homomorphic sum of
// ciphertexts, as r^n multiplies.
func (p PaillierProver) CombineRandomKeys(randomKeys []*big.Int) *big.Int {
	combined := big.NewInt(1)
	for _, r := range randomKeys {
		combined.Mul(combined, r).Mod(combined, p.Modulo)
	}
	return combined
}

// ProveKnowledge proves knowledge of the plaintext and the random key r of a
// ciphertext.
func (p PaillierProver) ProveKnowledge(ciphertext phe.Value, plaintext, r *big.Int, context interface{}) (*phe.ZKProof, error) {
	c, err := phe.AsInt(ciphertext)
	if err != nil {
		return nil, err
	}
	return ProvePaillierKnowledge(c, plaintext, r, p.N, p.Modulo, p.KnowledgeDomain, context)
}

// VerifyKnowledge verifies that the encryptor of a ciphertext knows its
// plaintext.
func (p PaillierProver) VerifyKnowledge(ciphertext phe.Value, proof *phe.ZKProof, context interface{}) bool {
	c, err := phe.AsInt(ciphertext)
	if err != nil {
		return false
	}
	return VerifyPaillierKnowledge(c, proof, p.N, p.Modulo, p.KnowledgeDomain, context)
}
