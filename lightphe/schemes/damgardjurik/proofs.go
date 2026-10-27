package damgardjurik

import (
	"encoding/json"
	"fmt"
	"math/big"

	"github.com/serengil/lightphe-go/lightphe/internal/mathutil"
	"github.com/serengil/lightphe-go/lightphe/internal/threshold"
	"github.com/serengil/lightphe-go/lightphe/internal/zkp"
	"github.com/serengil/lightphe-go/lightphe/phe"
)

// Domains separating the proofs of Damgard-Jurik from proofs of other statements.
const (
	MembershipDomain        = "lightphe/damgard-jurik/membership"
	KnowledgeDomain         = "lightphe/damgard-jurik/knowledge"
	PartialDecryptionDomain = "lightphe/damgard-jurik/partial-decryption"
)

var (
	_ phe.ThresholdDecrypter = (*Cryptosystem)(nil)
	_ phe.DecryptionProver   = (*Cryptosystem)(nil)
	_ phe.MembershipProver   = (*Cryptosystem)(nil)
	_ phe.KnowledgeProver    = (*Cryptosystem)(nil)
)

// GenerateSafe creates a fresh key pair with n = p q for safe primes
// p = 2p' + 1 and q = 2q' + 1. Then, the group of squares modulo n^(s+1) is
// cyclic, which partial decryptions are proven in. Key format is the same as
// regular keys. Pass s <= 0 to use DefaultS.
func GenerateSafe(keySize, s, maxTries int) (*Cryptosystem, error) {
	if keySize <= 0 {
		keySize = DefaultKeySize
	}
	if s <= 0 {
		s = DefaultS
	}
	p, q, err := mathutil.RandDistinctSafePrimes(keySize/2, maxTries)
	if err != nil {
		return nil, fmt.Errorf("damgardjurik: %v: %w", err, phe.ErrKeyGeneration)
	}
	n := new(big.Int).Mul(p, q)
	phi := new(big.Int).Mul(new(big.Int).Sub(p, big.NewInt(1)), new(big.Int).Sub(q, big.NewInt(1)))
	return New(Keys{
		PublicKey:  &PublicKey{G: new(big.Int).Add(n, big.NewInt(1)), N: n, S: big.NewInt(int64(s))},
		PrivateKey: &PrivateKey{Phi: phi},
	})
}

func (c *Cryptosystem) thresholdKey() threshold.Paillier {
	pk := c.keys.PublicKey
	return threshold.Paillier{
		N:                c.n,
		Modulo:           c.modulus,
		Threshold:        pk.Threshold,
		Parties:          pk.Parties,
		VerificationBase: pk.VerificationBase,
		VerificationKeys: pk.VerificationKeys,
	}
}

func (c *Cryptosystem) prover() zkp.PaillierProver {
	return zkp.PaillierProver{N: c.n, Modulo: c.modulus, MembershipDomain: MembershipDomain, KnowledgeDomain: KnowledgeDomain}
}

// GenerateThresholdKeys implements phe.ThresholdDecrypter. If keys are
// generated with safe primes, verification keys are published to verify
// partial decryptions.
func (c *Cryptosystem) GenerateThresholdKeys(t, parties int) ([]byte, [][]byte, error) {
	if !c.hasSecret {
		return nil, nil, phe.ErrMissingPrivateKey
	}
	shares, base, verificationKeys, err := threshold.SharePaillierKey(c.n, c.phi, int(c.keys.PublicKey.S.Int64()), c.modulus, t, parties)
	if err != nil {
		return nil, nil, err
	}
	pk := *c.keys.PublicKey
	pk.Threshold, pk.Parties, pk.VerificationBase, pk.VerificationKeys = t, parties, base, verificationKeys

	publicKey, err := json.Marshal(Keys{PublicKey: &pk})
	if err != nil {
		return nil, nil, err
	}
	shareKeys, err := threshold.ShareKeys(shares, func(key *phe.ThresholdKey) interface{} {
		return Keys{PublicKey: &pk, ThresholdKey: key}
	})
	return publicKey, shareKeys, err
}

// PartialDecrypt implements phe.ThresholdDecrypter. Keys must be generated
// with safe primes to prove it.
func (c *Cryptosystem) PartialDecrypt(ciphertext phe.Value, prove bool) (*phe.PartialDecryption, error) {
	v, err := phe.AsInt(ciphertext)
	if err != nil {
		return nil, err
	}
	return c.thresholdKey().PartialDecrypt(c.keys.ThresholdKey, v, prove, PartialDecryptionDomain)
}

// VerifyPartialDecryption implements phe.ThresholdDecrypter.
func (c *Cryptosystem) VerifyPartialDecryption(ciphertext phe.Value, partial *phe.PartialDecryption) (bool, error) {
	v, err := phe.AsInt(ciphertext)
	if err != nil {
		return false, err
	}
	return c.thresholdKey().VerifyPartialDecryption(v, partial, PartialDecryptionDomain)
}

// CombinePartialDecryptions implements phe.ThresholdDecrypter.
func (c *Cryptosystem) CombinePartialDecryptions(ciphertext phe.Value, partials []*phe.PartialDecryption, verify bool) (
	*big.Int, error) {
	v, err := phe.AsInt(ciphertext)
	if err != nil {
		return nil, err
	}
	return c.thresholdKey().Combine(v, partials, verify, PartialDecryptionDomain)
}

// DecryptWithProof implements phe.DecryptionProver. Randomness of the
// ciphertext is the proof, and anyone having the public key can check it.
func (c *Cryptosystem) DecryptWithProof(ciphertext phe.Value) (*big.Int, *phe.ZKProof, error) {
	plaintext, err := c.Decrypt(ciphertext)
	if err != nil {
		return nil, nil, err
	}
	v, _ := phe.AsInt(ciphertext)
	proof, err := zkp.ProvePaillierDecryption(v, plaintext, c.n, c.phi)
	if err != nil {
		return nil, nil, err
	}
	return plaintext, proof, nil
}

// VerifyDecryption implements phe.DecryptionProver.
func (c *Cryptosystem) VerifyDecryption(ciphertext phe.Value, plaintext *big.Int, proof *phe.ZKProof) (bool, error) {
	v, err := phe.AsInt(ciphertext)
	if err != nil {
		return false, nil
	}
	return zkp.VerifyPaillierDecryption(v, plaintext, proof, c.n), nil
}

// GenerateRandomKey implements phe.MembershipProver.
func (c *Cryptosystem) GenerateRandomKey() (*big.Int, error) { return mathutil.RandCoprime(c.n) }

// EncryptWithProof implements phe.MembershipProver.
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
	return c.prover().ProveMembership(ciphertext, plaintext, randomKey, values, context)
}

// CombineRandomKeys implements phe.MembershipProver.
func (c *Cryptosystem) CombineRandomKeys(randomKeys []*big.Int) *big.Int {
	return c.prover().CombineRandomKeys(randomKeys)
}

// VerifyCiphertext implements phe.MembershipProver.
func (c *Cryptosystem) VerifyCiphertext(ciphertext phe.Value, proof *phe.ZKProof, values []*big.Int,
	context interface{}) (bool, error) {
	return c.prover().VerifyCiphertext(ciphertext, proof, values, context), nil
}

// EncryptWithProofOfKnowledge implements phe.KnowledgeProver.
func (c *Cryptosystem) EncryptWithProofOfKnowledge(plaintext *big.Int, context interface{}) (phe.Value, *phe.ZKProof, error) {
	r, err := c.GenerateRandomKey()
	if err != nil {
		return nil, nil, err
	}
	ciphertext, err := c.EncryptWith(plaintext, r)
	if err != nil {
		return nil, nil, err
	}
	proof, err := c.prover().ProveKnowledge(ciphertext, plaintext, r, context)
	if err != nil {
		return nil, nil, err
	}
	return ciphertext, proof, nil
}

// VerifyKnowledge implements phe.KnowledgeProver.
func (c *Cryptosystem) VerifyKnowledge(ciphertext phe.Value, proof *phe.ZKProof, context interface{}) (bool, error) {
	return c.prover().VerifyKnowledge(ciphertext, proof, context), nil
}
