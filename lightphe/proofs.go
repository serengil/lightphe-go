package lightphe

import (
	"fmt"
	"math/big"

	"github.com/serengil/lightphe-go/lightphe/encrypted"
	"github.com/serengil/lightphe-go/lightphe/internal/zkp"
	"github.com/serengil/lightphe-go/lightphe/phe"
)

// ---------------------------------------------------------------------------
// Zero-knowledge proofs
//
// Context arguments are public data bound to a proof, e.g. the id of a voter,
// so that the proof cannot be copied for another context. They must be
// serializable to JSON, and nil is allowed.
// ---------------------------------------------------------------------------

func (c *Cryptosystem) decryptionProver() (phe.DecryptionProver, error) {
	if e, ok := c.unboosted().(phe.DecryptionProver); ok {
		return e, nil
	}
	return nil, phe.Unsupportedf(c.algorithm, phe.OpDecryptionProof)
}

func (c *Cryptosystem) membershipProver() (zkp.Prover, error) {
	if e, ok := c.unboosted().(zkp.Prover); ok {
		return e, nil
	}
	return nil, phe.Unsupportedf(c.algorithm, phe.OpMembershipProof)
}

func (c *Cryptosystem) knowledgeProver() (phe.KnowledgeProver, error) {
	if e, ok := c.unboosted().(phe.KnowledgeProver); ok {
		return e, nil
	}
	return nil, phe.Unsupportedf(c.algorithm, phe.OpKnowledgeProof)
}

// DecryptWithProof decrypts a ciphertext and proves that the decryption is
// correct, without revealing the private key. It runs on private key owner
// side, e.g. a tallying authority announcing the result of an election.
// Supported by ElGamal and Exponential-ElGamal (keys generated with
// WithPrimeOrder(true)), EllipticCurve-ElGamal, Paillier and Damgard-Jurik.
func (c *Cryptosystem) DecryptWithProof(ciphertext *encrypted.Ciphertext) (*big.Int, *ZKProof, error) {
	value, err := unboostedValue(ciphertext)
	if err != nil {
		return nil, nil, err
	}
	if !c.cs.HasPrivateKey() {
		return nil, nil, phe.ErrMissingPrivateKey
	}
	e, err := c.decryptionProver()
	if err != nil {
		return nil, nil, err
	}
	return e.DecryptWithProof(value)
}

// VerifyDecryption verifies that a ciphertext decrypts to the given
// plaintext. Public key is enough, so anyone can check an announced
// plaintext.
func (c *Cryptosystem) VerifyDecryption(ciphertext *encrypted.Ciphertext, plaintext *big.Int, proof *ZKProof) (bool, error) {
	e, err := c.decryptionProver()
	if err != nil {
		return false, err
	}
	if ciphertext == nil {
		return false, nil
	}
	return e.VerifyDecryption(ciphertext.Value, plaintext, proof)
}

// EncryptWithProof encrypts a plaintext and proves that it is one of the
// allowed values, without revealing which one. For instance, a voter proves
// that the encrypted vote is 0 or 1, so cannot cheat with a vote of 100 in the
// homomorphic tally. Nil values allow 0 and 1. Public key is enough.
// Supported by Exponential-ElGamal (keys generated with WithPrimeOrder(true)),
// EllipticCurve-ElGamal, Paillier and Damgard-Jurik.
func (c *Cryptosystem) EncryptWithProof(plaintext *big.Int, values []*big.Int, context interface{}) (
	*encrypted.Ciphertext, *ZKProof, error) {
	e, err := c.membershipProver()
	if err != nil {
		return nil, nil, err
	}
	normalized, err := c.normalizeValues(values)
	if err != nil {
		return nil, nil, err
	}
	m := phe.Normalize(plaintext, c.unboosted().PlaintextModulo())
	if _, err := zkp.IndexOf(m, normalized); err != nil {
		return nil, nil, err
	}
	value, proof, err := e.EncryptWithProof(m, normalized, context)
	if err != nil {
		return nil, nil, err
	}
	return encrypted.NewCiphertext(c.publicUnboosted(), value), proof, nil
}

// VerifyCiphertext verifies that a ciphertext encrypts one of the allowed
// values without decrypting it. Nil values allow 0 and 1. Public key is
// enough, e.g. anyone can check the ballots of an election.
func (c *Cryptosystem) VerifyCiphertext(ciphertext *encrypted.Ciphertext, proof *ZKProof, values []*big.Int,
	context interface{}) (bool, error) {
	e, err := c.membershipProver()
	if err != nil {
		return false, err
	}
	normalized, err := c.normalizeValues(values)
	if err != nil {
		return false, err
	}
	if ciphertext == nil {
		return false, nil
	}
	return e.VerifyCiphertext(ciphertext.Value, proof, normalized, context)
}

// EncryptWithProofOfKnowledge encrypts a plaintext and proves that the
// encryptor knows it, without revealing it. For instance, a bidder of a
// sealed-bid auction proves knowledge of the bid, so nobody can outbid by
// copying someone else's encrypted bid and adding 1 to it homomorphically.
// Public key is enough. Supported by ElGamal and Exponential-ElGamal (keys
// generated with WithPrimeOrder(true)), EllipticCurve-ElGamal, Paillier and
// Damgard-Jurik.
func (c *Cryptosystem) EncryptWithProofOfKnowledge(plaintext *big.Int, context interface{}) (*encrypted.Ciphertext, *ZKProof, error) {
	e, err := c.knowledgeProver()
	if err != nil {
		return nil, nil, err
	}
	value, proof, err := e.EncryptWithProofOfKnowledge(phe.Normalize(plaintext, c.unboosted().PlaintextModulo()), context)
	if err != nil {
		return nil, nil, err
	}
	return encrypted.NewCiphertext(c.publicUnboosted(), value), proof, nil
}

// VerifyKnowledge verifies that the encryptor of a ciphertext knows its
// plaintext without decrypting it. Public key is enough.
func (c *Cryptosystem) VerifyKnowledge(ciphertext *encrypted.Ciphertext, proof *ZKProof, context interface{}) (bool, error) {
	e, err := c.knowledgeProver()
	if err != nil {
		return false, err
	}
	if ciphertext == nil {
		return false, nil
	}
	return e.VerifyKnowledge(ciphertext.Value, proof, context)
}

// EncryptOneHot encrypts a choice among options as a one-hot vector, i.e. 1
// for the chosen option and 0 for others, and proves that exactly one option
// is chosen without revealing which one. For instance, a voter votes for one
// of many parties. Summing slots of all ballots homomorphically counts votes
// of each option separately, so the number of options is not limited. Public
// key is enough. Supported by Exponential-ElGamal (keys generated with
// WithPrimeOrder(true)), EllipticCurve-ElGamal, Paillier and Damgard-Jurik.
func (c *Cryptosystem) EncryptOneHot(choice, options int, context interface{}) ([]*encrypted.Ciphertext, *OneHotProof, error) {
	if options < 1 {
		return nil, nil, fmt.Errorf("lightphe: number of options must be at least 1")
	}
	if choice < 0 || choice >= options {
		return nil, nil, fmt.Errorf("lightphe: choice must be in [0, %d)", options)
	}
	e, err := c.membershipProver()
	if err != nil {
		return nil, nil, err
	}
	values, err := c.normalizeValues(nil)
	if err != nil {
		return nil, nil, err
	}
	slots, proof, err := zkp.ProveOneHot(e, choice, options, values[0], values[1], context)
	if err != nil {
		return nil, nil, err
	}
	ciphertexts := make([]*encrypted.Ciphertext, len(slots))
	for i, slot := range slots {
		ciphertexts[i] = encrypted.NewCiphertext(c.publicUnboosted(), slot)
	}
	return ciphertexts, proof, nil
}

// VerifyOneHot verifies that encrypted slots are a one-hot vector, i.e.
// exactly one option is chosen, without decrypting them. Public key is
// enough.
func (c *Cryptosystem) VerifyOneHot(ciphertexts []*encrypted.Ciphertext, proof *OneHotProof, context interface{}) (bool, error) {
	e, err := c.membershipProver()
	if err != nil {
		return false, err
	}
	values, err := c.normalizeValues(nil)
	if err != nil {
		return false, err
	}
	slots := make([]phe.Value, len(ciphertexts))
	for i, ciphertext := range ciphertexts {
		if ciphertext == nil {
			return false, nil
		}
		slots[i] = ciphertext.Value
	}
	return zkp.VerifyOneHot(e, slots, proof, values[0], values[1], context)
}

// EncryptWithRangeProof encrypts a plaintext and proves that it is in
// [low, high], without revealing it. For instance, an employee proves that the
// encrypted salary is in a sensible range, so cannot skew the average of
// salaries with a negative or huge value. Public key is enough. Proof size
// grows with the bit length of high - low. Supported by Exponential-ElGamal
// (keys generated with WithPrimeOrder(true)), EllipticCurve-ElGamal, Paillier
// and Damgard-Jurik.
func (c *Cryptosystem) EncryptWithRangeProof(plaintext, low, high *big.Int, context interface{}) (
	*encrypted.Ciphertext, *RangeProof, error) {
	e, err := c.membershipProver()
	if err != nil {
		return nil, nil, err
	}
	values, err := c.normalizeRange(low, high)
	if err != nil {
		return nil, nil, err
	}
	if plaintext == nil || plaintext.Cmp(low) < 0 || plaintext.Cmp(high) > 0 {
		return nil, nil, fmt.Errorf("lightphe: plaintext must be in [%s, %s]", low, high)
	}
	value, proof, err := zkp.ProveRange(e, plaintext, low, high, values[0], values[1], values[2], context)
	if err != nil {
		return nil, nil, err
	}
	return encrypted.NewCiphertext(c.publicUnboosted(), value), proof, nil
}

// VerifyRange verifies that a ciphertext encrypts a value in [low, high]
// without decrypting it. Public key is enough.
func (c *Cryptosystem) VerifyRange(ciphertext *encrypted.Ciphertext, proof *RangeProof, low, high *big.Int,
	context interface{}) (bool, error) {
	e, err := c.membershipProver()
	if err != nil {
		return false, err
	}
	values, err := c.normalizeRange(low, high)
	if err != nil {
		return false, err
	}
	if ciphertext == nil {
		return false, nil
	}
	return zkp.VerifyRange(e, ciphertext.Value, proof, low, high, values[0], values[1], values[2], context)
}

// normalizeRange validates the bounds of a range proof, and normalizes low, 0
// and 1 as Encrypt does.
func (c *Cryptosystem) normalizeRange(low, high *big.Int) ([]*big.Int, error) {
	if low == nil || high == nil {
		return nil, fmt.Errorf("lightphe: bounds of the range must be integers")
	}
	if low.Cmp(high) > 0 {
		return nil, fmt.Errorf("lightphe: lower bound %s must not be greater than upper bound %s", low, high)
	}
	modulo := c.unboosted().PlaintextModulo()
	if new(big.Int).Sub(high, low).Cmp(modulo) >= 0 {
		return nil, fmt.Errorf("lightphe: range must be narrower than the plaintext modulo")
	}
	return []*big.Int{phe.Normalize(low, modulo), big.NewInt(0), phe.Normalize(big.NewInt(1), modulo)}, nil
}

// normalizeValues validates the allowed values of a proof and normalizes them
// as Encrypt does. Nil values allow 0 and 1.
func (c *Cryptosystem) normalizeValues(values []*big.Int) ([]*big.Int, error) {
	if values == nil {
		values = []*big.Int{big.NewInt(0), big.NewInt(1)}
	}
	if len(values) == 0 {
		return nil, fmt.Errorf("lightphe: allowed values must be a non-empty list of integers")
	}
	modulo := c.unboosted().PlaintextModulo()
	normalized := make([]*big.Int, len(values))
	seen := make(map[string]bool, len(values))
	for i, v := range values {
		if v == nil {
			return nil, fmt.Errorf("lightphe: allowed values must be a non-empty list of integers")
		}
		normalized[i] = phe.Normalize(v, modulo)
		key := normalized[i].String()
		if seen[key] {
			return nil, fmt.Errorf("lightphe: allowed values must be distinct")
		}
		seen[key] = true
	}
	return normalized, nil
}
