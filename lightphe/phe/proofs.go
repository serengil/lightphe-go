package phe

import (
	"bytes"
	"encoding/json"
	"math/big"
)

// Threshold decryption and zero-knowledge proofs. Like the protocols in
// protocols.go, each capability is an optional interface, and callers report
// the operation as unsupported when a cryptosystem does not implement it.

// ThresholdKey is the share of a shareholder in threshold decryption. Index is
// in [1, parties].
type ThresholdKey struct {
	Index int      `json:"index"`
	Share *big.Int `json:"share"`
}

// ZKProof is a non-interactive zero-knowledge proof made with the Fiat-Shamir
// heuristic. Which fields are set depends on the statement being proven, and
// they are named as the keys of the Python library's proofs, so that proofs
// marshal to the same JSON.
type ZKProof struct {
	// Challenge and Response of Chaum-Pedersen and Schnorr proofs, and of
	// proofs of partial decryption.
	Challenge *big.Int `json:"challenge,omitempty"`
	Response  *big.Int `json:"response,omitempty"`

	// Challenges and Responses of each statement of a disjunctive proof.
	Challenges []*big.Int `json:"challenges,omitempty"`
	Responses  []*big.Int `json:"responses,omitempty"`

	// Randomness of a Paillier or Damgard-Jurik ciphertext, which proves its
	// decryption.
	Randomness *big.Int `json:"randomness,omitempty"`

	// Responses of a proof of knowledge of a Paillier or Damgard-Jurik
	// plaintext and its randomness.
	PlaintextResponse  *big.Int `json:"plaintext_response,omitempty"`
	RandomnessResponse *big.Int `json:"randomness_response,omitempty"`
}

// PartialDecryption is the output of a shareholder in threshold decryption.
// Value is an integer, or an elliptic curve point for EllipticCurve-ElGamal.
// Proof is set if the shareholder proved it.
type PartialDecryption struct {
	Index int      `json:"index"`
	Value Value    `json:"value"`
	Proof *ZKProof `json:"proof,omitempty"`
}

// UnmarshalJSON implements json.Unmarshaler. A value is decoded into an Int,
// or into a Point if it is a pair of coordinates.
func (p *PartialDecryption) UnmarshalJSON(data []byte) error {
	var raw struct {
		Index int             `json:"index"`
		Value json.RawMessage `json:"value"`
		Proof *ZKProof        `json:"proof,omitempty"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	value := bytes.TrimSpace(raw.Value)
	switch {
	case len(value) > 0 && (value[0] == '[' || string(value) == "null"):
		var point Point
		if err := json.Unmarshal(value, &point); err != nil {
			return err
		}
		p.Value = point
	default:
		v := new(big.Int)
		if err := json.Unmarshal(value, v); err != nil {
			return InvalidCiphertextf("decoding a partial decryption: %v", err)
		}
		p.Value = Int{V: v}
	}
	p.Index, p.Proof = raw.Index, raw.Proof
	return nil
}

// ThresholdDecrypter splits the private key into shares, so that any
// threshold many shareholders decrypt a ciphertext together, whereas fewer
// shareholders learn nothing.
type ThresholdDecrypter interface {
	// GenerateThresholdKeys runs on dealer side. It returns the public key
	// having threshold parameters, and the key of each shareholder, which must
	// be sent to its own shareholder secretly. All keys are JSON.
	GenerateThresholdKeys(threshold, parties int) (publicKey []byte, shareKeys [][]byte, err error)

	// PartialDecrypt decrypts a ciphertext partially with the share of a
	// shareholder, and optionally proves that it is computed with that share.
	PartialDecrypt(ciphertext Value, prove bool) (*PartialDecryption, error)

	// VerifyPartialDecryption verifies the proof of a partial decryption with
	// the public key only.
	VerifyPartialDecryption(ciphertext Value, partial *PartialDecryption) (bool, error)

	// CombinePartialDecryptions restores the plaintext from partial
	// decryptions of threshold many shareholders. If verify is true, partial
	// decryptions with invalid or missing proofs are discarded.
	CombinePartialDecryptions(ciphertext Value, partials []*PartialDecryption, verify bool) (*big.Int, error)
}

// DecryptionProver proves that a ciphertext decrypts to a plaintext, and
// anyone having the public key can verify it.
type DecryptionProver interface {
	DecryptWithProof(ciphertext Value) (*big.Int, *ZKProof, error)
	VerifyDecryption(ciphertext Value, plaintext *big.Int, proof *ZKProof) (bool, error)
}

// MembershipProver proves that a ciphertext encrypts one of the allowed
// values without revealing which one. Context is public data bound to a
// proof, e.g. the id of a voter, and it must be serializable to JSON.
type MembershipProver interface {
	EncryptWithProof(plaintext *big.Int, values []*big.Int, context interface{}) (Value, *ZKProof, error)
	VerifyCiphertext(ciphertext Value, proof *ZKProof, values []*big.Int, context interface{}) (bool, error)

	// ProveMembership proves a ciphertext whose plaintext and random key are
	// known by the prover, e.g. a sum of ciphertexts encrypted by the prover.
	ProveMembership(ciphertext Value, plaintext, randomKey *big.Int, values []*big.Int, context interface{}) (*ZKProof, error)

	// GenerateRandomKey, EncryptWith and CombineRandomKeys expose the random
	// keys of ciphertexts, which proofs of sums of ciphertexts need.
	GenerateRandomKey() (*big.Int, error)
	EncryptWith(plaintext, randomKey *big.Int) (Value, error)
	CombineRandomKeys(randomKeys []*big.Int) *big.Int
}

// KnowledgeProver proves that the encryptor of a ciphertext knows its
// plaintext without revealing it, so a copied, re-randomized or modified
// ciphertext of someone else cannot be proven.
type KnowledgeProver interface {
	EncryptWithProofOfKnowledge(plaintext *big.Int, context interface{}) (Value, *ZKProof, error)
	VerifyKnowledge(ciphertext Value, proof *ZKProof, context interface{}) (bool, error)
}

// RangeProof proves that a ciphertext encrypts a value in [low, high]. The
// value minus low is decomposed into bits, Ciphertexts are the encryptions of
// low and of the bits, and Proofs prove that they are low and 0 or 1. The
// ciphertext is restored from them homomorphically.
type RangeProof struct {
	Ciphertexts []Value    `json:"ciphertexts"`
	Proofs      []*ZKProof `json:"proofs"`
}

// UnmarshalJSON implements json.Unmarshaler. Ciphertexts are decoded into
// integers and tuples of them, and Cryptosystem.Deserialize restores the
// curve points of EllipticCurve-ElGamal from their coordinates.
func (p *RangeProof) UnmarshalJSON(data []byte) error {
	var raw struct {
		Ciphertexts []json.RawMessage `json:"ciphertexts"`
		Proofs      []*ZKProof        `json:"proofs"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	ciphertexts := make([]Value, len(raw.Ciphertexts))
	for i, item := range raw.Ciphertexts {
		v, err := decodeRawValue(item)
		if err != nil {
			return err
		}
		ciphertexts[i] = v
	}
	p.Ciphertexts, p.Proofs = ciphertexts, raw.Proofs
	return nil
}

// decodeRawValue decodes a value marshaled by MarshalJSON into an integer, a
// tuple, or the point at infinity for null.
func decodeRawValue(data json.RawMessage) (Value, error) {
	data = bytes.TrimSpace(data)
	switch {
	case string(data) == "null":
		return InfinityPoint(), nil
	case len(data) > 0 && data[0] == '[':
		var raw []json.RawMessage
		if err := json.Unmarshal(data, &raw); err != nil {
			return nil, err
		}
		items := make([]Value, len(raw))
		for i, item := range raw {
			v, err := decodeRawValue(item)
			if err != nil {
				return nil, err
			}
			items[i] = v
		}
		return Tuple{Items: items}, nil
	}
	v := new(big.Int)
	if err := json.Unmarshal(data, v); err != nil {
		return nil, InvalidCiphertextf("decoding a ciphertext of a range proof: %v", err)
	}
	return Int{V: v}, nil
}

// OneHotProof proves that encrypted slots are a one-hot vector: each slot is
// 0 or 1, and their sum is 1.
type OneHotProof struct {
	Slots []*ZKProof `json:"slots"`
	Sum   *ZKProof   `json:"sum"`
}
