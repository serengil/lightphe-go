package zkp

import (
	"math/big"

	"github.com/serengil/lightphe-go/lightphe/phe"
)

// Proofs composed of proofs of allowed values: range proofs and one-hot
// proofs.

// Prover is an additively homomorphic cryptosystem proving that ciphertexts
// encrypt one of the allowed values.
type Prover interface {
	phe.Homomorphic
	phe.MembershipProver
}

// RangeWeights returns the weights of bits to represent every integer in
// [0, width] exactly, i.e. 1, 2, 4, ..., 2^(k-2) and width - (2^(k-1) - 1)
// where k is the bit length of width. Sums of 0/1 bits with these weights
// cover [0, width], and nothing out of it.
func RangeWeights(width *big.Int) []*big.Int {
	k := width.BitLen()
	if k == 0 {
		return nil
	}
	weights := make([]*big.Int, k)
	for i := 0; i < k-1; i++ {
		weights[i] = new(big.Int).Lsh(one, uint(i))
	}
	last := new(big.Int).Lsh(one, uint(k-1))
	weights[k-1] = last.Sub(width, last.Sub(last, one))
	return weights
}

// Decompose finds the 0/1 bits of a value in [0, sum of weights] for the
// weights of RangeWeights.
func Decompose(value *big.Int, weights []*big.Int) []int {
	if len(weights) == 0 {
		return nil
	}
	k := len(weights)
	bits := make([]int, k)
	rest := new(big.Int).Set(value)
	if value.Cmp(weights[k-1]) >= 0 {
		bits[k-1] = 1
		rest.Sub(rest, weights[k-1])
	}
	for i := 0; i < k-1; i++ {
		bits[i] = int(rest.Bit(i))
	}
	return bits
}

// rangeContext binds every part of a range proof to its position and range,
// so parts cannot be reordered or moved into another proof.
func rangeContext(context interface{}, low, high *big.Int, index int) []interface{} {
	return []interface{}{"range", low, high, index, context}
}

// combineRange restores the ciphertext of a range proof homomorphically as
// c_low + sum of w_i c_i.
func combineRange(cs phe.Homomorphic, ciphertexts []phe.Value, weights []*big.Int) (phe.Value, error) {
	combined := ciphertexts[0]
	for i, weight := range weights {
		scaled, err := cs.MultiplyByConstant(ciphertexts[i+1], weight)
		if err != nil {
			return nil, err
		}
		if combined, err = cs.Add(combined, scaled); err != nil {
			return nil, err
		}
	}
	return combined, nil
}

// ProveRange encrypts a plaintext in [low, high] and proves that it is in
// this range without revealing it. It is decomposed into bits, each bit is
// encrypted with a proof that it is 0 or 1, and low is encrypted with a proof
// that it is low. normalizedLow, zero and one are low, 0 and 1 normalized into
// the plaintext space.
func ProveRange(cs Prover, plaintext, low, high, normalizedLow, zero, one *big.Int,
	context interface{}) (phe.Value, *phe.RangeProof, error) {
	weights := RangeWeights(new(big.Int).Sub(high, low))
	bits := Decompose(new(big.Int).Sub(plaintext, low), weights)

	ciphertexts := make([]phe.Value, 0, len(bits)+1)
	proofs := make([]*phe.ZKProof, 0, len(bits)+1)
	for index := 0; index <= len(bits); index++ {
		value, allowed := normalizedLow, []*big.Int{normalizedLow}
		if index > 0 {
			value, allowed = zero, []*big.Int{zero, one}
			if bits[index-1] == 1 {
				value = one
			}
		}
		ciphertext, proof, err := cs.EncryptWithProof(value, allowed, rangeContext(context, low, high, index))
		if err != nil {
			return nil, nil, err
		}
		ciphertexts = append(ciphertexts, ciphertext)
		proofs = append(proofs, proof)
	}

	ciphertext, err := combineRange(cs, ciphertexts, weights)
	if err != nil {
		return nil, nil, err
	}
	return ciphertext, &phe.RangeProof{Ciphertexts: ciphertexts, Proofs: proofs}, nil
}

// VerifyRange verifies that a ciphertext encrypts a value in [low, high] with
// the public key only.
func VerifyRange(cs Prover, ciphertext phe.Value, proof *phe.RangeProof, low, high, normalizedLow, zero, one *big.Int,
	context interface{}) (bool, error) {
	if proof == nil {
		return false, nil
	}
	weights := RangeWeights(new(big.Int).Sub(high, low))
	if len(proof.Ciphertexts) != len(weights)+1 || len(proof.Proofs) != len(weights)+1 {
		return false, nil
	}

	for index, part := range proof.Ciphertexts {
		allowed := []*big.Int{normalizedLow}
		if index > 0 {
			allowed = []*big.Int{zero, one}
		}
		valid, err := cs.VerifyCiphertext(part, proof.Proofs[index], allowed, rangeContext(context, low, high, index))
		if err != nil || !valid {
			return false, err
		}
	}

	combined, err := combineRange(cs, proof.Ciphertexts, weights)
	if err != nil {
		// malformed parts raise errors of the cryptosystem
		return false, nil
	}
	return combined.Equal(ciphertext), nil
}

// oneHotContext binds every slot of a one-hot proof to its position and the
// number of options, so slots cannot be reordered or moved into another
// ballot.
func oneHotContext(context interface{}, options int, slot interface{}) []interface{} {
	return []interface{}{"one-hot", options, slot, context}
}

// ProveOneHot encrypts a one-hot vector, i.e. 1 for the chosen option and 0
// for others, and proves that each slot is 0 or 1 and that slots sum to 1
// without revealing the choice. zero and one are normalized into the
// plaintext space.
func ProveOneHot(cs Prover, choice, options int, zero, one *big.Int, context interface{}) ([]phe.Value, *phe.OneHotProof, error) {
	ciphertexts := make([]phe.Value, options)
	randomKeys := make([]*big.Int, options)
	slotProofs := make([]*phe.ZKProof, options)
	for slot := 0; slot < options; slot++ {
		plaintext := zero
		if slot == choice {
			plaintext = one
		}
		randomKey, err := cs.GenerateRandomKey()
		if err != nil {
			return nil, nil, err
		}
		ciphertext, err := cs.EncryptWith(plaintext, randomKey)
		if err != nil {
			return nil, nil, err
		}
		proof, err := cs.ProveMembership(ciphertext, plaintext, randomKey, []*big.Int{zero, one},
			oneHotContext(context, options, slot))
		if err != nil {
			return nil, nil, err
		}
		ciphertexts[slot], randomKeys[slot], slotProofs[slot] = ciphertext, randomKey, proof
	}

	// sum of slots encrypts 1, and its random key is combined from random keys
	// of slots
	total, err := sum(cs, ciphertexts)
	if err != nil {
		return nil, nil, err
	}
	sumProof, err := cs.ProveMembership(total, one, cs.CombineRandomKeys(randomKeys), []*big.Int{one},
		oneHotContext(context, options, "sum"))
	if err != nil {
		return nil, nil, err
	}
	return ciphertexts, &phe.OneHotProof{Slots: slotProofs, Sum: sumProof}, nil
}

// VerifyOneHot verifies that encrypted slots are a one-hot vector with the
// public key only.
func VerifyOneHot(cs Prover, ciphertexts []phe.Value, proof *phe.OneHotProof, zero, one *big.Int,
	context interface{}) (bool, error) {
	if proof == nil || len(ciphertexts) == 0 || len(proof.Slots) != len(ciphertexts) {
		return false, nil
	}
	options := len(ciphertexts)
	for slot, ciphertext := range ciphertexts {
		valid, err := cs.VerifyCiphertext(ciphertext, proof.Slots[slot], []*big.Int{zero, one},
			oneHotContext(context, options, slot))
		if err != nil || !valid {
			return false, err
		}
	}

	total, err := sum(cs, ciphertexts)
	if err != nil {
		// malformed slots raise errors of the cryptosystem
		return false, nil
	}
	return cs.VerifyCiphertext(total, proof.Sum, []*big.Int{one}, oneHotContext(context, options, "sum"))
}

func sum(cs phe.Homomorphic, ciphertexts []phe.Value) (phe.Value, error) {
	total := ciphertexts[0]
	for _, ciphertext := range ciphertexts[1:] {
		var err error
		if total, err = cs.Add(total, ciphertext); err != nil {
			return nil, err
		}
	}
	return total, nil
}
