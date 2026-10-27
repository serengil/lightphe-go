package lightphe

import (
	"fmt"
	"math/big"
	"math/bits"
	"sort"

	"github.com/serengil/lightphe-go/lightphe/encrypted"
	"github.com/serengil/lightphe-go/lightphe/internal/mathutil"
	"github.com/serengil/lightphe-go/lightphe/phe"
	"github.com/serengil/lightphe-go/lightphe/schemes/catalanofiore"
)

// ---------------------------------------------------------------------------
// Encrypted nearest neighbor search
//
// Client (private key owner) encrypts a query vector, and server finds the k
// nearest vectors of its database by squared euclidean distance without
// learning the query, the distances or the result. Client learns only the
// indices, or the labels, of the k nearest vectors in order.
//   - distance: ||q - x||^2 = ||q||^2 - 2 <q, x> + ||x||^2 is linear in the
//     encrypted q when client sends E(||q||^2) as well, so server computes it
//     with additions and multiplications with constants only.
//   - argmin: argmax of 2^bitLength - 1 - distance with the interactive argmax
//     of Damgard-Geisler-Kroigaard, which reveals nothing to both parties.
//   - exclusion: server turns the encrypted index of the nearest vector into
//     an encrypted one-hot vector with the client's help, and lifts every
//     other value by 2^bitLength, so the next argmax finds the next nearest
//     vector.
//
// Reference: Erkin, Z. et al. (2009). Privacy-Preserving Face Recognition.
// PETS 2009.
// ---------------------------------------------------------------------------

// EncryptedQuery is a query vector encrypted for nearest neighbor search:
// ciphertexts of its entries and of its squared norm.
type EncryptedQuery struct {
	Query []*encrypted.Ciphertext
	Norm  *encrypted.Ciphertext
}

// KNNResult holds the encrypted indices of the nearest vectors from the
// nearest one, and their encrypted labels if labels are given.
type KNNResult struct {
	Indices []*encrypted.Ciphertext
	Labels  []*encrypted.Ciphertext
}

// NearestNeighbors holds the indices of the nearest vectors from the nearest
// one, and their squared distances.
type NearestNeighbors struct {
	Indices   []int
	Distances []*big.Int
}

// zeroTester checks that a ciphertext encrypts zero without decrypting it
// fully, as Damgard-Geisler-Kroigaard does.
type zeroTester interface {
	IsZero(ciphertext *big.Int) (bool, error)
}

func (c *Cryptosystem) requireKNNSupport() error {
	if c.algorithm != phe.DamgardGeislerKroigaard {
		return fmt.Errorf("lightphe: %s does not support encrypted nearest neighbor search, "+
			"use Damgard-Geisler-Kroigaard instead: %w", c.algorithm, phe.ErrUnsupportedOperation)
	}
	return nil
}

// EncryptKNNQuery encrypts a query vector for encrypted k nearest neighbor
// search. It runs on client side, e.g. a user searching a face embedding in
// the gallery of a server. Embeddings must be quantized to integers, e.g. by
// scaling and rounding. Only Damgard-Geisler-Kroigaard supports this.
func (c *Cryptosystem) EncryptKNNQuery(query []int64) (*EncryptedQuery, error) {
	if err := c.requireKNNSupport(); err != nil {
		return nil, err
	}
	if len(query) == 0 {
		return nil, fmt.Errorf("lightphe: query must be a non-empty list of integers")
	}
	cs := c.unboosted()
	u := cs.PlaintextModulo()
	out := &EncryptedQuery{Query: make([]*encrypted.Ciphertext, len(query))}
	norm := new(big.Int)
	for i, x := range query {
		value, err := cs.Encrypt(phe.Normalize(big.NewInt(x), u))
		if err != nil {
			return nil, err
		}
		out.Query[i] = encrypted.NewCiphertext(c.publicUnboosted(), value)
		norm.Add(norm, new(big.Int).Mul(big.NewInt(x), big.NewInt(x)))
	}
	value, err := cs.Encrypt(phe.Normalize(norm, u))
	if err != nil {
		return nil, err
	}
	out.Norm = encrypted.NewCiphertext(c.publicUnboosted(), value)
	return out, nil
}

// EvaluateKNN finds the k nearest vectors of a database to an encrypted query
// by squared euclidean distance. It runs on server side and talks to the
// client (private key owner) through the client callback, which is the
// client's AnswerKNN locally, or a network call otherwise. Server learns
// nothing, and client learns only the indices, or the labels, of the k
// nearest vectors, but not the distances or the other vectors. Earlier index
// is returned on ties. Squared distances between the query and vectors must
// be less than 2^bitLength, e.g. 24 for 128-dimensional embeddings of 8-bit
// entries. If labels are given, e.g. ids of people, encrypted labels of the
// nearest vectors are returned as well. Only Damgard-Geisler-Kroigaard
// supports this.
func (c *Cryptosystem) EvaluateKNN(query *EncryptedQuery, database [][]int64, k, bitLength int, client ArgmaxClient,
	labels []int64) (*KNNResult, error) {
	if err := c.requireKNNSupport(); err != nil {
		return nil, err
	}
	argmax, err := c.argmax()
	if err != nil {
		return nil, err
	}
	if query == nil || len(query.Query) == 0 || query.Norm == nil {
		return nil, fmt.Errorf("lightphe: encrypted query must be an output of EncryptKNNQuery")
	}
	if len(database) == 0 {
		return nil, fmt.Errorf("lightphe: database must be a non-empty list of vectors")
	}
	for _, vector := range database {
		if len(vector) != len(query.Query) {
			return nil, fmt.Errorf("lightphe: every vector of the database must be a list of %d integers", len(query.Query))
		}
	}
	if k < 1 || k > len(database) {
		return nil, fmt.Errorf("lightphe: k must be in [1, %d]", len(database))
	}
	if labels != nil && len(labels) != len(database) {
		return nil, fmt.Errorf("lightphe: labels must be a list of integers, one for each vector")
	}
	if bitLength < 1 {
		return nil, fmt.Errorf("lightphe: bit length must be a positive integer")
	}
	offset := new(big.Int).Lsh(big.NewInt(1), uint(bitLength))

	// argmax validates that lifted values fit into the plaintext space
	norms := make([]*big.Int, len(database))
	for i, vector := range database {
		norms[i] = new(big.Int)
		for _, x := range vector {
			norms[i].Add(norms[i], new(big.Int).Mul(big.NewInt(x), big.NewInt(x)))
		}
		if norms[i].Cmp(offset) >= 0 {
			return nil, fmt.Errorf("lightphe: squared norm %s of a vector in the database does not fit into %d bits",
				norms[i], bitLength)
		}
	}

	cs := c.unboosted()
	u := cs.PlaintextModulo()
	qs := make([]phe.Value, len(query.Query))
	for i, ciphertext := range query.Query {
		if ciphertext == nil {
			return nil, phe.InvalidCiphertextf("lightphe: nil ciphertext")
		}
		qs[i] = ciphertext.Value
	}

	// values = 2^bitLength - 1 - distance, so the nearest vector has the
	// greatest value
	minusNorm, err := cs.MultiplyByConstant(query.Norm.Value, new(big.Int).Sub(u, big.NewInt(1)))
	if err != nil {
		return nil, err
	}
	values := make([]phe.Value, len(database))
	for i, vector := range database {
		constant := new(big.Int).Sub(offset, big.NewInt(1))
		value, err := cs.Encrypt(phe.Normalize(constant.Sub(constant, norms[i]), u))
		if err != nil {
			return nil, err
		}
		if value, err = cs.Add(value, minusNorm); err != nil {
			return nil, err
		}
		for j, x := range vector {
			factor := phe.Normalize(big.NewInt(2*x), u)
			if phe.Normalize(big.NewInt(x), u).Sign() == 0 {
				continue
			}
			term, err := cs.MultiplyByConstant(qs[j], factor)
			if err != nil {
				return nil, err
			}
			if value, err = cs.Add(value, term); err != nil {
				return nil, err
			}
		}
		values[i] = value
	}

	// values are lifted by 2^bitLength in each round, so they need more bits
	argmaxBitLength := bitLength + bits.Len(uint(k))

	result := &KNNResult{}
	for round := 0; round < k; round++ {
		raw := make([]*big.Int, len(values))
		for i, value := range values {
			if raw[i], err = phe.AsInt(value); err != nil {
				return nil, err
			}
		}
		indexRaw, err := argmax.EvaluateArgmax(raw, argmaxBitLength, client)
		if err != nil {
			return nil, err
		}
		index := phe.Int{V: indexRaw}
		result.Indices = append(result.Indices, encrypted.NewCiphertext(c.publicUnboosted(), index))

		lastRound := round == k-1
		if lastRound && labels == nil {
			break
		}

		oneHot, err := c.oneHotIndex(cs, index, len(database), client)
		if err != nil {
			return nil, err
		}

		if labels != nil {
			label, err := cs.Encrypt(new(big.Int))
			if err != nil {
				return nil, err
			}
			for i, bit := range oneHot {
				plainLabel := phe.Normalize(big.NewInt(labels[i]), u)
				if plainLabel.Sign() == 0 {
					continue
				}
				term, err := cs.MultiplyByConstant(bit, plainLabel)
				if err != nil {
					return nil, err
				}
				if label, err = cs.Add(label, term); err != nil {
					return nil, err
				}
			}
			if label, err = cs.Reencrypt(label); err != nil {
				return nil, err
			}
			result.Labels = append(result.Labels, encrypted.NewCiphertext(c.publicUnboosted(), label))
		}

		if !lastRound {
			// every value except the found one is lifted by 2^bitLength:
			// value + offset (1 - bit)
			lift, err := cs.Encrypt(phe.Normalize(offset, u))
			if err != nil {
				return nil, err
			}
			negativeOffset := phe.Normalize(new(big.Int).Neg(offset), u)
			for i, bit := range oneHot {
				lifted, err := cs.Add(values[i], lift)
				if err != nil {
					return nil, err
				}
				term, err := cs.MultiplyByConstant(bit, negativeOffset)
				if err != nil {
					return nil, err
				}
				if values[i], err = cs.Add(lifted, term); err != nil {
					return nil, err
				}
			}
		}
	}
	return result, nil
}

// oneHotIndex turns an encrypted index into an encrypted one-hot vector with
// the client's help. Client receives E(r_i (index - i)) for random non-zero
// r_i in a random order, so it learns only that one of them is zero, but not
// its position.
func (c *Cryptosystem) oneHotIndex(cs phe.Homomorphic, index phe.Value, size int, client ArgmaxClient) ([]phe.Value, error) {
	u := cs.PlaintextModulo()
	order := make([]int, size)
	for i := range order {
		order[i] = i
	}
	for i := size - 1; i > 0; i-- {
		j, err := mathutil.RandBelow(big.NewInt(int64(i + 1)))
		if err != nil {
			return nil, err
		}
		order[i], order[j.Int64()] = order[j.Int64()], order[i]
	}

	blinded := make([]*big.Int, size)
	for position, i := range order {
		shift, err := cs.Encrypt(phe.Normalize(big.NewInt(int64(-i)), u))
		if err != nil {
			return nil, err
		}
		difference, err := cs.Add(index, shift)
		if err != nil {
			return nil, err
		}
		r, err := mathutil.RandRange(big.NewInt(1), new(big.Int).Sub(u, big.NewInt(1)))
		if err != nil {
			return nil, err
		}
		scaled, err := cs.MultiplyByConstant(difference, r)
		if err != nil {
			return nil, err
		}
		if scaled, err = cs.Reencrypt(scaled); err != nil {
			return nil, err
		}
		if blinded[position], err = phe.AsInt(scaled); err != nil {
			return nil, err
		}
	}

	response, err := client(ArgmaxMessage{Type: phe.ArgmaxEquality, Payload: blinded})
	if err != nil {
		return nil, err
	}
	if len(response) != size {
		return nil, fmt.Errorf("lightphe: client must answer %d ciphertexts, got %d", size, len(response))
	}
	oneHot := make([]phe.Value, size)
	for position, i := range order {
		oneHot[i] = phe.Int{V: response[position]}
	}
	return oneHot, nil
}

// AnswerKNN answers a message of the server during encrypted k nearest
// neighbor search. It runs on client side. Every value decrypted here is
// masked or shuffled, so client learns nothing but the final result. Only
// Damgard-Geisler-Kroigaard supports this.
func (c *Cryptosystem) AnswerKNN(message ArgmaxMessage) ([]*big.Int, error) {
	if err := c.requireKNNSupport(); err != nil {
		return nil, err
	}
	if !c.cs.HasPrivateKey() {
		return nil, phe.ErrMissingPrivateKey
	}
	if message.Type != phe.ArgmaxEquality {
		return c.AnswerArgmax(message)
	}
	cs := c.unboosted()
	tester, ok := cs.(zeroTester)
	if !ok {
		return nil, phe.Unsupportedf(c.algorithm, phe.OpNearestNeighbors)
	}
	out := make([]*big.Int, len(message.Payload))
	for i, ciphertext := range message.Payload {
		zero, err := tester.IsZero(ciphertext)
		if err != nil {
			return nil, err
		}
		bit := int64(0)
		if zero {
			bit = 1
		}
		value, err := cs.Encrypt(big.NewInt(bit))
		if err != nil {
			return nil, err
		}
		if out[i], err = phe.AsInt(value); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// EvaluateKNNDistances computes encrypted squared euclidean distances between
// an encrypted query and encrypted vectors. It runs on the side of an
// untrusted cloud storing the encrypted database of an owner, and requires
// the public key only. Both the query and the vectors are encrypted, so this
// requires WithBoost(CatalanoFiore) for one multiplication. Cloud learns
// nothing, and the owner finds the nearest vectors with DecryptKNN.
func (c *Cryptosystem) EvaluateKNNDistances(query []*encrypted.Ciphertext, database [][]*encrypted.Ciphertext) (
	[]*encrypted.Ciphertext, error) {
	if _, boosted := c.cs.(*catalanofiore.Cryptosystem); !boosted {
		return nil, fmt.Errorf("lightphe: encrypted distances between encrypted vectors require WithBoost(CatalanoFiore): %w",
			phe.ErrUnsupportedOperation)
	}
	isVector := func(vector []*encrypted.Ciphertext) bool {
		if len(vector) == 0 {
			return false
		}
		for _, ciphertext := range vector {
			if ciphertext == nil || !catalanofiore.IsFresh(ciphertext.Value) {
				return false
			}
		}
		return true
	}
	if !isVector(query) {
		return nil, fmt.Errorf("lightphe: encrypted query must be a non-empty list of encrypted integers")
	}
	if len(database) == 0 {
		return nil, fmt.Errorf("lightphe: encrypted database must be a non-empty list of vectors")
	}
	for _, vector := range database {
		if !isVector(vector) || len(vector) != len(query) {
			return nil, fmt.Errorf("lightphe: every vector of the database must be a list of %d encrypted integers", len(query))
		}
	}

	distances := make([]*encrypted.Ciphertext, len(database))
	err := parallelDo(len(database), func(i int) error {
		var total *encrypted.Ciphertext
		for j, x := range database[i] {
			negative, err := x.MultiplyByInt(-1)
			if err != nil {
				return err
			}
			difference, err := query[j].Add(negative)
			if err != nil {
				return err
			}
			square, err := difference.Multiply(difference)
			if err != nil {
				return err
			}
			if total == nil {
				total = square
			} else if total, err = total.Add(square); err != nil {
				return err
			}
		}
		distances[i] = total
		return nil
	})
	if err != nil {
		return nil, err
	}
	return distances, nil
}

// DecryptKNN finds the k nearest vectors from encrypted distances computed by
// EvaluateKNNDistances. It runs on owner side, and requires the private key.
// Earlier index is returned on ties.
func (c *Cryptosystem) DecryptKNN(distances []*encrypted.Ciphertext, k int) (*NearestNeighbors, error) {
	if !c.cs.HasPrivateKey() {
		return nil, phe.ErrMissingPrivateKey
	}
	if len(distances) == 0 {
		return nil, fmt.Errorf("lightphe: encrypted distances must be a non-empty list")
	}
	if k < 1 || k > len(distances) {
		return nil, fmt.Errorf("lightphe: k must be in [1, %d]", len(distances))
	}
	plain := make([]*big.Int, len(distances))
	for i, ciphertext := range distances {
		distance, err := c.Decrypt(ciphertext)
		if err != nil {
			return nil, err
		}
		plain[i] = distance
	}
	indices := make([]int, len(plain))
	for i := range indices {
		indices[i] = i
	}
	sort.SliceStable(indices, func(a, b int) bool { return plain[indices[a]].Cmp(plain[indices[b]]) < 0 })

	out := &NearestNeighbors{Indices: indices[:k], Distances: make([]*big.Int, k)}
	for i, index := range out.Indices {
		out.Distances[i] = plain[index]
	}
	return out, nil
}
