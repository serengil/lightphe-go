package phe

import (
	"fmt"
	"math/big"

	"github.com/serengil/lightphe-go/lightphe/ecc"
)

// Protocols beyond homomorphic operations. Only a few cryptosystems support
// them, so each one is an optional interface rather than a part of
// Homomorphic. Callers type-assert a cryptosystem to the interface and report
// the operation as unsupported when the assertion fails.

// NumericTree is either a leaf carrying a label, or a decision node that
// continues with IfLessOrEqual when the feature at Feature is less than or
// equal to Threshold, and with IfGreater otherwise. Build trees with
// NumericLeaf and NumericNode. Damgard-Geisler-Kroigaard evaluates them.
type NumericTree struct {
	// Value is the label of a leaf. It is nil for decision nodes.
	Value *big.Int

	// Feature is the index of the feature a decision node compares.
	Feature int

	// Threshold is the value the feature is compared with.
	Threshold int64

	// IfLessOrEqual and IfGreater are the sub trees of a decision node.
	IfLessOrEqual, IfGreater *NumericTree
}

// NumericLeaf builds a leaf that outputs label.
func NumericLeaf(label int64) *NumericTree {
	return &NumericTree{Value: big.NewInt(label)}
}

// NumericNode builds a decision node comparing the feature at index feature
// with threshold.
func NumericNode(feature int, threshold int64, ifLessOrEqual, ifGreater *NumericTree) *NumericTree {
	return &NumericTree{Feature: feature, Threshold: threshold, IfLessOrEqual: ifLessOrEqual, IfGreater: ifGreater}
}

// IsLeaf reports whether the tree is a leaf.
func (t *NumericTree) IsLeaf() bool { return t.Value != nil }

// Evaluate runs the tree on plain features.
func (t *NumericTree) Evaluate(features []int64) *big.Int {
	node := t
	for !node.IsLeaf() {
		if features[node.Feature] <= node.Threshold {
			node = node.IfLessOrEqual
		} else {
			node = node.IfGreater
		}
	}
	return new(big.Int).Set(node.Value)
}

// String implements fmt.Stringer.
func (t *NumericTree) String() string {
	if t.IsLeaf() {
		return t.Value.String()
	}
	return fmt.Sprintf("(%d, %d, %s, %s)", t.Feature, t.Threshold, t.IfLessOrEqual, t.IfGreater)
}

// DecisionTreeState is what the server keeps secret between the comparison
// and the leaf steps of a private decision tree evaluation.
type DecisionTreeState struct {
	Tree  *NumericTree
	Flips []int
}

// EncryptedLeaf is a leaf sent to the client in the last step of a private
// decision tree evaluation: E(r1 * cost) and E(r2 * cost + label). Only the
// reached leaf has cost 0.
type EncryptedLeaf struct {
	Cost  *big.Int `json:"cost"`
	Label *big.Int `json:"label"`
}

// Message types of encrypted argmax.
const (
	ArgmaxMaskedDifference = "masked_difference"
	ArgmaxComparisons      = "comparisons"
	ArgmaxProducts         = "products"
)

// ArgmaxMessage is a message the server sends to the client during encrypted
// argmax. Comparisons is set for the comparisons type, and Payload otherwise.
type ArgmaxMessage struct {
	Type        string       `json:"type"`
	Payload     []*big.Int   `json:"payload,omitempty"`
	Comparisons [][]*big.Int `json:"comparisons,omitempty"`
}

// ArgmaxClient delivers a message to the client and returns its response. It
// is the client's AnswerArgmax locally, or a network call otherwise.
type ArgmaxClient func(message ArgmaxMessage) ([]*big.Int, error)

// SecureComparer compares a client's encrypted value with a server's plain
// value.
type SecureComparer interface {
	EncryptComparisonInput(value int64, bitLength int) ([]*big.Int, error)
	EvaluateComparison(encryptedInput []*big.Int, value int64) ([]*big.Int, error)
	DecryptComparison(encryptedResult []*big.Int) (bool, error)
}

// NumericDecisionTreeEvaluator evaluates a server's decision tree with numeric
// thresholds on a client's encrypted features.
type NumericDecisionTreeEvaluator interface {
	EncryptDecisionTreeFeatures(features []int64, bitLength int) ([][]*big.Int, error)
	EvaluateDecisionTreeComparisons(tree *NumericTree, encryptedFeatures [][]*big.Int) ([][]*big.Int, *DecisionTreeState, error)
	AnswerDecisionTreeComparisons(encryptedComparisons [][]*big.Int) ([]*big.Int, error)
	EvaluateDecisionTreeLeaves(state *DecisionTreeState, encryptedAnswers []*big.Int) ([]EncryptedLeaf, error)
	DecryptDecisionTreeOutput(encryptedLeaves []EncryptedLeaf) (*big.Int, error)
}

// ArgmaxEvaluator finds the index of the maximum of encrypted values.
type ArgmaxEvaluator interface {
	EvaluateArgmax(encryptedValues []*big.Int, bitLength int, client ArgmaxClient) (*big.Int, error)
	AnswerArgmax(message ArgmaxMessage) ([]*big.Int, error)
}

// MasterKeyDecrypter decrypts ciphertexts of all users sharing a master key.
type MasterKeyDecrypter interface {
	// DecryptWithMasterKey decrypts a ciphertext encrypted for owner, which is
	// the cryptosystem of the user. The receiver's own public key is used if
	// owner is nil.
	DecryptWithMasterKey(ciphertext Value, owner Homomorphic) (*big.Int, error)

	// GenerateUserKeys generates JSON key material of a new user sharing the
	// master key.
	GenerateUserKeys() ([]byte, error)
}

// VerifiableCiphertext is the output of verifiable encryption: a ciphertext,
// a commitment to the secret and a proof that the ciphertext contains it.
type VerifiableCiphertext struct {
	Ciphertext []*big.Int `json:"ciphertext"`
	Commitment *big.Int   `json:"commitment"`
	Proof      *Proof     `json:"proof"`
}

// Proof is the non-interactive proof of a verifiable ciphertext.
type Proof struct {
	Challenge *big.Int `json:"challenge"`
	R         *big.Int `json:"r"`
	S         *big.Int `json:"s"`
	M         *big.Int `json:"m"`
}

// VerifiableEncrypter encrypts the discrete logarithm of an elliptic curve
// point and proves that the ciphertext contains it.
type VerifiableEncrypter interface {
	EncryptVerifiably(secret *big.Int, label string) (*VerifiableCiphertext, error)
	VerifyEncryption(ciphertext *VerifiableCiphertext, publicPoint ecc.Point, label string) (bool, error)
	DecryptVerifiableCiphertext(ciphertext *VerifiableCiphertext, label string) (*big.Int, error)
}
