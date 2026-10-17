package lightphe_test

import (
	"errors"
	"math/big"
	"math/rand"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/serengil/lightphe-go/lightphe"
	"github.com/serengil/lightphe-go/lightphe/encrypted"
	"github.com/serengil/lightphe-go/lightphe/phe"
)

func TestDamgardGeislerKroigaardAPI(t *testing.T) {
	cs := mustBuild(t, phe.DamgardGeislerKroigaard, lightphe.WithKeySize(testKeySize))
	modulo := cs.PlaintextModulo()

	const m1, m2 = 3, 4
	c1 := mustEncrypt(t, cs, m1)
	c2 := mustEncrypt(t, cs, m2)

	// proof of decryption
	assertDecrypts(t, cs, c1, m1)
	assertDecrypts(t, cs, c2, m2)

	// homomorphic addition and scalar multiplication wrap around the small
	// plaintext space
	sum, err := c1.Add(c2)
	if err != nil {
		t.Fatalf("homomorphic addition: %v", err)
	}
	assertDecrypts(t, cs, sum, new(big.Int).Mod(big.NewInt(m1+m2), modulo).Int64())

	scaled, err := c1.MultiplyByInt(m2)
	if err != nil {
		t.Fatalf("scalar multiplication: %v", err)
	}
	assertDecrypts(t, cs, scaled, new(big.Int).Mod(big.NewInt(m1*m2), modulo).Int64())

	// negative plaintexts
	c3 := mustEncrypt(t, cs, -2)
	assertDecrypts(t, cs, c3, modulo.Int64()-2)
	wrapped, err := c1.Add(c3)
	if err != nil {
		t.Fatalf("homomorphic addition: %v", err)
	}
	assertDecrypts(t, cs, wrapped, m1-2)

	// re-randomization
	regenerated, err := cs.RegenerateCiphertext(c1)
	if err != nil {
		t.Fatalf("regenerating: %v", err)
	}
	if regenerated.Value.Equal(c1.Value) {
		t.Fatal("regenerated ciphertext is identical to the original")
	}
	assertDecrypts(t, cs, regenerated, m1)

	// unsupported homomorphic operations
	_, err = c1.Multiply(c2)
	assertUnsupported(t, "multiplication", err)
	_, err = c1.Xor(c2)
	assertUnsupported(t, "exclusive or", err)
	_, err = c1.And(c2)
	assertUnsupported(t, "bitwise and", err)
}

func TestDamgardGeislerKroigaardAllPlaintextsInSmallSpace(t *testing.T) {
	cs := mustBuild(t, phe.DamgardGeislerKroigaard, lightphe.WithKeySize(32))
	modulo := cs.PlaintextModulo().Int64()
	for m := int64(0); m < modulo; m++ {
		assertDecrypts(t, cs, mustEncrypt(t, cs, m), m)
	}
}

func TestDamgardGeislerKroigaardLargeKeys(t *testing.T) {
	if testing.Short() {
		t.Skip("1024-bit keys are slow")
	}
	cs := mustBuild(t, phe.DamgardGeislerKroigaard, lightphe.WithKeySize(1024))
	modulo := cs.PlaintextModulo()

	const m1, m2 = 123456789, 987654321
	c1 := mustEncrypt(t, cs, m1)
	c2 := mustEncrypt(t, cs, m2)
	sum, err := c1.Add(c2)
	if err != nil {
		t.Fatalf("homomorphic addition: %v", err)
	}
	want := new(big.Int).Mod(big.NewInt(m1+m2), modulo)
	if got := mustDecrypt(t, cs, sum); got.Cmp(want) != 0 {
		t.Fatalf("decrypted %s, want %s", got, want)
	}

	// floats and tensors
	tensor, err := cs.EncryptTensor([]float64{1.5, 2.25, 3.5})
	if err != nil {
		t.Fatalf("encrypting a tensor: %v", err)
	}
	plain, err := cs.DecryptTensor(tensor)
	if err != nil {
		t.Fatalf("decrypting a tensor: %v", err)
	}
	if !reflect.DeepEqual(plain, []float64{1.5, 2.25, 3.5}) {
		t.Fatalf("tensor decrypted to %v", plain)
	}
}

// protocol cryptosystems of secure comparison, private decision trees and
// argmax: the client holds the private key and the server the public key.
var (
	protocolOnce   sync.Once
	protocolClient *lightphe.Cryptosystem
	protocolServer *lightphe.Cryptosystem
)

func protocolParties(t *testing.T) (*lightphe.Cryptosystem, *lightphe.Cryptosystem) {
	t.Helper()
	protocolOnce.Do(func() {
		client, err := lightphe.New(phe.DamgardGeislerKroigaard, lightphe.WithKeySize(256))
		if err != nil {
			t.Fatalf("building the client: %v", err)
		}
		keys, err := client.Keys(true)
		if err != nil {
			t.Fatalf("exporting the public key: %v", err)
		}
		server, err := lightphe.New(phe.DamgardGeislerKroigaard, lightphe.WithKeys(keys))
		if err != nil {
			t.Fatalf("building the server: %v", err)
		}
		protocolClient, protocolServer = client, server
	})
	if protocolClient == nil {
		t.Fatal("protocol parties could not be built")
	}
	return protocolClient, protocolServer
}

func runPrivateDecisionTree(t *testing.T, tree *lightphe.NumericTree, features []int64, bitLength int) *big.Int {
	t.Helper()
	client, server := protocolParties(t)

	encryptedFeatures, err := client.EncryptDecisionTreeFeatures(features, bitLength)
	if err != nil {
		t.Fatalf("encrypting features: %v", err)
	}
	comparisons, state, err := server.EvaluateDecisionTreeComparisons(tree, encryptedFeatures)
	if err != nil {
		t.Fatalf("evaluating comparisons: %v", err)
	}
	answers, err := client.AnswerDecisionTreeComparisons(comparisons)
	if err != nil {
		t.Fatalf("answering comparisons: %v", err)
	}
	leaves, err := server.EvaluateDecisionTreeLeaves(state, answers)
	if err != nil {
		t.Fatalf("evaluating leaves: %v", err)
	}
	label, err := client.DecryptDecisionTreeOutput(leaves)
	if err != nil {
		t.Fatalf("decrypting the output: %v", err)
	}
	return label
}

func TestSecureComparisonAllPairs(t *testing.T) {
	client, server := protocolParties(t)
	const bitLength = 4
	for x := int64(0); x < 1<<bitLength; x++ {
		encryptedX, err := client.EncryptComparisonInput(x, bitLength)
		if err != nil {
			t.Fatalf("encrypting %d: %v", x, err)
		}
		if len(encryptedX) != bitLength {
			t.Fatalf("got %d encrypted bits, want %d", len(encryptedX), bitLength)
		}
		for y := int64(0); y < 1<<bitLength; y++ {
			result, err := server.EvaluateComparison(encryptedX, y)
			if err != nil {
				t.Fatalf("comparing: %v", err)
			}
			if len(result) != bitLength+1 {
				t.Fatalf("got %d blinded ciphertexts, want %d", len(result), bitLength+1)
			}
			got, err := client.DecryptComparison(result)
			if err != nil {
				t.Fatalf("decrypting the comparison: %v", err)
			}
			if got != (x <= y) {
				t.Fatalf("%d <= %d decrypted to %v", x, y, got)
			}
		}
	}
}

func TestSecureComparisonEdgeValues(t *testing.T) {
	client, server := protocolParties(t)
	const bitLength = 16
	max := int64(1)<<bitLength - 1
	for _, pair := range [][2]int64{{0, 0}, {0, max}, {max, 0}, {max, max}, {max - 1, max}, {max, max - 1}} {
		encryptedX, err := client.EncryptComparisonInput(pair[0], bitLength)
		if err != nil {
			t.Fatalf("encrypting: %v", err)
		}
		result, err := server.EvaluateComparison(encryptedX, pair[1])
		if err != nil {
			t.Fatalf("comparing: %v", err)
		}
		if got, err := client.DecryptComparison(result); err != nil || got != (pair[0] <= pair[1]) {
			t.Fatalf("%d <= %d decrypted to %v (%v)", pair[0], pair[1], got, err)
		}
	}
}

func TestSecureComparisonInvalidInputs(t *testing.T) {
	client, server := protocolParties(t)

	for _, value := range []int64{-1, 16} {
		if _, err := client.EncryptComparisonInput(value, 4); err == nil {
			t.Fatalf("encrypting %d with 4 bits was accepted", value)
		}
	}
	encryptedX, err := client.EncryptComparisonInput(3, 4)
	if err != nil {
		t.Fatalf("encrypting: %v", err)
	}
	if _, err := server.EvaluateComparison(encryptedX, 16); err == nil {
		t.Fatal("comparing with a value out of range was accepted")
	}

	// plaintext space is too small for long bit lengths
	bitLength := int(client.PlaintextModulo().Int64() / 3)
	if _, err := client.EncryptComparisonInput(0, bitLength); err == nil || !strings.Contains(err.Error(), "too small") {
		t.Fatalf("comparing %d-bit values returned %v", bitLength, err)
	}

	// client side requires private key
	if _, err := server.DecryptComparison(encryptedX); !errors.Is(err, phe.ErrMissingPrivateKey) {
		t.Fatalf("decrypting a comparison without a private key returned %v", err)
	}
}

func TestPrivateDecisionTree(t *testing.T) {
	// loan approval: features are 0 (age), 1 (income in thousand dollars) and
	// 2 (number of open loans), and leaves are credit limits in thousand
	// dollars.
	//
	//                         F1: income <= 40?
	//                       /yes                 \no
	//           F0: age <= 25?               F2: open loans <= 2?
	//            /yes      \no                 /yes             \no
	//           0    F2: open loans <= 1?   F1: income <= 100?   10
	//                  /yes       \no         /yes       \no
	//                 5            0         20           50
	tree := lightphe.NumericNode(1, 40,
		lightphe.NumericNode(0, 25, lightphe.NumericLeaf(0), lightphe.NumericNode(2, 1, lightphe.NumericLeaf(5), lightphe.NumericLeaf(0))),
		lightphe.NumericNode(2, 2, lightphe.NumericNode(1, 100, lightphe.NumericLeaf(20), lightphe.NumericLeaf(50)), lightphe.NumericLeaf(10)),
	)
	samples := [][]int64{
		{22, 30, 0}, {30, 30, 1}, {30, 30, 3}, {40, 41, 0},
		{40, 100, 2}, {40, 101, 2}, {50, 200, 3}, {25, 40, 1},
	}
	for _, features := range samples {
		want := tree.Evaluate(features)
		// comparisons are flipped randomly, so run each sample several times
		for i := 0; i < 3; i++ {
			if got := runPrivateDecisionTree(t, tree, features, 8); got.Cmp(want) != 0 {
				t.Fatalf("%v evaluated to %s, want %s", features, got, want)
			}
		}
	}
}

func TestPrivateDecisionTreeAllInputs(t *testing.T) {
	tree := lightphe.NumericNode(0, 1,
		lightphe.NumericNode(1, 2, lightphe.NumericLeaf(1), lightphe.NumericLeaf(2)),
		lightphe.NumericNode(1, 0, lightphe.NumericLeaf(3), lightphe.NumericNode(0, 2, lightphe.NumericLeaf(4), lightphe.NumericLeaf(5))),
	)
	for a := int64(0); a < 4; a++ {
		for b := int64(0); b < 4; b++ {
			features := []int64{a, b}
			if got, want := runPrivateDecisionTree(t, tree, features, 2), tree.Evaluate(features); got.Cmp(want) != 0 {
				t.Fatalf("%v evaluated to %s, want %s", features, got, want)
			}
		}
	}
}

func TestPrivateDecisionTreeSingleLeaf(t *testing.T) {
	if got := runPrivateDecisionTree(t, lightphe.NumericLeaf(7), []int64{1, 2}, 4); got.Int64() != 7 {
		t.Fatalf("single leaf evaluated to %s, want 7", got)
	}
}

func TestPrivateDecisionTreeInvalidInputs(t *testing.T) {
	client, server := protocolParties(t)
	encryptedFeatures, err := client.EncryptDecisionTreeFeatures([]int64{1, 2}, 4)
	if err != nil {
		t.Fatalf("encrypting features: %v", err)
	}

	leaf0, leaf1 := lightphe.NumericLeaf(0), lightphe.NumericLeaf(1)
	if _, _, err := server.EvaluateDecisionTreeComparisons(lightphe.NumericNode(2, 1, leaf0, leaf1), encryptedFeatures); err == nil ||
		!strings.Contains(err.Error(), "feature index 2 does not exist") {
		t.Fatalf("missing feature returned %v", err)
	}
	if _, _, err := server.EvaluateDecisionTreeComparisons(lightphe.NumericNode(0, 0, leaf1, nil), encryptedFeatures); err == nil ||
		!strings.Contains(err.Error(), "must have both sub trees") {
		t.Fatalf("malformed node returned %v", err)
	}

	_, state, err := server.EvaluateDecisionTreeComparisons(lightphe.NumericNode(0, 1, leaf0, lightphe.NumericLeaf(-1)), encryptedFeatures)
	if err != nil {
		t.Fatalf("evaluating comparisons: %v", err)
	}
	zero := mustEncrypt(t, client, 0)
	answer, _ := phe.AsInt(zero.Value)
	if _, err := server.EvaluateDecisionTreeLeaves(state, []*big.Int{answer}); err == nil ||
		!strings.Contains(err.Error(), "leaf labels must be") {
		t.Fatalf("negative leaf label returned %v", err)
	}

	_, state, err = server.EvaluateDecisionTreeComparisons(lightphe.NumericNode(0, 1, leaf0, leaf1), encryptedFeatures)
	if err != nil {
		t.Fatalf("evaluating comparisons: %v", err)
	}
	if _, err := server.EvaluateDecisionTreeLeaves(state, nil); err == nil ||
		!strings.Contains(err.Error(), "expected 1 answers but got 0") {
		t.Fatalf("missing answers returned %v", err)
	}
}

func TestComparisonProtocolsAreUnsupportedByOtherSchemes(t *testing.T) {
	cs := mustBuild(t, phe.Paillier, lightphe.WithKeySize(testKeySize))

	_, err := cs.EncryptComparisonInput(1, 4)
	assertUnsupported(t, "secure comparison", err)
	_, err = cs.EvaluateComparison([]*big.Int{big.NewInt(1)}, 1)
	assertUnsupported(t, "secure comparison", err)
	_, err = cs.EncryptDecisionTreeFeatures([]int64{1}, 4)
	assertUnsupported(t, "private decision tree", err)
	_, _, err = cs.EvaluateDecisionTreeComparisons(lightphe.NumericNode(0, 1, lightphe.NumericLeaf(0), lightphe.NumericLeaf(1)), nil)
	assertUnsupported(t, "private decision tree", err)
	_, err = cs.EvaluateArgmax(nil, 8, cs.AnswerArgmax)
	assertUnsupported(t, "encrypted argmax", err)
	_, err = cs.AnswerArgmax(lightphe.ArgmaxMessage{Type: phe.ArgmaxProducts})
	assertUnsupported(t, "encrypted argmax", err)

	// Ishai-Paskin evaluates decision trees on bits only
	ip := mustBuild(t, phe.IshaiPaskin, lightphe.WithKeySize(testKeySize))
	_, err = ip.EncryptDecisionTreeFeatures([]int64{1}, 4)
	assertUnsupported(t, "private decision tree on Ishai-Paskin", err)

	// and Damgard-Geisler-Kroigaard on numeric features only
	dgk, _ := protocolParties(t)
	_, err = dgk.EncryptDecisionTreeInput([]int{1}, 1)
	assertUnsupported(t, "decision tree with bits on Damgard-Geisler-Kroigaard", err)
}

func runArgmax(t *testing.T, values []int64, bitLength int) int64 {
	t.Helper()
	client, server := protocolParties(t)
	encryptedValues := make([]*encrypted.Ciphertext, len(values))
	for i, v := range values {
		encryptedValues[i] = mustEncrypt(t, client, v)
	}
	index, err := server.EvaluateArgmax(encryptedValues, bitLength, client.AnswerArgmax)
	if err != nil {
		t.Fatalf("evaluating argmax of %v: %v", values, err)
	}
	return mustDecrypt(t, client, index).Int64()
}

// firstArgmax is the index of the first maximum.
func firstArgmax(values []int64) int64 {
	best := 0
	for i, v := range values {
		if v > values[best] {
			best = i
		}
	}
	return int64(best)
}

func TestArgmax(t *testing.T) {
	cases := [][]int64{
		{5}, {3, 9}, {9, 3}, {7, 7}, {1, 7, 3, 7}, {0, 0, 0, 0}, {255, 0, 254},
		{10, 20, 30, 40, 50}, {50, 40, 30, 20, 10}, {12, 200, 3, 199, 255, 17},
	}
	for _, values := range cases {
		if got, want := runArgmax(t, values, 8), firstArgmax(values); got != want {
			t.Fatalf("argmax of %v is %d, want %d", values, got, want)
		}
	}
}

func TestArgmaxRandomValues(t *testing.T) {
	rng := rand.New(rand.NewSource(42))
	// masks are random, so the comparison arc wraps around u in some rounds
	for i := 0; i < 30; i++ {
		bitLength := []int{1, 4, 8, 12}[rng.Intn(4)]
		values := make([]int64, 1+rng.Intn(6))
		for j := range values {
			values[j] = rng.Int63n(1 << uint(bitLength))
		}
		if got, want := runArgmax(t, values, bitLength), firstArgmax(values); got != want {
			t.Fatalf("argmax of %v is %d, want %d", values, got, want)
		}
	}
}

func TestArgmaxOfLinearClassifier(t *testing.T) {
	client, server := protocolParties(t)

	// client's encrypted features, server's private linear model with 3 classes
	features := []int64{3, 1, 4}
	weights := [][]int64{{1, 2, 0}, {0, 1, 3}, {2, 0, 1}}
	encryptedFeatures := make([]*encrypted.Ciphertext, len(features))
	for i, f := range features {
		encryptedFeatures[i] = mustEncrypt(t, client, f)
	}

	// server computes encrypted class scores homomorphically
	scores := make([]*encrypted.Ciphertext, len(weights))
	for i, classWeights := range weights {
		score, err := encryptedFeatures[0].MultiplyByInt(classWeights[0])
		if err != nil {
			t.Fatalf("scalar multiplication: %v", err)
		}
		for j := 1; j < len(features); j++ {
			term, err := encryptedFeatures[j].MultiplyByInt(classWeights[j])
			if err != nil {
				t.Fatalf("scalar multiplication: %v", err)
			}
			if score, err = score.Add(term); err != nil {
				t.Fatalf("homomorphic addition: %v", err)
			}
		}
		scores[i] = score
	}

	class, err := server.EvaluateArgmax(scores, 8, client.AnswerArgmax)
	if err != nil {
		t.Fatalf("evaluating argmax: %v", err)
	}
	assertDecrypts(t, client, class, 1)
}

func TestArgmaxClientSeesOnlyMaskedValues(t *testing.T) {
	client, server := protocolParties(t)
	var seen []string
	relay := func(message lightphe.ArgmaxMessage) ([]*big.Int, error) {
		seen = append(seen, message.Type)
		return client.AnswerArgmax(message)
	}

	values := []int64{10, 200, 30}
	encryptedValues := make([]*encrypted.Ciphertext, len(values))
	for i, v := range values {
		encryptedValues[i] = mustEncrypt(t, client, v)
	}
	index, err := server.EvaluateArgmax(encryptedValues, 8, relay)
	if err != nil {
		t.Fatalf("evaluating argmax: %v", err)
	}
	assertDecrypts(t, client, index, 1)

	// 3 round trips for each of the remaining 2 values
	round := []string{phe.ArgmaxMaskedDifference, phe.ArgmaxComparisons, phe.ArgmaxProducts}
	if want := append(append([]string{}, round...), round...); !reflect.DeepEqual(seen, want) {
		t.Fatalf("client saw %v, want %v", seen, want)
	}
}

func TestArgmaxLargeKeys(t *testing.T) {
	if testing.Short() {
		t.Skip("1024-bit keys are slow")
	}
	cs := mustBuild(t, phe.DamgardGeislerKroigaard, lightphe.WithKeySize(1024))
	values := []int64{40000, 65535, 3, 65534}
	encryptedValues := make([]*encrypted.Ciphertext, len(values))
	for i, v := range values {
		encryptedValues[i] = mustEncrypt(t, cs, v)
	}
	index, err := cs.EvaluateArgmax(encryptedValues, 16, cs.AnswerArgmax)
	if err != nil {
		t.Fatalf("evaluating argmax: %v", err)
	}
	assertDecrypts(t, cs, index, 1)
}

func TestArgmaxInvalidInputs(t *testing.T) {
	client, server := protocolParties(t)

	if _, err := server.EvaluateArgmax(nil, 8, client.AnswerArgmax); err == nil || !strings.Contains(err.Error(), "at least one value") {
		t.Fatalf("argmax of no values returned %v", err)
	}
	one := mustEncrypt(t, client, 1)
	bitLength := client.PlaintextModulo().BitLen()
	if _, err := server.EvaluateArgmax([]*encrypted.Ciphertext{one, one}, bitLength, client.AnswerArgmax); err == nil ||
		!strings.Contains(err.Error(), "too small for argmax") {
		t.Fatalf("argmax of %d-bit values returned %v", bitLength, err)
	}
	if _, err := client.AnswerArgmax(lightphe.ArgmaxMessage{Type: "unknown"}); err == nil ||
		!strings.Contains(err.Error(), "unknown argmax message type") {
		t.Fatalf("unknown message returned %v", err)
	}

	// client side requires private key
	if _, err := server.AnswerArgmax(lightphe.ArgmaxMessage{Type: phe.ArgmaxProducts}); !errors.Is(err, phe.ErrMissingPrivateKey) {
		t.Fatalf("answering without a private key returned %v", err)
	}
}

func TestReadmeNumericDecisionTree(t *testing.T) {
	publicFile := filepath.Join(t.TempDir(), "public.json")

	//                   F1: income <= 40?
	//                  /yes                \no
	//        F0: age <= 25?          F2: open loans <= 2?
	//         /yes      \no            /yes           \no
	//        0           5            20              10
	creditLimitTree := lightphe.NumericNode(1, 40,
		lightphe.NumericNode(0, 25, lightphe.NumericLeaf(0), lightphe.NumericLeaf(5)),
		lightphe.NumericNode(2, 2, lightphe.NumericLeaf(20), lightphe.NumericLeaf(10)),
	)

	// customer: age = 30, income = 75 and open loans = 1
	customer := mustBuild(t, phe.DamgardGeislerKroigaard, lightphe.WithKeySize(256))
	if err := customer.ExportKeys(publicFile, true); err != nil {
		t.Fatalf("exporting the public key: %v", err)
	}
	encryptedFeatures, err := customer.EncryptDecisionTreeFeatures([]int64{30, 75, 1}, 8)
	if err != nil {
		t.Fatalf("encrypting features: %v", err)
	}

	// bank, having the customer's public key only
	bank := mustBuild(t, phe.DamgardGeislerKroigaard, lightphe.WithKeyFile(publicFile))
	comparisons, state, err := bank.EvaluateDecisionTreeComparisons(creditLimitTree, encryptedFeatures)
	if err != nil {
		t.Fatalf("evaluating comparisons: %v", err)
	}

	// customer answers randomly flipped comparisons
	answers, err := customer.AnswerDecisionTreeComparisons(comparisons)
	if err != nil {
		t.Fatalf("answering comparisons: %v", err)
	}

	// bank keeps the state secret and finds the reached leaf in encrypted form
	leaves, err := bank.EvaluateDecisionTreeLeaves(state, answers)
	if err != nil {
		t.Fatalf("evaluating leaves: %v", err)
	}

	// customer learns only the credit limit
	limit, err := customer.DecryptDecisionTreeOutput(leaves)
	if err != nil {
		t.Fatalf("decrypting the output: %v", err)
	}
	if limit.Int64() != 20 {
		t.Fatalf("credit limit is %s, want 20", limit)
	}
}

func TestReadmeSecureComparison(t *testing.T) {
	publicFile := filepath.Join(t.TempDir(), "public.json")

	client := mustBuild(t, phe.DamgardGeislerKroigaard, lightphe.WithKeySize(256))
	if err := client.ExportKeys(publicFile, true); err != nil {
		t.Fatalf("exporting the public key: %v", err)
	}
	encryptedBid, err := client.EncryptComparisonInput(120, 16)
	if err != nil {
		t.Fatalf("encrypting the bid: %v", err)
	}

	server := mustBuild(t, phe.DamgardGeislerKroigaard, lightphe.WithKeyFile(publicFile))
	result, err := server.EvaluateComparison(encryptedBid, 150)
	if err != nil {
		t.Fatalf("comparing: %v", err)
	}

	if ok, err := client.DecryptComparison(result); err != nil || !ok {
		t.Fatalf("120 <= 150 decrypted to %v (%v)", ok, err)
	}
}
