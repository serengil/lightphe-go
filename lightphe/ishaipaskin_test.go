package lightphe_test

import (
	"errors"
	"math/big"
	"path/filepath"
	"testing"

	"github.com/serengil/lightphe-go/lightphe"
	"github.com/serengil/lightphe-go/lightphe/phe"
	"github.com/serengil/lightphe-go/lightphe/schemes/ishaipaskin"
)

// allBits enumerates every input of the given width.
func allBits(width int) [][]int {
	var out [][]int
	for i := 0; i < 1<<width; i++ {
		bits := make([]int, width)
		for j := 0; j < width; j++ {
			bits[j] = (i >> (width - 1 - j)) & 1
		}
		out = append(out, bits)
	}
	return out
}

// assertTree checks an encrypted evaluation against the plain one for every
// input of the given width.
func assertTree(t *testing.T, cs *lightphe.Cryptosystem, tree *lightphe.DecisionTree, width, depth int) {
	t.Helper()
	if depth == 0 {
		depth = tree.Depth()
		if depth == 0 {
			depth = 1
		}
	}
	for _, bits := range allBits(width) {
		encryptedInput, err := cs.EncryptDecisionTreeInput(bits, depth)
		if err != nil {
			t.Fatalf("encrypting input %v: %v", bits, err)
		}
		output, err := cs.EvaluateDecisionTree(tree, encryptedInput)
		if err != nil {
			t.Fatalf("evaluating %s on %v: %v", tree, bits, err)
		}
		if got, want := mustDecrypt(t, cs, output), tree.Evaluate(bits); got.Cmp(want) != 0 {
			t.Fatalf("%s on %v decrypted to %s, want %s", tree, bits, got, want)
		}
	}
}

func TestIshaiPaskinAPI(t *testing.T) {
	cs := mustBuild(t, phe.IshaiPaskin, lightphe.WithKeySize(testKeySize))

	// homomorphic addition and scalar multiplication inherited from Damgard-Jurik
	const m1, m2 = 17, 21
	c1 := mustEncrypt(t, cs, m1)
	c2 := mustEncrypt(t, cs, m2)

	sum, err := c1.Add(c2)
	if err != nil {
		t.Fatalf("homomorphic addition: %v", err)
	}
	assertDecrypts(t, cs, sum, m1+m2)

	scaled, err := c1.MultiplyByInt(m2)
	if err != nil {
		t.Fatalf("scalar multiplication: %v", err)
	}
	assertDecrypts(t, cs, scaled, m1*m2)

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
}

func TestIshaiPaskinEncryptionLevels(t *testing.T) {
	cs := mustBuild(t, phe.IshaiPaskin, lightphe.WithKeySize(testKeySize))
	ip := cs.Scheme().(*ishaipaskin.Cryptosystem)
	n := cs.PlaintextModulo()

	for level := 1; level <= 4; level++ {
		space := new(big.Int).Exp(n, big.NewInt(int64(level)), nil)
		ciphertextSpace := new(big.Int).Mul(space, n)

		// plaintext space of level s is Z_{n^s}
		for _, raw := range []*big.Int{
			big.NewInt(0), big.NewInt(1), big.NewInt(12345),
			new(big.Int).Add(n, big.NewInt(7)), new(big.Int).Sub(space, big.NewInt(1)),
		} {
			m := new(big.Int).Mod(raw, space)
			c, err := ip.EncryptAtLevel(m, level)
			if err != nil {
				t.Fatalf("encrypting at level %d: %v", level, err)
			}
			if c.Cmp(ciphertextSpace) >= 0 {
				t.Fatalf("level %d ciphertext exceeds n^(s+1)", level)
			}
			got, err := ip.DecryptAtLevel(c, level)
			if err != nil {
				t.Fatalf("decrypting at level %d: %v", level, err)
			}
			if got.Cmp(m) != 0 {
				t.Fatalf("level %d decrypted %s, want %s", level, got, m)
			}
		}

		// level s is additively homomorphic in Z_{n^s}
		c1, _ := ip.EncryptAtLevel(new(big.Int).Sub(space, big.NewInt(3)), level)
		c2, _ := ip.EncryptAtLevel(big.NewInt(10), level)
		product := new(big.Int).Mul(c1, c2)
		product.Mod(product, ciphertextSpace)
		if got, _ := ip.DecryptAtLevel(product, level); got.Int64() != 7 {
			t.Fatalf("level %d addition decrypted %s, want 7", level, got)
		}
	}
}

func TestIshaiPaskinBooleanTrees(t *testing.T) {
	cs := mustBuild(t, phe.IshaiPaskin, lightphe.WithKeySize(testKeySize))
	leaf, node := lightphe.Leaf, lightphe.Node

	assertTree(t, cs, node(0, node(1, leaf(0), leaf(1)), leaf(1)), 2, 0) // x0 OR x1
	assertTree(t, cs, node(0, leaf(0), node(1, leaf(0), leaf(1))), 2, 0) // x0 AND x1
	assertTree(t, cs, node(1, leaf(1), leaf(0)), 2, 0)                   // NOT x1

	// shared sub trees (DAG) are evaluated once
	x2Is0 := node(2, leaf(1), leaf(0))
	x2Is1 := node(2, leaf(0), leaf(1))
	x1XorX2 := node(1, x2Is1, x2Is0)
	x1XnorX2 := node(1, x2Is0, x2Is1)
	assertTree(t, cs, node(0, x1XorX2, x1XnorX2), 3, 0)

	majority := node(0, node(1, leaf(0), node(2, leaf(0), leaf(1))), node(1, node(2, leaf(0), leaf(1)), leaf(1)))
	assertTree(t, cs, majority, 3, 0)
}

func TestIshaiPaskinDecisionTreeWithNonBinaryLeaves(t *testing.T) {
	cs := mustBuild(t, phe.IshaiPaskin, lightphe.WithKeySize(testKeySize))
	leaf, node := lightphe.Leaf, lightphe.Node

	// leaves at different depths returning class labels
	decisionTree := node(0, node(1, leaf(10), node(2, leaf(20), leaf(30))), leaf(40))
	assertTree(t, cs, decisionTree, 3, 0)

	// encrypted input can be prepared for deeper trees than evaluated one
	assertTree(t, cs, decisionTree, 3, 5)

	// constant tree
	assertTree(t, cs, leaf(99), 1, 0)
}

func TestIshaiPaskinOutputIsRerandomized(t *testing.T) {
	cs := mustBuild(t, phe.IshaiPaskin, lightphe.WithKeySize(testKeySize))
	tree := lightphe.Node(0, lightphe.Node(1, lightphe.Leaf(0), lightphe.Leaf(1)), lightphe.Leaf(1))

	encryptedInput, err := cs.EncryptDecisionTreeInput([]int{1, 0}, 2)
	if err != nil {
		t.Fatalf("encrypting input: %v", err)
	}
	output1, err := cs.EvaluateDecisionTree(tree, encryptedInput)
	if err != nil {
		t.Fatalf("evaluating: %v", err)
	}
	output2, err := cs.EvaluateDecisionTree(tree, encryptedInput)
	if err != nil {
		t.Fatalf("evaluating: %v", err)
	}

	// output always wraps as many layers as the tree depth
	level1, value1, _ := phe.AsPair(output1.Value)
	level2, value2, _ := phe.AsPair(output2.Value)
	if !level1.Equal(phe.Int{V: big.NewInt(2)}) || !level2.Equal(phe.Int{V: big.NewInt(2)}) {
		t.Fatalf("outputs are at levels %s and %s, want 2", level1, level2)
	}
	if value1.Equal(value2) {
		t.Fatal("two evaluations produced the same ciphertext")
	}
	assertDecrypts(t, cs, output1, 1)
	assertDecrypts(t, cs, output2, 1)
}

func TestIshaiPaskinCreditLimitExampleInReadme(t *testing.T) {
	leaf, node := lightphe.Leaf, lightphe.Node

	// bank's secret tree: Q0 = has stable income?, Q1 = has existing debt?,
	// Q2 = owns a house?, leaves are credit limits in thousand dollars
	creditLimitTree := node(0,
		node(2, leaf(0), leaf(5)),
		node(1, leaf(20), node(2, leaf(5), leaf(10))),
	)

	// customer builds the cryptosystem and keeps the private key
	customerCs := mustBuild(t, lightphe.IshaiPaskin, lightphe.WithKeySize(testKeySize))

	// customer shares only the public key with the bank
	publicKeyFile := filepath.Join(t.TempDir(), "public.txt")
	if err := customerCs.ExportKeys(publicKeyFile, true); err != nil {
		t.Fatalf("exporting the public key: %v", err)
	}

	// bank builds its own cryptosystem with the customer's public key
	bankCs := mustBuild(t, lightphe.IshaiPaskin, lightphe.WithKeyFile(publicKeyFile))
	if bankCs.HasPrivateKey() {
		t.Fatal("the bank must not hold a private key")
	}

	// every path of the tree drawn in the readme
	expectedLimits := []struct {
		answers []int
		limit   int64
	}{
		{[]int{0, 0, 0}, 0},
		{[]int{0, 1, 0}, 0},
		{[]int{0, 0, 1}, 5},
		{[]int{0, 1, 1}, 5},
		{[]int{1, 0, 0}, 20},
		{[]int{1, 0, 1}, 20},
		{[]int{1, 1, 0}, 5},
		{[]int{1, 1, 1}, 10},
	}

	var encryptedLimit *lightphe.Ciphertext
	for _, tc := range expectedLimits {
		// customer encrypts the answers and sends them to the bank
		encryptedAnswers, err := customerCs.EncryptDecisionTreeInput(tc.answers, 3)
		if err != nil {
			t.Fatalf("encrypting answers: %v", err)
		}

		// bank runs its tree on encrypted answers
		encryptedLimit, err = bankCs.EvaluateDecisionTree(creditLimitTree, encryptedAnswers)
		if err != nil {
			t.Fatalf("evaluating the tree: %v", err)
		}
		if encryptedLimit.Scheme().HasPrivateKey() {
			t.Fatal("the encrypted limit exposes a private key")
		}

		// customer decrypts the result
		assertDecrypts(t, customerCs, encryptedLimit, tc.limit)
	}

	// bank cannot decrypt the result
	if _, err := bankCs.Decrypt(encryptedLimit); !errors.Is(err, lightphe.ErrMissingPrivateKey) {
		t.Fatalf("the bank decrypting returned %v, want ErrMissingPrivateKey", err)
	}

	// output can only be decrypted, homomorphic operations are not supported
	if _, err := encryptedLimit.Add(encryptedLimit); !errors.Is(err, ishaipaskin.ErrDecisionTreeOutput) {
		t.Fatalf("adding outputs returned %v, want ErrDecisionTreeOutput", err)
	}
	if _, err := encryptedLimit.MultiplyByInt(2); !errors.Is(err, ishaipaskin.ErrDecisionTreeOutput) {
		t.Fatalf("scaling an output returned %v, want ErrDecisionTreeOutput", err)
	}
	if _, err := customerCs.RegenerateCiphertext(encryptedLimit); !errors.Is(err, ishaipaskin.ErrDecisionTreeOutput) {
		t.Fatalf("regenerating an output returned %v, want ErrDecisionTreeOutput", err)
	}
}

func TestIshaiPaskinInvalidInputs(t *testing.T) {
	cs := mustBuild(t, phe.IshaiPaskin, lightphe.WithKeySize(testKeySize))
	leaf, node := lightphe.Leaf, lightphe.Node

	encryptedInput, err := cs.EncryptDecisionTreeInput([]int{1, 0}, 1)
	if err != nil {
		t.Fatalf("encrypting input: %v", err)
	}
	if _, err := cs.EvaluateDecisionTree(node(0, node(1, leaf(0), leaf(1)), leaf(1)), encryptedInput); err == nil {
		t.Fatal("a tree deeper than the encrypted input must be rejected")
	}
	if _, err := cs.EvaluateDecisionTree(node(2, leaf(0), leaf(1)), encryptedInput); err == nil {
		t.Fatal("an out of range variable index must be rejected")
	}
	if _, err := cs.EvaluateDecisionTree(node(0, leaf(1), nil), encryptedInput); err == nil {
		t.Fatal("a decision node without both sub trees must be rejected")
	}
	if _, err := cs.EncryptDecisionTreeInput([]int{2}, 1); err == nil {
		t.Fatal("a non-bit input must be rejected")
	}
	if _, err := cs.EncryptDecisionTreeInput([]int{1}, 0); err == nil {
		t.Fatal("a non-positive depth must be rejected")
	}
}

func TestDecisionTreesAreUnsupportedByOtherSchemes(t *testing.T) {
	cs := mustBuild(t, phe.Paillier, lightphe.WithKeySize(testKeySize))
	_, err := cs.EncryptDecisionTreeInput([]int{1}, 1)
	assertUnsupported(t, "encrypting decision tree input", err)
	_, err = cs.EvaluateDecisionTree(lightphe.Node(0, lightphe.Leaf(0), lightphe.Leaf(1)), [][]*big.Int{{big.NewInt(1)}})
	assertUnsupported(t, "evaluating a decision tree", err)
}

func TestIshaiPaskinLargeKeys(t *testing.T) {
	if testing.Short() {
		t.Skip("1024-bit keys are slow")
	}
	cs := mustBuild(t, phe.IshaiPaskin, lightphe.WithKeySize(1024))
	leaf, node := lightphe.Leaf, lightphe.Node
	majority := node(0, node(1, leaf(0), node(2, leaf(0), leaf(1))), node(1, node(2, leaf(0), leaf(1)), leaf(1)))

	for _, bits := range [][]int{{1, 0, 1}, {0, 1, 0}} {
		encryptedInput, err := cs.EncryptDecisionTreeInput(bits, 3)
		if err != nil {
			t.Fatalf("encrypting input: %v", err)
		}
		output, err := cs.EvaluateDecisionTree(majority, encryptedInput)
		if err != nil {
			t.Fatalf("evaluating: %v", err)
		}
		if got, want := mustDecrypt(t, cs, output), majority.Evaluate(bits); got.Cmp(want) != 0 {
			t.Fatalf("majority on %v decrypted to %s, want %s", bits, got, want)
		}
	}
}
