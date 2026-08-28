package encrypted_test

import (
	"errors"
	"math"
	"math/big"
	"testing"

	"github.com/serengil/lightphe-go/lightphe"
	"github.com/serengil/lightphe-go/lightphe/encrypted"
	"github.com/serengil/lightphe-go/lightphe/phe"
)

// testKeySize keeps key generation fast.
const testKeySize = 50

func mustBuild(t *testing.T, alg phe.Algorithm, opts ...lightphe.Option) *lightphe.Cryptosystem {
	t.Helper()
	cs, err := lightphe.New(alg, opts...)
	if err != nil {
		t.Fatalf("building %s: %v", alg, err)
	}
	return cs
}

// assertUnsupported checks that an operation is rejected as not homomorphic.
func assertUnsupported(t *testing.T, what string, err error) {
	t.Helper()
	if err == nil {
		t.Fatalf("%s: expected the operation to be rejected", what)
	}
	if !errors.Is(err, phe.ErrUnsupportedOperation) {
		t.Fatalf("%s: got %v, want an unsupported-operation error", what, err)
	}
}

// tensorThreshold is how far a decrypted element may drift from the expected
// value. Fixed point encoding truncates, so exact equality is not the bar.
const tensorThreshold = 1e-2

func mustEncryptTensor(t *testing.T, cs *lightphe.Cryptosystem, values []float64) *encrypted.Tensor {
	t.Helper()
	tensor, err := cs.EncryptTensor(values)
	if err != nil {
		t.Fatalf("encrypting a tensor: %v", err)
	}
	return tensor
}

func mustDecryptTensor(t *testing.T, cs *lightphe.Cryptosystem, tensor *encrypted.Tensor) []float64 {
	t.Helper()
	values, err := cs.DecryptTensor(tensor)
	if err != nil {
		t.Fatalf("decrypting a tensor: %v", err)
	}
	return values
}

func assertClose(t *testing.T, got, want, threshold float64, index int) {
	t.Helper()
	if math.Abs(got-want) > threshold {
		t.Fatalf("element %d decrypted to %v, want %v (tolerance %v)", index, got, want, threshold)
	}
}

func TestTensorRoundTrip(t *testing.T) {
	cs := mustBuild(t, phe.Paillier, lightphe.WithKeySize(testKeySize))

	tensor := []float64{1.005, 2.05, 3.005, 4.005, -5.05, 6, 7.003005, -3.5 * 7.002}
	restored := mustDecryptTensor(t, cs, mustEncryptTensor(t, cs, tensor))

	if len(restored) != len(tensor) {
		t.Fatalf("decrypted %d elements, want %d", len(restored), len(tensor))
	}
	for i, want := range tensor {
		assertClose(t, restored[i], want, tensorThreshold, i)
	}
}

func TestTensorElementsShareOneDivisor(t *testing.T) {
	cs := mustBuild(t, phe.Paillier, lightphe.WithKeySize(testKeySize))

	source := mustEncryptTensor(t, cs, []float64{7.11, 5.22, 5.33, 2.44, 3.55, 4.66})
	first := source.Fractions[0].Divisor
	for i, fraction := range source.Fractions[1:] {
		if !fraction.Divisor.Equal(first) {
			t.Fatalf("element %d has its own scale factor; the whole tensor should share one", i+1)
		}
	}
}

func TestTensorHomomorphicMultiplication(t *testing.T) {
	cs := mustBuild(t, phe.RSA, lightphe.WithKeySize(testKeySize))

	t1 := []float64{1.005, 2.05, -3.5, 3.1, -4}
	t2 := []float64{5, 6.2, -7.002, -7.1, 8.02}

	c1 := mustEncryptTensor(t, cs, t1)
	c2 := mustEncryptTensor(t, cs, t2)

	product, err := c1.Multiply(c2)
	if err != nil {
		t.Fatalf("homomorphic multiplication: %v", err)
	}
	restored := mustDecryptTensor(t, cs, product)
	for i := range t1 {
		assertClose(t, restored[i], t1[i]*t2[i], tensorThreshold, i)
	}

	// RSA is not additively homomorphic, and it cannot scale a ciphertext by a
	// known constant either.
	_, err = c1.Add(c2)
	assertUnsupported(t, "tensor addition", err)
	_, err = c2.MultiplyByConstant(2)
	assertUnsupported(t, "tensor scalar multiplication", err)
}

func TestTensorMultiplyByConstant(t *testing.T) {
	// Fractional constants ride on a modular inverse, so they are only exact
	// when the denominator divides the scaled element. Integer-valued tensors
	// satisfy that; fractional ones are covered by the integer constants.
	cases := []struct {
		name     string
		tensor   []float64
		constant float64
	}{
		{"positive integer", []float64{5, 6.2, 7.002, 7.002, 8.02}, 2},
		{"negative integer", []float64{5, 6.2, 7.002, 7.002, 8.02}, -2},
		{"positive float", []float64{10000, 15000, 20000}, 1.05},
		{"negative float", []float64{10000, 15000, 20000}, -1.05},
	}

	cs := mustBuild(t, phe.Paillier, lightphe.WithKeySize(testKeySize))

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			source := mustEncryptTensor(t, cs, tc.tensor)

			scaled, err := source.MultiplyByConstant(tc.constant)
			if err != nil {
				t.Fatalf("scaling the tensor: %v", err)
			}
			restored := mustDecryptTensor(t, cs, scaled)
			for i := range tc.tensor {
				assertClose(t, restored[i], tc.tensor[i]*tc.constant, tensorThreshold, i)
			}
		})
	}
}

func TestTensorHomomorphicAddition(t *testing.T) {
	cs := mustBuild(t, phe.Paillier, lightphe.WithKeySize(testKeySize))
	modulo := cs.PlaintextModulo()

	t1 := []float64{1.005, 2.05, 3.6, -4, 4.02, -3.5}
	t2 := []float64{5, 6.2, -7.5, 8.02, -8.02, -4.5}

	c1 := mustEncryptTensor(t, cs, t1)
	c2 := mustEncryptTensor(t, cs, t2)

	total, err := c1.Add(c2)
	if err != nil {
		t.Fatalf("homomorphic addition: %v", err)
	}
	restored := mustDecryptTensor(t, cs, total)

	for i := range t1 {
		want := t1[i] + t2[i]

		// Mixed signs hide whether the result is negative, so the tensor keeps
		// the modular representative instead. Same-sign additions, and mixed
		// ones that stay non-negative, come back exact.
		mixedNegative := (t1[i] < 0) != (t2[i] < 0) && want < 0
		if mixedNegative {
			want = wrappedNegative(want, modulo, cs.Precision())
		}
		assertClose(t, restored[i], want, tensorThreshold, i)
	}

	// Paillier cannot multiply two ciphertexts.
	_, err = c1.Multiply(c2)
	assertUnsupported(t, "tensor multiplication", err)
}

// wrappedNegative reproduces how a negative value looks once it has been folded
// into the message space and read back at the tensor's fixed point scale.
func wrappedNegative(value float64, modulo *big.Int, precision int) float64 {
	scale := new(big.Int).Exp(big.NewInt(10), big.NewInt(int64(precision)), nil)

	scaled := new(big.Rat).SetFloat64(value)
	scaled.Mul(scaled, new(big.Rat).SetInt(scale))
	dividend := new(big.Int).Quo(scaled.Num(), scaled.Denom())
	dividend.Mod(dividend, modulo)

	out, _ := new(big.Rat).SetFrac(dividend, scale).Float64()
	return out
}

func TestTensorElementWiseAndDotProduct(t *testing.T) {
	for _, alg := range []phe.Algorithm{phe.Paillier, phe.DamgardJurik} {
		alg := alg
		t.Run(alg.String(), func(t *testing.T) {
			t.Parallel()
			cs := mustBuild(t, alg, lightphe.WithKeySize(testKeySize))

			a := []float64{7.11, 5.22, 5.33, 2.44, 3.55, 4.66}
			b := []float64{5.66, 3.77, 2.88, 4, 0, 5.99}

			source := mustEncryptTensor(t, cs, a)

			// Element-wise product against a plain vector.
			products, err := source.MultiplyByPlain(b)
			if err != nil {
				t.Fatalf("element-wise multiplication: %v", err)
			}
			restored := mustDecryptTensor(t, cs, products)
			for i := range a {
				assertClose(t, restored[i], a[i]*b[i], 0.1, i)
			}

			// Dot product, the operation behind encrypted cosine similarity.
			similarity, err := source.Dot(b)
			if err != nil {
				t.Fatalf("dot product: %v", err)
			}
			decrypted := mustDecryptTensor(t, cs, similarity)
			if len(decrypted) != 1 {
				t.Fatalf("the dot product returned %d elements, want 1", len(decrypted))
			}

			var expected float64
			for i := range a {
				expected += a[i] * b[i]
			}
			assertClose(t, decrypted[0], expected, 0.1, 0)
		})
	}
}

func TestTensorRejectsMismatchedSizes(t *testing.T) {
	cs := mustBuild(t, phe.Paillier, lightphe.WithKeySize(testKeySize))

	c1 := mustEncryptTensor(t, cs, []float64{1, 2, 3})
	c2 := mustEncryptTensor(t, cs, []float64{1, 2})

	if _, err := c1.Add(c2); err == nil {
		t.Fatal("expected an error when adding tensors of different sizes")
	}
	if _, err := c1.MultiplyByPlain([]float64{1, 2}); err == nil {
		t.Fatal("expected an error when multiplying by a plain tensor of a different size")
	}
}

func TestTensorRejectsNegativeElementWiseOperands(t *testing.T) {
	cs := mustBuild(t, phe.Paillier, lightphe.WithKeySize(testKeySize))

	source := mustEncryptTensor(t, cs, []float64{1, 2, 3})
	if _, err := source.MultiplyByPlain([]float64{1, -2, 3}); err == nil {
		t.Fatal("expected an error for a negative plain tensor")
	}

	negative := mustEncryptTensor(t, cs, []float64{1, -2, 3})
	if _, err := negative.MultiplyByPlain([]float64{1, 2, 3}); err == nil {
		t.Fatal("expected an error for a negative encrypted tensor")
	}
}

func TestTensorRejectsPrecisionThatOverflowsTheMessageSpace(t *testing.T) {
	cs := mustBuild(t, phe.Paillier, lightphe.WithKeySize(testKeySize), lightphe.WithPrecision(40))
	if _, err := cs.EncryptTensor([]float64{1.5}); err == nil {
		t.Fatal("expected an error when the scale factor does not fit in the message space")
	}
}
