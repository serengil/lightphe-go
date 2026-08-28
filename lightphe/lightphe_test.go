package lightphe_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"math/big"
	"os"
	"path/filepath"
	"testing"

	"github.com/serengil/lightphe-go/lightphe"
	"github.com/serengil/lightphe-go/lightphe/encrypted"
	"github.com/serengil/lightphe-go/lightphe/phe"
)

// --------------------------------------------------------------------------
// Shared helpers and per-scheme API tests
// --------------------------------------------------------------------------

// testKeySize keeps key generation fast. Decryption in several schemes walks
// the message space, so small keys are what make the suite quick.
const testKeySize = 50

func mustBuild(t *testing.T, alg phe.Algorithm, opts ...lightphe.Option) *lightphe.Cryptosystem {
	t.Helper()
	cs, err := lightphe.New(alg, opts...)
	if err != nil {
		t.Fatalf("building %s: %v", alg, err)
	}
	return cs
}

func mustEncrypt(t *testing.T, cs *lightphe.Cryptosystem, m int64) *encrypted.Ciphertext {
	t.Helper()
	c, err := cs.EncryptInt(m)
	if err != nil {
		t.Fatalf("encrypting %d: %v", m, err)
	}
	return c
}

func mustDecrypt(t *testing.T, cs *lightphe.Cryptosystem, c *encrypted.Ciphertext) *big.Int {
	t.Helper()
	m, err := cs.Decrypt(c)
	if err != nil {
		t.Fatalf("decrypting: %v", err)
	}
	return m
}

func assertDecrypts(t *testing.T, cs *lightphe.Cryptosystem, c *encrypted.Ciphertext, want int64) {
	t.Helper()
	got := mustDecrypt(t, cs, c)
	if got.Cmp(big.NewInt(want)) != 0 {
		t.Fatalf("decrypted %s, want %d", got, want)
	}
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

func TestPaillierAPI(t *testing.T) {
	cs := mustBuild(t, phe.Paillier, lightphe.WithKeySize(testKeySize))

	const m1, m2 = 17, 21
	c1 := mustEncrypt(t, cs, m1)
	c2 := mustEncrypt(t, cs, m2)

	sum, err := c1.Add(c2)
	if err != nil {
		t.Fatalf("homomorphic addition: %v", err)
	}
	assertDecrypts(t, cs, sum, m1+m2)

	// Scalar multiplication works from either side and with either operand.
	for _, tc := range []struct {
		c *encrypted.Ciphertext
		k int64
	}{{c1, m2}, {c2, m1}} {
		scaled, err := tc.c.MultiplyByInt(tc.k)
		if err != nil {
			t.Fatalf("scalar multiplication: %v", err)
		}
		assertDecrypts(t, cs, scaled, m1*m2)
	}

	// Re-encryption produces a different ciphertext for the same plaintext.
	regenerated, err := cs.RegenerateCiphertext(c1)
	if err != nil {
		t.Fatalf("regenerating: %v", err)
	}
	if regenerated.Value.Equal(c1.Value) {
		t.Fatal("regenerated ciphertext is identical to the original")
	}
	assertDecrypts(t, cs, regenerated, m1)

	_, err = c1.Multiply(c2)
	assertUnsupported(t, "multiplication", err)
	_, err = c1.Xor(c2)
	assertUnsupported(t, "exclusive or", err)
	_, err = c1.And(c2)
	assertUnsupported(t, "bitwise and", err)
}

func TestPaillierFloatOperations(t *testing.T) {
	cs := mustBuild(t, phe.Paillier, lightphe.WithKeySize(testKeySize))
	modulo := cs.PlaintextModulo()

	const m1, m2 = 1000, -10
	c1 := mustEncrypt(t, cs, m1)
	c2 := mustEncrypt(t, cs, m2)

	// Negative plaintexts wrap into the message space, and additions that land
	// back in the positive range come out exact.
	sum, err := c1.Add(c2)
	if err != nil {
		t.Fatalf("homomorphic addition: %v", err)
	}
	assertDecrypts(t, cs, sum, m1+m2)

	scaled, err := c1.MultiplyByInt(20)
	if err != nil {
		t.Fatalf("scalar multiplication: %v", err)
	}
	assertDecrypts(t, cs, scaled, m1*20)

	// A float constant is encoded as a modular fraction.
	byFloat, err := c1.MultiplyByFloat(1.05)
	if err != nil {
		t.Fatalf("float scalar multiplication: %v", err)
	}
	assertDecrypts(t, cs, byFloat, 1050)

	// A negative constant wraps the same way a negative plaintext does.
	negative, err := c1.MultiplyByInt(-20)
	if err != nil {
		t.Fatalf("negative scalar multiplication: %v", err)
	}
	want := new(big.Int).Mod(big.NewInt(m1*-20), modulo)
	if got := mustDecrypt(t, cs, negative); got.Cmp(want) != 0 {
		t.Fatalf("decrypted %s, want %s", got, want)
	}
}

func TestElGamalMultiplicative(t *testing.T) {
	cs := mustBuild(t, phe.ElGamal, lightphe.WithKeySize(testKeySize))

	const m1, m2 = 17, 21
	c1 := mustEncrypt(t, cs, m1)
	c2 := mustEncrypt(t, cs, m2)

	product, err := c1.Multiply(c2)
	if err != nil {
		t.Fatalf("homomorphic multiplication: %v", err)
	}
	assertDecrypts(t, cs, product, m1*m2)

	_, err = c1.Add(c2)
	assertUnsupported(t, "addition", err)
	_, err = c1.Xor(c2)
	assertUnsupported(t, "exclusive or", err)
	_, err = c1.MultiplyByInt(5)
	assertUnsupported(t, "scalar multiplication", err)
}

func TestExponentialElGamalAdditive(t *testing.T) {
	cs := mustBuild(t, phe.ExponentialElGamal, lightphe.WithKeySize(testKeySize))

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

	_, err = c1.Multiply(c2)
	assertUnsupported(t, "multiplication", err)
	_, err = c1.Xor(c2)
	assertUnsupported(t, "exclusive or", err)
}

func TestRSAAPI(t *testing.T) {
	cs := mustBuild(t, phe.RSA, lightphe.WithKeySize(testKeySize))

	const m1, m2 = 17, 21
	c1 := mustEncrypt(t, cs, m1)
	c2 := mustEncrypt(t, cs, m2)

	product, err := c1.Multiply(c2)
	if err != nil {
		t.Fatalf("homomorphic multiplication: %v", err)
	}
	assertDecrypts(t, cs, product, m1*m2)

	_, err = c1.Add(c2)
	assertUnsupported(t, "addition", err)
	_, err = c1.Xor(c2)
	assertUnsupported(t, "exclusive or", err)
	_, err = c1.MultiplyByInt(5)
	assertUnsupported(t, "scalar multiplication", err)
}

func TestRSAFloatMultiplication(t *testing.T) {
	cs := mustBuild(t, phe.RSA)

	c1 := mustEncrypt(t, cs, 10000)
	c2, err := cs.EncryptFloat(1.05)
	if err != nil {
		t.Fatalf("encrypting a float: %v", err)
	}

	product, err := c1.Multiply(c2)
	if err != nil {
		t.Fatalf("homomorphic multiplication: %v", err)
	}
	assertDecrypts(t, cs, product, 10500)
}

func TestDamgardJurikAPI(t *testing.T) {
	cs := mustBuild(t, phe.DamgardJurik, lightphe.WithKeySize(testKeySize))

	const m1, m2 = 17, 21
	c1 := mustEncrypt(t, cs, m1)
	c2 := mustEncrypt(t, cs, m2)

	sum, err := c1.Add(c2)
	if err != nil {
		t.Fatalf("homomorphic addition: %v", err)
	}
	assertDecrypts(t, cs, sum, m1+m2)

	scaled, err := c2.MultiplyByInt(m1)
	if err != nil {
		t.Fatalf("scalar multiplication: %v", err)
	}
	assertDecrypts(t, cs, scaled, m1*m2)

	_, err = c1.Multiply(c2)
	assertUnsupported(t, "multiplication", err)
	_, err = c1.Xor(c2)
	assertUnsupported(t, "exclusive or", err)
}

func TestOkamotoUchiyamaAPI(t *testing.T) {
	cs := mustBuild(t, phe.OkamotoUchiyama, lightphe.WithKeySize(testKeySize))

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

	_, err = c1.Multiply(c2)
	assertUnsupported(t, "multiplication", err)
	_, err = c1.Xor(c2)
	assertUnsupported(t, "exclusive or", err)
}

func TestBenalohAPI(t *testing.T) {
	cs := mustBuild(t, phe.Benaloh, lightphe.WithKeySize(testKeySize))

	const m1, m2 = 17, 21
	// Benaloh's message space is small, so the test only holds while the
	// products stay inside it.
	if product := big.NewInt(m1 * m2); product.Cmp(cs.PlaintextModulo()) >= 0 {
		t.Skipf("message space %s is too small for this test", cs.PlaintextModulo())
	}

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

	_, err = c1.Multiply(c2)
	assertUnsupported(t, "multiplication", err)
	_, err = c1.Xor(c2)
	assertUnsupported(t, "exclusive or", err)
}

func TestBenalohRespectsPlaintextLimit(t *testing.T) {
	limit := big.NewInt(500)
	cs := mustBuild(t, phe.Benaloh, lightphe.WithKeySize(128), lightphe.WithPlaintextLimit(limit))

	if cs.PlaintextModulo().Cmp(limit) <= 0 {
		t.Fatalf("message space %s does not cover the requested limit %s", cs.PlaintextModulo(), limit)
	}
	c := mustEncrypt(t, cs, 499)
	assertDecrypts(t, cs, c, 499)
}

func TestNaccacheSternAPI(t *testing.T) {
	cs := mustBuild(t, phe.NaccacheStern, lightphe.WithKeySize(64))

	const m1, m2 = 17, 21
	if product := big.NewInt(m1 * m2); product.Cmp(cs.PlaintextModulo()) >= 0 {
		t.Skipf("message space %s is too small for this test", cs.PlaintextModulo())
	}

	c1 := mustEncrypt(t, cs, m1)
	c2 := mustEncrypt(t, cs, m2)

	sum, err := c1.Add(c2)
	if err != nil {
		t.Fatalf("homomorphic addition: %v", err)
	}
	assertDecrypts(t, cs, sum, m1+m2)

	scaled, err := c2.MultiplyByInt(m1)
	if err != nil {
		t.Fatalf("scalar multiplication: %v", err)
	}
	assertDecrypts(t, cs, scaled, m1*m2)

	_, err = c1.Multiply(c2)
	assertUnsupported(t, "multiplication", err)
	_, err = c1.Xor(c2)
	assertUnsupported(t, "exclusive or", err)
}

func TestGoldwasserMicaliAPI(t *testing.T) {
	cs := mustBuild(t, phe.GoldwasserMicali, lightphe.WithKeySize(testKeySize))

	// Messages of different bit lengths exercise the padding in Xor.
	cases := [][2]int64{{17, 21}, {117, 23}, {23, 117}, {1117, 23}, {12, 1118}}

	for _, tc := range cases {
		m1, m2 := tc[0], tc[1]
		c1 := mustEncrypt(t, cs, m1)
		c2 := mustEncrypt(t, cs, m2)

		combined, err := c1.Xor(c2)
		if err != nil {
			t.Fatalf("homomorphic xor: %v", err)
		}
		assertDecrypts(t, cs, combined, m1^m2)

		_, err = c1.Add(c2)
		assertUnsupported(t, "addition", err)
		_, err = c1.Multiply(c2)
		assertUnsupported(t, "multiplication", err)
		_, err = c1.MultiplyByInt(5)
		assertUnsupported(t, "scalar multiplication", err)
	}
}

func TestSanderYoungYungAPI(t *testing.T) {
	for _, limit := range []*big.Int{nil, big.NewInt(200)} {
		limit := limit
		name := "no-limit"
		if limit != nil {
			name = "limit-" + limit.String()
		}

		t.Run(name, func(t *testing.T) {
			cs := mustBuild(t, phe.SanderYoungYung,
				lightphe.WithKeySize(testKeySize),
				lightphe.WithPlaintextLimit(limit),
			)
			modulo := cs.PlaintextModulo()

			for _, tc := range [][2]int64{{17, 22}, {117, 23}, {23, 117}} {
				m1 := new(big.Int).Mod(big.NewInt(tc[0]), modulo)
				m2 := new(big.Int).Mod(big.NewInt(tc[1]), modulo)

				c1 := mustEncrypt(t, cs, tc[0])
				c2 := mustEncrypt(t, cs, tc[1])

				if got := mustDecrypt(t, cs, c1); got.Cmp(m1) != 0 {
					t.Fatalf("decrypted %s, want %s", got, m1)
				}
				if got := mustDecrypt(t, cs, c2); got.Cmp(m2) != 0 {
					t.Fatalf("decrypted %s, want %s", got, m2)
				}

				// Re-randomisation changes the ciphertext but not the message.
				refreshed, err := c1.Reencrypt()
				if err != nil {
					t.Fatalf("re-encrypting: %v", err)
				}
				if refreshed.Value.Equal(c1.Value) {
					t.Fatal("re-encrypted ciphertext is identical to the original")
				}
				if got := mustDecrypt(t, cs, refreshed); got.Cmp(m1) != 0 {
					t.Fatalf("re-encrypted decrypted to %s, want %s", got, m1)
				}

				combined, err := c1.And(c2)
				if err != nil {
					t.Fatalf("homomorphic and: %v", err)
				}
				want := new(big.Int).And(m1, m2)
				if got := mustDecrypt(t, cs, combined); got.Cmp(want) != 0 {
					t.Fatalf("decrypted %s, want %s", got, want)
				}

				_, err = c1.Add(c2)
				assertUnsupported(t, "addition", err)
				_, err = c1.Multiply(c2)
				assertUnsupported(t, "multiplication", err)
				_, err = c1.MultiplyByInt(5)
				assertUnsupported(t, "scalar multiplication", err)
			}
		})
	}
}

func TestEllipticCurveElGamalAPI(t *testing.T) {
	// Koblitz curves are excluded: binary field arithmetic makes key
	// generation slow enough to drag the suite down.
	for _, form := range []string{"weierstrass", "edwards"} {
		form := form
		t.Run(form, func(t *testing.T) {
			t.Parallel()
			cs := mustBuild(t, phe.EllipticCurveElGamal, lightphe.WithCurve(form, ""))

			const m1, m2 = 10, 5
			c1 := mustEncrypt(t, cs, m1)
			c2 := mustEncrypt(t, cs, m2)

			assertDecrypts(t, cs, c1, m1)
			assertDecrypts(t, cs, c2, m2)

			refreshed, err := c1.Reencrypt()
			if err != nil {
				t.Fatalf("re-encrypting: %v", err)
			}
			if refreshed.Value.Equal(c1.Value) {
				t.Fatal("re-encrypted ciphertext is identical to the original")
			}
			assertDecrypts(t, cs, refreshed, m1)

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

			_, err = c1.Multiply(c2)
			assertUnsupported(t, "multiplication", err)
			_, err = c1.Xor(c2)
			assertUnsupported(t, "exclusive or", err)
		})
	}
}

func TestBonehGohNissimAPI(t *testing.T) {
	cs := mustBuild(t, phe.BonehGohNissim, lightphe.WithKeySize(testKeySize))
	modulo := cs.PlaintextModulo()

	const m1, m2 = 83, 31
	c1 := mustEncrypt(t, cs, m1)
	c2 := mustEncrypt(t, cs, m2)

	assertDecrypts(t, cs, c1, m1)
	assertDecrypts(t, cs, c2, m2)

	sum, err := c1.Add(c2)
	if err != nil {
		t.Fatalf("homomorphic addition: %v", err)
	}
	want := new(big.Int).Mod(big.NewInt(m1+m2), modulo)
	if got := mustDecrypt(t, cs, sum); got.Cmp(want) != 0 {
		t.Fatalf("decrypted %s, want %s", got, want)
	}

	// One multiplication is allowed; it moves the ciphertext into the pairing
	// target group.
	product, err := c1.Multiply(c2)
	if err != nil {
		t.Fatalf("homomorphic multiplication: %v", err)
	}
	want = new(big.Int).Mod(big.NewInt(m1*m2), modulo)
	if got := mustDecrypt(t, cs, product); got.Cmp(want) != 0 {
		t.Fatalf("decrypted %s, want %s", got, want)
	}

	scaled, err := c1.MultiplyByInt(2)
	if err != nil {
		t.Fatalf("scalar multiplication: %v", err)
	}
	want = new(big.Int).Mod(big.NewInt(m1*2), modulo)
	if got := mustDecrypt(t, cs, scaled); got.Cmp(want) != 0 {
		t.Fatalf("decrypted %s, want %s", got, want)
	}

	// A second multiplication is not.
	_, err = product.Multiply(c2)
	assertUnsupported(t, "second multiplication", err)

	_, err = c1.And(c2)
	assertUnsupported(t, "bitwise and", err)
	_, err = c1.Xor(c2)
	assertUnsupported(t, "exclusive or", err)

	refreshed, err := c1.Reencrypt()
	if err != nil {
		t.Fatalf("re-encrypting: %v", err)
	}
	assertDecrypts(t, cs, refreshed, m1)
}

func TestBonehGohNissimLinearRegression(t *testing.T) {
	cs := mustBuild(t, phe.BonehGohNissim, lightphe.WithKeySize(testKeySize))

	const x1, w1, x2, w2 = 5, 7, 3, 4

	x1Enc := mustEncrypt(t, cs, x1)
	w1Enc := mustEncrypt(t, cs, w1)
	x2Enc := mustEncrypt(t, cs, x2)
	w2Enc := mustEncrypt(t, cs, w2)

	term1, err := x1Enc.Multiply(w1Enc)
	if err != nil {
		t.Fatalf("multiplying: %v", err)
	}
	term2, err := x2Enc.Multiply(w2Enc)
	if err != nil {
		t.Fatalf("multiplying: %v", err)
	}
	// Additions still work after the multiplication, inside the target group.
	sum, err := term1.Add(term2)
	if err != nil {
		t.Fatalf("adding pairing values: %v", err)
	}
	assertDecrypts(t, cs, sum, x1*w1+x2*w2)

	scaled, err := term1.MultiplyByInt(5)
	if err != nil {
		t.Fatalf("scaling a pairing value: %v", err)
	}
	assertDecrypts(t, cs, scaled, 5*x1*w1)

	_, err = term1.Multiply(w2Enc)
	assertUnsupported(t, "second multiplication", err)
}

func TestBonehGohNissimEuclideanDistance(t *testing.T) {
	cs := mustBuild(t, phe.BonehGohNissim, lightphe.WithKeySize(testKeySize))

	source := []int64{5, 2, 8}
	target := []int64{1, 1, 2}

	var accumulated *encrypted.Ciphertext
	for i := range source {
		a := mustEncrypt(t, cs, source[i])
		b := mustEncrypt(t, cs, -target[i])

		diff, err := a.Add(b)
		if err != nil {
			t.Fatalf("adding: %v", err)
		}
		square, err := diff.Multiply(diff)
		if err != nil {
			t.Fatalf("squaring: %v", err)
		}
		if accumulated == nil {
			accumulated = square
			continue
		}
		if accumulated, err = accumulated.Add(square); err != nil {
			t.Fatalf("accumulating: %v", err)
		}
	}

	var want int64
	for i := range source {
		d := source[i] - target[i]
		want += d * d
	}
	assertDecrypts(t, cs, accumulated, want)
}

// TestSalary reproduces the worked example from the documentation: a base
// salary is raised by a fixed amount and then by a percentage, all under
// encryption.
func TestSalary(t *testing.T) {
	cs := mustBuild(t, phe.Paillier, lightphe.WithKeySize(testKeySize))

	const salary, raise = 10000, 1000
	salaryEnc := mustEncrypt(t, cs, salary)
	raiseEnc := mustEncrypt(t, cs, raise)

	total, err := salaryEnc.Add(raiseEnc)
	if err != nil {
		t.Fatalf("homomorphic addition: %v", err)
	}
	assertDecrypts(t, cs, total, salary+raise)

	increased, err := salaryEnc.MultiplyByFloat(1.05)
	if err != nil {
		t.Fatalf("percentage raise: %v", err)
	}
	assertDecrypts(t, cs, increased, 10500)
}

func TestUnimplementedAlgorithmIsRejected(t *testing.T) {
	if _, err := lightphe.New("Rivest-Adleman-Dertouzos"); err == nil {
		t.Fatal("expected an error for an unknown algorithm")
	}
}

// --------------------------------------------------------------------------
// Key export, restoration and validation
// --------------------------------------------------------------------------

// restoreCase describes how to exercise one cryptosystem across an
// export/restore round trip.
type restoreCase struct {
	alg  phe.Algorithm
	opts []lightphe.Option

	// evaluate applies the homomorphic operation the scheme supports.
	evaluate func(c1, c2 *encrypted.Ciphertext) (*encrypted.Ciphertext, error)

	// want returns the plaintext the evaluation should decrypt to, given the
	// message space of the restored cryptosystem.
	want func(modulo *big.Int) *big.Int
}

const (
	restoreM1 = 217
	restoreM2 = 23
)

func addition(c1, c2 *encrypted.Ciphertext) (*encrypted.Ciphertext, error) { return c1.Add(c2) }
func multiplication(c1, c2 *encrypted.Ciphertext) (*encrypted.Ciphertext, error) {
	return c1.Multiply(c2)
}
func exclusiveOr(c1, c2 *encrypted.Ciphertext) (*encrypted.Ciphertext, error) { return c1.Xor(c2) }
func bitwiseAnd(c1, c2 *encrypted.Ciphertext) (*encrypted.Ciphertext, error)  { return c1.And(c2) }

func sum(modulo *big.Int) *big.Int {
	return new(big.Int).Mod(big.NewInt(restoreM1+restoreM2), modulo)
}

func restoreCases() []restoreCase {
	small := []lightphe.Option{lightphe.WithKeySize(testKeySize)}

	return []restoreCase{
		{phe.RSA, small, multiplication, func(m *big.Int) *big.Int {
			return new(big.Int).Mod(big.NewInt(restoreM1*restoreM2), m)
		}},
		{phe.ElGamal, small, multiplication, func(m *big.Int) *big.Int {
			return new(big.Int).Mod(big.NewInt(restoreM1*restoreM2), m)
		}},
		{phe.ExponentialElGamal, small, addition, sum},
		{phe.Paillier, small, addition, sum},
		{phe.DamgardJurik, small, addition, sum},
		{phe.OkamotoUchiyama, small, addition, sum},
		{phe.Benaloh, small, addition, sum},
		{phe.NaccacheStern, []lightphe.Option{lightphe.WithKeySize(64)}, addition, sum},
		{phe.GoldwasserMicali, small, exclusiveOr, func(*big.Int) *big.Int {
			return big.NewInt(restoreM1 ^ restoreM2)
		}},
		{phe.EllipticCurveElGamal, nil, addition, func(*big.Int) *big.Int {
			return big.NewInt(restoreM1 + restoreM2)
		}},
		{phe.BonehGohNissim, small, addition, sum},
		{phe.SanderYoungYung, small, bitwiseAnd, func(m *big.Int) *big.Int {
			a := new(big.Int).Mod(big.NewInt(restoreM1), m)
			b := new(big.Int).Mod(big.NewInt(restoreM2), m)
			return new(big.Int).And(a, b)
		}},
	}
}

// TestKeyRestoration walks the full split-trust workflow: keys are generated
// and exported on premises, an evaluator rebuilt from the public key alone
// encrypts and evaluates, and the on-premises side restores the private key to
// decrypt the result.
func TestKeyRestoration(t *testing.T) {
	dir := t.TempDir()

	for _, tc := range restoreCases() {
		tc := tc
		t.Run(tc.alg.String(), func(t *testing.T) {
			t.Parallel()

			privateFile := filepath.Join(dir, string(tc.alg)+"_secret.json")
			publicFile := filepath.Join(dir, string(tc.alg)+"_public.json")

			onprem := mustBuild(t, tc.alg, tc.opts...)
			if err := onprem.ExportKeys(privateFile, false); err != nil {
				t.Fatalf("exporting the private key: %v", err)
			}
			if err := onprem.ExportKeys(publicFile, true); err != nil {
				t.Fatalf("exporting the public key: %v", err)
			}

			// The evaluator only ever sees the public key.
			cloud := mustBuild(t, tc.alg, lightphe.WithKeyFile(publicFile))
			if cloud.HasPrivateKey() {
				t.Fatal("a cryptosystem restored from a public key file must not hold a private key")
			}

			c1 := mustEncrypt(t, cloud, restoreM1)
			c2 := mustEncrypt(t, cloud, restoreM2)
			result, err := tc.evaluate(c1, c2)
			if err != nil {
				t.Fatalf("evaluating: %v", err)
			}

			restored := mustBuild(t, tc.alg, lightphe.WithKeyFile(privateFile))
			if !restored.HasPrivateKey() {
				t.Fatal("a cryptosystem restored from a private key file must hold a private key")
			}

			want := tc.want(restored.PlaintextModulo())
			if got := mustDecrypt(t, restored, result); got.Cmp(want) != 0 {
				t.Fatalf("decrypted %s, want %s", got, want)
			}
		})
	}
}

func TestPublicKeyFileOmitsPrivateKey(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "public.json")

	cs := mustBuild(t, phe.RSA, lightphe.WithKeySize(testKeySize))
	if err := cs.ExportKeys(target, true); err != nil {
		t.Fatalf("exporting: %v", err)
	}

	// Exporting a public key must not disarm the live cryptosystem.
	if !cs.HasPrivateKey() {
		t.Fatal("exporting the public key dropped the in-memory private key")
	}

	data, err := os.ReadFile(target)
	if err != nil {
		t.Fatalf("reading the key file: %v", err)
	}
	var keys map[string]json.RawMessage
	if err := json.Unmarshal(data, &keys); err != nil {
		t.Fatalf("decoding the key file: %v", err)
	}
	if _, present := keys["private_key"]; present {
		t.Fatal("the public key file contains a private key")
	}
	if _, present := keys["public_key"]; !present {
		t.Fatal("the public key file has no public key")
	}
}

func TestCiphertextCarriesNoPrivateKey(t *testing.T) {
	cs := mustBuild(t, phe.Paillier, lightphe.WithKeySize(testKeySize))

	c := mustEncrypt(t, cs, 17)
	if c.Scheme().HasPrivateKey() {
		t.Fatal("ciphertext exposes the private key")
	}
	if !cs.HasPrivateKey() {
		t.Fatal("the cryptosystem itself lost its private key")
	}

	tensor, err := cs.EncryptTensor([]float64{1.5, 2.4, 3.3, 4.2, 5.1})
	if err != nil {
		t.Fatalf("encrypting a tensor: %v", err)
	}
	if tensor.Scheme().HasPrivateKey() {
		t.Fatal("encrypted tensor exposes the private key")
	}
}

// TestCloudWorkflow evaluates over ciphertexts on a party that holds only the
// public key, using pre-generated 20-bit RSA keys.
func TestCloudWorkflow(t *testing.T) {
	const (
		privateKeys = `{"public_key": {"n": 175501, "e": 101753}, "private_key": {"d": 30365}}`
		publicKeys  = `{"public_key": {"n": 175501, "e": 101753}}`
	)

	cloud := mustBuild(t, phe.RSA, lightphe.WithKeys([]byte(publicKeys)))
	onprem := mustBuild(t, phe.RSA, lightphe.WithKeys([]byte(privateKeys)))

	c1 := mustEncrypt(t, cloud, 10000)
	c2, err := cloud.EncryptFloat(1.05)
	if err != nil {
		t.Fatalf("encrypting a float: %v", err)
	}
	assertDecrypts(t, onprem, c1, 10000)

	// The evaluator cannot decrypt what it holds.
	if _, err := cloud.Decrypt(c1); !errors.Is(err, phe.ErrMissingPrivateKey) {
		t.Fatalf("decrypting without a private key returned %v, want ErrMissingPrivateKey", err)
	}

	// Ciphertext payloads survive a round trip through raw values, which is
	// how they would travel over the wire.
	product, err := cloud.CreateCiphertext(c1.Value).Multiply(cloud.CreateCiphertext(c2.Value))
	if err != nil {
		t.Fatalf("homomorphic multiplication: %v", err)
	}
	assertDecrypts(t, onprem, cloud.CreateCiphertext(product.Value), 10500)
}

// keyFieldCase names one required field of each key section, so that dropping
// it can be shown to be rejected.
type keyFieldCase struct {
	alg          phe.Algorithm
	opts         []lightphe.Option
	publicField  string
	privateField string
}

func keyFieldCases() []keyFieldCase {
	small := []lightphe.Option{lightphe.WithKeySize(testKeySize)}

	return []keyFieldCase{
		{phe.RSA, small, "n", "d"},
		{phe.ElGamal, small, "p", "x"},
		{phe.ExponentialElGamal, small, "p", "x"},
		{phe.EllipticCurveElGamal, nil, "Qa", "ka"},
		{phe.Paillier, small, "g", "phi"},
		{phe.DamgardJurik, small, "g", "phi"},
		{phe.OkamotoUchiyama, small, "n", "p"},
		{phe.Benaloh, small, "y", "p"},
		{phe.NaccacheStern, []lightphe.Option{lightphe.WithKeySize(64)}, "n", "a"},
		{phe.GoldwasserMicali, small, "n", "p"},
		{phe.SanderYoungYung, small, "n", "p"},
		{phe.BonehGohNissim, small, "curve", "q1"},
	}
}

func TestMissingKeyFieldsAreRejected(t *testing.T) {
	for _, tc := range keyFieldCases() {
		tc := tc
		t.Run(tc.alg.String(), func(t *testing.T) {
			t.Parallel()
			cs := mustBuild(t, tc.alg, tc.opts...)

			keys, err := cs.Keys(false)
			if err != nil {
				t.Fatalf("exporting keys: %v", err)
			}

			for section, field := range map[string]string{
				"public_key":  tc.publicField,
				"private_key": tc.privateField,
			} {
				broken := withoutField(t, keys, section, field)
				if _, err := lightphe.New(tc.alg, lightphe.WithKeys(broken)); !errors.Is(err, phe.ErrInvalidKeys) {
					t.Fatalf("dropping %s.%s returned %v, want ErrInvalidKeys", section, field, err)
				}
				if err != nil && !bytes.Contains([]byte(err.Error()), []byte(field)) {
					t.Fatalf("the error for a missing %s.%s does not name the field: %v", section, field, err)
				}
			}
		})
	}
}

func TestMissingPublicKeySectionIsRejected(t *testing.T) {
	if _, err := lightphe.New(phe.RSA, lightphe.WithKeys([]byte(`{}`))); !errors.Is(err, phe.ErrInvalidKeys) {
		t.Fatalf("empty keys returned %v, want ErrInvalidKeys", err)
	}
}

func TestPrivateKeyOnlyIsRejected(t *testing.T) {
	keys := []byte(`{"private_key": {"d": 30365}}`)
	if _, err := lightphe.New(phe.RSA, lightphe.WithKeys(keys)); !errors.Is(err, phe.ErrInvalidKeys) {
		t.Fatalf("private-key-only material returned %v, want ErrInvalidKeys", err)
	}
}

func TestMalformedKeysAreRejected(t *testing.T) {
	if _, err := lightphe.New(phe.RSA, lightphe.WithKeys([]byte(`"not-an-object"`))); !errors.Is(err, phe.ErrInvalidKeys) {
		t.Fatalf("malformed key material returned %v, want ErrInvalidKeys", err)
	}
}

func TestPublicKeyOnlyIsAccepted(t *testing.T) {
	cs := mustBuild(t, phe.RSA, lightphe.WithKeySize(testKeySize))
	keys, err := cs.Keys(true)
	if err != nil {
		t.Fatalf("exporting the public key: %v", err)
	}

	public := mustBuild(t, phe.RSA, lightphe.WithKeys(keys))
	if public.HasPrivateKey() {
		t.Fatal("a public-key-only cryptosystem reports a private key")
	}
	if _, err := public.EncryptInt(17); err != nil {
		t.Fatalf("encrypting with a public key only: %v", err)
	}
}

func TestBonehGohNissimNestedCurveFieldIsRejected(t *testing.T) {
	cs := mustBuild(t, phe.BonehGohNissim, lightphe.WithKeySize(testKeySize))
	keys, err := cs.Keys(false)
	if err != nil {
		t.Fatalf("exporting keys: %v", err)
	}

	var doc map[string]interface{}
	decodeKeys(t, keys, &doc)
	public := doc["public_key"].(map[string]interface{})
	curve := public["curve"].(map[string]interface{})
	delete(curve, "a")

	broken, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("re-encoding keys: %v", err)
	}
	if _, err := lightphe.New(phe.BonehGohNissim, lightphe.WithKeys(broken)); !errors.Is(err, phe.ErrInvalidKeys) {
		t.Fatalf("dropping public_key.curve.a returned %v, want ErrInvalidKeys", err)
	}
}

func TestDecryptWithoutPrivateKeyIsRejected(t *testing.T) {
	cs := mustBuild(t, phe.Paillier, lightphe.WithKeySize(testKeySize))
	keys, err := cs.Keys(true)
	if err != nil {
		t.Fatalf("exporting the public key: %v", err)
	}
	public := mustBuild(t, phe.Paillier, lightphe.WithKeys(keys))

	c := mustEncrypt(t, public, 17)
	if _, err := public.Decrypt(c); !errors.Is(err, phe.ErrMissingPrivateKey) {
		t.Fatalf("decrypting without a private key returned %v, want ErrMissingPrivateKey", err)
	}
}

func TestCiphertextsFromDifferentSchemesCannotBeCombined(t *testing.T) {
	paillier := mustBuild(t, phe.Paillier, lightphe.WithKeySize(testKeySize))
	damgard := mustBuild(t, phe.DamgardJurik, lightphe.WithKeySize(testKeySize))

	c1 := mustEncrypt(t, paillier, 17)
	c2 := mustEncrypt(t, damgard, 21)

	if _, err := c1.Add(c2); !errors.Is(err, phe.ErrInvalidCiphertext) {
		t.Fatalf("mixing cryptosystems returned %v, want ErrInvalidCiphertext", err)
	}
}

// withoutField re-encodes key material with one field of one section removed.
func withoutField(t *testing.T, keys []byte, section, field string) []byte {
	t.Helper()

	var doc map[string]interface{}
	decodeKeys(t, keys, &doc)

	values, ok := doc[section].(map[string]interface{})
	if !ok {
		t.Fatalf("key material has no %q section", section)
	}
	if _, present := values[field]; !present {
		t.Fatalf("key section %q has no field %q", section, field)
	}
	delete(values, field)

	broken, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("re-encoding keys: %v", err)
	}
	return broken
}

// decodeKeys decodes key material while keeping the arbitrary precision
// integers intact, which a plain json.Unmarshal into interface{} would round
// through float64 and destroy.
func decodeKeys(t *testing.T, keys []byte, out interface{}) {
	t.Helper()
	dec := json.NewDecoder(bytes.NewReader(keys))
	dec.UseNumber()
	if err := dec.Decode(out); err != nil {
		t.Fatalf("decoding keys: %v", err)
	}
}

// --------------------------------------------------------------------------
// Runnable documentation examples
// --------------------------------------------------------------------------

// An additively homomorphic cryptosystem lets a party that holds no private key
// raise a salary and apply a percentage increase.
func Example() {
	cs, err := lightphe.New(lightphe.Paillier, lightphe.WithKeySize(512))
	if err != nil {
		log.Fatal(err)
	}

	salary, err := cs.EncryptInt(10000)
	if err != nil {
		log.Fatal(err)
	}
	raise, err := cs.EncryptInt(500)
	if err != nil {
		log.Fatal(err)
	}

	// Neither of these needs the private key.
	total, err := salary.Add(raise)
	if err != nil {
		log.Fatal(err)
	}
	increased, err := salary.MultiplyByFloat(1.05)
	if err != nil {
		log.Fatal(err)
	}

	// Decryption does.
	sum, err := cs.Decrypt(total)
	if err != nil {
		log.Fatal(err)
	}
	scaled, err := cs.Decrypt(increased)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(sum, scaled)
	// Output: 10500 10500
}

// A multiplicatively homomorphic cryptosystem multiplies ciphertexts instead.
func Example_multiplicative() {
	cs, err := lightphe.New(lightphe.RSA, lightphe.WithKeySize(512))
	if err != nil {
		log.Fatal(err)
	}

	c1, err := cs.EncryptInt(17)
	if err != nil {
		log.Fatal(err)
	}
	c2, err := cs.EncryptInt(21)
	if err != nil {
		log.Fatal(err)
	}

	product, err := c1.Multiply(c2)
	if err != nil {
		log.Fatal(err)
	}
	m, err := cs.Decrypt(product)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(m)
	// Output: 357
}

// Asking a scheme for an operation it does not support returns an error rather
// than silently producing nonsense.
func Example_unsupportedOperation() {
	cs, err := lightphe.New(lightphe.Paillier, lightphe.WithKeySize(512))
	if err != nil {
		log.Fatal(err)
	}
	c, err := cs.EncryptInt(17)
	if err != nil {
		log.Fatal(err)
	}

	if _, err := c.Multiply(c); err != nil {
		fmt.Println(err)
	}
	// Output: lightphe: Paillier does not support multiplication: lightphe: unsupported homomorphic operation
}

// Encrypted vectors support element-wise arithmetic and dot products, which is
// what privacy preserving similarity search is built on.
func Example_dotProduct() {
	cs, err := lightphe.New(lightphe.Paillier, lightphe.WithKeySize(512))
	if err != nil {
		log.Fatal(err)
	}

	source := []float64{1.5, 2.5, 3.5}
	target := []float64{2.0, 1.0, 4.0}

	encrypted, err := cs.EncryptTensor(source)
	if err != nil {
		log.Fatal(err)
	}
	similarity, err := encrypted.Dot(target)
	if err != nil {
		log.Fatal(err)
	}
	decrypted, err := cs.DecryptTensor(similarity)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("%.2f\n", decrypted[0])
	// Output: 19.50
}

// Elliptic curve ElGamal picks its curve form and curve by name.
func ExampleWithCurve() {
	cs, err := lightphe.New(lightphe.EllipticCurveElGamal, lightphe.WithCurve("edwards", "ed25519"))
	if err != nil {
		log.Fatal(err)
	}

	c, err := cs.EncryptInt(10)
	if err != nil {
		log.Fatal(err)
	}
	doubled, err := c.MultiplyByConstant(big.NewInt(2))
	if err != nil {
		log.Fatal(err)
	}
	m, err := cs.Decrypt(doubled)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(m)
	// Output: 20
}
