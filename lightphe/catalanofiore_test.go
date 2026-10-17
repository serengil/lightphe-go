package lightphe_test

import (
	"errors"
	"math/big"
	"path/filepath"
	"strings"
	"testing"

	"github.com/serengil/lightphe-go/lightphe"
	"github.com/serengil/lightphe-go/lightphe/encrypted"
	"github.com/serengil/lightphe-go/lightphe/internal/mathutil"
	"github.com/serengil/lightphe-go/lightphe/phe"
	"github.com/serengil/lightphe-go/lightphe/schemes/catalanofiore"
)

// boostedPaillier returns a plain Paillier cryptosystem and the one supporting
// multiplication with the same keys.
func boostedPaillier(t *testing.T) (*lightphe.Cryptosystem, *lightphe.Cryptosystem) {
	t.Helper()
	cs := mustBuild(t, phe.Paillier, lightphe.WithKeySize(128))
	keys, err := cs.Keys(false)
	if err != nil {
		t.Fatalf("exporting keys: %v", err)
	}
	return cs, mustBuild(t, phe.Paillier, lightphe.WithKeys(keys), lightphe.WithBoost(lightphe.CatalanoFiore))
}

func cfAdd(t *testing.T, a, b *encrypted.Ciphertext) *encrypted.Ciphertext {
	t.Helper()
	c, err := a.Add(b)
	if err != nil {
		t.Fatalf("homomorphic addition: %v", err)
	}
	return c
}

func cfMul(t *testing.T, a, b *encrypted.Ciphertext) *encrypted.Ciphertext {
	t.Helper()
	c, err := a.Multiply(b)
	if err != nil {
		t.Fatalf("homomorphic multiplication: %v", err)
	}
	return c
}

func cfScale(t *testing.T, a *encrypted.Ciphertext, k *big.Int) *encrypted.Ciphertext {
	t.Helper()
	c, err := a.MultiplyByConstant(k)
	if err != nil {
		t.Fatalf("scalar multiplication: %v", err)
	}
	return c
}

func TestCatalanoFioreDegree2Functions(t *testing.T) {
	for _, alg := range catalanofiore.SupportedAlgorithms {
		alg := alg
		t.Run(alg.String(), func(t *testing.T) {
			t.Parallel()
			cs := mustBuild(t, alg, lightphe.WithKeySize(64), lightphe.WithBoost(lightphe.CatalanoFiore))
			modulo := cs.PlaintextModulo()
			mod := func(x *big.Int) *big.Int { return x.Mod(x, modulo) }

			for i := 0; i < 5; i++ {
				values := make([]*big.Int, 4)
				for j := range values {
					v, err := mathutil.RandBelow(modulo)
					if err != nil {
						t.Fatal(err)
					}
					values[j] = v
				}
				x, y, z, k := values[0], values[1], values[2], values[3]
				cx, err := cs.Encrypt(x)
				if err != nil {
					t.Fatalf("encrypting: %v", err)
				}
				cy, _ := cs.Encrypt(y)
				cz, _ := cs.Encrypt(z)

				check := func(what string, c *encrypted.Ciphertext, want *big.Int) {
					t.Helper()
					if got := mustDecrypt(t, cs, c); got.Cmp(want) != 0 {
						t.Fatalf("%s decrypted to %s, want %s", what, got, want)
					}
				}
				check("x", cx, x)
				check("x + y", cfAdd(t, cx, cy), mod(new(big.Int).Add(x, y)))
				check("x * k", cfScale(t, cx, k), mod(new(big.Int).Mul(x, k)))
				check("x * y", cfMul(t, cx, cy), mod(new(big.Int).Mul(x, y)))
				check("x * x", cfMul(t, cx, cx), mod(new(big.Int).Mul(x, x)))

				// x * y + k * z * x - y
				minusY := cfScale(t, cy, big.NewInt(-1))
				result := cfAdd(t, cfAdd(t, cfMul(t, cx, cy), cfScale(t, cfMul(t, cz, cx), k)), minusY)
				want := new(big.Int).Mul(x, y)
				want.Add(want, new(big.Int).Mul(k, new(big.Int).Mul(z, x))).Sub(want, y)
				check("x * y + k * z * x - y", result, mod(want))
			}
		})
	}
}

func TestCatalanoFioreOperations(t *testing.T) {
	_, cf := boostedPaillier(t)
	modulo := cf.PlaintextModulo()
	c3, c4, c5 := mustEncrypt(t, cf, 3), mustEncrypt(t, cf, 4), mustEncrypt(t, cf, 5)

	// one multiplication, then additions and scalar multiplications
	assertDecrypts(t, cf, cfAdd(t, cfMul(t, c3, c4), c5), 17)
	assertDecrypts(t, cf, cfAdd(t, cfScale(t, cfMul(t, c3, c4), big.NewInt(2)), cfMul(t, c3, c5)), 39)
	assertDecrypts(t, cf, cfScale(t, cfMul(t, c3, c4), big.NewInt(2)), 24)

	// subtraction, negation and wrapping around the plaintext modulo
	negate := func(c *encrypted.Ciphertext) *encrypted.Ciphertext { return cfScale(t, c, big.NewInt(-1)) }
	if got := mustDecrypt(t, cf, cfAdd(t, c3, negate(c4))); got.Cmp(new(big.Int).Sub(modulo, big.NewInt(1))) != 0 {
		t.Fatalf("3 - 4 decrypted to %s", got)
	}
	if got := mustDecrypt(t, cf, negate(c3)); got.Cmp(new(big.Int).Sub(modulo, big.NewInt(3))) != 0 {
		t.Fatalf("-3 decrypted to %s", got)
	}
	if got := mustDecrypt(t, cf, cfAdd(t, cfMul(t, c3, c4), negate(cfMul(t, c5, c5)))); got.Cmp(new(big.Int).Sub(modulo, big.NewInt(13))) != 0 {
		t.Fatalf("3 * 4 - 5 * 5 decrypted to %s", got)
	}

	// a sum of products and fresh ciphertexts
	assertDecrypts(t, cf, cfAdd(t, cfAdd(t, cfMul(t, c3, c4), c5), c3), 20)

	// negative and zero plaintexts, and multiplication with zero
	minusSix := mustEncrypt(t, cf, -6)
	if got := mustDecrypt(t, cf, minusSix); got.Cmp(new(big.Int).Sub(modulo, big.NewInt(6))) != 0 {
		t.Fatalf("-6 decrypted to %s", got)
	}
	if got := mustDecrypt(t, cf, cfMul(t, minusSix, c4)); got.Cmp(new(big.Int).Sub(modulo, big.NewInt(24))) != 0 {
		t.Fatalf("-6 * 4 decrypted to %s", got)
	}
	assertDecrypts(t, cf, cfMul(t, mustEncrypt(t, cf, 0), c4), 0)
	assertDecrypts(t, cf, cfScale(t, cfMul(t, c3, c4), big.NewInt(0)), 0)
}

func TestCatalanoFioreCiphertextsAreRandomized(t *testing.T) {
	_, cf := boostedPaillier(t)
	c1, c2 := mustEncrypt(t, cf, 5), mustEncrypt(t, cf, 5)
	if c1.Value.Equal(c2.Value) {
		t.Fatal("two encryptions of the same plaintext are identical")
	}
	assertDecrypts(t, cf, c1, 5)
	assertDecrypts(t, cf, c2, 5)
}

func TestCatalanoFioreCiphertextsDoNotCarryPrivateKey(t *testing.T) {
	_, cf := boostedPaillier(t)
	c := cfAdd(t, cfMul(t, mustEncrypt(t, cf, 5), mustEncrypt(t, cf, 6)), mustEncrypt(t, cf, 7))
	if c.Scheme().HasPrivateKey() {
		t.Fatal("ciphertext exposes the private key")
	}

	// ciphertexts can be sent to another party as raw values, and still be
	// decrypted by the key owner
	restored := cf.CreateCiphertext(c.Value)
	assertDecrypts(t, cf, cfAdd(t, restored, mustEncrypt(t, cf, 1)), 38)
}

func TestCatalanoFioreDotProductOfEncryptedVectors(t *testing.T) {
	_, cf := boostedPaillier(t)
	xs := []int64{3, 141, 59, 265, 358, 979, 323, 846, 264, 338}
	ys := []int64{271, 828, 182, 845, 904, 523, 536, 28, 747, 135}

	var result *encrypted.Ciphertext
	var want int64
	for i := range xs {
		product := cfMul(t, mustEncrypt(t, cf, xs[i]), mustEncrypt(t, cf, ys[i]))
		if result == nil {
			result = product
		} else {
			result = cfAdd(t, result, product)
		}
		want += xs[i] * ys[i]
	}
	assertDecrypts(t, cf, result, want)

	// a pair of ciphertexts is kept for every product
	pairs := result.Value.(phe.Tuple).Items[2].(phe.Tuple)
	if pairs.Len() != len(xs) {
		t.Fatalf("dot product keeps %d pairs, want %d", pairs.Len(), len(xs))
	}
}

func TestCatalanoFioreOnlyOneMultiplication(t *testing.T) {
	_, cf := boostedPaillier(t)
	c1, c2, c3 := mustEncrypt(t, cf, 2), mustEncrypt(t, cf, 3), mustEncrypt(t, cf, 4)
	product := cfMul(t, c1, c2)
	if _, err := product.Multiply(c3); !errors.Is(err, catalanofiore.ErrMultipliedTwice) {
		t.Fatalf("multiplying a product returned %v", err)
	}
	if _, err := c3.Multiply(product); !errors.Is(err, phe.ErrUnsupportedOperation) {
		t.Fatalf("multiplying with a product returned %v", err)
	}
}

func TestCatalanoFioreWithPublicKeyOnly(t *testing.T) {
	cs, cf := boostedPaillier(t)
	publicFile := filepath.Join(t.TempDir(), "public.json")
	if err := cs.ExportKeys(publicFile, true); err != nil {
		t.Fatalf("exporting the public key: %v", err)
	}

	// server encrypts and evaluates with the public key only
	server := mustBuild(t, phe.Paillier, lightphe.WithKeyFile(publicFile), lightphe.WithBoost(lightphe.CatalanoFiore))
	result := cfAdd(t, cfMul(t, mustEncrypt(t, cf, 6), mustEncrypt(t, server, 7)), mustEncrypt(t, server, 8))

	if _, err := server.Decrypt(result); !errors.Is(err, phe.ErrMissingPrivateKey) {
		t.Fatalf("decrypting without a private key returned %v", err)
	}
	assertDecrypts(t, cf, result, 50)
}

func TestCatalanoFioreInvalidInputs(t *testing.T) {
	_, cf := boostedPaillier(t)
	c := mustEncrypt(t, cf, 5)

	if _, err := cf.EncryptFloat(1.5); !errors.Is(err, lightphe.ErrFloatNotSupported) {
		t.Fatalf("encrypting a float returned %v", err)
	}
	if _, err := cf.EncryptTensor([]float64{1, 2}); !errors.Is(err, lightphe.ErrFloatNotSupported) {
		t.Fatalf("encrypting a tensor returned %v", err)
	}
	if _, err := c.MultiplyByFloat(1.5); !errors.Is(err, lightphe.ErrFloatNotSupported) {
		t.Fatalf("multiplying by a float returned %v", err)
	}
	if _, err := cf.RegenerateCiphertext(c); err == nil || !strings.Contains(err.Error(), "cannot be regenerated") {
		t.Fatalf("regenerating returned %v", err)
	}

	other := mustBuild(t, phe.Paillier, lightphe.WithKeySize(128), lightphe.WithBoost(lightphe.CatalanoFiore))
	if _, err := c.Add(mustEncrypt(t, other, 1)); !errors.Is(err, phe.ErrInvalidCiphertext) {
		t.Fatalf("mixing cryptosystems returned %v", err)
	}
}

func TestCatalanoFioreUnsupportedAlgorithms(t *testing.T) {
	cases := []struct {
		alg     phe.Algorithm
		keySize int
		reason  string
	}{
		{phe.ExponentialElGamal, 64, "discrete logarithm"},
		{phe.EllipticCurveElGamal, 0, "discrete logarithm"},
		{phe.OkamotoUchiyama, 64, "plaintext modulus p is secret"},
		{phe.Regev, 16, "noise budget"},
		{phe.GoldwasserMicali, 64, "xor only"},
		{phe.BonehGohNissim, 64, "already supports one multiplication"},
		{phe.BrakerskiVaikuntanathan, 16, "already supports one multiplication"},
		{phe.FreemanBonehGohNissim, 64, "already supports one multiplication"},
		{phe.GentryHaleviVaikuntanathan, 2, "already supports one multiplication"},
		{phe.RSA, 64, "not additively homomorphic"},
		{phe.ElGamal, 64, "not additively homomorphic"},
	}
	for _, tc := range cases {
		_, err := lightphe.New(tc.alg, lightphe.WithKeySize(tc.keySize), lightphe.WithBoost(lightphe.CatalanoFiore))
		if err == nil || !strings.Contains(err.Error(), "does not support "+tc.alg.String()+" because") ||
			!strings.Contains(err.Error(), tc.reason) {
			t.Fatalf("boosting %s returned %v", tc.alg, err)
		}
	}
}

func TestUnknownBoost(t *testing.T) {
	if _, err := lightphe.New(phe.Paillier, lightphe.WithKeySize(64), lightphe.WithBoost("something")); err == nil ||
		!strings.Contains(err.Error(), "unknown boost") {
		t.Fatalf("an unknown boost returned %v", err)
	}
}

func TestCatalanoFioreDefaultBehaviourIsUnchanged(t *testing.T) {
	cs, cf := boostedPaillier(t)

	// no boost by default, so ciphertexts are regular ones
	c1 := mustEncrypt(t, cs, 5)
	assertDecrypts(t, cs, cfAdd(t, c1, mustEncrypt(t, cs, 3)), 8)
	_, err := c1.Multiply(mustEncrypt(t, cs, 3))
	assertUnsupported(t, "multiplication without boost", err)

	// each one decrypts ciphertexts of the other, as they have the same keys
	assertDecrypts(t, cf, c1, 5)
	assertDecrypts(t, cs, cfMul(t, mustEncrypt(t, cf, 5), mustEncrypt(t, cf, 6)), 30)
}

func TestCatalanoFioreLargeKeys(t *testing.T) {
	if testing.Short() {
		t.Skip("1024-bit keys are slow")
	}
	cf := mustBuild(t, phe.Paillier, lightphe.WithKeySize(1024), lightphe.WithBoost(lightphe.CatalanoFiore))
	x, _ := mathutil.RandBits(400)
	y, _ := mathutil.RandBits(400)
	cx, _ := cf.Encrypt(x)
	cy, _ := cf.Encrypt(y)
	if got, want := mustDecrypt(t, cf, cfMul(t, cx, cy)), new(big.Int).Mul(x, y); got.Cmp(want) != 0 {
		t.Fatalf("decrypted %s, want %s", got, want)
	}
}

func TestReadmeCatalanoFiore(t *testing.T) {
	// client builds a boosted cryptosystem, and encrypts its private vectors
	client := mustBuild(t, phe.Paillier, lightphe.WithBoost(lightphe.CatalanoFiore))
	x := []int64{3, 1, 4}
	y := []int64{1, 5, 9}

	// server computes dot product and squared euclidean distance of encrypted
	// vectors with the public key carried by the ciphertexts
	var dot, distance *encrypted.Ciphertext
	for i := range x {
		ex, ey := mustEncrypt(t, client, x[i]), mustEncrypt(t, client, y[i])
		product := cfMul(t, ex, ey)
		difference := cfAdd(t, ex, cfScale(t, ey, big.NewInt(-1)))
		square := cfMul(t, difference, difference)
		if dot == nil {
			dot, distance = product, square
		} else {
			dot, distance = cfAdd(t, dot, product), cfAdd(t, distance, square)
		}
	}

	// client decrypts the results
	assertDecrypts(t, client, dot, 44)
	assertDecrypts(t, client, distance, 45)
}
