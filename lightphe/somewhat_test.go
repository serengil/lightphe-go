package lightphe_test

import (
	"errors"
	"math/big"
	"math/rand"
	"testing"

	"github.com/serengil/lightphe-go/lightphe"
	"github.com/serengil/lightphe-go/lightphe/encrypted"
	"github.com/serengil/lightphe-go/lightphe/phe"
	"github.com/serengil/lightphe-go/lightphe/schemes/brakerskivaikuntanathan"
	"github.com/serengil/lightphe-go/lightphe/schemes/freemanbonehgohnissim"
	"github.com/serengil/lightphe-go/lightphe/schemes/gentryhalevivaikuntanathan"
)

// Regev, Brakerski-Vaikuntanathan, Freeman-Boneh-Goh-Nissim and
// Gentry-Halevi-Vaikuntanathan support integers only. All but Regev support
// one multiplication of ciphertexts.

type somewhatCase struct {
	alg      phe.Algorithm
	keySize  int
	multiply bool
}

var somewhatCases = []somewhatCase{
	{phe.Regev, 64, false},
	{phe.BrakerskiVaikuntanathan, 64, true},
	{phe.FreemanBonehGohNissim, 64, true},
	{phe.GentryHaleviVaikuntanathan, 2, true},
}

func TestSomewhatSchemesAPI(t *testing.T) {
	for _, tc := range somewhatCases {
		tc := tc
		t.Run(tc.alg.String(), func(t *testing.T) {
			t.Parallel()
			cs := mustBuild(t, tc.alg, lightphe.WithKeySize(tc.keySize))
			modulo := cs.PlaintextModulo().Int64()

			const m1, m2 = 17, 21
			c1 := mustEncrypt(t, cs, m1)
			c2 := mustEncrypt(t, cs, m2)

			// proof of decryption
			assertDecrypts(t, cs, c1, m1)
			assertDecrypts(t, cs, c2, m2)

			// homomorphic addition and scalar multiplication
			assertDecrypts(t, cs, cfAdd(t, c1, c2), (m1+m2)%modulo)
			assertDecrypts(t, cs, cfScale(t, c1, big.NewInt(m2)), (m1*m2)%modulo)

			// negative plaintexts
			c3 := mustEncrypt(t, cs, -5)
			assertDecrypts(t, cs, c3, modulo-5)
			assertDecrypts(t, cs, cfAdd(t, c1, c3), m1-5)

			// homomorphic multiplication
			if tc.multiply {
				assertDecrypts(t, cs, cfMul(t, c1, c2), (m1*m2)%modulo)
				assertDecrypts(t, cs, cfMul(t, c1, c3), mod(-5*m1, modulo))
			} else {
				_, err := c1.Multiply(c2)
				assertUnsupported(t, "multiplication", err)
			}

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
			_, err = c1.Xor(c2)
			assertUnsupported(t, "exclusive or", err)
			_, err = c1.And(c2)
			assertUnsupported(t, "bitwise and", err)

			// floats and tensors are not supported
			if _, err := cs.EncryptFloat(1.5); !errors.Is(err, lightphe.ErrFloatNotSupported) {
				t.Fatalf("encrypting a float returned %v", err)
			}
			if _, err := cs.EncryptTensor([]float64{1, 2, 3}); !errors.Is(err, lightphe.ErrFloatNotSupported) {
				t.Fatalf("encrypting a tensor returned %v", err)
			}
			if _, err := c1.MultiplyByFloat(1.5); !errors.Is(err, lightphe.ErrFloatNotSupported) {
				t.Fatalf("multiplying by a float returned %v", err)
			}

			// Catalano-Fiore is not needed
			keys, err := cs.Keys(false)
			if err != nil {
				t.Fatalf("exporting keys: %v", err)
			}
			if _, err := lightphe.New(tc.alg, lightphe.WithKeys(keys), lightphe.WithBoost(lightphe.CatalanoFiore)); err == nil {
				t.Fatal("boosting a somewhat homomorphic scheme was accepted")
			}
		})
	}
}

func mod(x, m int64) int64 {
	r := x % m
	if r < 0 {
		r += m
	}
	return r
}

func TestSomewhatSchemesDegree2Functions(t *testing.T) {
	for _, tc := range somewhatCases {
		if !tc.multiply {
			continue
		}
		tc := tc
		t.Run(tc.alg.String(), func(t *testing.T) {
			t.Parallel()
			cs := mustBuild(t, tc.alg, lightphe.WithKeySize(tc.keySize))
			modulo := cs.PlaintextModulo().Int64()
			rng := rand.New(rand.NewSource(1))

			for i := 0; i < 10; i++ {
				// decryption of Freeman-Boneh-Goh-Nissim solves discrete
				// logarithm, so its values are small
				x, y, z := rng.Int63n(201)-100, rng.Int63n(201)-100, rng.Int63n(201)-100
				k := rng.Int63n(41) - 20
				cx, cy, cz := mustEncrypt(t, cs, x), mustEncrypt(t, cs, y), mustEncrypt(t, cs, z)

				check := func(what string, c *encrypted.Ciphertext, want int64) {
					t.Helper()
					if got := mustDecrypt(t, cs, c).Int64(); got != mod(want, modulo) {
						t.Fatalf("%s decrypted to %d, want %d", what, got, mod(want, modulo))
					}
				}
				check("x * x", cfMul(t, cx, cx), x*x)
				check("(x + y) * z", cfMul(t, cfAdd(t, cx, cy), cz), (x+y)*z)

				// multiplied ciphertexts can be added with each other and with
				// fresh ciphertexts
				check("x * y + z * z + x", cfAdd(t, cfAdd(t, cfMul(t, cx, cy), cfMul(t, cz, cz)), cx), x*y+z*z+x)
				check("z + x * y", cfAdd(t, cz, cfMul(t, cx, cy)), z+x*y)

				// constants before and after multiplication, including zero
				check("(x * k) * y", cfMul(t, cfScale(t, cx, big.NewInt(k)), cy), k*x*y)
				check("x * y * k", cfScale(t, cfMul(t, cx, cy), big.NewInt(k)), k*x*y)
				check("x * 0", cfScale(t, cx, big.NewInt(0)), 0)
			}

			// only one multiplication
			c1, c2, c3 := mustEncrypt(t, cs, 2), mustEncrypt(t, cs, 3), mustEncrypt(t, cs, 4)
			product := cfMul(t, c1, c2)
			if _, err := product.Multiply(c3); !errors.Is(err, phe.ErrUnsupportedOperation) {
				t.Fatalf("multiplying a product returned %v", err)
			}
			if _, err := c3.Multiply(product); !errors.Is(err, phe.ErrUnsupportedOperation) {
				t.Fatalf("multiplying with a product returned %v", err)
			}
		})
	}
}

func TestRegevAllPlaintextsOfSmallSpace(t *testing.T) {
	cs := mustBuild(t, phe.Regev, lightphe.WithKeySize(32), lightphe.WithPlaintextLimit(big.NewInt(16)))
	if cs.PlaintextModulo().Int64() != 16 {
		t.Fatalf("plaintext modulo is %s, want 16", cs.PlaintextModulo())
	}
	for m := int64(0); m < 16; m++ {
		assertDecrypts(t, cs, mustEncrypt(t, cs, m), m)
	}
}

func TestRegevPlaintextLimit(t *testing.T) {
	// rounded up to a power of 2
	if got := mustBuild(t, phe.Regev, lightphe.WithKeySize(32), lightphe.WithPlaintextLimit(big.NewInt(1000))).PlaintextModulo(); got.Int64() != 1024 {
		t.Fatalf("plaintext modulo is %s, want 1024", got)
	}
	if got := mustBuild(t, phe.Regev, lightphe.WithKeySize(32)).PlaintextModulo(); got.Int64() != 1<<24 {
		t.Fatalf("plaintext modulo is %s, want 2^24", got)
	}

	big32 := mustBuild(t, phe.Regev, lightphe.WithKeySize(32), lightphe.WithPlaintextLimit(big.NewInt(1<<32)))
	assertDecrypts(t, big32, mustEncrypt(t, big32, 1<<32-7), 1<<32-7)

	// no room for noise
	if _, err := lightphe.New(phe.Regev, lightphe.WithKeySize(32), lightphe.WithPlaintextLimit(big.NewInt(1<<45))); !errors.Is(err, phe.ErrKeyGeneration) {
		t.Fatalf("a plaintext limit without room for noise returned %v", err)
	}
	if _, err := lightphe.New(phe.Regev, lightphe.WithKeySize(4)); !errors.Is(err, phe.ErrKeyGeneration) {
		t.Fatalf("a tiny dimension returned %v", err)
	}
}

func TestRegevNoiseBudget(t *testing.T) {
	cs := mustBuild(t, phe.Regev, lightphe.WithKeySize(64))
	modulo := cs.PlaintextModulo().Int64()
	const m = 4567
	c := mustEncrypt(t, cs, m)

	// many additions
	total := mustEncrypt(t, cs, 0)
	for i := 0; i < 1000; i++ {
		total = cfAdd(t, total, c)
	}
	assertDecrypts(t, cs, total, (1000*m)%modulo)

	// large and negative constants
	assertDecrypts(t, cs, cfScale(t, c, big.NewInt(4000)), (4000*m)%modulo)
	assertDecrypts(t, cs, cfScale(t, c, big.NewInt(-3)), mod(-3*m, modulo))
	assertDecrypts(t, cs, cfScale(t, c, big.NewInt(modulo-1)), mod(-m, modulo))

	// random linear combinations
	rng := rand.New(rand.NewSource(7))
	for i := 0; i < 20; i++ {
		var result *encrypted.Ciphertext
		var want int64
		for j := 0; j < 5; j++ {
			v, w := rng.Int63n(1001), rng.Int63n(101)-50
			term := cfScale(t, mustEncrypt(t, cs, v), big.NewInt(w))
			if result == nil {
				result = term
			} else {
				result = cfAdd(t, result, term)
			}
			want += v * w
		}
		assertDecrypts(t, cs, result, mod(want, modulo))
	}
}

func TestRegevLargeKeys(t *testing.T) {
	if testing.Short() {
		t.Skip("dimension 2048 is slow")
	}
	// dimension giving about 128-bit security against quantum attacks
	cs := mustBuild(t, phe.Regev)
	c1, c2 := mustEncrypt(t, cs, 1500), mustEncrypt(t, cs, 2500)
	assertDecrypts(t, cs, cfAdd(t, c1, c2), 4000)
	assertDecrypts(t, cs, cfScale(t, c1, big.NewInt(3)), 4500)
}

func TestBrakerskiVaikuntanathanPlaintextLimit(t *testing.T) {
	if got := mustBuild(t, phe.BrakerskiVaikuntanathan, lightphe.WithKeySize(16), lightphe.WithPlaintextLimit(big.NewInt(1000))).PlaintextModulo(); got.Int64() != 1024 {
		t.Fatalf("plaintext modulo is %s, want 1024", got)
	}

	big32 := mustBuild(t, phe.BrakerskiVaikuntanathan, lightphe.WithKeySize(16), lightphe.WithPlaintextLimit(big.NewInt(1<<32)))
	x, y := int64(1<<32-7), int64(1<<31+5)
	want := new(big.Int).Mul(big.NewInt(x), big.NewInt(y))
	want.Mod(want, big.NewInt(1<<32))
	if got := mustDecrypt(t, big32, cfMul(t, mustEncrypt(t, big32, x), mustEncrypt(t, big32, y))); got.Cmp(want) != 0 {
		t.Fatalf("decrypted %s, want %s", got, want)
	}

	// product of ciphertexts would not be decrypted correctly
	if _, err := lightphe.New(phe.BrakerskiVaikuntanathan, lightphe.WithKeySize(16), lightphe.WithPlaintextLimit(big.NewInt(1<<45))); !errors.Is(err, phe.ErrKeyGeneration) {
		t.Fatalf("a plaintext limit without room for noise returned %v", err)
	}
	for _, keySize := range []int{4, 100} {
		if _, err := lightphe.New(phe.BrakerskiVaikuntanathan, lightphe.WithKeySize(keySize)); !errors.Is(err, phe.ErrKeyGeneration) {
			t.Fatalf("key size %d returned %v", keySize, err)
		}
	}
}

func TestBrakerskiVaikuntanathanLargeKeys(t *testing.T) {
	if testing.Short() {
		t.Skip("ring degree 4096 is slow")
	}
	// ring degree giving about 128-bit security against quantum attacks
	cs := mustBuild(t, phe.BrakerskiVaikuntanathan)
	c1, c2, c3 := mustEncrypt(t, cs, 15), mustEncrypt(t, cs, 25), mustEncrypt(t, cs, 100)

	// one multiplication, then additions and multiplications with constants
	assertDecrypts(t, cs, cfAdd(t, cfMul(t, c1, c2), c3), 475)
	assertDecrypts(t, cs, cfAdd(t, cfScale(t, cfMul(t, c1, c2), big.NewInt(2)), cfMul(t, c1, c3)), 2250)
}

func TestBrakerskiVaikuntanathanKeysAreWellFormed(t *testing.T) {
	cs := mustBuild(t, phe.BrakerskiVaikuntanathan, lightphe.WithKeySize(64))
	keys := cs.Scheme().(*brakerskivaikuntanathan.Cryptosystem).Keys()
	if keys.PublicKey.Q.BitLen() != brakerskivaikuntanathan.LogQ || keys.PublicKey.Q.Bit(0) != 1 {
		t.Fatal("q must be an odd number of 100 bits")
	}
	for _, x := range keys.PrivateKey.S {
		if x < -21 || x > 21 {
			t.Fatalf("secret coefficient %d is not small", x)
		}
	}
}

func TestFreemanBonehGohNissimPlaintextLimit(t *testing.T) {
	cs := mustBuild(t, phe.FreemanBonehGohNissim, lightphe.WithKeySize(64), lightphe.WithPlaintextLimit(big.NewInt(100)))
	modulo := cs.PlaintextModulo()
	assertDecrypts(t, cs, mustEncrypt(t, cs, 100), 100)
	if got := mustDecrypt(t, cs, mustEncrypt(t, cs, -100)); got.Cmp(new(big.Int).Sub(modulo, big.NewInt(100))) != 0 {
		t.Fatalf("-100 decrypted to %s", got)
	}
	assertDecrypts(t, cs, cfMul(t, mustEncrypt(t, cs, 10), mustEncrypt(t, cs, 10)), 100)

	// results out of the limit cannot be restored
	if _, err := cs.Decrypt(mustEncrypt(t, cs, 101)); !errors.Is(err, phe.ErrDecryptionFailed) {
		t.Fatalf("decrypting a value out of the limit returned %v", err)
	}
	if _, err := cs.Decrypt(cfMul(t, mustEncrypt(t, cs, 11), mustEncrypt(t, cs, 10))); !errors.Is(err, phe.ErrDecryptionFailed) {
		t.Fatalf("decrypting a product out of the limit returned %v", err)
	}

	if _, err := lightphe.New(phe.FreemanBonehGohNissim, lightphe.WithKeySize(64), lightphe.WithPlaintextLimit(big.NewInt(1<<40))); !errors.Is(err, phe.ErrKeyGeneration) {
		t.Fatalf("a plaintext limit beyond the group order returned %v", err)
	}
	if _, err := lightphe.New(phe.FreemanBonehGohNissim, lightphe.WithKeySize(16)); !errors.Is(err, phe.ErrKeyGeneration) {
		t.Fatalf("a tiny key size returned %v", err)
	}

	// re-encryption of multiplied ciphertexts is not supported
	_, err := cs.RegenerateCiphertext(cfMul(t, mustEncrypt(t, cs, 2), mustEncrypt(t, cs, 3)))
	assertUnsupported(t, "re-encrypting a product", err)
}

func TestFreemanBonehGohNissimKeysAreWellFormed(t *testing.T) {
	cs := mustBuild(t, phe.FreemanBonehGohNissim, lightphe.WithKeySize(128))
	keys := cs.Scheme().(*freemanbonehgohnissim.Cryptosystem).Keys()
	p, r := keys.PublicKey.P, keys.PublicKey.R
	if new(big.Int).Mod(p, big.NewInt(4)).Int64() != 3 || new(big.Int).Mod(new(big.Int).Add(p, big.NewInt(1)), r).Sign() != 0 {
		t.Fatal("p must be 3 mod 4 and r must divide p + 1")
	}
	if keys.PublicKey.Limit.Int64() != freemanbonehgohnissim.DefaultPlaintextLimit {
		t.Fatalf("limit is %s, want 2^20", keys.PublicKey.Limit)
	}
}

func TestFreemanBonehGohNissimLargeKeys(t *testing.T) {
	if testing.Short() {
		t.Skip("1024-bit keys are slow")
	}
	cs := mustBuild(t, phe.FreemanBonehGohNissim)
	c1, c2 := mustEncrypt(t, cs, 1500), mustEncrypt(t, cs, 300)
	assertDecrypts(t, cs, cfAdd(t, c1, c2), 1800)
	assertDecrypts(t, cs, cfMul(t, c1, c2), 450000)
}

func TestGentryHaleviVaikuntanathanKeysAreWellFormed(t *testing.T) {
	cs := mustBuild(t, phe.GentryHaleviVaikuntanathan)
	keys := cs.Scheme().(*gentryhalevivaikuntanathan.Cryptosystem).Keys()
	a, q, p := keys.PublicKey.A, keys.PublicKey.Q, keys.PublicKey.P.Int64()
	tMatrix, u := keys.PrivateKey.T, keys.PrivateKey.U
	m := len(a)

	// trapdoor T is square, short, and T A = 0 mod q
	bound := int64(q.BitLen() * m)
	for _, row := range tMatrix {
		if len(row) != m {
			t.Fatal("T is not square")
		}
		for _, x := range row {
			if x <= -bound || x >= bound {
				t.Fatalf("entry %d of T is not short", x)
			}
		}
	}
	for _, row := range tMatrix {
		for j := range a[0] {
			acc := new(big.Int)
			for i, x := range row {
				acc.Add(acc, new(big.Int).Mul(big.NewInt(x), new(big.Int).SetUint64(a[i][j])))
			}
			if acc.Mod(acc, q).Sign() != 0 {
				t.Fatal("T A is not 0 mod q")
			}
		}
	}

	// u is the first row of T^-1 modulo p
	for j := 0; j < m; j++ {
		var acc int64
		for i := 0; i < m; i++ {
			acc = mod(acc+u[i]*mod(tMatrix[i][j], p), p)
		}
		want := int64(0)
		if j == 0 {
			want = 1
		}
		if acc != want {
			t.Fatalf("u T column %d is %d, want %d", j, acc, want)
		}
	}
}

func TestGentryHaleviVaikuntanathanKeySizeAndPlaintextLimit(t *testing.T) {
	for _, keySize := range []int{1, 9, 1024} {
		if _, err := lightphe.New(phe.GentryHaleviVaikuntanathan, lightphe.WithKeySize(keySize)); !errors.Is(err, phe.ErrKeyGeneration) {
			t.Fatalf("key size %d returned %v", keySize, err)
		}
	}
	if got := mustBuild(t, phe.GentryHaleviVaikuntanathan).PlaintextModulo(); got.Int64() != 101 {
		t.Fatalf("plaintext modulo is %s, want 101", got)
	}

	// plaintext modulus is the smallest prime greater than or equal to the
	// limit
	cs := mustBuild(t, phe.GentryHaleviVaikuntanathan, lightphe.WithKeySize(2), lightphe.WithPlaintextLimit(big.NewInt(1000)))
	if cs.PlaintextModulo().Int64() != 1009 {
		t.Fatalf("plaintext modulo is %s, want 1009", cs.PlaintextModulo())
	}
	assertDecrypts(t, cs, cfMul(t, mustEncrypt(t, cs, 1000), mustEncrypt(t, cs, 999)), (1000*999)%1009)
}
