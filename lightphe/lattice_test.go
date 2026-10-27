package lightphe_test

import (
	"crypto/rand"
	"errors"
	"math/big"
	mrand "math/rand"
	"path/filepath"
	"strings"
	"testing"

	"github.com/serengil/lightphe-go/lightphe"
	"github.com/serengil/lightphe-go/lightphe/encrypted"
	"github.com/serengil/lightphe-go/lightphe/phe"
)

// Lyubashevsky-Peikert-Regev, ML-KEM and Gentry-Sahai-Waters rely on learning
// with errors problems over rings and modules.

func TestLyubashevskyPeikertRegevAllPlaintextsOfSmallSpace(t *testing.T) {
	cs := mustBuild(t, phe.LyubashevskyPeikertRegev, lightphe.WithKeySize(32), lightphe.WithPlaintextLimit(big.NewInt(16)))
	if cs.PlaintextModulo().Int64() != 16 {
		t.Fatalf("plaintext modulo is %s, want 16", cs.PlaintextModulo())
	}
	for m := int64(0); m < 16; m++ {
		assertDecrypts(t, cs, mustEncrypt(t, cs, m), m)
	}
}

func TestLyubashevskyPeikertRegevPlaintextLimit(t *testing.T) {
	alg := phe.LyubashevskyPeikertRegev
	// rounded up to a power of 2
	if got := mustBuild(t, alg, lightphe.WithKeySize(32), lightphe.WithPlaintextLimit(big.NewInt(1000))).PlaintextModulo(); got.Int64() != 1024 {
		t.Fatalf("plaintext modulo is %s, want 1024", got)
	}
	if got := mustBuild(t, alg, lightphe.WithKeySize(32)).PlaintextModulo(); got.Int64() != 1<<24 {
		t.Fatalf("plaintext modulo is %s, want 2^24", got)
	}

	big32 := mustBuild(t, alg, lightphe.WithKeySize(32), lightphe.WithPlaintextLimit(big.NewInt(1<<32)))
	assertDecrypts(t, big32, mustEncrypt(t, big32, 1<<32-7), 1<<32-7)

	// no room for noise
	if _, err := lightphe.New(alg, lightphe.WithKeySize(32), lightphe.WithPlaintextLimit(big.NewInt(1<<45))); !errors.Is(err, phe.ErrKeyGeneration) {
		t.Fatalf("a plaintext limit without room for noise returned %v", err)
	}

	// ring degree must be a power of 2
	for _, keySize := range []int{4, 48, 100} {
		if _, err := lightphe.New(alg, lightphe.WithKeySize(keySize)); !errors.Is(err, phe.ErrKeyGeneration) {
			t.Fatalf("key size %d returned %v", keySize, err)
		}
	}
}

func TestLyubashevskyPeikertRegevNoiseBudget(t *testing.T) {
	cs := mustBuild(t, phe.LyubashevskyPeikertRegev, lightphe.WithKeySize(64))
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
	rng := mrand.New(mrand.NewSource(7))
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

func TestLyubashevskyPeikertRegevLargeKeys(t *testing.T) {
	if testing.Short() {
		t.Skip("degree 2048 is slow")
	}
	// ring degree giving about 128-bit security against quantum attacks
	cs := mustBuild(t, phe.LyubashevskyPeikertRegev)
	modulo := cs.PlaintextModulo().Int64()
	const m1, m2 = 1234567, 7654321
	c1, c2 := mustEncrypt(t, cs, m1), mustEncrypt(t, cs, m2)
	if tuple, err := phe.AsTuple(c1.Value); err != nil || tuple.Len() != 2048+1 {
		t.Fatalf("ciphertext has %d entries, want 2049", tuple.Len())
	}

	assertDecrypts(t, cs, c1, m1)
	assertDecrypts(t, cs, cfAdd(t, c1, c2), m1+m2)
	assertDecrypts(t, cs, cfScale(t, c1, big.NewInt(1000)), (m1*1000)%modulo)
	assertDecrypts(t, cs, cfAdd(t, cfScale(t, c1, big.NewInt(-1000)), cfScale(t, c2, big.NewInt(3))), mod(-1000*m1+3*m2, modulo))

	total := mustEncrypt(t, cs, 0)
	for i := 0; i < 1000; i++ {
		total = cfAdd(t, total, c1)
	}
	assertDecrypts(t, cs, total, (1000*m1)%modulo)
}

func random256(t *testing.T) *big.Int {
	t.Helper()
	m, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 256))
	if err != nil {
		t.Fatalf("reading randomness: %v", err)
	}
	return m
}

func mustEncryptBig(t *testing.T, cs *lightphe.Cryptosystem, m *big.Int) *encrypted.Ciphertext {
	t.Helper()
	c, err := cs.Encrypt(m)
	if err != nil {
		t.Fatalf("encrypting %s: %v", m, err)
	}
	return c
}

func assertDecryptsBig(t *testing.T, cs *lightphe.Cryptosystem, c *encrypted.Ciphertext, want *big.Int) {
	t.Helper()
	if got := mustDecrypt(t, cs, c); got.Cmp(want) != 0 {
		t.Fatalf("decrypted %s, want %s", got, want)
	}
}

func xor(t *testing.T, a, b *encrypted.Ciphertext) *encrypted.Ciphertext {
	t.Helper()
	c, err := a.Xor(b)
	if err != nil {
		t.Fatalf("exclusive or: %v", err)
	}
	return c
}

func and(t *testing.T, a, b *encrypted.Ciphertext) *encrypted.Ciphertext {
	t.Helper()
	c, err := a.And(b)
	if err != nil {
		t.Fatalf("and: %v", err)
	}
	return c
}

func TestMLKEMAPI(t *testing.T) {
	for _, parameterSet := range []int{512, 768, 1024} {
		parameterSet := parameterSet
		t.Run(big.NewInt(int64(parameterSet)).String(), func(t *testing.T) {
			t.Parallel()
			cs := mustBuild(t, phe.MLKEM, lightphe.WithKeySize(parameterSet))
			var c1 *encrypted.Ciphertext
			var m1 *big.Int
			for i := 0; i < 5; i++ {
				m1, m2 := random256(t), random256(t)
				c1, c2 := mustEncryptBig(t, cs, m1), mustEncryptBig(t, cs, m2)

				// proof of decryption
				assertDecryptsBig(t, cs, c1, m1)
				assertDecryptsBig(t, cs, c2, m2)

				// homomorphic exclusive or
				assertDecryptsBig(t, cs, xor(t, c1, c2), new(big.Int).Xor(m1, m2))
				assertDecryptsBig(t, cs, xor(t, c1, c1), new(big.Int))
			}

			// k + 1 polynomials of 256 coefficients in [0, q)
			k := map[int]int{512: 2, 768: 3, 1024: 4}[parameterSet]
			m1 = random256(t)
			c1 = mustEncryptBig(t, cs, m1)
			if tuple, err := phe.AsTuple(c1.Value); err != nil || tuple.Len() != k+1 {
				t.Fatalf("ciphertext has %d polynomials, want %d", tuple.Len(), k+1)
			}

			// edge plaintexts and plaintexts exceeding 256 bits
			limit := new(big.Int).Lsh(big.NewInt(1), 256)
			for _, m := range []*big.Int{big.NewInt(0), big.NewInt(1), new(big.Int).Lsh(big.NewInt(1), 255),
				new(big.Int).Sub(limit, big.NewInt(1))} {
				assertDecryptsBig(t, cs, mustEncryptBig(t, cs, m), m)
			}
			assertDecryptsBig(t, cs, mustEncryptBig(t, cs, new(big.Int).Add(limit, big.NewInt(5))), big.NewInt(5))
			assertDecryptsBig(t, cs, mustEncryptBig(t, cs, big.NewInt(-1)), new(big.Int).Sub(limit, big.NewInt(1)))

			// re-randomization
			regenerated, err := cs.RegenerateCiphertext(c1)
			if err != nil {
				t.Fatalf("regenerating: %v", err)
			}
			if regenerated.Value.Equal(c1.Value) {
				t.Fatal("regenerated ciphertext is identical to the original")
			}
			assertDecryptsBig(t, cs, regenerated, m1)

			// unsupported homomorphic operations
			_, err = c1.Add(c1)
			assertUnsupported(t, "addition", err)
			_, err = c1.Multiply(c1)
			assertUnsupported(t, "multiplication", err)
			_, err = c1.MultiplyByInt(3)
			assertUnsupported(t, "scalar multiplication", err)
			_, err = c1.And(c1)
			assertUnsupported(t, "bitwise and", err)

			// failure probability of combining 6 ciphertexts is about 2^-36 or less
			expected := random256(t)
			total := mustEncryptBig(t, cs, expected)
			for i := 0; i < 5; i++ {
				m := random256(t)
				total = xor(t, total, mustEncryptBig(t, cs, m))
				expected.Xor(expected, m)
			}
			assertDecryptsBig(t, cs, total, expected)
		})
	}
}

func TestMLKEMInvalidInputs(t *testing.T) {
	cs := mustBuild(t, phe.MLKEM, lightphe.WithKeySize(512))
	if _, err := cs.EncryptFloat(1.5); !errors.Is(err, lightphe.ErrFloatNotSupported) {
		t.Fatalf("encrypting a float returned %v", err)
	}
	if _, err := cs.EncryptTensor([]float64{1, 2, 3}); !errors.Is(err, lightphe.ErrFloatNotSupported) {
		t.Fatalf("encrypting a tensor returned %v", err)
	}
	for _, keySize := range []int{256, 1000, 2048} {
		if _, err := lightphe.New(phe.MLKEM, lightphe.WithKeySize(keySize)); !errors.Is(err, phe.ErrKeyGeneration) {
			t.Fatalf("key size %d returned %v", keySize, err)
		}
	}

	// default parameter set is ML-KEM-768
	keys, err := mustBuild(t, phe.MLKEM).Keys(true)
	if err != nil {
		t.Fatalf("exporting keys: %v", err)
	}
	if !strings.Contains(string(keys), `"parameter_set":768`) {
		t.Fatalf("default parameter set is not 768: %s", keys[:64])
	}
}

func TestMLKEMExportedKeys(t *testing.T) {
	dir := t.TempDir()
	publicFile, privateFile := filepath.Join(dir, "public.txt"), filepath.Join(dir, "private.txt")
	cs := mustBuild(t, phe.MLKEM)
	if err := cs.ExportKeys(publicFile, true); err != nil {
		t.Fatalf("exporting: %v", err)
	}
	if err := cs.ExportKeys(privateFile, false); err != nil {
		t.Fatalf("exporting: %v", err)
	}

	m1, m2 := random256(t), random256(t)
	publicCs := mustBuild(t, phe.MLKEM, lightphe.WithKeyFile(publicFile))
	c := xor(t, mustEncryptBig(t, publicCs, m1), mustEncryptBig(t, publicCs, m2))
	if _, err := publicCs.Decrypt(c); !errors.Is(err, phe.ErrMissingPrivateKey) {
		t.Fatalf("decrypting with the public key returned %v", err)
	}

	restored := mustBuild(t, phe.MLKEM, lightphe.WithKeyFile(privateFile))
	assertDecryptsBig(t, restored, c, new(big.Int).Xor(m1, m2))
	assertDecryptsBig(t, cs, c, new(big.Int).Xor(m1, m2))
}

func TestGentrySahaiWatersTruthTables(t *testing.T) {
	cs := mustBuild(t, phe.GentrySahaiWaters, lightphe.WithKeySize(64))
	for a := int64(0); a <= 1; a++ {
		for b := int64(0); b <= 1; b++ {
			ca, cb := mustEncrypt(t, cs, a), mustEncrypt(t, cs, b)
			assertDecrypts(t, cs, ca, a)
			assertDecrypts(t, cs, and(t, ca, cb), a&b)
			assertDecrypts(t, cs, cfMul(t, ca, cb), a*b)
			assertDecrypts(t, cs, xor(t, ca, cb), a^b)
		}
	}

	// not is exclusive or with 1
	one := mustEncrypt(t, cs, 1)
	assertDecrypts(t, cs, xor(t, mustEncrypt(t, cs, 0), one), 1)
	assertDecrypts(t, cs, xor(t, mustEncrypt(t, cs, 1), one), 0)

	// re-randomization
	c := mustEncrypt(t, cs, 1)
	regenerated, err := cs.RegenerateCiphertext(c)
	if err != nil {
		t.Fatalf("regenerating: %v", err)
	}
	if regenerated.Value.Equal(c.Value) {
		t.Fatal("regenerated ciphertext is identical to the original")
	}
	assertDecrypts(t, cs, regenerated, 1)

	// unsupported homomorphic operations
	_, err = c.Add(regenerated)
	assertUnsupported(t, "addition", err)
	_, err = c.MultiplyByInt(3)
	assertUnsupported(t, "scalar multiplication", err)
}

func TestGentrySahaiWatersCircuitsOfDepthTwo(t *testing.T) {
	cs := mustBuild(t, phe.GentrySahaiWaters, lightphe.WithKeySize(64))
	for x := int64(0); x < 16; x++ {
		a, b, c, d := x&1, (x>>1)&1, (x>>2)&1, (x>>3)&1
		ca, cb, cc, cd := mustEncrypt(t, cs, a), mustEncrypt(t, cs, b), mustEncrypt(t, cs, c), mustEncrypt(t, cs, d)

		// product of products
		assertDecrypts(t, cs, and(t, and(t, ca, cb), and(t, cc, cd)), a&b&c&d)

		// majority of three
		majority := xor(t, xor(t, and(t, ca, cb), and(t, ca, cc)), and(t, cb, cc))
		want := int64(0)
		if a+b+c >= 2 {
			want = 1
		}
		assertDecrypts(t, cs, majority, want)

		// exclusive or of products, and product of exclusive ors
		assertDecrypts(t, cs, xor(t, and(t, ca, cb), and(t, cc, cd)), (a&b)^(c&d))
		assertDecrypts(t, cs, and(t, xor(t, ca, cb), xor(t, cc, cd)), (a^b)&(c^d))
	}
}

func TestGentrySahaiWatersLongChainOfAnds(t *testing.T) {
	cs := mustBuild(t, phe.GentrySahaiWaters, lightphe.WithKeySize(64))
	// acc = acc & fresh adds a fixed noise each time
	for _, zeroAt := range []int{-1, 20} {
		acc := mustEncrypt(t, cs, 1)
		want := int64(1)
		for i := 1; i < 40; i++ {
			bit := int64(1)
			if i == zeroAt {
				bit, want = 0, 0
			}
			acc = and(t, acc, mustEncrypt(t, cs, bit))
		}
		assertDecrypts(t, cs, acc, want)
	}
}

func TestGentrySahaiWatersRippleCarryAdder(t *testing.T) {
	cs := mustBuild(t, phe.GentrySahaiWaters, lightphe.WithKeySize(64))
	rng := mrand.New(mrand.NewSource(3))
	// add two encrypted 8-bit integers bit by bit. carry is chained with fresh
	// bits.
	for i := 0; i < 3; i++ {
		x, y := rng.Int63n(256), rng.Int63n(256)
		carry := mustEncrypt(t, cs, 0)
		var resultBits []*encrypted.Ciphertext
		for j := uint(0); j < 8; j++ {
			a, b := mustEncrypt(t, cs, (x>>j)&1), mustEncrypt(t, cs, (y>>j)&1)
			half := xor(t, a, b)
			resultBits = append(resultBits, xor(t, half, carry))
			// carry = a & b ^ carry & (a ^ b)
			carry = xor(t, and(t, a, b), and(t, carry, half))
		}
		resultBits = append(resultBits, carry)

		result := int64(0)
		for j, bit := range resultBits {
			result |= mustDecrypt(t, cs, bit).Int64() << uint(j)
		}
		if result != x+y {
			t.Fatalf("%d + %d = %d, want %d", x, y, result, x+y)
		}
	}
}

func TestGentrySahaiWatersInvalidInputs(t *testing.T) {
	cs := mustBuild(t, phe.GentrySahaiWaters, lightphe.WithKeySize(16))
	for _, m := range []int64{2, -1} {
		if _, err := cs.EncryptInt(m); !errors.Is(err, lightphe.ErrFloatNotSupported) {
			t.Fatalf("encrypting %d returned %v", m, err)
		}
	}
	if _, err := cs.EncryptFloat(1.5); !errors.Is(err, lightphe.ErrFloatNotSupported) {
		t.Fatalf("encrypting a float returned %v", err)
	}
	if _, err := cs.EncryptTensor([]float64{0, 1}); !errors.Is(err, lightphe.ErrFloatNotSupported) {
		t.Fatalf("encrypting a tensor returned %v", err)
	}
	if _, err := mustEncrypt(t, cs, 1).MultiplyByFloat(1.5); !errors.Is(err, lightphe.ErrFloatNotSupported) {
		t.Fatalf("multiplying by a float returned %v", err)
	}
	for _, keySize := range []int{4, 48, 100} {
		if _, err := lightphe.New(phe.GentrySahaiWaters, lightphe.WithKeySize(keySize)); !errors.Is(err, phe.ErrKeyGeneration) {
			t.Fatalf("key size %d returned %v", keySize, err)
		}
	}
}

func TestGentrySahaiWatersExportedKeys(t *testing.T) {
	cs := mustBuild(t, phe.GentrySahaiWaters, lightphe.WithKeySize(64))
	publicFile := filepath.Join(t.TempDir(), "public.txt")
	if err := cs.ExportKeys(publicFile, true); err != nil {
		t.Fatalf("exporting: %v", err)
	}
	publicCs := mustBuild(t, phe.GentrySahaiWaters, lightphe.WithKeyFile(publicFile))
	c := and(t, mustEncrypt(t, publicCs, 1), mustEncrypt(t, publicCs, 1))
	assertDecrypts(t, cs, c, 1)
	if _, err := publicCs.Decrypt(c); !errors.Is(err, phe.ErrMissingPrivateKey) {
		t.Fatalf("decrypting with the public key returned %v", err)
	}
}

func TestGentrySahaiWatersLargeKeys(t *testing.T) {
	if testing.Short() {
		t.Skip("degree 2048 is slow")
	}
	// products of products of depth 2 stay below q / 4 for the default degree
	cs := mustBuild(t, phe.GentrySahaiWaters)
	a, b, c, d := mustEncrypt(t, cs, 1), mustEncrypt(t, cs, 1), mustEncrypt(t, cs, 1), mustEncrypt(t, cs, 1)
	abcd := and(t, and(t, a, b), and(t, c, d))
	assertDecrypts(t, cs, abcd, 1)

	// a chain with a fresh ciphertext on the right adds a small noise
	assertDecrypts(t, cs, and(t, abcd, mustEncrypt(t, cs, 0)), 0)

	// majority of three and a product of products
	c0 := mustEncrypt(t, cs, 0)
	assertDecrypts(t, cs, xor(t, xor(t, and(t, a, b), and(t, a, c0)), and(t, b, c0)), 1)
	assertDecrypts(t, cs, and(t, and(t, a, b), and(t, c0, d)), 0)
}
