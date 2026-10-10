package lightphe_test

import (
	"errors"
	"math/big"
	"testing"

	"github.com/serengil/lightphe-go/lightphe"
	"github.com/serengil/lightphe-go/lightphe/phe"
)

// Joye-Libert and Castagnos-Laguillaumie are both additively homomorphic with
// a decryption that needs no brute force, so they share one set of tests.
var linearAlgorithms = []phe.Algorithm{phe.JoyeLibert, phe.CastagnosLaguillaumie}

func TestLinearSchemesAPI(t *testing.T) {
	for _, alg := range linearAlgorithms {
		alg := alg
		t.Run(alg.String(), func(t *testing.T) {
			t.Parallel()
			cs := mustBuild(t, alg, lightphe.WithKeySize(testKeySize))
			modulo := cs.PlaintextModulo()

			const m1, m2 = 17, 21
			c1 := mustEncrypt(t, cs, m1)
			c2 := mustEncrypt(t, cs, m2)

			// proof of decryption
			assertDecrypts(t, cs, c1, m1)
			assertDecrypts(t, cs, c2, m2)

			// homomorphic addition
			sum, err := c1.Add(c2)
			if err != nil {
				t.Fatalf("homomorphic addition: %v", err)
			}
			assertDecrypts(t, cs, sum, m1+m2)

			// homomorphic scalar multiplication
			scaled, err := c1.MultiplyByInt(m2)
			if err != nil {
				t.Fatalf("scalar multiplication: %v", err)
			}
			assertDecrypts(t, cs, scaled, m1*m2)

			// negative plaintexts and addition wrapping around the plaintext modulo
			c3 := mustEncrypt(t, cs, -5)
			want := new(big.Int).Sub(modulo, big.NewInt(5))
			if got := mustDecrypt(t, cs, c3); got.Cmp(want) != 0 {
				t.Fatalf("decrypted -5 as %s, want %s", got, want)
			}
			wrapped, err := c1.Add(c3)
			if err != nil {
				t.Fatalf("homomorphic addition: %v", err)
			}
			assertDecrypts(t, cs, wrapped, m1-5)

			top, err := cs.Encrypt(new(big.Int).Sub(modulo, big.NewInt(1)))
			if err != nil {
				t.Fatalf("encrypting modulo - 1: %v", err)
			}
			around, err := top.Add(c1)
			if err != nil {
				t.Fatalf("homomorphic addition: %v", err)
			}
			assertDecrypts(t, cs, around, m1-1)

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
		})
	}
}

func TestLinearSchemesRestoreEveryPlaintextOfSmallKeySpace(t *testing.T) {
	for _, alg := range linearAlgorithms {
		alg := alg
		t.Run(alg.String(), func(t *testing.T) {
			t.Parallel()
			cs := mustBuild(t, alg, lightphe.WithKeySize(24))
			modulo := cs.PlaintextModulo().Int64()
			for m := int64(0); m < modulo; m++ {
				assertDecrypts(t, cs, mustEncrypt(t, cs, m), m)
			}
		})
	}
}

func TestLinearSchemesLargeKeys(t *testing.T) {
	if testing.Short() {
		t.Skip("1024-bit keys are slow")
	}
	for _, alg := range linearAlgorithms {
		alg := alg
		t.Run(alg.String(), func(t *testing.T) {
			t.Parallel()
			cs := mustBuild(t, alg, lightphe.WithKeySize(1024))
			if cs.PlaintextModulo().BitLen() <= 200 {
				t.Fatalf("plaintext modulo has only %d bits", cs.PlaintextModulo().BitLen())
			}

			const m1, m2 = 123456789, 987654321
			c1 := mustEncrypt(t, cs, m1)
			c2 := mustEncrypt(t, cs, m2)
			sum, err := c1.Add(c2)
			if err != nil {
				t.Fatalf("homomorphic addition: %v", err)
			}
			assertDecrypts(t, cs, sum, m1+m2)

			scaled, err := c1.MultiplyByInt(1000)
			if err != nil {
				t.Fatalf("scalar multiplication: %v", err)
			}
			assertDecrypts(t, cs, scaled, m1*1000)
		})
	}
}

func TestJoyeLibertRejectsFloats(t *testing.T) {
	cs := mustBuild(t, phe.JoyeLibert, lightphe.WithKeySize(1024))
	c1 := mustEncrypt(t, cs, 17)

	// powers of 10 are not invertible in Z_{2^k}, so floats are not supported
	if _, err := c1.MultiplyByFloat(1.5); !errors.Is(err, lightphe.ErrFloatNotSupported) {
		t.Fatalf("multiplying by a float returned %v, want ErrFloatNotSupported", err)
	}
	if _, err := cs.EncryptFloat(1.5); !errors.Is(err, lightphe.ErrFloatNotSupported) {
		t.Fatalf("encrypting a float returned %v, want ErrFloatNotSupported", err)
	}

	// floats without a fractional part need no inverse, so they still work
	scaled, err := c1.MultiplyByFloat(2)
	if err != nil {
		t.Fatalf("multiplying by 2.0: %v", err)
	}
	assertDecrypts(t, cs, scaled, 34)

	// tensors are still supported because division happens after decryption
	tensor, err := cs.EncryptTensor([]float64{1.5, 2.25, 3.5})
	if err != nil {
		t.Fatalf("encrypting a tensor: %v", err)
	}
	plain, err := cs.DecryptTensor(tensor)
	if err != nil {
		t.Fatalf("decrypting a tensor: %v", err)
	}
	for i, want := range []float64{1.5, 2.25, 3.5} {
		if plain[i] != want {
			t.Fatalf("tensor element %d decrypted to %v, want %v", i, plain[i], want)
		}
	}
	dot, err := tensor.Dot([]float64{2, 4, 1})
	if err != nil {
		t.Fatalf("dot product: %v", err)
	}
	if got, err := cs.DecryptTensor(dot); err != nil || got[0] != 15.5 {
		t.Fatalf("dot product decrypted to %v (%v), want 15.5", got, err)
	}

	// but multiplying a tensor with a float constant is not
	if _, err := tensor.MultiplyByConstant(1.5); !errors.Is(err, lightphe.ErrFloatNotSupported) {
		t.Fatalf("multiplying a tensor by a float returned %v, want ErrFloatNotSupported", err)
	}
}
