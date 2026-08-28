package elgamal_test

import (
	"errors"
	"math/big"
	"testing"

	"github.com/serengil/lightphe-go/lightphe/phe"
	"github.com/serengil/lightphe-go/lightphe/schemes/elgamal"
)

// keySize stays small because exponential ElGamal decryption solves a discrete
// logarithm over the whole message space.
const keySize = 64

func build(t *testing.T, exponential bool) *elgamal.Cryptosystem {
	t.Helper()
	cs, err := elgamal.Generate(keySize, exponential)
	if err != nil {
		t.Fatalf("generating keys: %v", err)
	}
	return cs
}

func TestTextbookRoundTrip(t *testing.T) {
	cs := build(t, false)

	for _, m := range []int64{1, 17, 21, 4242} {
		plaintext := big.NewInt(m)
		c, err := cs.Encrypt(plaintext)
		if err != nil {
			t.Fatalf("encrypting %d: %v", m, err)
		}
		got, err := cs.Decrypt(c)
		if err != nil {
			t.Fatalf("decrypting %d: %v", m, err)
		}
		if got.Cmp(plaintext) != 0 {
			t.Fatalf("round trip of %d produced %s", m, got)
		}
	}
}

func TestExponentialRoundTrip(t *testing.T) {
	cs := build(t, true)

	for _, m := range []int64{0, 1, 17, 21} {
		plaintext := big.NewInt(m)
		c, err := cs.Encrypt(plaintext)
		if err != nil {
			t.Fatalf("encrypting %d: %v", m, err)
		}
		got, err := cs.Decrypt(c)
		if err != nil {
			t.Fatalf("decrypting %d: %v", m, err)
		}
		if got.Cmp(plaintext) != 0 {
			t.Fatalf("round trip of %d produced %s", m, got)
		}
	}
}

func TestMultiplicativeHomomorphism(t *testing.T) {
	cs := build(t, false)

	m1, m2 := big.NewInt(17), big.NewInt(21)
	c1, _ := cs.Encrypt(m1)
	c2, _ := cs.Encrypt(m2)

	product, err := cs.Multiply(c1, c2)
	if err != nil {
		t.Fatalf("multiplying: %v", err)
	}
	got, err := cs.Decrypt(product)
	if err != nil {
		t.Fatalf("decrypting: %v", err)
	}
	if want := new(big.Int).Mul(m1, m2); got.Cmp(want) != 0 {
		t.Fatalf("decrypted %s, want %s", got, want)
	}

	// The textbook variant is not additively homomorphic.
	if _, err := cs.Add(c1, c2); !errors.Is(err, phe.ErrUnsupportedOperation) {
		t.Fatalf("addition returned %v, want ErrUnsupportedOperation", err)
	}
	if _, err := cs.MultiplyByConstant(c1, m2); !errors.Is(err, phe.ErrUnsupportedOperation) {
		t.Fatalf("scalar multiplication returned %v, want ErrUnsupportedOperation", err)
	}
}

func TestAdditiveHomomorphism(t *testing.T) {
	cs := build(t, true)

	m1, m2 := big.NewInt(17), big.NewInt(21)
	c1, _ := cs.Encrypt(m1)
	c2, _ := cs.Encrypt(m2)

	sum, err := cs.Add(c1, c2)
	if err != nil {
		t.Fatalf("adding: %v", err)
	}
	got, err := cs.Decrypt(sum)
	if err != nil {
		t.Fatalf("decrypting: %v", err)
	}
	if want := new(big.Int).Add(m1, m2); got.Cmp(want) != 0 {
		t.Fatalf("decrypted %s, want %s", got, want)
	}

	scaled, err := cs.MultiplyByConstant(c1, m2)
	if err != nil {
		t.Fatalf("scaling: %v", err)
	}
	if got, err = cs.Decrypt(scaled); err != nil {
		t.Fatalf("decrypting: %v", err)
	}
	if want := new(big.Int).Mul(m1, m2); got.Cmp(want) != 0 {
		t.Fatalf("decrypted %s, want %s", got, want)
	}

	// The exponential variant is not multiplicatively homomorphic.
	if _, err := cs.Multiply(c1, c2); !errors.Is(err, phe.ErrUnsupportedOperation) {
		t.Fatalf("multiplication returned %v, want ErrUnsupportedOperation", err)
	}
}

func TestReencryptionPreservesThePlaintext(t *testing.T) {
	for _, exponential := range []bool{false, true} {
		cs := build(t, exponential)

		m := big.NewInt(17)
		c, err := cs.Encrypt(m)
		if err != nil {
			t.Fatalf("encrypting: %v", err)
		}
		refreshed, err := cs.Reencrypt(c)
		if err != nil {
			t.Fatalf("re-encrypting: %v", err)
		}
		if refreshed.Equal(c) {
			t.Fatal("re-encryption returned the same ciphertext")
		}
		got, err := cs.Decrypt(refreshed)
		if err != nil {
			t.Fatalf("decrypting: %v", err)
		}
		if got.Cmp(m) != 0 {
			t.Fatalf("re-encrypted ciphertext decrypted to %s, want %s", got, m)
		}
	}
}

func TestPublicOnlyCannotDecrypt(t *testing.T) {
	cs := build(t, true)
	public, err := cs.PublicOnly()
	if err != nil {
		t.Fatalf("dropping the private key: %v", err)
	}

	c, err := public.Encrypt(big.NewInt(17))
	if err != nil {
		t.Fatalf("encrypting: %v", err)
	}
	if _, err := public.Decrypt(c); !errors.Is(err, phe.ErrMissingPrivateKey) {
		t.Fatalf("decrypting returned %v, want ErrMissingPrivateKey", err)
	}
	got, err := cs.Decrypt(c)
	if err != nil {
		t.Fatalf("decrypting: %v", err)
	}
	if got.Int64() != 17 {
		t.Fatalf("decrypted %s, want 17", got)
	}
}

func TestKeysRoundTripThroughJSON(t *testing.T) {
	cs := build(t, true)

	exported, err := cs.ExportKeys(true)
	if err != nil {
		t.Fatalf("exporting keys: %v", err)
	}
	restored, err := elgamal.FromJSON(exported, true)
	if err != nil {
		t.Fatalf("restoring keys: %v", err)
	}

	c, err := cs.Encrypt(big.NewInt(21))
	if err != nil {
		t.Fatalf("encrypting: %v", err)
	}
	got, err := restored.Decrypt(c)
	if err != nil {
		t.Fatalf("decrypting: %v", err)
	}
	if got.Int64() != 21 {
		t.Fatalf("decrypted %s, want 21", got)
	}
}

func TestIncompleteKeysAreRejected(t *testing.T) {
	if _, err := elgamal.New(elgamal.Keys{}, false); !errors.Is(err, phe.ErrInvalidKeys) {
		t.Fatalf("empty keys returned %v, want ErrInvalidKeys", err)
	}
	keys := elgamal.Keys{PublicKey: &elgamal.PublicKey{P: big.NewInt(23), G: big.NewInt(5)}}
	if _, err := elgamal.New(keys, false); !errors.Is(err, phe.ErrInvalidKeys) {
		t.Fatalf("a public key without y returned %v, want ErrInvalidKeys", err)
	}
}
