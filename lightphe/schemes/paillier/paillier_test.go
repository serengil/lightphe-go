package paillier_test

import (
	"errors"
	"math/big"
	"testing"

	"github.com/serengil/lightphe-go/lightphe/phe"
	"github.com/serengil/lightphe-go/lightphe/schemes/paillier"
)

const keySize = 128

func build(t *testing.T) *paillier.Cryptosystem {
	t.Helper()
	cs, err := paillier.Generate(keySize)
	if err != nil {
		t.Fatalf("generating keys: %v", err)
	}
	return cs
}

func TestEncryptDecryptRoundTrip(t *testing.T) {
	cs := build(t)

	for _, m := range []int64{0, 1, 17, 21, 1000, 123456789} {
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

func TestEncryptionIsProbabilistic(t *testing.T) {
	cs := build(t)
	m := big.NewInt(17)

	first, err := cs.Encrypt(m)
	if err != nil {
		t.Fatalf("encrypting: %v", err)
	}
	second, err := cs.Encrypt(m)
	if err != nil {
		t.Fatalf("encrypting: %v", err)
	}
	if first.Equal(second) {
		t.Fatal("two encryptions of the same plaintext produced identical ciphertexts")
	}
}

func TestAdditiveHomomorphism(t *testing.T) {
	cs := build(t)

	m1, m2 := big.NewInt(17), big.NewInt(21)
	c1, err := cs.Encrypt(m1)
	if err != nil {
		t.Fatalf("encrypting: %v", err)
	}
	c2, err := cs.Encrypt(m2)
	if err != nil {
		t.Fatalf("encrypting: %v", err)
	}

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
}

func TestScalarMultiplication(t *testing.T) {
	cs := build(t)

	m, k := big.NewInt(17), big.NewInt(21)
	c, err := cs.Encrypt(m)
	if err != nil {
		t.Fatalf("encrypting: %v", err)
	}
	scaled, err := cs.MultiplyByConstant(c, k)
	if err != nil {
		t.Fatalf("scaling: %v", err)
	}
	got, err := cs.Decrypt(scaled)
	if err != nil {
		t.Fatalf("decrypting: %v", err)
	}
	if want := new(big.Int).Mul(m, k); got.Cmp(want) != 0 {
		t.Fatalf("decrypted %s, want %s", got, want)
	}
}

func TestUnsupportedOperations(t *testing.T) {
	cs := build(t)
	c, err := cs.Encrypt(big.NewInt(17))
	if err != nil {
		t.Fatalf("encrypting: %v", err)
	}

	for name, op := range map[string]func() (phe.Value, error){
		"multiplication": func() (phe.Value, error) { return cs.Multiply(c, c) },
		"exclusive or":   func() (phe.Value, error) { return cs.Xor(c, c) },
		"bitwise and":    func() (phe.Value, error) { return cs.And(c, c) },
	} {
		if _, err := op(); !errors.Is(err, phe.ErrUnsupportedOperation) {
			t.Fatalf("%s returned %v, want ErrUnsupportedOperation", name, err)
		}
	}
}

func TestPublicOnlyCannotDecrypt(t *testing.T) {
	cs := build(t)
	public, err := cs.PublicOnly()
	if err != nil {
		t.Fatalf("dropping the private key: %v", err)
	}
	if public.HasPrivateKey() {
		t.Fatal("the public cryptosystem still reports a private key")
	}

	c, err := public.Encrypt(big.NewInt(17))
	if err != nil {
		t.Fatalf("encrypting: %v", err)
	}
	if _, err := public.Decrypt(c); !errors.Is(err, phe.ErrMissingPrivateKey) {
		t.Fatalf("decrypting returned %v, want ErrMissingPrivateKey", err)
	}

	// The original still decrypts what the public half produced.
	got, err := cs.Decrypt(c)
	if err != nil {
		t.Fatalf("decrypting: %v", err)
	}
	if got.Int64() != 17 {
		t.Fatalf("decrypted %s, want 17", got)
	}
}

func TestKeysRoundTripThroughJSON(t *testing.T) {
	cs := build(t)

	exported, err := cs.ExportKeys(true)
	if err != nil {
		t.Fatalf("exporting keys: %v", err)
	}
	restored, err := paillier.FromJSON(exported)
	if err != nil {
		t.Fatalf("restoring keys: %v", err)
	}

	c, err := cs.Encrypt(big.NewInt(4242))
	if err != nil {
		t.Fatalf("encrypting: %v", err)
	}
	got, err := restored.Decrypt(c)
	if err != nil {
		t.Fatalf("decrypting: %v", err)
	}
	if got.Int64() != 4242 {
		t.Fatalf("decrypted %s, want 4242", got)
	}
}

func TestIncompleteKeysAreRejected(t *testing.T) {
	if _, err := paillier.New(paillier.Keys{}); !errors.Is(err, phe.ErrInvalidKeys) {
		t.Fatalf("empty keys returned %v, want ErrInvalidKeys", err)
	}
	keys := paillier.Keys{PublicKey: &paillier.PublicKey{N: big.NewInt(15)}}
	if _, err := paillier.New(keys); !errors.Is(err, phe.ErrInvalidKeys) {
		t.Fatalf("a public key without g returned %v, want ErrInvalidKeys", err)
	}
}

func TestConcurrentUseIsSafe(t *testing.T) {
	cs := build(t)
	const workers = 16

	errs := make(chan error, workers)
	for i := 0; i < workers; i++ {
		go func(m int64) {
			c, err := cs.Encrypt(big.NewInt(m))
			if err != nil {
				errs <- err
				return
			}
			got, err := cs.Decrypt(c)
			if err != nil {
				errs <- err
				return
			}
			if got.Int64() != m {
				errs <- errors.New("round trip mismatch")
				return
			}
			errs <- nil
		}(int64(i))
	}
	for i := 0; i < workers; i++ {
		if err := <-errs; err != nil {
			t.Fatalf("concurrent use failed: %v", err)
		}
	}
}
