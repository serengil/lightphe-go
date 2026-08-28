package phe

import "math/big"

// Homomorphic is the contract every cryptosystem in this library fulfils.
//
// Implementations are immutable after construction: key material is never
// written to again, and every operation returns a freshly allocated Value. A
// single Homomorphic may therefore be shared by any number of goroutines.
//
// The optional operations (Add, Multiply, MultiplyByConstant, Xor, And,
// Reencrypt) return an error wrapping ErrUnsupportedOperation when the scheme
// is not homomorphic with respect to them. Embedding Base gives a cryptosystem
// those defaults for free.
type Homomorphic interface {
	// Algorithm reports which cryptosystem this is.
	Algorithm() Algorithm

	// PlaintextModulo is the size of the message space. Plaintexts are
	// normalised into [0, PlaintextModulo) before encryption.
	PlaintextModulo() *big.Int

	// CiphertextModulo is the modulus ciphertext arithmetic is carried out in.
	CiphertextModulo() *big.Int

	// HasPrivateKey reports whether decryption is possible.
	HasPrivateKey() bool

	// PublicOnly returns an equivalent cryptosystem stripped of its private
	// key, suitable for handing to an untrusted party that should be able to
	// encrypt and evaluate but not decrypt.
	PublicOnly() (Homomorphic, error)

	// ExportKeys serialises the key material as JSON. When includePrivate is
	// false the private key is omitted.
	ExportKeys(includePrivate bool) ([]byte, error)

	// Encrypt encrypts a plaintext that is already reduced modulo
	// PlaintextModulo.
	Encrypt(plaintext *big.Int) (Value, error)

	// Decrypt recovers the plaintext. It requires the private key.
	Decrypt(ciphertext Value) (*big.Int, error)

	// Add evaluates E(m1 + m2) from E(m1) and E(m2).
	Add(a, b Value) (Value, error)

	// Multiply evaluates E(m1 * m2) from E(m1) and E(m2).
	Multiply(a, b Value) (Value, error)

	// MultiplyByConstant evaluates E(m * k) from E(m) and a known k.
	MultiplyByConstant(ciphertext Value, constant *big.Int) (Value, error)

	// Xor evaluates E(m1 ^ m2) from E(m1) and E(m2).
	Xor(a, b Value) (Value, error)

	// And evaluates E(m1 & m2) from E(m1) and E(m2).
	And(a, b Value) (Value, error)

	// Reencrypt returns a different ciphertext for the same plaintext.
	Reencrypt(ciphertext Value) (Value, error)
}

// Base supplies the default, "not homomorphic with respect to this operation"
// behaviour for the optional parts of the Homomorphic contract. Cryptosystems
// embed it and shadow the operations they actually support.
type Base struct {
	Alg Algorithm
}

// Algorithm implements Homomorphic.
func (b Base) Algorithm() Algorithm { return b.Alg }

// Add implements Homomorphic by reporting the operation as unsupported.
func (b Base) Add(_, _ Value) (Value, error) {
	return nil, Unsupportedf(b.Alg, OpAddition)
}

// Multiply implements Homomorphic by reporting the operation as unsupported.
func (b Base) Multiply(_, _ Value) (Value, error) {
	return nil, Unsupportedf(b.Alg, OpMultiplication)
}

// MultiplyByConstant implements Homomorphic by reporting the operation as
// unsupported.
func (b Base) MultiplyByConstant(_ Value, _ *big.Int) (Value, error) {
	return nil, Unsupportedf(b.Alg, OpScalarMultiplcation)
}

// Xor implements Homomorphic by reporting the operation as unsupported.
func (b Base) Xor(_, _ Value) (Value, error) {
	return nil, Unsupportedf(b.Alg, OpExclusiveOr)
}

// And implements Homomorphic by reporting the operation as unsupported.
func (b Base) And(_, _ Value) (Value, error) {
	return nil, Unsupportedf(b.Alg, OpBitwiseAnd)
}

// Reencrypt implements Homomorphic by reporting the operation as unsupported.
func (b Base) Reencrypt(_ Value) (Value, error) {
	return nil, Unsupportedf(b.Alg, OpReencryption)
}

// Normalize reduces value into [0, modulo). It accepts negative inputs, which
// are mapped onto the upper half of the message space the same way the Python
// implementation does.
func Normalize(value, modulo *big.Int) *big.Int {
	return new(big.Int).Mod(value, modulo)
}
