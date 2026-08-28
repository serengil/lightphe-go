package phe

import (
	"errors"
	"fmt"
)

// Sentinel errors returned across the library. Callers should test them with
// errors.Is rather than comparing error strings.
var (
	// ErrUnsupportedOperation reports that a cryptosystem is not homomorphic
	// with respect to the requested operation.
	ErrUnsupportedOperation = errors.New("lightphe: unsupported homomorphic operation")

	// ErrMissingPrivateKey reports that an operation needs the private key but
	// the cryptosystem was built from a public key only.
	ErrMissingPrivateKey = errors.New("lightphe: private key is required")

	// ErrMissingPublicKey reports that an operation needs the public key.
	ErrMissingPublicKey = errors.New("lightphe: public key is required")

	// ErrInvalidKeys reports malformed or incomplete key material.
	ErrInvalidKeys = errors.New("lightphe: invalid key material")

	// ErrInvalidCiphertext reports a ciphertext whose shape does not match the
	// cryptosystem that was asked to operate on it.
	ErrInvalidCiphertext = errors.New("lightphe: invalid ciphertext")

	// ErrKeyGeneration reports that key generation gave up.
	ErrKeyGeneration = errors.New("lightphe: key generation failed")

	// ErrDecryptionFailed reports that a plaintext could not be recovered.
	ErrDecryptionFailed = errors.New("lightphe: decryption failed")
)

// Operation names used when reporting an unsupported homomorphic operation.
const (
	OpAddition            = "addition"
	OpMultiplication      = "multiplication"
	OpExclusiveOr         = "exclusive or"
	OpBitwiseAnd          = "bitwise and"
	OpScalarMultiplcation = "multiplication by a known constant"
	OpReencryption        = "re-encryption"
)

// Unsupportedf builds an ErrUnsupportedOperation for the given algorithm and
// operation name.
func Unsupportedf(alg Algorithm, op string) error {
	return fmt.Errorf("lightphe: %s does not support %s: %w", alg, op, ErrUnsupportedOperation)
}

// InvalidKeysf builds an ErrInvalidKeys with additional context.
func InvalidKeysf(format string, args ...interface{}) error {
	return fmt.Errorf("lightphe: "+format+": %w", append(args, ErrInvalidKeys)...)
}

// InvalidCiphertextf builds an ErrInvalidCiphertext with additional context.
func InvalidCiphertextf(format string, args ...interface{}) error {
	return fmt.Errorf("lightphe: "+format+": %w", append(args, ErrInvalidCiphertext)...)
}
