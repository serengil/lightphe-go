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

	// ErrFloatNotSupported reports a float plaintext, constant or tensor given
	// to a cryptosystem that only works on integers.
	ErrFloatNotSupported = errors.New("lightphe: float values are not supported")
)

// Operation names used when reporting an unsupported homomorphic operation.
const (
	OpAddition            = "addition"
	OpMultiplication      = "multiplication"
	OpExclusiveOr         = "exclusive or"
	OpBitwiseAnd          = "bitwise and"
	OpScalarMultiplcation = "multiplication by a known constant"
	OpReencryption        = "re-encryption"
	OpDecisionTree        = "evaluating decision trees"
	OpDecisionTreeInput   = "evaluating decision trees with bits and depth"
	OpNumericDecisionTree = "private decision tree evaluation with numeric features"
	OpSecureComparison    = "secure comparison"
	OpArgmax              = "encrypted argmax"
	OpMasterKey           = "master key decryption"
	OpUserKeys            = "generating user keys sharing a master key"
	OpVerifiable          = "verifiable encryption"
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

// floatError is an error whose message names the cryptosystem and the reason,
// while errors.Is still matches ErrFloatNotSupported.
type floatError struct{ msg string }

func (e *floatError) Error() string { return e.msg }

func (e *floatError) Is(target error) bool { return target == ErrFloatNotSupported }

// FloatNotSupported builds an error matching ErrFloatNotSupported with the
// given message.
func FloatNotSupported(msg string) error { return &floatError{msg: msg} }

// FloatRejecter is implemented by cryptosystems that support integers only.
// Encrypting floats or tensors, and multiplying with float constants, are
// rejected with the returned error for them.
type FloatRejecter interface {
	FloatsUnsupported() error
}

// RejectsFloats returns the error of a cryptosystem supporting integers only,
// or nil if it supports floats.
func RejectsFloats(cs Homomorphic) error {
	if r, ok := cs.(FloatRejecter); ok {
		return r.FloatsUnsupported()
	}
	return nil
}
