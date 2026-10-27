package lightphe

import (
	"fmt"
	"math/big"

	"github.com/serengil/lightphe-go/lightphe/encrypted"
	"github.com/serengil/lightphe-go/lightphe/internal/threshold"
	"github.com/serengil/lightphe-go/lightphe/phe"
	"github.com/serengil/lightphe-go/lightphe/schemes/catalanofiore"
)

// ---------------------------------------------------------------------------
// Threshold decryption
// ---------------------------------------------------------------------------

// ErrBoostedThreshold reports threshold decryption requested for a ciphertext
// supporting multiplication.
var ErrBoostedThreshold = fmt.Errorf("lightphe: ciphertexts supporting multiplication do not support threshold "+
	"decryption: %w", phe.ErrUnsupportedOperation)

// TensorPartialDecryption is the partial decryption of an element of an
// encrypted tensor.
type TensorPartialDecryption struct {
	AbsDividend *PartialDecryption `json:"abs_dividend"`
	Divisor     *PartialDecryption `json:"divisor"`
}

func (c *Cryptosystem) thresholdDecrypter() (phe.ThresholdDecrypter, error) {
	if e, ok := c.unboosted().(phe.ThresholdDecrypter); ok {
		return e, nil
	}
	return nil, phe.Unsupportedf(c.algorithm, phe.OpThreshold)
}

// publicUnboosted returns the public cryptosystem of the algorithm itself,
// which ciphertexts of protocols that do not support the transform are bound
// to.
func (c *Cryptosystem) publicUnboosted() phe.Homomorphic {
	if cf, ok := c.public.(*catalanofiore.Cryptosystem); ok {
		return cf.Inner()
	}
	return c.public
}

// unboostedValue returns the raw value of a ciphertext, rejecting ciphertexts
// supporting multiplication.
func unboostedValue(ciphertext *encrypted.Ciphertext) (phe.Value, error) {
	if ciphertext == nil {
		return nil, phe.InvalidCiphertextf("lightphe: nil ciphertext")
	}
	if _, boosted := ciphertext.Scheme().(*catalanofiore.Cryptosystem); boosted {
		return nil, ErrBoostedThreshold
	}
	return ciphertext.Value, nil
}

// GenerateThresholdKeys splits the private key into shares for threshold
// decryption. Any threshold many shareholders decrypt a ciphertext together,
// but fewer shareholders cannot. It runs on dealer side, and returns the JSON
// public key having threshold parameters, and the JSON key of each
// shareholder, which must be sent to its own shareholder secretly.
// Shareholders build their cryptosystems with WithKeys. The dealer must
// publish the returned public key instead of its own, and forget its private
// key. Supported by ElGamal, Exponential-ElGamal, EllipticCurve-ElGamal,
// Paillier and Damgard-Jurik. ElGamal and Exponential-ElGamal keys must be
// generated with WithPrimeOrder(true).
func (c *Cryptosystem) GenerateThresholdKeys(t, parties int) (publicKey []byte, shareKeys [][]byte, err error) {
	if !c.cs.HasPrivateKey() {
		return nil, nil, phe.ErrMissingPrivateKey
	}
	if err := threshold.Validate(t, parties); err != nil {
		return nil, nil, err
	}
	e, err := c.thresholdDecrypter()
	if err != nil {
		return nil, nil, err
	}
	return e.GenerateThresholdKeys(t, parties)
}

// PartialDecrypt decrypts a ciphertext partially with the share of a
// shareholder. A partial decryption reveals nothing about the plaintext alone.
// It runs on shareholder side. Set prove to true to attach a zero-knowledge
// proof that the partial decryption is computed with the share of this
// shareholder, which ElGamal, Exponential-ElGamal, EllipticCurve-ElGamal, and
// Paillier and Damgard-Jurik with keys generated with WithSafePrimes(true)
// support.
func (c *Cryptosystem) PartialDecrypt(ciphertext *encrypted.Ciphertext, prove bool) (*PartialDecryption, error) {
	value, err := unboostedValue(ciphertext)
	if err != nil {
		return nil, err
	}
	e, err := c.thresholdDecrypter()
	if err != nil {
		return nil, err
	}
	return e.PartialDecrypt(value, prove)
}

// CombinePartialDecryptions restores the plaintext from partial decryptions
// of at least threshold many shareholders. Public key is enough, so anyone can
// combine them. Set verify to true to check zero-knowledge proofs of partial
// decryptions, and discard invalid or unproven ones. Otherwise, a cheating
// shareholder can cause a wrong plaintext silently.
func (c *Cryptosystem) CombinePartialDecryptions(ciphertext *encrypted.Ciphertext, partials []*PartialDecryption,
	verify bool) (*big.Int, error) {
	value, err := unboostedValue(ciphertext)
	if err != nil {
		return nil, err
	}
	e, err := c.thresholdDecrypter()
	if err != nil {
		return nil, err
	}
	return e.CombinePartialDecryptions(value, partials, verify)
}

// VerifyPartialDecryption verifies that a partial decryption is computed with
// the share of its shareholder. Public key is enough, and the partial
// decryption must be created with prove = true. CombinePartialDecryptions does
// this if verify is true and discards invalid ones, so this is useful to find
// a cheating shareholder.
func (c *Cryptosystem) VerifyPartialDecryption(ciphertext *encrypted.Ciphertext, partial *PartialDecryption) (bool, error) {
	value, err := unboostedValue(ciphertext)
	if err != nil {
		return false, err
	}
	e, err := c.thresholdDecrypter()
	if err != nil {
		return false, err
	}
	return e.VerifyPartialDecryption(value, partial)
}

// PartialDecryptTensor decrypts every element of an encrypted tensor
// partially with the share of a shareholder.
func (c *Cryptosystem) PartialDecryptTensor(tensor *encrypted.Tensor, prove bool) ([]TensorPartialDecryption, error) {
	if tensor == nil {
		return nil, phe.InvalidCiphertextf("lightphe: nil tensor")
	}
	e, err := c.thresholdDecrypter()
	if err != nil {
		return nil, err
	}
	out := make([]TensorPartialDecryption, len(tensor.Fractions))
	for i, fraction := range tensor.Fractions {
		if out[i].AbsDividend, err = e.PartialDecrypt(fraction.AbsDividend, prove); err != nil {
			return nil, err
		}
		if out[i].Divisor, err = e.PartialDecrypt(fraction.Divisor, prove); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// CombineTensorPartialDecryptions restores an encrypted tensor from partial
// decryptions of at least threshold many shareholders. Each item of partials
// is the output of PartialDecryptTensor of a shareholder.
func (c *Cryptosystem) CombineTensorPartialDecryptions(tensor *encrypted.Tensor, partials [][]TensorPartialDecryption,
	verify bool) ([]float64, error) {
	if tensor == nil {
		return nil, phe.InvalidCiphertextf("lightphe: nil tensor")
	}
	e, err := c.thresholdDecrypter()
	if err != nil {
		return nil, err
	}
	out := make([]float64, len(tensor.Fractions))
	for k, fraction := range tensor.Fractions {
		absDividends := make([]*PartialDecryption, 0, len(partials))
		divisors := make([]*PartialDecryption, 0, len(partials))
		for _, p := range partials {
			if len(p) != len(tensor.Fractions) {
				return nil, fmt.Errorf("lightphe: partial decryptions of a tensor must have %d elements", len(tensor.Fractions))
			}
			absDividends = append(absDividends, p[k].AbsDividend)
			divisors = append(divisors, p[k].Divisor)
		}
		absDividend, err := e.CombinePartialDecryptions(fraction.AbsDividend, absDividends, verify)
		if err != nil {
			return nil, err
		}
		divisor, err := e.CombinePartialDecryptions(fraction.Divisor, divisors, verify)
		if err != nil {
			return nil, err
		}
		if divisor.Sign() == 0 {
			return nil, fmt.Errorf("lightphe: element %d decrypted to a zero scale factor: %w", k, phe.ErrDecryptionFailed)
		}
		value, _ := new(big.Rat).SetFrac(absDividend, divisor).Float64()
		out[k] = float64(fraction.Sign) * value
	}
	return out, nil
}
