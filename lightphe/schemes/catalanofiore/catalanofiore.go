// Package catalanofiore implements the Catalano-Fiore transform, which
// upgrades a linearly homomorphic cryptosystem to support one homomorphic
// multiplication, i.e. evaluating degree-2 functions such as dot products of
// two encrypted vectors, variances or squared distances. It wraps a built
// cryptosystem, and uses its public operations only: encryption, decryption,
// homomorphic addition and multiplication with a constant. So, the underlying
// cryptosystem is used as is, and the transform is as secure as it is.
//
// Plaintext space is Z_M, where M is the plaintext modulo of the underlying
// cryptosystem.
//   - encryption of m: (a, Enc(b)) where b is uniformly random in Z_M and
//     a = m - b. a is in clear, but reveals nothing as b is uniformly random
//     and secret.
//   - addition: (a1 + a2, Enc(b1) + Enc(b2))
//   - multiplication: m1 m2 = a1 a2 + a1 b2 + a2 b1 + b1 b2, so the result is
//     alpha = Enc(a1 a2) + a1 Enc(b2) + a2 Enc(b1), which encrypts
//     m1 m2 - b1 b2, together with the pair (Enc(b1), Enc(b2)) to restore
//     b1 b2 in decryption.
//   - decryption of a multiplied ciphertext: Dec(alpha) + sum of
//     Dec(Enc(b1)) Dec(Enc(b2)) for all pairs.
//
// Multiplied ciphertexts can be added with each other and with non-multiplied
// ciphertexts, and they can be multiplied with plain constants. But they
// cannot be multiplied with ciphertexts again.
//
// A multiplied ciphertext keeps a pair of ciphertexts for every product it
// contains, so its size grows with the number of products summed. For
// instance, dot product of two encrypted vectors of length d has d pairs. The
// pairs also reveal which ciphertexts were multiplied, but not their values.
//
// Encryption and homomorphic operations require the public key only, and
// decryption requires the private key of the underlying cryptosystem. Only
// integers are supported.
//
// Reference: Catalano, D., Fiore, D. (2015). Using Linearly-Homomorphic
// Encryption to Evaluate Degree-2 Functions on Encrypted Data. ACM CCS 2015.
package catalanofiore

import (
	"fmt"
	"math/big"
	"strings"

	"github.com/serengil/lightphe-go/lightphe/internal/mathutil"
	"github.com/serengil/lightphe-go/lightphe/phe"
)

// Name is the name of the transform.
const Name = "Catalano-Fiore"

// SupportedAlgorithms are the additively homomorphic algorithms whose
// plaintext space Z_M is public, and which can decrypt any value in it.
var SupportedAlgorithms = []phe.Algorithm{
	phe.Paillier,
	phe.DamgardJurik,
	phe.BressonCatalanoPointcheval,
	phe.CamenischShoup,
	phe.EllipticCurvePaillier,
	phe.JoyeLibert,
	phe.CastagnosLaguillaumie,
	phe.NaccacheStern,
	phe.Benaloh,
	phe.DamgardGeislerKroigaard,
}

// unsupportedReasons explain why algorithms cannot be upgraded.
var unsupportedReasons = map[phe.Algorithm]string{
	phe.ExponentialElGamal: "its decryption solves discrete logarithm, which is infeasible for the uniformly " +
		"random values the transform encrypts",
	phe.EllipticCurveElGamal: "its decryption solves discrete logarithm, which is infeasible for the uniformly " +
		"random values the transform encrypts",
	phe.OkamotoUchiyama:            "its plaintext modulus p is secret, so the encryptor cannot compute m - b mod p",
	phe.Regev:                      "multiplying with uniformly random constants exceeds its noise budget",
	phe.LyubashevskyPeikertRegev:   "multiplying with uniformly random constants exceeds its noise budget",
	phe.MLKEM:                      "it is homomorphic with respect to xor only, without addition",
	phe.GoldwasserMicali:           "it encrypts integers bit by bit and supports xor only, without multiplication with a constant",
	phe.BonehGohNissim:             "it already supports one multiplication natively",
	phe.BrakerskiVaikuntanathan:    "it already supports one multiplication natively",
	phe.FreemanBonehGohNissim:      "it already supports one multiplication natively",
	phe.GentryHaleviVaikuntanathan: "it already supports one multiplication natively",
	phe.GentrySahaiWaters:          "it already supports multiplications of bits natively",
}

// ErrFloatNotSupported reports a float plaintext, constant or tensor.
var ErrFloatNotSupported = phe.FloatNotSupported("lightphe: Catalano-Fiore transform supports integers only")

// ErrMultipliedTwice reports a multiplication involving an already multiplied
// ciphertext.
var ErrMultipliedTwice = fmt.Errorf("lightphe: Catalano-Fiore transform supports only one multiplication, "+
	"multiplied ciphertexts cannot be multiplied with ciphertexts again: %w", phe.ErrUnsupportedOperation)

// ErrNoRegeneration reports a re-encryption request, which the transform does
// not support.
var ErrNoRegeneration = fmt.Errorf("lightphe: ciphertexts supporting multiplication cannot be regenerated, "+
	"encrypt the plaintext again instead: %w", phe.ErrUnsupportedOperation)

// ciphertext tags, kept as the first item of the tuple
const (
	tagFresh      = 1
	tagMultiplied = 2
)

// Cryptosystem wraps an additively homomorphic cryptosystem. It is immutable
// and safe for concurrent use as long as the wrapped one is.
//
// A non-multiplied ciphertext is the tuple (1, a, Enc(b)), and a multiplied
// one is (2, alpha, ((Enc(b1), Enc(b2)), ...)).
type Cryptosystem struct {
	phe.Base

	inner  phe.Homomorphic
	modulo *big.Int
}

var (
	_ phe.Homomorphic   = (*Cryptosystem)(nil)
	_ phe.FloatRejecter = (*Cryptosystem)(nil)
)

// New wraps a built cryptosystem of a supported algorithm.
func New(inner phe.Homomorphic) (*Cryptosystem, error) {
	alg := inner.Algorithm()
	supported := false
	for _, a := range SupportedAlgorithms {
		if a == alg {
			supported = true
		}
	}
	if !supported {
		reason, ok := unsupportedReasons[alg]
		if !ok {
			reason = "it is not additively homomorphic"
		}
		names := make([]string, len(SupportedAlgorithms))
		for i, a := range SupportedAlgorithms {
			names[i] = string(a)
		}
		return nil, fmt.Errorf("lightphe: Catalano-Fiore transform does not support %s because %s, "+
			"supported algorithms are %s: %w", alg, reason, strings.Join(names, ", "), phe.ErrUnsupportedOperation)
	}
	return &Cryptosystem{Base: phe.Base{Alg: alg}, inner: inner, modulo: inner.PlaintextModulo()}, nil
}

// Inner returns the wrapped cryptosystem.
func (c *Cryptosystem) Inner() phe.Homomorphic { return c.inner }

// PlaintextModulo implements phe.Homomorphic.
func (c *Cryptosystem) PlaintextModulo() *big.Int { return new(big.Int).Set(c.modulo) }

// CiphertextModulo implements phe.Homomorphic.
func (c *Cryptosystem) CiphertextModulo() *big.Int { return c.inner.CiphertextModulo() }

// HasPrivateKey implements phe.Homomorphic.
func (c *Cryptosystem) HasPrivateKey() bool { return c.inner.HasPrivateKey() }

// FloatsUnsupported implements phe.FloatRejecter.
func (c *Cryptosystem) FloatsUnsupported() error { return ErrFloatNotSupported }

// PublicOnly implements phe.Homomorphic.
func (c *Cryptosystem) PublicOnly() (phe.Homomorphic, error) {
	public, err := c.inner.PublicOnly()
	if err != nil {
		return nil, err
	}
	return New(public)
}

// ExportKeys implements phe.Homomorphic with the keys of the wrapped
// cryptosystem.
func (c *Cryptosystem) ExportKeys(includePrivate bool) ([]byte, error) {
	return c.inner.ExportKeys(includePrivate)
}

// Encrypt implements phe.Homomorphic as (a, Enc(b)) where a = m - b and b is
// uniformly random.
func (c *Cryptosystem) Encrypt(plaintext *big.Int) (phe.Value, error) {
	b, err := mathutil.RandBelow(c.modulo)
	if err != nil {
		return nil, err
	}
	beta, err := c.inner.Encrypt(b)
	if err != nil {
		return nil, err
	}
	a := new(big.Int).Sub(plaintext, b)
	return fresh(a.Mod(a, c.modulo), beta), nil
}

// Decrypt implements phe.Homomorphic for non-multiplied and multiplied
// ciphertexts.
func (c *Cryptosystem) Decrypt(ciphertext phe.Value) (*big.Int, error) {
	if !c.inner.HasPrivateKey() {
		return nil, phe.ErrMissingPrivateKey
	}
	parsed, err := parse(ciphertext)
	if err != nil {
		return nil, err
	}
	if !parsed.multiplied {
		b, err := c.inner.Decrypt(parsed.beta)
		if err != nil {
			return nil, err
		}
		b.Add(b, parsed.a)
		return b.Mod(b, c.modulo), nil
	}

	result, err := c.inner.Decrypt(parsed.alpha)
	if err != nil {
		return nil, err
	}
	for _, pair := range parsed.pairs {
		b1, err := c.inner.Decrypt(pair[0])
		if err != nil {
			return nil, err
		}
		b2, err := c.inner.Decrypt(pair[1])
		if err != nil {
			return nil, err
		}
		result.Add(result, b1.Mul(b1, b2))
	}
	return result.Mod(result, c.modulo), nil
}

// Add implements phe.Homomorphic.
func (c *Cryptosystem) Add(a, b phe.Value) (phe.Value, error) {
	first, err := parse(a)
	if err != nil {
		return nil, err
	}
	second, err := parse(b)
	if err != nil {
		return nil, err
	}

	if !first.multiplied && !second.multiplied {
		beta, err := c.inner.Add(first.beta, second.beta)
		if err != nil {
			return nil, err
		}
		sum := new(big.Int).Add(first.a, second.a)
		return fresh(sum.Mod(sum, c.modulo), beta), nil
	}

	if first, err = c.toMultiplied(first); err != nil {
		return nil, err
	}
	if second, err = c.toMultiplied(second); err != nil {
		return nil, err
	}
	alpha, err := c.inner.Add(first.alpha, second.alpha)
	if err != nil {
		return nil, err
	}
	pairs := append(append([][2]phe.Value{}, first.pairs...), second.pairs...)
	return multipliedValue(alpha, pairs), nil
}

// Multiply implements phe.Homomorphic once. Enc(a1 a2) + a1 Enc(b2) +
// a2 Enc(b1) encrypts m1 m2 - b1 b2.
func (c *Cryptosystem) Multiply(a, b phe.Value) (phe.Value, error) {
	first, err := parse(a)
	if err != nil {
		return nil, err
	}
	second, err := parse(b)
	if err != nil {
		return nil, err
	}
	if first.multiplied || second.multiplied {
		return nil, ErrMultipliedTwice
	}

	product := new(big.Int).Mul(first.a, second.a)
	alpha, err := c.inner.Encrypt(product.Mod(product, c.modulo))
	if err != nil {
		return nil, err
	}
	for _, term := range []struct {
		beta     phe.Value
		constant *big.Int
	}{{second.beta, first.a}, {first.beta, second.a}} {
		scaled, err := c.inner.MultiplyByConstant(term.beta, term.constant)
		if err != nil {
			return nil, err
		}
		if alpha, err = c.inner.Add(alpha, scaled); err != nil {
			return nil, err
		}
	}
	return multipliedValue(alpha, [][2]phe.Value{{first.beta, second.beta}}), nil
}

// MultiplyByConstant implements phe.Homomorphic.
func (c *Cryptosystem) MultiplyByConstant(ciphertext phe.Value, constant *big.Int) (phe.Value, error) {
	parsed, err := parse(ciphertext)
	if err != nil {
		return nil, err
	}
	k := new(big.Int).Mod(constant, c.modulo)

	if !parsed.multiplied {
		beta, err := c.inner.MultiplyByConstant(parsed.beta, k)
		if err != nil {
			return nil, err
		}
		a := new(big.Int).Mul(parsed.a, k)
		return fresh(a.Mod(a, c.modulo), beta), nil
	}

	// scaling the first ciphertext of each pair scales the product b1 b2
	alpha, err := c.inner.MultiplyByConstant(parsed.alpha, k)
	if err != nil {
		return nil, err
	}
	pairs := make([][2]phe.Value, len(parsed.pairs))
	for i, pair := range parsed.pairs {
		scaled, err := c.inner.MultiplyByConstant(pair[0], k)
		if err != nil {
			return nil, err
		}
		pairs[i] = [2]phe.Value{scaled, pair[1]}
	}
	return multipliedValue(alpha, pairs), nil
}

// Reencrypt implements phe.Homomorphic by reporting the operation as
// unsupported.
func (c *Cryptosystem) Reencrypt(_ phe.Value) (phe.Value, error) {
	return nil, ErrNoRegeneration
}

// toMultiplied represents a non-multiplied ciphertext (a, Enc(b)) as a
// multiplied one with alpha = Enc(a) + Enc(b) and no pairs.
func (c *Cryptosystem) toMultiplied(p parsed) (parsed, error) {
	if p.multiplied {
		return p, nil
	}
	encryptedA, err := c.inner.Encrypt(p.a)
	if err != nil {
		return parsed{}, err
	}
	alpha, err := c.inner.Add(encryptedA, p.beta)
	if err != nil {
		return parsed{}, err
	}
	return parsed{multiplied: true, alpha: alpha}, nil
}

// parsed is a decoded ciphertext of the transform.
type parsed struct {
	multiplied bool

	// non-multiplied ciphertexts
	a    *big.Int
	beta phe.Value

	// multiplied ciphertexts
	alpha phe.Value
	pairs [][2]phe.Value
}

func fresh(a *big.Int, beta phe.Value) phe.Value {
	return phe.NewTuple(phe.Int{V: big.NewInt(tagFresh)}, phe.Int{V: a}, beta)
}

func multipliedValue(alpha phe.Value, pairs [][2]phe.Value) phe.Value {
	items := make([]phe.Value, len(pairs))
	for i, pair := range pairs {
		items[i] = phe.NewTuple(pair[0], pair[1])
	}
	return phe.NewTuple(phe.Int{V: big.NewInt(tagMultiplied)}, alpha, phe.Tuple{Items: items})
}

// IsFresh reports whether a value is a ciphertext of the transform that can
// be multiplied, i.e. it is not the result of a multiplication.
func IsFresh(v phe.Value) bool {
	p, err := parse(v)
	return err == nil && !p.multiplied
}

func parse(v phe.Value) (parsed, error) {
	t, err := phe.AsTuple(v)
	if err != nil {
		return parsed{}, err
	}
	if t.Len() != 3 {
		return parsed{}, phe.InvalidCiphertextf("catalanofiore: ciphertext must be created by Catalano-Fiore transform")
	}
	tag, err := phe.AsInt(t.Items[0])
	if err != nil {
		return parsed{}, phe.InvalidCiphertextf("catalanofiore: ciphertext must be created by Catalano-Fiore transform")
	}
	switch tag.Int64() {
	case tagFresh:
		a, err := phe.AsInt(t.Items[1])
		if err != nil {
			return parsed{}, err
		}
		return parsed{a: a, beta: t.Items[2]}, nil
	case tagMultiplied:
		list, err := phe.AsTuple(t.Items[2])
		if err != nil {
			return parsed{}, err
		}
		pairs := make([][2]phe.Value, list.Len())
		for i, item := range list.Items {
			b1, b2, err := phe.AsPair(item)
			if err != nil {
				return parsed{}, err
			}
			pairs[i] = [2]phe.Value{b1, b2}
		}
		return parsed{multiplied: true, alpha: t.Items[1], pairs: pairs}, nil
	}
	return parsed{}, phe.InvalidCiphertextf("catalanofiore: ciphertext must be created by Catalano-Fiore transform")
}
