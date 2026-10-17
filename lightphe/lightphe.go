// Package lightphe is a lightweight partially homomorphic encryption library.
//
// It gathers over twenty partially and somewhat homomorphic cryptosystems
// behind one interface, so that ciphertexts can be added, multiplied or combined
// bitwise by a party that never sees the private key. Everything is pure Go and
// built on the standard library alone: math/big for the arithmetic and
// crypto/rand for every random value.
//
// A typical session builds a cryptosystem, encrypts, evaluates and decrypts:
//
//	cs, err := lightphe.New(lightphe.Paillier)
//	c1, err := cs.Encrypt(big.NewInt(10000))
//	c2, err := cs.Encrypt(big.NewInt(500))
//	c3, err := c1.Add(c2)          // no private key needed
//	m, err := cs.Decrypt(c3)       // private key needed
//
// Which operations a cryptosystem supports depends on the scheme; unsupported
// ones return an error wrapping ErrUnsupportedOperation.
//
// Importing this package alone is enough. The algorithm constants, the
// sentinel errors and the encrypted value types are all re-exported here as
// aliases of their definitions in the phe and encrypted packages, so Encrypt
// returns a *Ciphertext and EncryptTensor a *Tensor without a second import.
//
// A Cryptosystem and the values it produces are immutable after construction
// and safe for concurrent use.
package lightphe

import (
	"fmt"
	"math"
	"math/big"
	"os"
	"runtime"
	"sync"

	"github.com/serengil/lightphe-go/lightphe/ecc"
	"github.com/serengil/lightphe-go/lightphe/encrypted"
	"github.com/serengil/lightphe-go/lightphe/internal/fixedpoint"
	"github.com/serengil/lightphe-go/lightphe/phe"
	"github.com/serengil/lightphe-go/lightphe/schemes/benaloh"
	"github.com/serengil/lightphe-go/lightphe/schemes/bonehgohnissim"
	"github.com/serengil/lightphe-go/lightphe/schemes/brakerskivaikuntanathan"
	"github.com/serengil/lightphe-go/lightphe/schemes/bressoncatalanopointcheval"
	"github.com/serengil/lightphe-go/lightphe/schemes/camenischshoup"
	"github.com/serengil/lightphe-go/lightphe/schemes/castagnoslaguillaumie"
	"github.com/serengil/lightphe-go/lightphe/schemes/catalanofiore"
	"github.com/serengil/lightphe-go/lightphe/schemes/damgardgeislerkroigaard"
	"github.com/serengil/lightphe-go/lightphe/schemes/damgardjurik"
	"github.com/serengil/lightphe-go/lightphe/schemes/ecelgamal"
	"github.com/serengil/lightphe-go/lightphe/schemes/elgamal"
	"github.com/serengil/lightphe-go/lightphe/schemes/ellipticcurvepaillier"
	"github.com/serengil/lightphe-go/lightphe/schemes/freemanbonehgohnissim"
	"github.com/serengil/lightphe-go/lightphe/schemes/gentryhalevivaikuntanathan"
	"github.com/serengil/lightphe-go/lightphe/schemes/goldwassermicali"
	"github.com/serengil/lightphe-go/lightphe/schemes/ishaipaskin"
	"github.com/serengil/lightphe-go/lightphe/schemes/joyelibert"
	"github.com/serengil/lightphe-go/lightphe/schemes/naccachestern"
	"github.com/serengil/lightphe-go/lightphe/schemes/okamotouchiyama"
	"github.com/serengil/lightphe-go/lightphe/schemes/paillier"
	"github.com/serengil/lightphe-go/lightphe/schemes/regev"
	"github.com/serengil/lightphe-go/lightphe/schemes/rsa"
	"github.com/serengil/lightphe-go/lightphe/schemes/sanderyoungyung"
)

// Version is the library version.
const Version = "0.3.0"

// DefaultPrecision is the number of decimal digits kept when encrypting
// floating point tensors.
const DefaultPrecision = 5

// ---------------------------------------------------------------------------
// Re-exports
//
// Everything the common path needs is aliased here, so importing this package
// alone is enough:
//
//	import "github.com/serengil/lightphe-go/lightphe"
//
//	cs, err := lightphe.New(lightphe.Paillier)
//
// The originals live in the phe and encrypted packages, which stay importable
// for code that works against the interface or names the types directly. These
// are aliases, not copies: lightphe.Ciphertext and encrypted.Ciphertext are the
// same type, so values pass freely between the two spellings.
// ---------------------------------------------------------------------------

// Aliases for the shared contract in package phe.
type (
	// Algorithm names a cryptosystem.
	Algorithm = phe.Algorithm

	// Value is a raw ciphertext payload.
	Value = phe.Value

	// Homomorphic is the contract every cryptosystem implements.
	Homomorphic = phe.Homomorphic

	// DecisionTree is a decision tree evaluated by Ishai-Paskin. Build one with
	// Leaf and Node.
	DecisionTree = phe.DecisionTree

	// NumericTree is a decision tree with numeric thresholds evaluated by
	// Damgard-Geisler-Kroigaard. Build one with NumericLeaf and NumericNode.
	NumericTree = phe.NumericTree

	// DecisionTreeState is what the server keeps secret between the steps of
	// a private decision tree evaluation with numeric thresholds.
	DecisionTreeState = phe.DecisionTreeState

	// EncryptedLeaf is a leaf of a private decision tree evaluation sent to
	// the client.
	EncryptedLeaf = phe.EncryptedLeaf

	// ArgmaxMessage is a message the server sends to the client during
	// encrypted argmax.
	ArgmaxMessage = phe.ArgmaxMessage

	// ArgmaxClient delivers a message to the client during encrypted argmax.
	ArgmaxClient = phe.ArgmaxClient

	// VerifiableCiphertext is the output of verifiable encryption.
	VerifiableCiphertext = phe.VerifiableCiphertext
)

// Leaf builds a decision tree leaf that outputs value.
func Leaf(value int64) *DecisionTree { return phe.Leaf(value) }

// Node builds a decision tree node that continues with ifZero when the input
// bit at variable is 0, and with ifOne when it is 1.
func Node(variable int, ifZero, ifOne *DecisionTree) *DecisionTree {
	return phe.Node(variable, ifZero, ifOne)
}

// NumericLeaf builds a numeric decision tree leaf that outputs label.
func NumericLeaf(label int64) *NumericTree { return phe.NumericLeaf(label) }

// NumericNode builds a numeric decision tree node that continues with
// ifLessOrEqual when the feature at index feature is less than or equal to
// threshold, and with ifGreater otherwise.
func NumericNode(feature int, threshold int64, ifLessOrEqual, ifGreater *NumericTree) *NumericTree {
	return phe.NumericNode(feature, threshold, ifLessOrEqual, ifGreater)
}

// Aliases for the encrypted values in package encrypted.
type (
	// Ciphertext is an encrypted message plus the public cryptosystem needed
	// to evaluate on it.
	Ciphertext = encrypted.Ciphertext

	// Tensor is a vector of encrypted real numbers.
	Tensor = encrypted.Tensor

	// Fraction is one element of an encrypted tensor.
	Fraction = encrypted.Fraction
)

// Supported cryptosystems.
const (
	RSA                   = phe.RSA
	ElGamal               = phe.ElGamal
	ExponentialElGamal    = phe.ExponentialElGamal
	EllipticCurveElGamal  = phe.EllipticCurveElGamal
	Paillier              = phe.Paillier
	DamgardJurik          = phe.DamgardJurik
	OkamotoUchiyama       = phe.OkamotoUchiyama
	Benaloh               = phe.Benaloh
	NaccacheStern         = phe.NaccacheStern
	GoldwasserMicali      = phe.GoldwasserMicali
	SanderYoungYung       = phe.SanderYoungYung
	BonehGohNissim        = phe.BonehGohNissim
	JoyeLibert            = phe.JoyeLibert
	CastagnosLaguillaumie = phe.CastagnosLaguillaumie
	IshaiPaskin           = phe.IshaiPaskin

	DamgardGeislerKroigaard    = phe.DamgardGeislerKroigaard
	BressonCatalanoPointcheval = phe.BressonCatalanoPointcheval
	CamenischShoup             = phe.CamenischShoup
	EllipticCurvePaillier      = phe.EllipticCurvePaillier
	Regev                      = phe.Regev
	BrakerskiVaikuntanathan    = phe.BrakerskiVaikuntanathan
	FreemanBonehGohNissim      = phe.FreemanBonehGohNissim
	GentryHaleviVaikuntanathan = phe.GentryHaleviVaikuntanathan
)

// Boost names a transform upgrading a cryptosystem.
type Boost string

// CatalanoFiore lets ciphertexts of an additively homomorphic algorithm be
// multiplied once. Then, Encrypt returns ciphertexts supporting one
// multiplication, and only integers are supported. It is supported for
// Paillier, Damgard-Jurik, Bresson-Catalano-Pointcheval, Camenisch-Shoup,
// EllipticCurve-Paillier, Joye-Libert, Castagnos-Laguillaumie, Naccache-Stern,
// Benaloh and Damgard-Geisler-Kroigaard.
const CatalanoFiore Boost = catalanofiore.Name

// Sentinel errors, re-exported so that errors.Is works without importing phe.
var (
	ErrUnsupportedOperation = phe.ErrUnsupportedOperation
	ErrMissingPrivateKey    = phe.ErrMissingPrivateKey
	ErrMissingPublicKey     = phe.ErrMissingPublicKey
	ErrInvalidKeys          = phe.ErrInvalidKeys
	ErrInvalidCiphertext    = phe.ErrInvalidCiphertext
	ErrKeyGeneration        = phe.ErrKeyGeneration
	ErrDecryptionFailed     = phe.ErrDecryptionFailed
	ErrFloatNotSupported    = phe.ErrFloatNotSupported
)

// Algorithms lists every cryptosystem this library ships with.
func Algorithms() []Algorithm { return phe.Algorithms() }

// ---------------------------------------------------------------------------
// Options
// ---------------------------------------------------------------------------

// config collects everything New needs to build a cryptosystem. Callers fill it
// through Option values rather than touching it directly.
type config struct {
	keySize        int
	keys           []byte
	keyFile        string
	precision      int
	form           string
	curve          string
	plaintextLimit *big.Int
	maxTries       int
	damgardJurikS  int
	deterministic  bool
	boost          Boost
}

// Option customises how a cryptosystem is built.
type Option func(*config)

// WithKeySize sets the key size in bits. Ignored when existing keys are
// supplied. For Regev, it is the lattice dimension. For
// Brakerski-Vaikuntanathan, it is the ring degree. For Freeman-Boneh-Goh-Nissim,
// it is the bit length of the field size. For Gentry-Halevi-Vaikuntanathan, it
// is the lattice dimension in [2, 8].
func WithKeySize(bits int) Option {
	return func(c *config) { c.keySize = bits }
}

// WithKeys builds the cryptosystem from exported JSON key material instead of
// generating a new key pair.
func WithKeys(keys []byte) Option {
	return func(c *config) { c.keys = keys }
}

// WithKeyFile builds the cryptosystem from a key file written by ExportKeys.
func WithKeyFile(path string) Option {
	return func(c *config) { c.keyFile = path }
}

// WithPrecision sets how many decimal digits survive tensor encryption.
func WithPrecision(digits int) Option {
	return func(c *config) { c.precision = digits }
}

// WithCurve selects the elliptic curve form and curve name. It only affects
// EllipticCurve-ElGamal and Camenisch-Shoup, which uses it for verifiable
// encryption. An empty form defaults to weierstrass and an empty curve to that
// form's standard curve.
func WithCurve(form, curve string) Option {
	return func(c *config) {
		c.form = form
		c.curve = curve
	}
}

// WithPlaintextLimit sets an upper bound for plaintexts. It only affects
// Benaloh, Sander-Young-Yung, Regev, Brakerski-Vaikuntanathan,
// Freeman-Boneh-Goh-Nissim and Gentry-Halevi-Vaikuntanathan, which size their
// message space around it.
func WithPlaintextLimit(limit *big.Int) Option {
	return func(c *config) { c.plaintextLimit = limit }
}

// WithMaxTries bounds the randomized search during key generation. It only
// affects the schemes whose key generation can fail and retry: RSA, Benaloh,
// Naccache-Stern, Goldwasser-Micali, Sander-Young-Yung, Boneh-Goh-Nissim,
// Joye-Libert, Castagnos-Laguillaumie, Damgard-Geisler-Kroigaard,
// Bresson-Catalano-Pointcheval and Camenisch-Shoup.
func WithMaxTries(tries int) Option {
	return func(c *config) { c.maxTries = tries }
}

// WithDamgardJurikS sets the exponent s that fixes the Damgard-Jurik ciphertext
// modulus n^(s+1). It only affects Damgard-Jurik.
func WithDamgardJurikS(s int) Option {
	return func(c *config) { c.damgardJurikS = s }
}

// WithDeterministic selects the deterministic variant of Naccache-Stern, which
// drops the random blinding factor. It leaks equality of plaintexts and cannot
// re-encrypt, so only reach for it deliberately.
func WithDeterministic(deterministic bool) Option {
	return func(c *config) { c.deterministic = deterministic }
}

// WithBoost upgrades the algorithm with a transform. See CatalanoFiore.
func WithBoost(boost Boost) Option {
	return func(c *config) { c.boost = boost }
}

func newConfig(opts []Option) *config {
	c := &config{precision: DefaultPrecision}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

// ---------------------------------------------------------------------------
// Cryptosystem
// ---------------------------------------------------------------------------

// Cryptosystem is a configured homomorphic scheme together with the
// conveniences the schemes themselves do not need to know about: fixed point
// encoding, tensors and key files. Build one with New.
type Cryptosystem struct {
	algorithm phe.Algorithm
	cs        phe.Homomorphic
	public    phe.Homomorphic
	precision int
}

// New builds a cryptosystem for the requested algorithm. Without options it
// generates a fresh key pair at the scheme's default key size.
func New(algorithm phe.Algorithm, opts ...Option) (*Cryptosystem, error) {
	cfg := newConfig(opts)

	if cfg.keyFile != "" {
		data, err := os.ReadFile(cfg.keyFile)
		if err != nil {
			return nil, fmt.Errorf("lightphe: reading key file %q: %w", cfg.keyFile, err)
		}
		cfg.keys = data
	}

	cs, err := build(algorithm, cfg)
	if err != nil {
		return nil, err
	}

	// Catalano-Fiore transform wraps the built cryptosystem
	switch cfg.boost {
	case "":
	case CatalanoFiore:
		if cs, err = catalanofiore.New(cs); err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("lightphe: unknown boost %q, options are: %s", cfg.boost, CatalanoFiore)
	}

	public, err := cs.PublicOnly()
	if err != nil {
		return nil, fmt.Errorf("lightphe: deriving the public cryptosystem: %w", err)
	}

	precision := cfg.precision
	if precision <= 0 {
		precision = DefaultPrecision
	}

	return &Cryptosystem{algorithm: algorithm, cs: cs, public: public, precision: precision}, nil
}

// build dispatches to the requested scheme, either restoring supplied keys or
// generating a new pair.
func build(algorithm phe.Algorithm, cfg *config) (phe.Homomorphic, error) {
	restoring := len(cfg.keys) > 0

	switch algorithm {
	case phe.RSA:
		if restoring {
			return rsa.FromJSON(cfg.keys)
		}
		return rsa.Generate(cfg.keySize, cfg.maxTries)

	case phe.ElGamal, phe.ExponentialElGamal:
		exponential := algorithm == phe.ExponentialElGamal
		if restoring {
			return elgamal.FromJSON(cfg.keys, exponential)
		}
		return elgamal.Generate(cfg.keySize, exponential)

	case phe.EllipticCurveElGamal:
		if restoring {
			return ecelgamal.FromJSON(cfg.keys)
		}
		return ecelgamal.Generate(cfg.keySize, cfg.form, cfg.curve)

	case phe.Paillier:
		if restoring {
			return paillier.FromJSON(cfg.keys)
		}
		return paillier.Generate(cfg.keySize)

	case phe.DamgardJurik:
		if restoring {
			return damgardjurik.FromJSON(cfg.keys)
		}
		return damgardjurik.Generate(cfg.keySize, cfg.damgardJurikS)

	case phe.OkamotoUchiyama:
		if restoring {
			return okamotouchiyama.FromJSON(cfg.keys)
		}
		return okamotouchiyama.Generate(cfg.keySize, cfg.maxTries)

	case phe.Benaloh:
		if restoring {
			return benaloh.FromJSON(cfg.keys)
		}
		return benaloh.Generate(cfg.keySize, cfg.plaintextLimit, cfg.maxTries)

	case phe.NaccacheStern:
		if restoring {
			return naccachestern.FromJSON(cfg.keys)
		}
		return naccachestern.Generate(cfg.keySize, cfg.maxTries)

	case phe.GoldwasserMicali:
		if restoring {
			return goldwassermicali.FromJSON(cfg.keys)
		}
		return goldwassermicali.Generate(cfg.keySize, cfg.maxTries)

	case phe.SanderYoungYung:
		if restoring {
			return sanderyoungyung.FromJSON(cfg.keys)
		}
		return sanderyoungyung.Generate(cfg.keySize, cfg.plaintextLimit, cfg.maxTries)

	case phe.BonehGohNissim:
		if restoring {
			return bonehgohnissim.FromJSON(cfg.keys)
		}
		return bonehgohnissim.Generate(cfg.keySize, cfg.maxTries)

	case phe.JoyeLibert:
		if restoring {
			return joyelibert.FromJSON(cfg.keys)
		}
		return joyelibert.Generate(cfg.keySize, cfg.maxTries)

	case phe.CastagnosLaguillaumie:
		if restoring {
			return castagnoslaguillaumie.FromJSON(cfg.keys)
		}
		return castagnoslaguillaumie.Generate(cfg.keySize, cfg.maxTries)

	case phe.IshaiPaskin:
		if restoring {
			return ishaipaskin.FromJSON(cfg.keys)
		}
		return ishaipaskin.Generate(cfg.keySize)

	case phe.DamgardGeislerKroigaard:
		if restoring {
			return damgardgeislerkroigaard.FromJSON(cfg.keys)
		}
		return damgardgeislerkroigaard.Generate(cfg.keySize, cfg.maxTries)

	case phe.BressonCatalanoPointcheval:
		if restoring {
			return bressoncatalanopointcheval.FromJSON(cfg.keys)
		}
		return bressoncatalanopointcheval.Generate(cfg.keySize, cfg.maxTries)

	case phe.CamenischShoup:
		if restoring {
			return camenischshoup.FromJSON(cfg.keys, cfg.form, cfg.curve)
		}
		return camenischshoup.Generate(cfg.keySize, cfg.maxTries, cfg.form, cfg.curve)

	case phe.EllipticCurvePaillier:
		if restoring {
			return ellipticcurvepaillier.FromJSON(cfg.keys)
		}
		return ellipticcurvepaillier.Generate(cfg.keySize)

	case phe.Regev:
		if restoring {
			return regev.FromJSON(cfg.keys)
		}
		return regev.Generate(cfg.keySize, cfg.plaintextLimit)

	case phe.BrakerskiVaikuntanathan:
		if restoring {
			return brakerskivaikuntanathan.FromJSON(cfg.keys)
		}
		return brakerskivaikuntanathan.Generate(cfg.keySize, cfg.plaintextLimit)

	case phe.FreemanBonehGohNissim:
		if restoring {
			return freemanbonehgohnissim.FromJSON(cfg.keys)
		}
		return freemanbonehgohnissim.Generate(cfg.keySize, cfg.plaintextLimit)

	case phe.GentryHaleviVaikuntanathan:
		if restoring {
			return gentryhalevivaikuntanathan.FromJSON(cfg.keys)
		}
		return gentryhalevivaikuntanathan.Generate(cfg.keySize, cfg.plaintextLimit)

	default:
		return nil, fmt.Errorf("lightphe: unimplemented algorithm %q", algorithm)
	}
}

// Algorithm reports which cryptosystem this instance uses.
func (c *Cryptosystem) Algorithm() phe.Algorithm { return c.algorithm }

// Scheme exposes the underlying cryptosystem for advanced use. It is the
// Catalano-Fiore transform wrapping the algorithm when it is boosted.
func (c *Cryptosystem) Scheme() phe.Homomorphic { return c.cs }

// unboosted returns the algorithm itself, without the transform wrapping it.
func (c *Cryptosystem) unboosted() phe.Homomorphic {
	if cf, ok := c.cs.(*catalanofiore.Cryptosystem); ok {
		return cf.Inner()
	}
	return c.cs
}

// Precision reports how many decimal digits tensor encryption keeps.
func (c *Cryptosystem) Precision() int { return c.precision }

// PlaintextModulo reports the size of the message space.
func (c *Cryptosystem) PlaintextModulo() *big.Int { return c.cs.PlaintextModulo() }

// HasPrivateKey reports whether this instance can decrypt.
func (c *Cryptosystem) HasPrivateKey() bool { return c.cs.HasPrivateKey() }

// ---------------------------------------------------------------------------
// Scalar encryption
// ---------------------------------------------------------------------------

// Encrypt encrypts an integer, reducing it into the message space first.
// Negative values wrap onto the upper half of that space, exactly as they do in
// modular arithmetic.
//
// The returned ciphertext carries only the public key, so it can be handed to
// an untrusted evaluator as is.
func (c *Cryptosystem) Encrypt(plaintext *big.Int) (*encrypted.Ciphertext, error) {
	m := phe.Normalize(plaintext, c.cs.PlaintextModulo())
	value, err := c.cs.Encrypt(m)
	if err != nil {
		return nil, err
	}
	return encrypted.NewCiphertext(c.public, value), nil
}

// EncryptInt is a convenience wrapper around Encrypt.
func (c *Cryptosystem) EncryptInt(plaintext int64) (*encrypted.Ciphertext, error) {
	return c.Encrypt(big.NewInt(plaintext))
}

// EncryptFloat encrypts a non-negative float by mapping it onto the message
// space as a modular fraction. Decrypting the result of an operation involving
// it yields the scaled integer, so the caller has to interpret it in the same
// fixed point terms. For vectors of floats, prefer EncryptTensor.
func (c *Cryptosystem) EncryptFloat(plaintext float64) (*encrypted.Ciphertext, error) {
	if err := phe.RejectsFloats(c.cs); err != nil {
		return nil, err
	}
	if c.algorithm == phe.JoyeLibert && plaintext != math.Trunc(plaintext) {
		return nil, joyelibert.ErrFloatNotSupported
	}
	m, err := fixedpoint.Normalize(plaintext, c.cs.PlaintextModulo())
	if err != nil {
		return nil, err
	}
	return c.Encrypt(m)
}

// Decrypt recovers the plaintext behind a ciphertext. It needs the private key.
func (c *Cryptosystem) Decrypt(ciphertext *encrypted.Ciphertext) (*big.Int, error) {
	if ciphertext == nil {
		return nil, phe.InvalidCiphertextf("lightphe: nil ciphertext")
	}
	if !c.cs.HasPrivateKey() {
		return nil, phe.ErrMissingPrivateKey
	}

	// boosted and plain cryptosystems with the same keys decrypt each other's
	// ciphertexts
	_, boosted := c.cs.(*catalanofiore.Cryptosystem)
	_, boostedCiphertext := ciphertext.Scheme().(*catalanofiore.Cryptosystem)
	switch {
	case boostedCiphertext && !boosted:
		cf, err := catalanofiore.New(c.cs)
		if err != nil {
			return nil, err
		}
		return cf.Decrypt(ciphertext.Value)
	case boosted && !boostedCiphertext:
		return c.unboosted().Decrypt(ciphertext.Value)
	}
	return c.cs.Decrypt(ciphertext.Value)
}

// RegenerateCiphertext returns a different ciphertext for the same plaintext.
// Doing this repeatedly makes it harder to correlate ciphertexts across
// observations.
func (c *Cryptosystem) RegenerateCiphertext(ciphertext *encrypted.Ciphertext) (*encrypted.Ciphertext, error) {
	if ciphertext == nil {
		return nil, phe.InvalidCiphertextf("lightphe: nil ciphertext")
	}
	value, err := c.cs.Reencrypt(ciphertext.Value)
	if err != nil {
		return nil, err
	}
	return encrypted.NewCiphertext(c.public, value), nil
}

// CreateCiphertext wraps a raw ciphertext value so that homomorphic operations
// can be applied to it. This is how an evaluator that received only ciphertext
// payloads over the wire gets back into the API.
func (c *Cryptosystem) CreateCiphertext(value phe.Value) *encrypted.Ciphertext {
	return encrypted.NewCiphertext(c.public, value)
}

// ---------------------------------------------------------------------------
// Decision trees
// ---------------------------------------------------------------------------

// EncryptDecisionTreeInput encrypts the input bits (answers to the questions)
// of a decision tree. depth is the maximum number of decisions on a path of
// the tree. Only Ishai-Paskin supports this.
func (c *Cryptosystem) EncryptDecisionTreeInput(bits []int, depth int) ([][]*big.Int, error) {
	return c.cs.EncryptDecisionTreeInput(bits, depth)
}

// EvaluateDecisionTree evaluates a decision tree on encrypted input and
// returns its encrypted output. The private key is not required. Only
// Ishai-Paskin supports this.
func (c *Cryptosystem) EvaluateDecisionTree(tree *DecisionTree, encryptedInput [][]*big.Int) (*encrypted.Ciphertext, error) {
	value, err := c.public.EvaluateDecisionTree(tree, encryptedInput)
	if err != nil {
		return nil, err
	}
	return encrypted.NewCiphertext(c.public, value), nil
}

// ---------------------------------------------------------------------------
// Private decision trees with numeric thresholds
// ---------------------------------------------------------------------------

func (c *Cryptosystem) numericTrees() (phe.NumericDecisionTreeEvaluator, error) {
	if e, ok := c.unboosted().(phe.NumericDecisionTreeEvaluator); ok {
		return e, nil
	}
	return nil, phe.Unsupportedf(c.algorithm, phe.OpNumericDecisionTree)
}

// EncryptDecisionTreeFeatures encrypts client's numeric features, each in
// [0, 2^bitLength), to be evaluated in a decision tree owned by the server.
// 1st step of private decision tree evaluation, runs on client side. Only
// Damgard-Geisler-Kroigaard supports this.
func (c *Cryptosystem) EncryptDecisionTreeFeatures(features []int64, bitLength int) ([][]*big.Int, error) {
	e, err := c.numericTrees()
	if err != nil {
		return nil, err
	}
	return e.EncryptDecisionTreeFeatures(features, bitLength)
}

// EvaluateDecisionTreeComparisons compares encrypted features with thresholds
// of all decision nodes. 2nd step of private decision tree evaluation, runs on
// server side. The encrypted comparisons are sent to the client, and the state
// must be kept secret on server side for the 4th step. Only
// Damgard-Geisler-Kroigaard supports this.
func (c *Cryptosystem) EvaluateDecisionTreeComparisons(tree *NumericTree, encryptedFeatures [][]*big.Int) (
	[][]*big.Int, *DecisionTreeState, error) {
	e, err := c.numericTrees()
	if err != nil {
		return nil, nil, err
	}
	return e.EvaluateDecisionTreeComparisons(tree, encryptedFeatures)
}

// AnswerDecisionTreeComparisons answers server's comparisons in encrypted
// form. Comparisons are randomly flipped by the server, so client does not
// learn the path in the tree. 3rd step of private decision tree evaluation,
// runs on client side. Only Damgard-Geisler-Kroigaard supports this.
func (c *Cryptosystem) AnswerDecisionTreeComparisons(encryptedComparisons [][]*big.Int) ([]*big.Int, error) {
	e, err := c.numericTrees()
	if err != nil {
		return nil, err
	}
	return e.AnswerDecisionTreeComparisons(encryptedComparisons)
}

// EvaluateDecisionTreeLeaves finds the reached leaf in encrypted form. 4th
// step of private decision tree evaluation, runs on server side. Only
// Damgard-Geisler-Kroigaard supports this.
func (c *Cryptosystem) EvaluateDecisionTreeLeaves(state *DecisionTreeState, encryptedAnswers []*big.Int) ([]EncryptedLeaf, error) {
	e, err := c.numericTrees()
	if err != nil {
		return nil, err
	}
	return e.EvaluateDecisionTreeLeaves(state, encryptedAnswers)
}

// DecryptDecisionTreeOutput restores the label of the reached leaf. Client
// learns only this label. Last step of private decision tree evaluation, runs
// on client side. Only Damgard-Geisler-Kroigaard supports this.
func (c *Cryptosystem) DecryptDecisionTreeOutput(encryptedLeaves []EncryptedLeaf) (*big.Int, error) {
	e, err := c.numericTrees()
	if err != nil {
		return nil, err
	}
	return e.DecryptDecisionTreeOutput(encryptedLeaves)
}

// ---------------------------------------------------------------------------
// Secure comparison
// ---------------------------------------------------------------------------

func (c *Cryptosystem) comparer() (phe.SecureComparer, error) {
	if e, ok := c.unboosted().(phe.SecureComparer); ok {
		return e, nil
	}
	return nil, phe.Unsupportedf(c.algorithm, phe.OpSecureComparison)
}

// EncryptComparisonInput encrypts bits of client's value x in
// [0, 2^bitLength) to compare it with server's value y. 1st step of secure
// comparison, runs on client side. Only Damgard-Geisler-Kroigaard supports
// this.
func (c *Cryptosystem) EncryptComparisonInput(value int64, bitLength int) ([]*big.Int, error) {
	e, err := c.comparer()
	if err != nil {
		return nil, err
	}
	return e.EncryptComparisonInput(value, bitLength)
}

// EvaluateComparison compares client's encrypted value x with server's value
// y. 2nd step of secure comparison, runs on server side. Private key is not
// required and server learns nothing about x. Only Damgard-Geisler-Kroigaard
// supports this.
func (c *Cryptosystem) EvaluateComparison(encryptedInput []*big.Int, value int64) ([]*big.Int, error) {
	e, err := c.comparer()
	if err != nil {
		return nil, err
	}
	return e.EvaluateComparison(encryptedInput, value)
}

// DecryptComparison restores the result of secure comparison, true if x <= y.
// 3rd step of secure comparison, runs on client side. Client learns only
// whether x <= y, but not y. Only Damgard-Geisler-Kroigaard supports this.
func (c *Cryptosystem) DecryptComparison(encryptedResult []*big.Int) (bool, error) {
	e, err := c.comparer()
	if err != nil {
		return false, err
	}
	return e.DecryptComparison(encryptedResult)
}

// ---------------------------------------------------------------------------
// Encrypted argmax
// ---------------------------------------------------------------------------

func (c *Cryptosystem) argmax() (phe.ArgmaxEvaluator, error) {
	if e, ok := c.unboosted().(phe.ArgmaxEvaluator); ok {
		return e, nil
	}
	return nil, phe.Unsupportedf(c.algorithm, phe.OpArgmax)
}

// EvaluateArgmax finds the index of the maximum of encrypted values in
// [0, 2^bitLength) without decrypting them. It runs on server side and talks
// to the client (private key owner) through the client callback, which can be
// the client's AnswerArgmax locally, or a network call otherwise. Client
// learns only the index, and server learns nothing. Index of the first maximum
// is returned on ties. Only Damgard-Geisler-Kroigaard supports this.
func (c *Cryptosystem) EvaluateArgmax(encryptedValues []*encrypted.Ciphertext, bitLength int, client ArgmaxClient) (
	*encrypted.Ciphertext, error) {
	e, err := c.argmax()
	if err != nil {
		return nil, err
	}
	values := make([]*big.Int, len(encryptedValues))
	for i, ciphertext := range encryptedValues {
		if ciphertext == nil {
			return nil, phe.InvalidCiphertextf("lightphe: nil ciphertext")
		}
		if values[i], err = phe.AsInt(ciphertext.Value); err != nil {
			return nil, err
		}
	}
	output, err := e.EvaluateArgmax(values, bitLength, client)
	if err != nil {
		return nil, err
	}
	return encrypted.NewCiphertext(c.public, phe.Int{V: output}), nil
}

// AnswerArgmax answers a message of the server during encrypted argmax. It
// runs on client side. Every value decrypted here is masked with a uniformly
// random value. Only Damgard-Geisler-Kroigaard supports this.
func (c *Cryptosystem) AnswerArgmax(message ArgmaxMessage) ([]*big.Int, error) {
	e, err := c.argmax()
	if err != nil {
		return nil, err
	}
	return e.AnswerArgmax(message)
}

// ---------------------------------------------------------------------------
// Master key decryption
// ---------------------------------------------------------------------------

func (c *Cryptosystem) masterKey() (phe.MasterKeyDecrypter, error) {
	if e, ok := c.unboosted().(phe.MasterKeyDecrypter); ok {
		return e, nil
	}
	return nil, phe.Unsupportedf(c.algorithm, phe.OpMasterKey)
}

// DecryptWithMasterKey decrypts a ciphertext with the master key instead of
// the private key of its owner. The master key can decrypt ciphertexts of all
// users sharing it. Only Bresson-Catalano-Pointcheval supports this.
func (c *Cryptosystem) DecryptWithMasterKey(ciphertext *encrypted.Ciphertext) (*big.Int, error) {
	if ciphertext == nil {
		return nil, phe.InvalidCiphertextf("lightphe: nil ciphertext")
	}
	e, err := c.masterKey()
	if err != nil {
		return nil, err
	}
	return e.DecryptWithMasterKey(ciphertext.Value, ciphertext.Scheme())
}

// DecryptTensorWithMasterKey decrypts an encrypted tensor of any user with the
// master key. Only Bresson-Catalano-Pointcheval supports this.
func (c *Cryptosystem) DecryptTensorWithMasterKey(tensor *encrypted.Tensor) ([]float64, error) {
	if tensor == nil {
		return nil, phe.InvalidCiphertextf("lightphe: nil tensor")
	}
	e, err := c.masterKey()
	if err != nil {
		return nil, err
	}
	owner := tensor.Scheme()
	return decryptFractions(tensor, func(v phe.Value) (*big.Int, error) {
		return e.DecryptWithMasterKey(v, owner)
	})
}

// GenerateUserKeys generates JSON key material of a new user of a master key.
// Public key of the authority holding the master key is enough to generate it.
// The master key can decrypt ciphertexts encrypted for the new user, but the
// new user cannot decrypt ciphertexts of others. Build the user's cryptosystem
// with WithKeys. Only Bresson-Catalano-Pointcheval supports this.
func (c *Cryptosystem) GenerateUserKeys() ([]byte, error) {
	e, err := c.masterKey()
	if err != nil {
		return nil, err
	}
	return e.GenerateUserKeys()
}

// ---------------------------------------------------------------------------
// Verifiable encryption
// ---------------------------------------------------------------------------

func (c *Cryptosystem) verifiable() (phe.VerifiableEncrypter, error) {
	if e, ok := c.unboosted().(phe.VerifiableEncrypter); ok {
		return e, nil
	}
	return nil, phe.Unsupportedf(c.algorithm, phe.OpVerifiable)
}

// EncryptVerifiably encrypts the discrete logarithm of an elliptic curve
// point, e.g. a private key, for the owner of this cryptosystem and proves
// that the ciphertext contains it. Label is public data bound to the
// ciphertext, e.g. decryption conditions, and the ciphertext cannot be
// decrypted with a different label. It runs on prover side and needs the
// public key of the trusted third party only. Only Camenisch-Shoup supports
// this.
func (c *Cryptosystem) EncryptVerifiably(secret *big.Int, label string) (*VerifiableCiphertext, error) {
	e, err := c.verifiable()
	if err != nil {
		return nil, err
	}
	return e.EncryptVerifiably(secret, label)
}

// VerifyEncryption verifies that a verifiable ciphertext contains the discrete
// logarithm of a public point bound to label, without decrypting it. It runs
// on verifier side and needs the public key of the trusted third party only.
// Only Camenisch-Shoup supports this.
func (c *Cryptosystem) VerifyEncryption(ciphertext *VerifiableCiphertext, publicPoint ecc.Point, label string) (bool, error) {
	e, err := c.verifiable()
	if err != nil {
		return false, err
	}
	return e.VerifyEncryption(ciphertext, publicPoint, label)
}

// DecryptVerifiableCiphertext restores the secret from a verifiable
// ciphertext with the label used in encryption. It runs on the side of the
// private key owner, e.g. a trusted third party, and does not check the proof,
// as VerifyEncryption does that. Only Camenisch-Shoup supports this.
func (c *Cryptosystem) DecryptVerifiableCiphertext(ciphertext *VerifiableCiphertext, label string) (*big.Int, error) {
	e, err := c.verifiable()
	if err != nil {
		return nil, err
	}
	return e.DecryptVerifiableCiphertext(ciphertext, label)
}

// ---------------------------------------------------------------------------
// Tensor encryption
// ---------------------------------------------------------------------------

// EncryptTensor encrypts a vector of real numbers. Elements are encrypted
// concurrently across the available cores.
func (c *Cryptosystem) EncryptTensor(tensor []float64) (*encrypted.Tensor, error) {
	if err := phe.RejectsFloats(c.cs); err != nil {
		return nil, err
	}
	if len(tensor) == 0 {
		return nil, fmt.Errorf("lightphe: cannot encrypt an empty tensor")
	}
	modulo := c.cs.PlaintextModulo()

	scale := new(big.Int).Exp(big.NewInt(10), big.NewInt(int64(c.precision)), nil)
	if scale.Cmp(modulo) >= 0 {
		return nil, fmt.Errorf("lightphe: precision %d needs a scale of %s which does not fit in the message space %s",
			c.precision, scale, modulo)
	}

	// The scale factor and zero are the same for every element, so encrypt them
	// once and share the ciphertexts.
	encryptedDivisor, err := c.cs.Encrypt(scale)
	if err != nil {
		return nil, err
	}
	encryptedZero, err := c.cs.Encrypt(new(big.Int))
	if err != nil {
		return nil, err
	}

	fractions := make([]encrypted.Fraction, len(tensor))
	err = parallelDo(len(tensor), func(i int) error {
		fraction, err := c.encryptElement(tensor[i], modulo, encryptedZero, encryptedDivisor)
		if err != nil {
			return err
		}
		fractions[i] = fraction
		return nil
	})
	if err != nil {
		return nil, err
	}

	return encrypted.NewTensor(c.public, fractions, c.precision), nil
}

// encryptElement turns one real number into a Fraction.
func (c *Cryptosystem) encryptElement(m float64, modulo *big.Int, encryptedZero, encryptedDivisor phe.Value) (encrypted.Fraction, error) {
	if m == 0 {
		// Zeros are common in real embeddings, so reuse the shared ciphertext.
		return encrypted.Fraction{
			Dividend:    encryptedZero,
			AbsDividend: encryptedZero,
			Divisor:     encryptedDivisor,
			Sign:        1,
		}, nil
	}

	dividend, _ := fixedpoint.Fractionize(m, modulo, c.precision)
	encryptedDividend, err := c.cs.Encrypt(dividend)
	if err != nil {
		return encrypted.Fraction{}, err
	}

	sign := 1
	encryptedAbs := encryptedDividend
	if m < 0 {
		sign = -1
		absDividend, _ := fixedpoint.Fractionize(-m, modulo, c.precision)
		if encryptedAbs, err = c.cs.Encrypt(absDividend); err != nil {
			return encrypted.Fraction{}, err
		}
	}

	return encrypted.Fraction{
		Dividend:    encryptedDividend,
		AbsDividend: encryptedAbs,
		Divisor:     encryptedDivisor,
		Sign:        sign,
	}, nil
}

// DecryptTensor recovers the real numbers behind an encrypted tensor.
func (c *Cryptosystem) DecryptTensor(tensor *encrypted.Tensor) ([]float64, error) {
	if tensor == nil {
		return nil, phe.InvalidCiphertextf("lightphe: nil tensor")
	}
	if !c.cs.HasPrivateKey() {
		return nil, phe.ErrMissingPrivateKey
	}
	return decryptFractions(tensor, c.cs.Decrypt)
}

// decryptFractions recovers the real numbers behind an encrypted tensor with
// the given decryption function.
func decryptFractions(tensor *encrypted.Tensor, decrypt func(phe.Value) (*big.Int, error)) ([]float64, error) {
	out := make([]float64, len(tensor.Fractions))
	err := parallelDo(len(tensor.Fractions), func(i int) error {
		fraction := tensor.Fractions[i]

		absDividend, err := decrypt(fraction.AbsDividend)
		if err != nil {
			return err
		}
		divisor, err := decrypt(fraction.Divisor)
		if err != nil {
			return err
		}
		if divisor.Sign() == 0 {
			return fmt.Errorf("lightphe: element %d decrypted to a zero scale factor: %w", i, phe.ErrDecryptionFailed)
		}

		value, _ := new(big.Rat).SetFrac(absDividend, divisor).Float64()
		out[i] = float64(fraction.Sign) * value
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// ---------------------------------------------------------------------------
// Key material
// ---------------------------------------------------------------------------

// Keys serialises the key material as JSON. Pass false to keep the private key.
func (c *Cryptosystem) Keys(publicOnly bool) ([]byte, error) {
	return c.cs.ExportKeys(!publicOnly)
}

// ExportKeys writes the key material to a file. Pass public = true to publish
// the public key alone; otherwise the file contains the private key and must be
// protected accordingly. The file is created with owner-only permissions.
func (c *Cryptosystem) ExportKeys(targetFile string, public bool) error {
	data, err := c.cs.ExportKeys(!public)
	if err != nil {
		return err
	}
	mode := os.FileMode(0600)
	if public {
		mode = 0644
	}
	if err := os.WriteFile(targetFile, data, mode); err != nil {
		return fmt.Errorf("lightphe: writing key file %q: %w", targetFile, err)
	}
	return nil
}

// parallelDo runs fn for every index in [0, n) across a bounded pool of
// goroutines and returns the first error reported.
func parallelDo(n int, fn func(i int) error) error {
	workers := runtime.NumCPU()
	if workers > n {
		workers = n
	}
	if workers < 1 {
		workers = 1
	}

	var (
		wg       sync.WaitGroup
		mu       sync.Mutex
		firstErr error
		next     = make(chan int)
	)

	go func() {
		defer close(next)
		for i := 0; i < n; i++ {
			next <- i
		}
	}()

	wg.Add(workers)
	for w := 0; w < workers; w++ {
		go func() {
			defer wg.Done()
			for i := range next {
				// Keep draining after a failure so the producer never blocks;
				// the remaining indices are skipped rather than processed.
				mu.Lock()
				failed := firstErr != nil
				mu.Unlock()
				if failed {
					continue
				}
				if err := fn(i); err != nil {
					mu.Lock()
					if firstErr == nil {
						firstErr = err
					}
					mu.Unlock()
				}
			}
		}()
	}
	wg.Wait()
	return firstErr
}
