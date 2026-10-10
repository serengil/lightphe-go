// Package ishaipaskin implements the Ishai-Paskin cryptosystem, which
// evaluates a decision tree on encrypted data.
//
// A client encrypts its input bits, a server holding a private decision tree
// evaluates it on the encrypted input and returns an encryption of the
// output. Ciphertext size depends on the depth of the tree, not on its size.
// The paper calls these branching programs. Decision trees are their most
// common form, and trees sharing sub trees (DAGs) are supported as well.
//
// It is built on length flexible Damgard-Jurik: level s encrypts messages in
// Z_{n^s} into ciphertexts in Z_{n^(s+1)}, so a level s ciphertext fits into
// the plaintext space of level s+1. Each level of the tree wraps one more
// encryption layer around the result. It is also homomorphic with respect to
// addition as Damgard-Jurik.
//
// Reference: Ishai, Y., Paskin, A. (2007). Evaluating Branching Programs on
// Encrypted Data. TCC 2007. https://doi.org/10.1007/978-3-540-70936-7_31
package ishaipaskin

import (
	"encoding/json"
	"fmt"
	"math/big"

	"github.com/serengil/lightphe-go/lightphe/internal/mathutil"
	"github.com/serengil/lightphe-go/lightphe/phe"
	"github.com/serengil/lightphe-go/lightphe/schemes/damgardjurik"
)

// DefaultKeySize is used when the caller does not specify a key size.
const DefaultKeySize = 1024

// ErrDecisionTreeOutput reports a homomorphic operation on the output of a
// decision tree evaluation, which can only be decrypted.
var ErrDecisionTreeOutput = fmt.Errorf("lightphe: output of a decision tree can only be decrypted, "+
	"homomorphic operations are not supported on it: %w", phe.ErrUnsupportedOperation)

// Keys is the Damgard-Jurik key pair Ishai-Paskin is built on.
type Keys = damgardjurik.Keys

// Cryptosystem is a configured Ishai-Paskin instance. It is immutable and safe
// for concurrent use.
type Cryptosystem struct {
	*damgardjurik.Cryptosystem

	n, g, phi *big.Int
	hasSecret bool
}

var _ phe.Homomorphic = (*Cryptosystem)(nil)

// Generate creates a fresh key pair with a modulus of keySize bits.
func Generate(keySize int) (*Cryptosystem, error) {
	if keySize <= 0 {
		keySize = DefaultKeySize
	}
	dj, err := damgardjurik.Generate(keySize, 0)
	if err != nil {
		return nil, fmt.Errorf("ishaipaskin: %w", err)
	}
	return New(dj.Keys())
}

// New builds a cryptosystem around an existing key pair.
func New(keys Keys) (*Cryptosystem, error) {
	if err := validate(keys); err != nil {
		return nil, err
	}
	dj, err := damgardjurik.New(keys)
	if err != nil {
		return nil, err
	}
	c := &Cryptosystem{
		Cryptosystem: dj,
		n:            new(big.Int).Set(keys.PublicKey.N),
		g:            new(big.Int).Set(keys.PublicKey.G),
	}
	if keys.PrivateKey != nil {
		c.phi = new(big.Int).Set(keys.PrivateKey.Phi)
		c.hasSecret = true
	}
	return c, nil
}

// validate reports missing key fields under the Ishai-Paskin name.
func validate(k Keys) error {
	if k.PublicKey == nil {
		return phe.RequireSection(phe.IshaiPaskin, phe.SectionPublic)
	}
	if err := phe.RequireFields(phe.IshaiPaskin, phe.SectionPublic,
		phe.Field("g", k.PublicKey.G != nil),
		phe.Field("n", k.PublicKey.N != nil),
		phe.Field("s", k.PublicKey.S != nil),
	); err != nil {
		return err
	}
	if k.PrivateKey != nil {
		return phe.RequireFields(phe.IshaiPaskin, phe.SectionPrivate,
			phe.Field("phi", k.PrivateKey.Phi != nil),
		)
	}
	return nil
}

// FromJSON rebuilds a cryptosystem from exported key material.
func FromJSON(data []byte) (*Cryptosystem, error) {
	var keys Keys
	if err := json.Unmarshal(data, &keys); err != nil {
		return nil, phe.InvalidKeysf("ishaipaskin: decoding keys: %v", err)
	}
	return New(keys)
}

// Algorithm implements phe.Homomorphic.
func (c *Cryptosystem) Algorithm() phe.Algorithm { return phe.IshaiPaskin }

// PublicOnly implements phe.Homomorphic.
func (c *Cryptosystem) PublicOnly() (phe.Homomorphic, error) {
	return New(Keys{PublicKey: c.Keys().PublicKey})
}

// EncryptAtLevel encrypts a plaintext in Z_{n^level} with Damgard-Jurik at the
// given level. The ciphertext is in Z_{n^(level+1)}.
func (c *Cryptosystem) EncryptAtLevel(plaintext *big.Int, level int) (*big.Int, error) {
	r, err := mathutil.RandCoprime(c.n)
	if err != nil {
		return nil, fmt.Errorf("ishaipaskin: %w", err)
	}
	return c.EncryptAtLevelWith(plaintext, level, r), nil
}

// EncryptAtLevelWith encrypts at the given level using a caller supplied
// random key coprime to n.
func (c *Cryptosystem) EncryptAtLevelWith(plaintext *big.Int, level int, random *big.Int) *big.Int {
	modulo := c.power(level + 1)
	left := new(big.Int).Exp(c.g, plaintext, modulo)
	right := new(big.Int).Exp(random, c.power(level), modulo)
	return left.Mul(left, right).Mod(left, modulo)
}

// DecryptAtLevel decrypts a ciphertext of the given level back to Z_{n^level}.
func (c *Cryptosystem) DecryptAtLevel(ciphertext *big.Int, level int) (*big.Int, error) {
	if !c.hasSecret {
		return nil, phe.ErrMissingPrivateKey
	}
	plaintextModulo := c.power(level)

	// randomness vanishes because the order of Z*_{n^(s+1)} is phi * n^s.
	// what remains is (1 + n)^(m * phi)
	a := new(big.Int).Exp(ciphertext, c.phi, c.power(level+1))
	mPhi, err := c.dlog(a, level)
	if err != nil {
		return nil, err
	}
	phiInv, err := mathutil.ModInverse(c.phi, plaintextModulo)
	if err != nil {
		return nil, fmt.Errorf("ishaipaskin: %v: %w", err, phe.ErrDecryptionFailed)
	}
	return mPhi.Mul(mPhi, phiInv).Mod(mPhi, plaintextModulo), nil
}

// dlog finds i such that a = (1 + n)^i mod n^(s+1) with Damgard-Jurik's
// recursive algorithm.
func (c *Cryptosystem) dlog(a *big.Int, level int) (*big.Int, error) {
	one := big.NewInt(1)
	i := new(big.Int)
	for j := 1; j <= level; j++ {
		nj := c.power(j)
		t1 := new(big.Int).Mod(a, c.power(j+1))
		t1.Sub(t1, one).Quo(t1, c.n)
		t2 := new(big.Int).Set(i)
		factorial := big.NewInt(1)
		for k := 2; k <= j; k++ {
			i.Sub(i, one)
			t2.Mul(t2, i).Mod(t2, nj)
			factorial.Mul(factorial, big.NewInt(int64(k)))
			inv, err := mathutil.ModInverse(factorial, nj)
			if err != nil {
				return nil, fmt.Errorf("ishaipaskin: %v: %w", err, phe.ErrDecryptionFailed)
			}
			term := new(big.Int).Mul(t2, c.power(k-1))
			term.Mul(term, inv)
			t1.Sub(t1, term).Mod(t1, nj)
		}
		i = t1
	}
	return i, nil
}

// EncryptDecisionTreeInput implements phe.Homomorphic. Each bit is encrypted
// at every level from 1 to depth because the server decides which level it
// needs. Item [i][s-1] is the encryption of bit i at level s.
func (c *Cryptosystem) EncryptDecisionTreeInput(bits []int, depth int) ([][]*big.Int, error) {
	if depth < 1 {
		return nil, fmt.Errorf("ishaipaskin: depth must be a positive integer but it is %d", depth)
	}
	encrypted := make([][]*big.Int, len(bits))
	for i, bit := range bits {
		if bit != 0 && bit != 1 {
			return nil, fmt.Errorf("ishaipaskin: input must consist of bits (0 or 1) but got %d", bit)
		}
		levels := make([]*big.Int, depth)
		for level := 1; level <= depth; level++ {
			ciphertext, err := c.EncryptAtLevel(big.NewInt(int64(bit)), level)
			if err != nil {
				return nil, err
			}
			levels[level-1] = ciphertext
		}
		encrypted[i] = levels
	}
	return encrypted, nil
}

// leveled is an evaluated node: level 0 is a plain leaf value, level l > 0 a
// ciphertext wrapped in l layers of encryption.
type leveled struct {
	level int
	value *big.Int
}

// EvaluateDecisionTree implements phe.Homomorphic. The private key is not
// required. The output is the tuple (level, ciphertext) where ciphertext wraps
// level layers of encryption around the output of the tree.
func (c *Cryptosystem) EvaluateDecisionTree(tree *phe.DecisionTree, encryptedInput [][]*big.Int) (phe.Value, error) {
	if tree == nil {
		return nil, fmt.Errorf("ishaipaskin: decision tree must not be nil")
	}
	depth := 0
	if len(encryptedInput) > 0 {
		depth = len(encryptedInput[0])
	}
	memo := make(map[*phe.DecisionTree]leveled)
	result, err := c.evaluateNode(tree, encryptedInput, depth, memo)
	if err != nil {
		return nil, err
	}

	if result.level == 0 {
		// tree is a constant, still return an encrypted output
		ciphertext, err := c.EncryptAtLevel(result.value, 1)
		if err != nil {
			return nil, err
		}
		result = leveled{level: 1, value: ciphertext}
	}

	return phe.NewTuple(phe.Int{V: big.NewInt(int64(result.level))}, phe.Int{V: result.value}), nil
}

// evaluateNode evaluates a node of a decision tree bottom up.
func (c *Cryptosystem) evaluateNode(tree *phe.DecisionTree, encryptedInput [][]*big.Int, depth int,
	memo map[*phe.DecisionTree]leveled) (leveled, error) {
	if tree.IsLeaf() {
		return leveled{level: 0, value: new(big.Int).Mod(tree.Value, c.n)}, nil
	}
	if tree.IfZero == nil || tree.IfOne == nil {
		return leveled{}, fmt.Errorf("ishaipaskin: decision node %d must have both sub trees", tree.Variable)
	}
	if cached, ok := memo[tree]; ok {
		return cached, nil
	}
	if tree.Variable < 0 || tree.Variable >= len(encryptedInput) {
		return leveled{}, fmt.Errorf("ishaipaskin: variable index %d is out of input range [0, %d)",
			tree.Variable, len(encryptedInput))
	}

	evaluated0, err := c.evaluateNode(tree.IfZero, encryptedInput, depth, memo)
	if err != nil {
		return leveled{}, err
	}
	evaluated1, err := c.evaluateNode(tree.IfOne, encryptedInput, depth, memo)
	if err != nil {
		return leveled{}, err
	}

	// bring both branches to the same level by wrapping fresh encryption layers
	level := evaluated0.level
	if evaluated1.level > level {
		level = evaluated1.level
	}
	value0, err := c.lift(evaluated0, level)
	if err != nil {
		return leveled{}, err
	}
	value1, err := c.lift(evaluated1, level)
	if err != nil {
		return leveled{}, err
	}

	// values at level l are in Z_{n^(l+1)}, which is plaintext space of level
	// l+1. E(x)^(v1 - v0) * E(v0) = E(v0 + x * (v1 - v0)) = E(v_x)
	level++
	if level > depth {
		return leveled{}, fmt.Errorf("ishaipaskin: decision tree is deeper than %d levels of encrypted input", depth)
	}

	plaintextModulo := c.power(level)
	ciphertextModulo := c.power(level + 1)

	encryptedBit := encryptedInput[tree.Variable][level-1]
	difference := new(big.Int).Sub(value1, value0)
	difference.Mod(difference, plaintextModulo)

	encryptedValue0, err := c.EncryptAtLevel(value0, level)
	if err != nil {
		return leveled{}, err
	}
	ciphertext := new(big.Int).Exp(encryptedBit, difference, ciphertextModulo)
	ciphertext.Mul(ciphertext, encryptedValue0).Mod(ciphertext, ciphertextModulo)

	result := leveled{level: level, value: ciphertext}
	memo[tree] = result
	return result, nil
}

// lift wraps encryption layers around a value with fresh randomness.
func (c *Cryptosystem) lift(evaluated leveled, toLevel int) (*big.Int, error) {
	value := evaluated.value
	for level := evaluated.level + 1; level <= toLevel; level++ {
		lifted, err := c.EncryptAtLevel(value, level)
		if err != nil {
			return nil, err
		}
		value = lifted
	}
	return value, nil
}

// Decrypt implements phe.Homomorphic. It accepts a ciphertext created by
// Encrypt, or the (level, ciphertext) output of a decision tree evaluation.
func (c *Cryptosystem) Decrypt(ciphertext phe.Value) (*big.Int, error) {
	if !c.hasSecret {
		return nil, phe.ErrMissingPrivateKey
	}
	if _, ok := ciphertext.(phe.Int); ok {
		return c.Cryptosystem.Decrypt(ciphertext)
	}

	levelValue, wrapped, err := phe.AsPair(ciphertext)
	if err != nil {
		return nil, err
	}
	level, err := phe.AsInt(levelValue)
	if err != nil {
		return nil, err
	}
	value, err := phe.AsInt(wrapped)
	if err != nil {
		return nil, err
	}

	// peel encryption layers from outer to inner
	for current := int(level.Int64()); current > 0; current-- {
		if value, err = c.DecryptAtLevel(value, current); err != nil {
			return nil, err
		}
	}
	return value, nil
}

// Add implements phe.Homomorphic.
func (c *Cryptosystem) Add(a, b phe.Value) (phe.Value, error) {
	if !isInt(a) || !isInt(b) {
		return nil, ErrDecisionTreeOutput
	}
	return c.Cryptosystem.Add(a, b)
}

// MultiplyByConstant implements phe.Homomorphic.
func (c *Cryptosystem) MultiplyByConstant(ciphertext phe.Value, constant *big.Int) (phe.Value, error) {
	if !isInt(ciphertext) {
		return nil, ErrDecisionTreeOutput
	}
	return c.Cryptosystem.MultiplyByConstant(ciphertext, constant)
}

// Reencrypt implements phe.Homomorphic.
func (c *Cryptosystem) Reencrypt(ciphertext phe.Value) (phe.Value, error) {
	if !isInt(ciphertext) {
		return nil, ErrDecisionTreeOutput
	}
	return c.Cryptosystem.Reencrypt(ciphertext)
}

// Multiply implements phe.Homomorphic by reporting the operation as
// unsupported under the Ishai-Paskin name.
func (c *Cryptosystem) Multiply(_, _ phe.Value) (phe.Value, error) {
	return nil, phe.Unsupportedf(phe.IshaiPaskin, phe.OpMultiplication)
}

// Xor implements phe.Homomorphic by reporting the operation as unsupported.
func (c *Cryptosystem) Xor(_, _ phe.Value) (phe.Value, error) {
	return nil, phe.Unsupportedf(phe.IshaiPaskin, phe.OpExclusiveOr)
}

// And implements phe.Homomorphic by reporting the operation as unsupported.
func (c *Cryptosystem) And(_, _ phe.Value) (phe.Value, error) {
	return nil, phe.Unsupportedf(phe.IshaiPaskin, phe.OpBitwiseAnd)
}

// power returns n^exponent.
func (c *Cryptosystem) power(exponent int) *big.Int {
	return new(big.Int).Exp(c.n, big.NewInt(int64(exponent)), nil)
}

func isInt(v phe.Value) bool {
	_, ok := v.(phe.Int)
	return ok
}
