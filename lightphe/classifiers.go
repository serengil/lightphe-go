package lightphe

import (
	"fmt"
	"math"
	"math/big"

	"github.com/serengil/lightphe-go/lightphe/encrypted"
	"github.com/serengil/lightphe-go/lightphe/phe"
)

// ---------------------------------------------------------------------------
// Classification over encrypted data
//
// Client (private key owner) encrypts its features, and server evaluates its
// private model on them, so client learns only the predicted class, and
// server learns nothing about the features.
//   - hyperplane: class scores <w_i, x> + b_i are linear in the encrypted
//     features. They are shifted by 2^bitLength to be non-negative, which
//     keeps the argmax.
//   - naive bayes: client encrypts each categorical feature as a one-hot
//     vector, so the score log P(c) + sum of log P(x_j | c) is linear in it.
//     Log probabilities are quantized, and the log probabilities of each
//     feature are shifted by their minimum, which adds the same constant to
//     scores of all classes, so it keeps the argmax.
//   - argmax: interactive argmax of Damgard-Geisler-Kroigaard on encrypted
//     scores.
//
// Reference: Bost, R., Popa, R. A., Tu, S., Goldwasser, S. (2015). Machine
// Learning Classification over Encrypted Data. NDSS 2015.
// ---------------------------------------------------------------------------

func (c *Cryptosystem) requireClassifierSupport() error {
	if c.algorithm != phe.DamgardGeislerKroigaard {
		return fmt.Errorf("lightphe: %s does not support encrypted classification, "+
			"use Damgard-Geisler-Kroigaard instead: %w", c.algorithm, phe.ErrUnsupportedOperation)
	}
	return nil
}

// linearScore returns E(constant + sum of coefficients_i x_i) for encrypted
// x_i, skipping zero coefficients.
func linearScore(cs phe.Homomorphic, constant *big.Int, coefficients []*big.Int, xs []phe.Value) (*big.Int, error) {
	u := cs.PlaintextModulo()
	score, err := cs.Encrypt(phe.Normalize(constant, u))
	if err != nil {
		return nil, err
	}
	for i, coefficient := range coefficients {
		k := phe.Normalize(coefficient, u)
		if k.Sign() == 0 {
			continue
		}
		term, err := cs.MultiplyByConstant(xs[i], k)
		if err != nil {
			return nil, err
		}
		if score, err = cs.Add(score, term); err != nil {
			return nil, err
		}
	}
	return phe.AsInt(score)
}

// EvaluateHyperplane classifies encrypted features with a private linear
// model, i.e. finds the class of the greatest score <w_i, x> + b_i, e.g.
// logistic regression or a linear SVM. Weights and biases must be integers,
// so quantize them first, and nil biases are zeros. Absolute values of scores
// must be less than 2^bitLength. It runs on server side and talks to the
// client (private key owner) through the client callback, which is the
// client's AnswerArgmax locally. Client learns only the predicted class, and
// server learns nothing. The returned index of the predicted class is to be
// decrypted by the client, and earlier class is returned on ties. Only
// Damgard-Geisler-Kroigaard supports this.
func (c *Cryptosystem) EvaluateHyperplane(features []*encrypted.Ciphertext, weights [][]int64, bitLength int,
	client ArgmaxClient, biases []int64) (*encrypted.Ciphertext, error) {
	if err := c.requireClassifierSupport(); err != nil {
		return nil, err
	}
	argmax, err := c.argmax()
	if err != nil {
		return nil, err
	}
	if len(weights) == 0 {
		return nil, fmt.Errorf("lightphe: weights must be a non-empty list of class weights")
	}
	for _, w := range weights {
		if len(w) != len(weights[0]) {
			return nil, fmt.Errorf("lightphe: every class must have the same number of weights")
		}
	}
	if biases == nil {
		biases = make([]int64, len(weights))
	}
	if len(biases) != len(weights) {
		return nil, fmt.Errorf("lightphe: there must be a bias for each class")
	}
	if len(features) != len(weights[0]) {
		return nil, fmt.Errorf("lightphe: encrypted features must be a list of %d ciphertexts", len(weights[0]))
	}
	xs := make([]phe.Value, len(features))
	for i, feature := range features {
		if feature == nil {
			return nil, phe.InvalidCiphertextf("lightphe: nil ciphertext")
		}
		xs[i] = feature.Value
	}
	if bitLength < 1 {
		return nil, fmt.Errorf("lightphe: bit length must be a positive integer")
	}

	cs := c.unboosted()
	offset := new(big.Int).Lsh(big.NewInt(1), uint(bitLength))
	scores := make([]*big.Int, len(weights))
	for i, classWeights := range weights {
		coefficients := make([]*big.Int, len(classWeights))
		for j, w := range classWeights {
			coefficients[j] = big.NewInt(w)
		}
		if scores[i], err = linearScore(cs, new(big.Int).Add(big.NewInt(biases[i]), offset), coefficients, xs); err != nil {
			return nil, err
		}
	}

	// scores are in [0, 2^(bitLength + 1)) after the shift
	output, err := argmax.EvaluateArgmax(scores, bitLength+1, client)
	if err != nil {
		return nil, err
	}
	return encrypted.NewCiphertext(c.publicUnboosted(), phe.Int{V: output}), nil
}

// EncryptNaiveBayesInput encrypts categorical features for naive bayes
// classification as one-hot vectors. Each feature is in [0, domain size), and
// the server shares the domain sizes as a part of its model. It runs on client
// side. Only Damgard-Geisler-Kroigaard supports this.
func (c *Cryptosystem) EncryptNaiveBayesInput(features []int, domainSizes []int) ([][]*encrypted.Ciphertext, error) {
	if err := c.requireClassifierSupport(); err != nil {
		return nil, err
	}
	if len(features) == 0 || len(features) != len(domainSizes) {
		return nil, fmt.Errorf("lightphe: there must be a domain size for each feature")
	}
	for i, feature := range features {
		if domainSizes[i] < 1 {
			return nil, fmt.Errorf("lightphe: domain sizes must be positive integers")
		}
		if feature < 0 || feature >= domainSizes[i] {
			return nil, fmt.Errorf("lightphe: feature %d must be an integer in [0, %d)", feature, domainSizes[i])
		}
	}

	cs := c.unboosted()
	out := make([][]*encrypted.Ciphertext, len(features))
	for i, feature := range features {
		out[i] = make([]*encrypted.Ciphertext, domainSizes[i])
		for value := range out[i] {
			bit := int64(0)
			if value == feature {
				bit = 1
			}
			ciphertext, err := cs.Encrypt(big.NewInt(bit))
			if err != nil {
				return nil, err
			}
			out[i][value] = encrypted.NewCiphertext(c.publicUnboosted(), ciphertext)
		}
	}
	return out, nil
}

// EvaluateNaiveBayes classifies encrypted categorical features with a private
// naive bayes model, i.e. finds the class of the greatest log P(c) + sum of
// log P(x_j | c). priors are P(c) of each class, and likelihoods[c][j][v] is
// P(x_j = v | c). Probabilities must be positive, e.g. smoothed with Laplace
// smoothing. precision is the number of decimal digits kept from log
// probabilities, e.g. 3, and greater values need more bits for scores. It
// runs on server side and talks to the client (private key owner) through the
// client callback, which is the client's AnswerArgmax locally. Client learns
// only the predicted class, and server learns nothing. Earlier class is
// returned on ties. Only Damgard-Geisler-Kroigaard supports this.
func (c *Cryptosystem) EvaluateNaiveBayes(input [][]*encrypted.Ciphertext, priors []float64, likelihoods [][][]float64,
	client ArgmaxClient, precision int) (*encrypted.Ciphertext, error) {
	if err := c.requireClassifierSupport(); err != nil {
		return nil, err
	}
	argmax, err := c.argmax()
	if err != nil {
		return nil, err
	}
	if len(likelihoods) == 0 {
		return nil, fmt.Errorf("lightphe: likelihoods must be a non-empty list of class likelihoods")
	}
	domainSizes := make([]int, len(likelihoods[0]))
	for j, values := range likelihoods[0] {
		domainSizes[j] = len(values)
	}
	for _, classLikelihoods := range likelihoods {
		if len(classLikelihoods) != len(domainSizes) {
			return nil, fmt.Errorf("lightphe: every class must have likelihoods of the same features and values")
		}
		for j, values := range classLikelihoods {
			if len(values) != domainSizes[j] {
				return nil, fmt.Errorf("lightphe: every class must have likelihoods of the same features and values")
			}
		}
	}
	if len(priors) != len(likelihoods) {
		return nil, fmt.Errorf("lightphe: there must be a prior for each class")
	}
	if len(input) != len(domainSizes) {
		return nil, fmt.Errorf("lightphe: encrypted input must be one-hot vectors of domain sizes %v", domainSizes)
	}
	xs := make([][]phe.Value, len(input))
	for j, oneHot := range input {
		if len(oneHot) != domainSizes[j] {
			return nil, fmt.Errorf("lightphe: encrypted input must be one-hot vectors of domain sizes %v", domainSizes)
		}
		xs[j] = make([]phe.Value, len(oneHot))
		for v, ciphertext := range oneHot {
			if ciphertext == nil {
				return nil, phe.InvalidCiphertextf("lightphe: nil ciphertext")
			}
			xs[j][v] = ciphertext.Value
		}
	}
	if precision < 0 {
		return nil, fmt.Errorf("lightphe: precision must be a non-negative integer")
	}

	quantizedPriors, quantizedLikelihoods, bitLength, err := quantizeNaiveBayes(priors, likelihoods, precision)
	if err != nil {
		return nil, err
	}

	cs := c.unboosted()
	scores := make([]*big.Int, len(priors))
	for class, prior := range quantizedPriors {
		var coefficients []*big.Int
		var bits []phe.Value
		for j, values := range quantizedLikelihoods[class] {
			for v, value := range values {
				coefficients = append(coefficients, big.NewInt(value))
				bits = append(bits, xs[j][v])
			}
		}
		if scores[class], err = linearScore(cs, big.NewInt(prior), coefficients, bits); err != nil {
			return nil, err
		}
	}
	output, err := argmax.EvaluateArgmax(scores, bitLength, client)
	if err != nil {
		return nil, err
	}
	return encrypted.NewCiphertext(c.publicUnboosted(), phe.Int{V: output}), nil
}

// quantizeNaiveBayes quantizes log probabilities of a naive bayes model to
// non-negative integers, and returns the bit length of scores.
func quantizeNaiveBayes(priors []float64, likelihoods [][][]float64, precision int) ([]int64, [][][]int64, int, error) {
	scale := math.Pow10(precision)
	logOf := func(p float64) (float64, error) {
		if !(p > 0 && p <= 1) {
			return 0, fmt.Errorf("lightphe: probabilities must be in (0, 1], got %v. Smooth zero probabilities, "+
				"e.g. with Laplace smoothing", p)
		}
		return math.Log(p), nil
	}
	quantize := func(x float64) int64 { return int64(math.RoundToEven(x * scale)) }

	logPriors := make([]float64, len(priors))
	lowestPrior := math.Inf(1)
	for i, p := range priors {
		x, err := logOf(p)
		if err != nil {
			return nil, nil, 0, err
		}
		logPriors[i] = x
		lowestPrior = math.Min(lowestPrior, x)
	}
	quantizedPriors := make([]int64, len(priors))
	for i, x := range logPriors {
		quantizedPriors[i] = quantize(x - lowestPrior)
	}

	quantizedLikelihoods := make([][][]int64, len(likelihoods))
	for class := range likelihoods {
		quantizedLikelihoods[class] = make([][]int64, len(likelihoods[0]))
	}
	for j := range likelihoods[0] {
		logs := make([][]float64, len(likelihoods))
		lowest := math.Inf(1)
		for class, classLikelihoods := range likelihoods {
			logs[class] = make([]float64, len(classLikelihoods[j]))
			for v, p := range classLikelihoods[j] {
				x, err := logOf(p)
				if err != nil {
					return nil, nil, 0, err
				}
				logs[class][v] = x
				lowest = math.Min(lowest, x)
			}
		}
		for class, values := range logs {
			quantized := make([]int64, len(values))
			for v, x := range values {
				quantized[v] = quantize(x - lowest)
			}
			quantizedLikelihoods[class][j] = quantized
		}
	}

	largest := int64(0)
	for class, prior := range quantizedPriors {
		score := prior
		for _, values := range quantizedLikelihoods[class] {
			best := int64(0)
			for _, x := range values {
				if x > best {
					best = x
				}
			}
			score += best
		}
		if score > largest {
			largest = score
		}
	}
	bitLength := big.NewInt(largest).BitLen()
	if bitLength < 1 {
		bitLength = 1
	}
	return quantizedPriors, quantizedLikelihoods, bitLength, nil
}
