package lightphe_test

import (
	"math"
	"math/rand"
	"strings"
	"testing"

	"github.com/serengil/lightphe-go/lightphe"
	"github.com/serengil/lightphe-go/lightphe/encrypted"
	"github.com/serengil/lightphe-go/lightphe/phe"
)

func classifyHyperplane(t *testing.T, features []int64, weights [][]int64, bitLength int, biases []int64) int64 {
	t.Helper()
	clientCs, serverCs := classifierParties(t)
	var encryptedFeatures []*encrypted.Ciphertext
	for _, x := range features {
		encryptedFeatures = append(encryptedFeatures, mustEncrypt(t, clientCs, x))
	}
	class, err := serverCs.EvaluateHyperplane(encryptedFeatures, weights, bitLength, clientCs.AnswerArgmax, biases)
	if err != nil {
		t.Fatalf("evaluating: %v", err)
	}
	return mustDecrypt(t, clientCs, class).Int64()
}

func classifyNaiveBayes(t *testing.T, features []int, priors []float64, likelihoods [][][]float64) int64 {
	t.Helper()
	clientCs, serverCs := classifierParties(t)
	domainSizes := make([]int, len(likelihoods[0]))
	for j, values := range likelihoods[0] {
		domainSizes[j] = len(values)
	}
	input, err := clientCs.EncryptNaiveBayesInput(features, domainSizes)
	if err != nil {
		t.Fatalf("encrypting: %v", err)
	}
	class, err := serverCs.EvaluateNaiveBayes(input, priors, likelihoods, clientCs.AnswerArgmax, 3)
	if err != nil {
		t.Fatalf("evaluating: %v", err)
	}
	return mustDecrypt(t, clientCs, class).Int64()
}

func argmaxOf(scores []float64) int64 {
	best := 0
	for i, s := range scores {
		if s > scores[best] {
			best = i
		}
	}
	return int64(best)
}

func TestHyperplaneMatchesPlainArgmax(t *testing.T) {
	rng := rand.New(rand.NewSource(1))
	for i := 0; i < 8; i++ {
		weights := randomVectors(rng, 4, 6, -20, 20)
		biases := randomVectors(rng, 1, 4, -100, 100)[0]
		features := randomVectors(rng, 1, 6, -30, 30)[0]
		scores := make([]float64, len(weights))
		for c, w := range weights {
			for j, x := range features {
				scores[c] += float64(w[j] * x)
			}
			scores[c] += float64(biases[c])
		}
		// scores are in (-2^13, 2^13)
		if got := classifyHyperplane(t, features, weights, 13, biases); got != argmaxOf(scores) {
			t.Fatalf("predicted class %d, want %d", got, argmaxOf(scores))
		}
	}
}

func TestHyperplaneTiesAndBinaryClassification(t *testing.T) {
	// earlier class on ties
	if got := classifyHyperplane(t, []int64{1, 1}, [][]int64{{2, 0}, {0, 2}, {1, 1}}, 4, nil); got != 0 {
		t.Fatalf("predicted class %d on a tie, want 0", got)
	}

	// a binary linear classifier is a hyperplane of two classes: 0 and w
	weights := []int64{3, -2, 5}
	for _, features := range [][]int64{{1, 4, 0}, {2, 1, 1}} {
		var score int64
		for j, x := range features {
			score += weights[j] * x
		}
		want := int64(0)
		if score-4 > 0 {
			want = 1
		}
		if got := classifyHyperplane(t, features, [][]int64{{0, 0, 0}, weights}, 8, []int64{0, -4}); got != want {
			t.Fatalf("predicted class %d, want %d", got, want)
		}
	}
}

func TestCreditApprovalWithLogisticRegression(t *testing.T) {
	// features: income in thousands, debt in thousands, years of employment,
	// late payments
	floatWeights := []float64{0.042, -0.065, 0.31, -0.9}
	const floatBias = -1.2
	quantized := make([]int64, len(floatWeights))
	for i, w := range floatWeights {
		quantized[i] = int64(math.Round(w * 1000))
	}
	weights := [][]int64{{0, 0, 0, 0}, quantized}
	biases := []int64{0, int64(math.Round(floatBias * 1000))}

	for _, features := range [][]int64{{85, 20, 6, 0}, {30, 45, 1, 3}, {55, 10, 3, 1}} {
		logit := floatBias
		for i, x := range features {
			logit += floatWeights[i] * float64(x)
		}
		want := int64(0)
		if logit > 0 {
			want = 1
		}
		if got := classifyHyperplane(t, features, weights, 16, biases); got != want {
			t.Fatalf("approval of %v is %d, want %d", features, got, want)
		}
	}
}

func TestNaiveBayesMatchesPlainPrediction(t *testing.T) {
	rng := rand.New(rand.NewSource(2))
	domainSizes := []int{2, 3, 2}
	priors := []float64{0.5, 0.3, 0.2}
	likelihoods := make([][][]float64, len(priors))
	for c := range priors {
		for _, size := range domainSizes {
			values := make([]float64, size)
			var sum float64
			for v := range values {
				values[v] = 0.05 + rng.Float64()*0.95
				sum += values[v]
			}
			for v := range values {
				values[v] /= sum
			}
			likelihoods[c] = append(likelihoods[c], values)
		}
	}

	for a := 0; a < 2; a++ {
		for b := 0; b < 3; b++ {
			for d := 0; d < 2; d++ {
				features := []int{a, b, d}
				scores := make([]float64, len(priors))
				for c := range priors {
					scores[c] = math.Log(priors[c])
					for j, v := range features {
						scores[c] += math.Log(likelihoods[c][j][v])
					}
				}
				best := argmaxOf(scores)
				// quantization with precision 3 cannot separate scores closer
				// than about 10^-2
				close := false
				for c, s := range scores {
					close = close || (int64(c) != best && scores[best]-s < 1e-2)
				}
				if close {
					continue
				}
				if got := classifyNaiveBayes(t, features, priors, likelihoods); got != best {
					t.Fatalf("predicted class %d for %v, want %d", got, features, best)
				}
			}
		}
	}
}

func TestMedicalDiagnosisWithNaiveBayes(t *testing.T) {
	// symptoms: fever (no, yes), cough (none, dry, wet), fatigue (no, yes)
	// diagnoses: cold, flu, allergy
	records := [][][]int{
		{{0, 2, 0}, {0, 2, 1}, {1, 2, 0}, {0, 1, 0}, {0, 2, 0}},
		{{1, 1, 1}, {1, 2, 1}, {1, 1, 1}, {1, 1, 0}, {0, 1, 1}},
		{{0, 0, 0}, {0, 1, 0}, {0, 0, 1}, {0, 0, 0}},
	}
	domainSizes := []int{2, 3, 2}
	total := 0
	for _, rows := range records {
		total += len(rows)
	}
	priors := make([]float64, len(records))
	likelihoods := make([][][]float64, len(records))
	for c, rows := range records {
		priors[c] = float64(len(rows)) / float64(total)
		for j, size := range domainSizes {
			// laplace smoothing keeps probabilities positive
			values := make([]float64, size)
			for v := range values {
				count := 0
				for _, row := range rows {
					if row[j] == v {
						count++
					}
				}
				values[v] = float64(count+1) / float64(len(rows)+size)
			}
			likelihoods[c] = append(likelihoods[c], values)
		}
	}

	for _, tt := range []struct {
		symptoms []int
		want     int64
	}{{[]int{1, 1, 1}, 1}, {[]int{0, 2, 0}, 0}, {[]int{0, 0, 0}, 2}} {
		if got := classifyNaiveBayes(t, tt.symptoms, priors, likelihoods); got != tt.want {
			t.Fatalf("diagnosis of %v is %d, want %d", tt.symptoms, got, tt.want)
		}
	}
}

func TestClassifiersInvalidInputs(t *testing.T) {
	clientCs, serverCs := classifierParties(t)
	features := []*encrypted.Ciphertext{mustEncrypt(t, clientCs, 1), mustEncrypt(t, clientCs, 2)}

	for _, tt := range []struct {
		weights   [][]int64
		bitLength int
		biases    []int64
		message   string
	}{
		{[][]int64{{1, 2}, {3}}, 8, nil, "same number of weights"},
		{[][]int64{{1, 2, 3}}, 8, nil, "list of 3 ciphertexts"},
		{[][]int64{{1, 2}}, 8, []int64{1, 2}, "bias for each class"},
		{[][]int64{{1, 2}}, 40, nil, "too small for argmax"},
	} {
		if _, err := serverCs.EvaluateHyperplane(features, tt.weights, tt.bitLength, clientCs.AnswerArgmax, tt.biases); err == nil ||
			!strings.Contains(err.Error(), tt.message) {
			t.Fatalf("expected %q, got %v", tt.message, err)
		}
	}

	likelihoods := [][][]float64{{{0.5, 0.5}}, {{0.2, 0.8}}}
	input, err := clientCs.EncryptNaiveBayesInput([]int{1}, []int{2})
	if err != nil {
		t.Fatalf("encrypting: %v", err)
	}
	if _, err := serverCs.EvaluateNaiveBayes(input, []float64{0.5, 0.5}, [][][]float64{{{1, 0}}, {{0.2, 0.8}}},
		clientCs.AnswerArgmax, 3); err == nil || !strings.Contains(err.Error(), "Smooth zero probabilities") {
		t.Fatalf("a zero probability returned %v", err)
	}
	if _, err := serverCs.EvaluateNaiveBayes(input, []float64{1}, likelihoods, clientCs.AnswerArgmax, 3); err == nil ||
		!strings.Contains(err.Error(), "prior for each class") {
		t.Fatalf("missing priors returned %v", err)
	}
	wide, err := clientCs.EncryptNaiveBayesInput([]int{1}, []int{3})
	if err != nil {
		t.Fatalf("encrypting: %v", err)
	}
	if _, err := serverCs.EvaluateNaiveBayes(wide, []float64{0.5, 0.5}, likelihoods, clientCs.AnswerArgmax, 3); err == nil ||
		!strings.Contains(err.Error(), "domain sizes") {
		t.Fatalf("another domain size returned %v", err)
	}
	if _, err := clientCs.EncryptNaiveBayesInput([]int{2}, []int{2}); err == nil || !strings.Contains(err.Error(), "must be an integer in") {
		t.Fatalf("a feature out of its domain returned %v", err)
	}

	paillier := mustBuild(t, phe.Paillier, lightphe.WithKeySize(64))
	_, err = paillier.EncryptNaiveBayesInput([]int{0}, []int{2})
	assertUnsupported(t, "encrypted classification", err)
}
