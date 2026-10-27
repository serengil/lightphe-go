package lightphe_test

import (
	"math"
	"math/big"
	"math/rand"
	"strings"
	"testing"

	"github.com/serengil/lightphe-go/lightphe"
	"github.com/serengil/lightphe-go/lightphe/phe"
)

// quantization error of a value is at most half of 10^-precision
const aggregationTolerance = 1e-5

// buildCommittee splits the key of a dealer among a committee, and returns the
// server having the public key only and the committee.
func buildCommittee(t *testing.T, threshold, parties int) (*lightphe.Cryptosystem, []*lightphe.Cryptosystem) {
	t.Helper()
	dealer := mustBuild(t, phe.Paillier, lightphe.WithKeySize(256), lightphe.WithSafePrimes(true))
	publicKey, shareKeys, err := dealer.GenerateThresholdKeys(threshold, parties)
	if err != nil {
		t.Fatalf("generating threshold keys: %v", err)
	}
	committee := make([]*lightphe.Cryptosystem, len(shareKeys))
	for i, keys := range shareKeys {
		committee[i] = mustBuild(t, phe.Paillier, lightphe.WithKeys(keys))
	}
	return mustBuild(t, phe.Paillier, lightphe.WithKeys(publicKey)), committee
}

func mustAggregate(t *testing.T, server *lightphe.Cryptosystem, updates [][]float64, maxValue float64,
	maxClients int) *lightphe.EncryptedUpdate {
	t.Helper()
	encrypted := make([]*lightphe.EncryptedUpdate, len(updates))
	for i, update := range updates {
		e, err := server.EncryptUpdate(update, maxValue, maxClients)
		if err != nil {
			t.Fatalf("encrypting an update: %v", err)
		}
		encrypted[i] = e
	}
	sum, err := server.AggregateUpdates(encrypted)
	if err != nil {
		t.Fatalf("aggregating: %v", err)
	}
	return sum
}

func partialDecryptAggregate(t *testing.T, committee []*lightphe.Cryptosystem, sum *lightphe.EncryptedUpdate,
	prove bool) [][]*lightphe.PartialDecryption {
	t.Helper()
	out := make([][]*lightphe.PartialDecryption, len(committee))
	for i, member := range committee {
		partials, err := member.PartialDecryptAggregate(sum, prove)
		if err != nil {
			t.Fatalf("partial decryption: %v", err)
		}
		out[i] = partials
	}
	return out
}

func assertClose(t *testing.T, what string, got, want []float64, tolerance float64) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("%s has %d values, want %d", what, len(got), len(want))
	}
	for i := range got {
		if math.Abs(got[i]-want[i]) > tolerance {
			t.Fatalf("%s value %d is %v, want %v", what, i, got[i], want[i])
		}
	}
}

func randomUpdates(rng *rand.Rand, clients, length int) ([][]float64, []float64) {
	updates := make([][]float64, clients)
	sum := make([]float64, length)
	for i := range updates {
		updates[i] = make([]float64, length)
		for j := range updates[i] {
			updates[i][j] = rng.Float64()*2 - 1
			sum[j] += updates[i][j]
		}
	}
	return updates, sum
}

func TestThresholdAggregation(t *testing.T) {
	server, committee := buildCommittee(t, 3, 5)
	const length, clients = 120, 6
	updates, expected := randomUpdates(rand.New(rand.NewSource(1)), clients, length)

	first, err := server.EncryptUpdate(updates[0], 1, 50)
	if err != nil {
		t.Fatalf("encrypting: %v", err)
	}
	if len(first.Chunks) >= length || len(first.Chunks) != (length+first.Layout.Slots-1)/first.Layout.Slots {
		t.Fatalf("update of %d values is packed into %d chunks", length, len(first.Chunks))
	}

	sum := mustAggregate(t, server, updates, 1, 50)
	if sum.Count != clients {
		t.Fatalf("sum has %d updates, want %d", sum.Count, clients)
	}

	// any 3 of 5 members decrypt the sum, e.g. if 2 members drop out
	partials := partialDecryptAggregate(t, committee, sum, true)
	mean := make([]float64, length)
	for i, x := range expected {
		mean[i] = x / clients
	}
	for _, subset := range [][][]*lightphe.PartialDecryption{partials[:3], partials[2:]} {
		result, err := server.CombineAggregate(sum, subset, true)
		if err != nil {
			t.Fatalf("combining: %v", err)
		}
		if result.Count != clients {
			t.Fatalf("result has %d updates", result.Count)
		}
		assertClose(t, "sum", result.Sum, expected, clients*aggregationTolerance)
		assertClose(t, "mean", result.Mean, mean, aggregationTolerance)
	}

	// 2 members cannot decrypt the sum
	if _, err := server.CombineAggregate(sum, partials[:2], false); err == nil || !strings.Contains(err.Error(), "at least 3") {
		t.Fatalf("2 members returned %v", err)
	}
}

func TestCheatingCommitteeMemberIsDiscarded(t *testing.T) {
	server, committee := buildCommittee(t, 3, 5)
	updates, expected := randomUpdates(rand.New(rand.NewSource(2)), 3, 10)
	sum := mustAggregate(t, server, updates, 1, 10)
	partials := partialDecryptAggregate(t, committee[:4], sum, true)

	// member 1 shifts its partial decryption of the first chunk to bias the sum
	n := server.PlaintextModulo()
	modulo := server.Scheme().CiphertextModulo()
	value, _ := phe.AsInt(partials[0][0].Value)
	forged := *partials[0][0]
	shifted := new(big.Int).Mul(value, new(big.Int).Add(n, big.NewInt(1)))
	forged.Value = phe.Int{V: shifted.Mod(shifted, modulo)}
	partials[0] = append([]*lightphe.PartialDecryption{&forged}, partials[0][1:]...)

	// without verification, the sum is wrong
	biased, err := server.CombineAggregate(sum, partials[:3], false)
	if err != nil {
		t.Fatalf("combining: %v", err)
	}
	wrong := false
	for i := range expected {
		wrong = wrong || math.Abs(biased.Sum[i]-expected[i]) > 3*aggregationTolerance
	}
	if !wrong {
		t.Fatal("a forged partial decryption did not change the sum")
	}

	// with verification, the forged partial decryption is discarded
	result, err := server.CombineAggregate(sum, partials, true)
	if err != nil {
		t.Fatalf("combining: %v", err)
	}
	assertClose(t, "sum", result.Sum, expected, 3*aggregationTolerance)
}

func TestFederatedAveraging(t *testing.T) {
	// clients train a linear model y = w x + b on their private data, and the
	// committee decrypts only the average of their weights in each round
	server, committee := buildCommittee(t, 2, 3)
	rng := rand.New(rand.NewSource(3))
	const trueW, trueB = 2.0, -1.0
	type client struct{ xs, ys []float64 }
	var clients []client
	for i := 0; i < 4; i++ {
		var c client
		for j := 0; j < 30; j++ {
			x := rng.Float64()*2 - 1
			c.xs = append(c.xs, x)
			c.ys = append(c.ys, trueW*x+trueB+rng.NormFloat64()*0.01)
		}
		clients = append(clients, c)
	}

	weights := []float64{0, 0}
	for round := 0; round < 30; round++ {
		var updates [][]float64
		for _, c := range clients {
			// one local step of gradient descent on mean squared error
			w, b := weights[0], weights[1]
			var gradW, gradB float64
			for j, x := range c.xs {
				residual := w*x + b - c.ys[j]
				gradW += 2 * residual * x / float64(len(c.xs))
				gradB += 2 * residual / float64(len(c.xs))
			}
			updates = append(updates, []float64{w - 0.5*gradW, b - 0.5*gradB})
		}
		sum := mustAggregate(t, server, updates, 10, 4)
		result, err := server.CombineAggregate(sum, partialDecryptAggregate(t, committee[:2], sum, false), false)
		if err != nil {
			t.Fatalf("combining: %v", err)
		}
		weights = result.Mean
	}
	assertClose(t, "weights", weights, []float64{trueW, trueB}, 0.05)
}

func TestSingleKeyOwnerAggregation(t *testing.T) {
	for _, alg := range []phe.Algorithm{phe.Paillier, phe.DamgardJurik} {
		cs := mustBuild(t, alg, lightphe.WithKeySize(256))
		sum := mustAggregate(t, cs, [][]float64{{0.5, -0.25, 1.0}, {-1.0, 0.75, 0.0}}, 1, 2)
		result, err := cs.DecryptAggregate(sum)
		if err != nil {
			t.Fatalf("decrypting: %v", err)
		}
		assertClose(t, "sum", result.Sum, []float64{-0.5, 0.5, 1.0}, 1e-9)
		assertClose(t, "mean", result.Mean, []float64{-0.25, 0.25, 0.5}, 1e-9)
	}
}

func TestAggregationInvalidInputs(t *testing.T) {
	cs := mustBuild(t, phe.Paillier, lightphe.WithKeySize(256))
	for _, tt := range []struct {
		update   []float64
		maxValue float64
		message  string
	}{
		{[]float64{0.5, 1.5}, 1, "exceeds the maximum value"},
		{[]float64{0.5, math.NaN()}, 1, "not a finite number"},
		{nil, 1, "at least one value"},
		// a single slot needs more bits than the plaintext space of a 256-bit
		// key has
		{[]float64{0.5}, 1e80, "too small"},
	} {
		if _, err := cs.EncryptUpdate(tt.update, tt.maxValue, 2); err == nil || !strings.Contains(err.Error(), tt.message) {
			t.Fatalf("encrypting %v returned %v", tt.update, err)
		}
	}

	a, err := cs.EncryptUpdate([]float64{0.5, 0.5}, 1, 2)
	if err != nil {
		t.Fatalf("encrypting: %v", err)
	}
	b, err := cs.EncryptUpdate([]float64{0.5}, 1, 2)
	if err != nil {
		t.Fatalf("encrypting: %v", err)
	}
	if _, err := cs.AggregateUpdates([]*lightphe.EncryptedUpdate{a, b}); err == nil || !strings.Contains(err.Error(), "same layout") {
		t.Fatalf("different layouts returned %v", err)
	}

	// summing more updates than the slots are packed for would overflow
	if _, err := cs.AggregateUpdates([]*lightphe.EncryptedUpdate{a, a, a}); err == nil || !strings.Contains(err.Error(), "overflow") {
		t.Fatalf("too many updates returned %v", err)
	}

	elgamal := mustBuild(t, phe.ExponentialElGamal, lightphe.WithKeySize(testKeySize))
	_, err = elgamal.EncryptUpdate([]float64{0.5}, 1, 2)
	assertUnsupported(t, "secure aggregation", err)
}
