package lightphe

import (
	"math"
	"math/big"
	"math/rand"
	"testing"
)

func TestPackingRoundTrip(t *testing.T) {
	modulo := new(big.Int).Lsh(big.NewInt(1), 1024)
	layout, err := buildLayout(100, 3, 2.5, 7, modulo)
	if err != nil {
		t.Fatalf("building the layout: %v", err)
	}
	if layout.Bound.Int64() != 2500 {
		t.Fatalf("bound is %s, want 2500", layout.Bound)
	}
	if layout.SlotBits != big.NewInt(7*2*2500).BitLen() || layout.Slots != (modulo.BitLen()-1)/layout.SlotBits {
		t.Fatalf("layout is %+v", layout)
	}

	rng := rand.New(rand.NewSource(1))
	updates := make([][]float64, 7)
	for i := range updates {
		updates[i] = make([]float64, 100)
		for j := range updates[i] {
			updates[i][j] = math.Round((rng.Float64()*5-2.5)*1000) / 1000
		}
	}
	copy(updates[0], []float64{2.5, -2.5, 0})

	// sum of packed plaintexts unpacks to the sum of updates, as slots never
	// overflow
	chunks := (layout.Length + layout.Slots - 1) / layout.Slots
	total := make([]*big.Int, chunks)
	for i := range total {
		total[i] = new(big.Int)
	}
	for _, update := range updates {
		plaintexts, err := pack(update, layout)
		if err != nil {
			t.Fatalf("packing: %v", err)
		}
		if len(plaintexts) != chunks {
			t.Fatalf("update is packed into %d chunks, want %d", len(plaintexts), chunks)
		}
		for i, plaintext := range plaintexts {
			if plaintext.Cmp(modulo) >= 0 {
				t.Fatal("packed plaintext exceeds the modulo")
			}
			total[i].Add(total[i], plaintext)
		}
	}
	for i, x := range unpack(total, layout, 7) {
		var want float64
		for _, update := range updates {
			want += update[i]
		}
		if math.Abs(x-want) > 1e-9 {
			t.Fatalf("value %d is %v, want %v", i, x, want)
		}
	}
}

func TestQuantizationOfNaiveBayes(t *testing.T) {
	priors, likelihoods, bitLength, err := quantizeNaiveBayes([]float64{0.25, 0.75},
		[][][]float64{{{0.5, 0.5}}, {{0.1, 0.9}}}, 3)
	if err != nil {
		t.Fatalf("quantizing: %v", err)
	}

	// log probabilities are shifted by their minimum, so the smallest one is 0
	lowest, largest := int64(math.MaxInt64), int64(0)
	for c, prior := range priors {
		score := prior
		lowestLikelihood := int64(math.MaxInt64)
		for _, values := range likelihoods[c] {
			best := int64(0)
			for _, x := range values {
				if x < 0 {
					t.Fatalf("quantized log likelihood %d is negative", x)
				}
				if x > best {
					best = x
				}
				if x < lowestLikelihood {
					lowestLikelihood = x
				}
			}
			score += best
		}
		if prior < lowest {
			lowest = prior
		}
		if score > largest {
			largest = score
		}
	}
	if lowest != 0 {
		t.Fatalf("smallest quantized log prior is %d, want 0", lowest)
	}
	if largest >= int64(1)<<uint(bitLength) {
		t.Fatalf("score %d does not fit into %d bits", largest, bitLength)
	}

	// python's round, ties to even
	if x, _ := roundHalfEven(2.5); x.Int64() != 2 {
		t.Fatalf("2.5 is rounded to %s", x)
	}
	if x, _ := roundHalfEven(-3.5); x.Int64() != -4 {
		t.Fatalf("-3.5 is rounded to %s", x)
	}
}
