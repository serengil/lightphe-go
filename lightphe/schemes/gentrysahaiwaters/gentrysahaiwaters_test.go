package gentrysahaiwaters

import (
	"math/big"
	"math/bits"
	"math/rand"
	"testing"

	"github.com/serengil/lightphe-go/lightphe/phe"
)

func centered(x uint64) int64 {
	x &= qMask
	if x > q/2 {
		return int64(x) - int64(q)
	}
	return int64(x)
}

// noiseBits is the bit length of the phase of the decrypted row minus m q / 2.
func noiseBits(t *testing.T, cs *Cryptosystem, value phe.Value, bit uint64) int {
	t.Helper()
	rows, err := cs.rows(value)
	if err != nil {
		t.Fatalf("parsing: %v", err)
	}
	r := rows[ell-1]
	phase := centered(r[0][0] + constantTerm(r[1], cs.keys.PrivateKey.S) - bit*(q/2))
	if phase < 0 {
		phase = -phase
	}
	return bits.Len64(uint64(phase))
}

func TestKeysAreWellFormed(t *testing.T) {
	cs, err := Generate(64)
	if err != nil {
		t.Fatalf("generating keys: %v", err)
	}
	keys := cs.Keys()
	a := expand(keys.PublicKey.Seed, cs.d)
	for _, x := range keys.PrivateKey.S {
		if x < -eta || x > eta {
			t.Fatalf("secret coefficient %d is not small", x)
		}
	}

	// b + a s = e where e is small
	for i, x := range polyMul(a, keys.PrivateKey.S) {
		if e := centered(keys.PublicKey.B[i] + x); e < -eta || e > eta {
			t.Fatalf("coefficient %d of the error is %d, which is not small", i, e)
		}
	}
}

func TestGadgetDecomposition(t *testing.T) {
	// sum of digits times gadget entries restores the polynomial up to rounding
	if offset+logB*(ell-1) != LogQ-1 {
		t.Fatal("the last gadget entry is not q / 2")
	}
	rng := rand.New(rand.NewSource(1))
	poly := []uint64{0, 1, q - 1, q / 2, q/2 - 1}
	for i := 0; i < 64; i++ {
		poly = append(poly, rng.Uint64()&qMask)
	}
	digits := decompose(poly)
	if len(digits) != ell {
		t.Fatalf("decomposition has %d digits, want %d", len(digits), ell)
	}
	for i, x := range poly {
		var restored uint64
		for j := 0; j < ell; j++ {
			if digits[j][i] < -(1<<(logB-1)) || digits[j][i] >= 1<<(logB-1) {
				t.Fatalf("digit %d is out of range", digits[j][i])
			}
			restored += uint64(digits[j][i]) * gadget(j)
		}
		if e := centered(x - restored); e < -(1<<(offset-1)) || e > 1<<(offset-1) {
			t.Fatalf("decomposition of %d is off by %d", x, e)
		}
	}
}

func TestPolynomialMultiplication(t *testing.T) {
	rng := rand.New(rand.NewSource(1))
	for _, d := range []int{8, 64} {
		p := make([]uint64, d)
		small := make([]int64, d)
		for j := range p {
			p[j] = rng.Uint64() & qMask
			small[j] = rng.Int63n(1024) - 512
		}

		// schoolbook multiplication in Z_q[x] / (x^d + 1)
		want := make([]*big.Int, d)
		for i := range want {
			want[i] = new(big.Int)
		}
		for i := 0; i < d; i++ {
			for j := 0; j < d; j++ {
				term := new(big.Int).Mul(new(big.Int).SetUint64(p[i]), big.NewInt(small[j]))
				if i+j < d {
					want[i+j].Add(want[i+j], term)
				} else {
					want[i+j-d].Sub(want[i+j-d], term)
				}
			}
		}
		for i, x := range polyMul(p, small) {
			if w := want[i].Mod(want[i], new(big.Int).SetUint64(q)); w.Uint64() != x {
				t.Fatalf("coefficient %d of the product is %d, want %s", i, x, w)
			}
		}
	}
}

func TestNoiseBudgetOfLargeKeys(t *testing.T) {
	if testing.Short() {
		t.Skip("degree 2048 is slow")
	}
	// products of products of depth 2 stay below q / 4 = 2^48 for the default
	// degree
	cs, err := Generate(DefaultKeySize)
	if err != nil {
		t.Fatalf("generating keys: %v", err)
	}
	encrypt := func() phe.Value {
		v, err := cs.Encrypt(big.NewInt(1))
		if err != nil {
			t.Fatalf("encrypting: %v", err)
		}
		return v
	}
	product := func(x, y phe.Value) phe.Value {
		v, err := cs.And(x, y)
		if err != nil {
			t.Fatalf("and: %v", err)
		}
		return v
	}
	a, b, c, d := encrypt(), encrypt(), encrypt(), encrypt()
	if n := noiseBits(t, cs, a, 1); n > 16 {
		t.Fatalf("fresh noise has %d bits", n)
	}
	ab, cd := product(a, b), product(c, d)
	if n := noiseBits(t, cs, ab, 1); n > 32 {
		t.Fatalf("noise of a product has %d bits", n)
	}
	if n := noiseBits(t, cs, product(ab, cd), 1); n > 46 {
		t.Fatalf("noise of a product of products has %d bits", n)
	}
}
