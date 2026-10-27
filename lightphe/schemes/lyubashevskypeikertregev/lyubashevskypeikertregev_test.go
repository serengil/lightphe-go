package lyubashevskypeikertregev

import (
	"math/big"
	"math/rand"
	"testing"
)

// negacyclicProduct is the schoolbook multiplication in Z_q[x] / (x^d + 1).
func negacyclicProduct(p1 []uint64, p2 []int64) []int64 {
	d := len(p1)
	q := int64(1) << LogQ
	out := make([]*big.Int, d)
	for i := range out {
		out[i] = new(big.Int)
	}
	for i := 0; i < d; i++ {
		for j := 0; j < d; j++ {
			term := new(big.Int).Mul(new(big.Int).SetUint64(p1[i]), big.NewInt(p2[j]))
			if i+j < d {
				out[i+j].Add(out[i+j], term)
			} else {
				out[i+j-d].Sub(out[i+j-d], term)
			}
		}
	}
	result := make([]int64, d)
	for i, x := range out {
		result[i] = x.Mod(x, big.NewInt(q)).Int64()
	}
	return result
}

func centered(x int64) int64 {
	q := int64(1) << LogQ
	x = ((x % q) + q) % q
	if x > q/2 {
		x -= q
	}
	return x
}

func TestKeysAreWellFormed(t *testing.T) {
	cs, err := Generate(64, nil)
	if err != nil {
		t.Fatalf("generating keys: %v", err)
	}
	keys := cs.Keys()
	d := int(keys.PublicKey.D.Int64())
	a := expand(keys.PublicKey.Seed, d)
	s := keys.PrivateKey.S
	for _, x := range s {
		if x < -eta || x > eta {
			t.Fatalf("secret coefficient %d is not small", x)
		}
	}

	// b = a s + e where e is small
	for i, x := range negacyclicProduct(a, s) {
		if e := centered(int64(keys.PublicKey.B[i]) - x); e < -eta || e > eta {
			t.Fatalf("coefficient %d of the error is %d, which is not small", i, e)
		}
	}
}

func TestCiphertextsAreWellFormed(t *testing.T) {
	cs, err := Generate(64, nil)
	if err != nil {
		t.Fatalf("generating keys: %v", err)
	}
	keys := cs.Keys()
	d := cs.d
	a := expand(keys.PublicKey.Seed, d)
	u, err := sampleSmall(d)
	if err != nil {
		t.Fatalf("sampling: %v", err)
	}
	const m = 12345
	value, err := cs.EncryptWith(big.NewInt(m), u)
	if err != nil {
		t.Fatalf("encrypting: %v", err)
	}
	entries, err := cs.entries(value)
	if err != nil {
		t.Fatalf("parsing: %v", err)
	}

	// c1 = a u + e1 and c2 = constant term of b u + e2 + m q / t, where u, e1
	// and e2 are small
	for i, x := range negacyclicProduct(a, u) {
		if e := centered(int64(entries[i]) - x); e < -eta || e > eta {
			t.Fatalf("coefficient %d of e1 is %d", i, e)
		}
	}
	bu := negacyclicProduct(keys.PublicKey.B, u)
	delta := int64(1) << LogQ / int64(cs.t)
	if e := centered(int64(entries[d]) - bu[0] - m*delta); e < -eta || e > eta {
		t.Fatalf("e2 is %d", e)
	}
}

func TestPolynomialMultiplication(t *testing.T) {
	rng := rand.New(rand.NewSource(1))
	for _, d := range []int{8, 64} {
		for i := 0; i < 10; i++ {
			p := make([]uint64, d)
			small := make([]int64, d)
			for j := range p {
				p[j] = rng.Uint64() & qMask
				small[j] = rng.Int63n(2*eta+1) - eta
			}
			want := negacyclicProduct(p, small)
			for j, x := range polyMul(p, small) {
				if int64(x) != want[j] {
					t.Fatalf("coefficient %d of the product is %d, want %d", j, x, want[j])
				}
			}
		}
	}
}
