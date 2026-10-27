package mlkem

import (
	"crypto/rand"
	"math"
	"math/big"
	mrand "math/rand"
	"testing"
)

// negacyclicProduct is the schoolbook multiplication in Z_q[x] / (x^256 + 1).
func negacyclicProduct(p1, p2 []int64) []int64 {
	result := make([]int64, N)
	for i := 0; i < N; i++ {
		for j := 0; j < N; j++ {
			if i+j < N {
				result[i+j] += p1[i] * p2[j]
			} else {
				result[i+j-N] -= p1[i] * p2[j]
			}
		}
	}
	for i, x := range result {
		result[i] = (x%Q + Q) % Q
	}
	return result
}

func centered(x int64) int64 {
	x = (x%Q + Q) % Q
	if x > Q/2 {
		x -= Q
	}
	return x
}

func TestParametersOfFIPS203(t *testing.T) {
	// FIPS 203, table 2
	if Q != 3329 || N != 256 {
		t.Fatal("q and n are not the parameters of FIPS 203")
	}
	want := map[int64]parameterSet{512: {2, 3, 2}, 768: {3, 2, 2}, 1024: {4, 2, 2}}
	for name, params := range want {
		if parameterSets[name] != params {
			t.Fatalf("parameters of ML-KEM-%d are %+v, want %+v", name, parameterSets[name], params)
		}
	}
}

func TestKeysAreWellFormed(t *testing.T) {
	for name, params := range parameterSets {
		cs, err := Generate(int(name))
		if err != nil {
			t.Fatalf("generating keys: %v", err)
		}
		keys := cs.Keys()
		a := expand(keys.PublicKey.Seed, params.k)

		// t = A s + e where s and e are small
		for i := 0; i < params.k; i++ {
			as := make([]int64, N)
			for j := 0; j < params.k; j++ {
				for x, y := range negacyclicProduct(a[i][j], keys.PrivateKey.S[j]) {
					as[x] += y
				}
			}
			for x, y := range as {
				if e := centered(keys.PublicKey.T[i][x] - y); e < -int64(params.eta1) || e > int64(params.eta1) {
					t.Fatalf("coefficient %d of the error is %d, which is not small", x, e)
				}
			}
		}
	}
}

func TestPolynomialMultiplication(t *testing.T) {
	rng := mrand.New(mrand.NewSource(1))
	for i := 0; i < 5; i++ {
		p1, p2 := make([]int64, N), make([]int64, N)
		for j := range p1 {
			p1[j] = rng.Int63n(Q)
			p2[j] = rng.Int63n(7) - 3
		}
		want := negacyclicProduct(p1, p2)
		for j, x := range polyMul(p1, p2) {
			if x != want[j] {
				t.Fatalf("coefficient %d of the product is %d, want %d", j, x, want[j])
			}
		}
	}
}

func TestNoiseMatchesTheEstimate(t *testing.T) {
	for name, params := range parameterSets {
		cs, err := Generate(int(name))
		if err != nil {
			t.Fatalf("generating keys: %v", err)
		}
		// noise e^T r + e2 - s^T e1 has variance k 256 (var1^2 + var1 var2) + var2
		var1, var2 := float64(params.eta1)/2, float64(params.eta2)/2
		sigma := math.Sqrt(float64(params.k*N)*(var1*var1+var1*var2) + var2)

		var samples []int64
		for i := 0; i < 4; i++ {
			m, _ := rand.Int(rand.Reader, cs.PlaintextModulo())
			value, err := cs.Encrypt(m)
			if err != nil {
				t.Fatalf("encrypting: %v", err)
			}
			polys, _ := cs.polys(value)
			su := dot(polys[:params.k], cs.keys.PrivateKey.S)
			for x := 0; x < N; x++ {
				samples = append(samples, centered(polys[params.k][x]-su[x]-int64(m.Bit(x))*halfQ))
			}
		}
		var squares, largest float64
		for _, x := range samples {
			squares += float64(x * x)
			largest = math.Max(largest, math.Abs(float64(x)))
		}
		measured := math.Sqrt(squares / float64(len(samples)))
		if math.Abs(measured-sigma)/sigma > 0.15 {
			t.Fatalf("ML-KEM-%d noise deviation is %.2f, want about %.2f", name, measured, sigma)
		}

		// fresh noise is far below q / 4
		if largest >= Q/4/3 {
			t.Fatalf("ML-KEM-%d fresh noise %v is too large", name, largest)
		}
	}
}

func TestPlaintextModulo(t *testing.T) {
	cs, err := Generate(512)
	if err != nil {
		t.Fatalf("generating keys: %v", err)
	}
	if cs.PlaintextModulo().Cmp(new(big.Int).Lsh(big.NewInt(1), 256)) != 0 {
		t.Fatalf("plaintext modulo is %s, want 2^256", cs.PlaintextModulo())
	}
}
