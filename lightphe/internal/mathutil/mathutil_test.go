package mathutil

import (
	"math/big"
	"testing"
)

func TestRandPrimeHasTheRequestedSize(t *testing.T) {
	for _, bits := range []int{8, 16, 64, 256} {
		p, err := RandPrime(bits)
		if err != nil {
			t.Fatalf("generating a %d-bit prime: %v", bits, err)
		}
		if p.BitLen() != bits {
			t.Fatalf("generated a %d-bit prime, want %d bits", p.BitLen(), bits)
		}
		if !IsPrime(p) {
			t.Fatalf("%s is not prime", p)
		}
	}
}

func TestRandPrimeRejectsTinySizes(t *testing.T) {
	if _, err := RandPrime(1); err == nil {
		t.Fatal("expected an error for a 1-bit prime")
	}
}

func TestRandDistinctPrimes(t *testing.T) {
	p, q, err := RandDistinctPrimes(32)
	if err != nil {
		t.Fatalf("generating primes: %v", err)
	}
	if p.Cmp(q) == 0 {
		t.Fatal("the two primes are identical")
	}
}

func TestRandRangeStaysInBounds(t *testing.T) {
	lo, hi := big.NewInt(100), big.NewInt(110)
	for i := 0; i < 200; i++ {
		v, err := RandRange(lo, hi)
		if err != nil {
			t.Fatalf("drawing a value: %v", err)
		}
		if v.Cmp(lo) < 0 || v.Cmp(hi) > 0 {
			t.Fatalf("drew %s outside [%s, %s]", v, lo, hi)
		}
	}
	if _, err := RandRange(hi, lo); err == nil {
		t.Fatal("expected an error for an inverted range")
	}
}

func TestRandCoprime(t *testing.T) {
	n := big.NewInt(3 * 5 * 7)
	for i := 0; i < 50; i++ {
		r, err := RandCoprime(n)
		if err != nil {
			t.Fatalf("drawing a unit: %v", err)
		}
		if !IsCoprime(r, n) {
			t.Fatalf("%s is not coprime to %s", r, n)
		}
	}
}

func TestNextPrime(t *testing.T) {
	cases := map[int64]int64{0: 2, 1: 2, 2: 3, 7: 11, 100: 101, 1000: 1009}
	for input, want := range cases {
		if got := NextPrime(big.NewInt(input)); got.Int64() != want {
			t.Fatalf("NextPrime(%d) = %s, want %d", input, got, want)
		}
	}
}

func TestPrimeFactors(t *testing.T) {
	cases := map[int64][]int64{
		2:      {2},
		12:     {2, 3},
		255255: {3, 5, 7, 11, 13, 17},
	}
	for input, want := range cases {
		got, err := PrimeFactors(big.NewInt(input))
		if err != nil {
			t.Fatalf("factoring %d: %v", input, err)
		}
		if len(got) != len(want) {
			t.Fatalf("factoring %d gave %v, want %v", input, got, want)
		}
		for i, w := range want {
			if got[i].Int64() != w {
				t.Fatalf("factoring %d gave %v, want %v", input, got, want)
			}
		}
	}
	if _, err := PrimeFactors(big.NewInt(0)); err == nil {
		t.Fatal("expected an error when factoring zero")
	}
}

func TestCRT(t *testing.T) {
	// x = 2 (mod 3), x = 3 (mod 5), x = 2 (mod 7) has the solution 23 mod 105.
	residues := []*big.Int{big.NewInt(2), big.NewInt(3), big.NewInt(2)}
	moduli := []*big.Int{big.NewInt(3), big.NewInt(5), big.NewInt(7)}

	x, m, err := CRT(residues, moduli)
	if err != nil {
		t.Fatalf("solving the congruence system: %v", err)
	}
	if x.Int64() != 23 || m.Int64() != 105 {
		t.Fatalf("got x = %s mod %s, want 23 mod 105", x, m)
	}

	if _, _, err := CRT(residues, moduli[:2]); err == nil {
		t.Fatal("expected an error for mismatched input lengths")
	}
	if _, _, err := CRT([]*big.Int{big.NewInt(1), big.NewInt(1)},
		[]*big.Int{big.NewInt(4), big.NewInt(6)}); err == nil {
		t.Fatal("expected an error for moduli that are not coprime")
	}
}

func TestSqrtMod(t *testing.T) {
	// 23 = 3 (mod 4) exercises the closed form; 17 = 1 (mod 4) exercises
	// Tonelli-Shanks.
	for _, p := range []int64{23, 17, 1009} {
		prime := big.NewInt(p)
		for a := int64(1); a < p && a < 40; a++ {
			value := big.NewInt(a)
			root, err := SqrtMod(value, prime)
			if err != nil {
				continue // a is a non-residue, which SqrtMod is allowed to reject
			}
			square := new(big.Int).Mul(root, root)
			square.Mod(square, prime)
			if square.Cmp(value) != 0 {
				t.Fatalf("sqrt(%d) mod %d = %s, but its square is %s", a, p, root, square)
			}
		}
	}
}

func TestSqrtModRejectsNonResidues(t *testing.T) {
	// 5 is a quadratic non-residue modulo 23.
	if _, err := SqrtMod(big.NewInt(5), big.NewInt(23)); err == nil {
		t.Fatal("expected an error for a quadratic non-residue")
	}
}

func TestModInverse(t *testing.T) {
	inv, err := ModInverse(big.NewInt(3), big.NewInt(11))
	if err != nil {
		t.Fatalf("inverting: %v", err)
	}
	if inv.Int64() != 4 {
		t.Fatalf("3^-1 mod 11 = %s, want 4", inv)
	}
	if _, err := ModInverse(big.NewInt(4), big.NewInt(8)); err == nil {
		t.Fatal("expected an error for a non-invertible value")
	}
}

func TestJacobi(t *testing.T) {
	// 2 is a quadratic residue modulo 7 and a non-residue modulo 5.
	if got := Jacobi(big.NewInt(2), big.NewInt(7)); got != 1 {
		t.Fatalf("Jacobi(2, 7) = %d, want 1", got)
	}
	if got := Jacobi(big.NewInt(2), big.NewInt(5)); got != -1 {
		t.Fatalf("Jacobi(2, 5) = %d, want -1", got)
	}
}
