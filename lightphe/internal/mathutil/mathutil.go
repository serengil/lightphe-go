// Package mathutil collects the number-theoretic helpers shared by the
// cryptosystems. Every function draws randomness from crypto/rand and works on
// arbitrary precision integers, so the package is safe for concurrent use.
package mathutil

import (
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
)

var (
	// ErrNoSolution is returned when a requested value does not exist, for
	// example a modular square root of a quadratic non-residue.
	ErrNoSolution = errors.New("mathutil: no solution exists")

	// ErrExhausted is returned when a randomized search gave up.
	ErrExhausted = errors.New("mathutil: search exhausted")
)

// Shared read-only constants. Nothing in this package writes to them; every
// computation allocates its own result.
var (
	one   = big.NewInt(1)
	two   = big.NewInt(2)
	three = big.NewInt(3)
	four  = big.NewInt(4)
)

// RandPrime returns a cryptographically random prime of exactly bits length.
func RandPrime(bits int) (*big.Int, error) {
	if bits < 2 {
		return nil, fmt.Errorf("mathutil: prime size %d is too small", bits)
	}
	p, err := rand.Prime(rand.Reader, bits)
	if err != nil {
		return nil, fmt.Errorf("mathutil: generating %d-bit prime: %w", bits, err)
	}
	return p, nil
}

// RandDistinctPrimes returns two distinct random primes of the given bit size.
func RandDistinctPrimes(bits int) (*big.Int, *big.Int, error) {
	p, err := RandPrime(bits)
	if err != nil {
		return nil, nil, err
	}
	for i := 0; i < 1000; i++ {
		q, err := RandPrime(bits)
		if err != nil {
			return nil, nil, err
		}
		if p.Cmp(q) != 0 {
			return p, q, nil
		}
	}
	return nil, nil, fmt.Errorf("mathutil: could not draw two distinct %d-bit primes: %w", bits, ErrExhausted)
}

// RandRangePrime returns a random prime in the inclusive range [lo, hi]. The
// range has to be wide enough to contain at least one prime.
func RandRangePrime(lo, hi *big.Int) (*big.Int, error) {
	for i := 0; i < 10000; i++ {
		candidate, err := RandRange(lo, hi)
		if err != nil {
			return nil, err
		}
		p := NextPrime(new(big.Int).Sub(candidate, one))
		if p.Cmp(hi) <= 0 && p.Cmp(lo) >= 0 {
			return p, nil
		}
	}
	return nil, fmt.Errorf("mathutil: no prime found in [%s, %s]: %w", lo, hi, ErrExhausted)
}

// RandBelow returns a uniform random value in [0, n).
func RandBelow(n *big.Int) (*big.Int, error) {
	if n.Sign() <= 0 {
		return nil, fmt.Errorf("mathutil: upper bound %s must be positive", n)
	}
	v, err := rand.Int(rand.Reader, n)
	if err != nil {
		return nil, fmt.Errorf("mathutil: reading randomness: %w", err)
	}
	return v, nil
}

// RandRange returns a uniform random value in the inclusive range [lo, hi].
func RandRange(lo, hi *big.Int) (*big.Int, error) {
	if lo.Cmp(hi) > 0 {
		return nil, fmt.Errorf("mathutil: empty range [%s, %s]", lo, hi)
	}
	span := new(big.Int).Sub(hi, lo)
	span.Add(span, one)
	v, err := RandBelow(span)
	if err != nil {
		return nil, err
	}
	return v.Add(v, lo), nil
}

// RandBits returns a uniform random value in [0, 2^bits).
func RandBits(bits int) (*big.Int, error) {
	if bits <= 0 {
		return nil, fmt.Errorf("mathutil: bit length %d must be positive", bits)
	}
	limit := new(big.Int).Lsh(one, uint(bits))
	return RandBelow(limit)
}

// RandCoprime returns a uniform random value in [1, n) that is coprime to n.
func RandCoprime(n *big.Int) (*big.Int, error) {
	if n.Cmp(two) < 0 {
		return nil, fmt.Errorf("mathutil: modulus %s must be at least 2", n)
	}
	g := new(big.Int)
	for i := 0; i < 10000; i++ {
		r, err := RandBelow(n)
		if err != nil {
			return nil, err
		}
		if r.Sign() == 0 {
			continue
		}
		if g.GCD(nil, nil, r, n).Cmp(one) == 0 {
			return r, nil
		}
	}
	return nil, fmt.Errorf("mathutil: no unit found modulo %s: %w", n, ErrExhausted)
}

// GCD returns the greatest common divisor of a and b.
func GCD(a, b *big.Int) *big.Int {
	return new(big.Int).GCD(nil, nil, new(big.Int).Abs(a), new(big.Int).Abs(b))
}

// IsCoprime reports whether gcd(a, b) == 1.
func IsCoprime(a, b *big.Int) bool {
	return GCD(a, b).Cmp(one) == 0
}

// ModInverse returns a^-1 mod m, or an error when a is not invertible.
func ModInverse(a, m *big.Int) (*big.Int, error) {
	inv := new(big.Int).ModInverse(new(big.Int).Mod(a, m), m)
	if inv == nil {
		return nil, fmt.Errorf("mathutil: %s is not invertible modulo %s: %w", a, m, ErrNoSolution)
	}
	return inv, nil
}

// IsPrime reports whether n is prime with an error probability below 2^-128.
func IsPrime(n *big.Int) bool {
	if n.Sign() <= 0 {
		return false
	}
	return n.ProbablyPrime(64)
}

// NextPrime returns the smallest prime strictly greater than n.
func NextPrime(n *big.Int) *big.Int {
	c := new(big.Int).Add(n, one)
	if c.Cmp(two) <= 0 {
		return big.NewInt(2)
	}
	if c.Bit(0) == 0 {
		c.Add(c, one)
	}
	for !c.ProbablyPrime(64) {
		c.Add(c, two)
	}
	return c
}

// PrimeFactors returns the distinct prime factors of n in ascending order. It
// uses trial division and is therefore only meant for the small, smooth moduli
// that Benaloh and Naccache-Stern build their plaintext space from.
func PrimeFactors(n *big.Int) ([]*big.Int, error) {
	if n.Sign() <= 0 {
		return nil, fmt.Errorf("mathutil: cannot factor non-positive %s", n)
	}
	remaining := new(big.Int).Set(n)
	factors := make([]*big.Int, 0, 8)

	d := big.NewInt(2)
	sq := new(big.Int)
	for {
		if remaining.Cmp(one) == 0 {
			break
		}
		if remaining.ProbablyPrime(64) {
			factors = append(factors, new(big.Int).Set(remaining))
			break
		}
		if sq.Mul(d, d).Cmp(remaining) > 0 {
			factors = append(factors, new(big.Int).Set(remaining))
			break
		}
		if new(big.Int).Mod(remaining, d).Sign() == 0 {
			factors = append(factors, new(big.Int).Set(d))
			for new(big.Int).Mod(remaining, d).Sign() == 0 {
				remaining.Div(remaining, d)
			}
		}
		if d.Cmp(two) == 0 {
			d.Add(d, one)
		} else {
			d.Add(d, two)
		}
		if d.BitLen() > 40 {
			return nil, fmt.Errorf("mathutil: %s is not smooth enough to factor by trial division: %w", n, ErrExhausted)
		}
	}
	return factors, nil
}

// Jacobi returns the Jacobi symbol (a/n) for odd positive n.
func Jacobi(a, n *big.Int) int {
	return big.Jacobi(new(big.Int).Mod(a, n), n)
}

// CRT solves the system x = residues[i] (mod moduli[i]) and returns x together
// with the combined modulus. The moduli must be pairwise coprime.
func CRT(residues, moduli []*big.Int) (*big.Int, *big.Int, error) {
	if len(residues) != len(moduli) {
		return nil, nil, errors.New("mathutil: residues and moduli must have the same length")
	}
	if len(residues) == 0 {
		return nil, nil, errors.New("mathutil: empty congruence system")
	}

	x := new(big.Int).Mod(residues[0], moduli[0])
	m := new(big.Int).Set(moduli[0])

	for i := 1; i < len(residues); i++ {
		mi := moduli[i]
		if !IsCoprime(m, mi) {
			return nil, nil, fmt.Errorf("mathutil: moduli %s and %s are not coprime: %w", m, mi, ErrNoSolution)
		}
		inv, err := ModInverse(m, mi)
		if err != nil {
			return nil, nil, err
		}
		// x' = x + m * ((residues[i] - x) * m^-1 mod mi)
		diff := new(big.Int).Sub(residues[i], x)
		diff.Mul(diff, inv)
		diff.Mod(diff, mi)
		x.Add(x, new(big.Int).Mul(m, diff))
		m.Mul(m, mi)
		x.Mod(x, m)
	}
	return x, m, nil
}

// SqrtMod returns a square root of a modulo the odd prime p using the
// Tonelli-Shanks algorithm. It reports ErrNoSolution when a is a quadratic
// non-residue.
func SqrtMod(a, p *big.Int) (*big.Int, error) {
	a = new(big.Int).Mod(a, p)
	if a.Sign() == 0 {
		return new(big.Int), nil
	}
	if p.Cmp(two) == 0 {
		return a, nil
	}
	if big.Jacobi(a, p) != 1 {
		return nil, fmt.Errorf("mathutil: %s is not a quadratic residue modulo %s: %w", a, p, ErrNoSolution)
	}

	// p = 3 (mod 4) has the closed form a^((p+1)/4).
	if new(big.Int).Mod(p, four).Cmp(three) == 0 {
		e := new(big.Int).Add(p, one)
		e.Rsh(e, 2)
		return new(big.Int).Exp(a, e, p), nil
	}

	// Write p-1 = q * 2^s with q odd.
	q := new(big.Int).Sub(p, one)
	s := 0
	for q.Bit(0) == 0 {
		q.Rsh(q, 1)
		s++
	}

	// Find a quadratic non-residue z.
	z := big.NewInt(2)
	for big.Jacobi(z, p) != -1 {
		z.Add(z, one)
		if z.Cmp(p) >= 0 {
			return nil, fmt.Errorf("mathutil: no quadratic non-residue modulo %s: %w", p, ErrNoSolution)
		}
	}

	m := s
	c := new(big.Int).Exp(z, q, p)
	t := new(big.Int).Exp(a, q, p)
	e := new(big.Int).Add(q, one)
	e.Rsh(e, 1)
	r := new(big.Int).Exp(a, e, p)

	for t.Cmp(one) != 0 {
		// Find the least i in [1, m) with t^(2^i) == 1.
		i := 0
		t2 := new(big.Int).Set(t)
		for t2.Cmp(one) != 0 {
			t2.Mul(t2, t2)
			t2.Mod(t2, p)
			i++
			if i == m {
				return nil, fmt.Errorf("mathutil: Tonelli-Shanks failed for %s mod %s: %w", a, p, ErrNoSolution)
			}
		}
		b := new(big.Int).Set(c)
		for j := 0; j < m-i-1; j++ {
			b.Mul(b, b)
			b.Mod(b, p)
		}
		m = i
		c.Mul(b, b)
		c.Mod(c, p)
		t.Mul(t, c)
		t.Mod(t, p)
		r.Mul(r, b)
		r.Mod(r, p)
	}
	return r, nil
}
