package ecc

import "math/big"

// Carry-less arithmetic in GF(2^m). Field elements are bit strings packed into
// a big.Int: bit i of the integer is the coefficient of x^i. Addition is XOR,
// so there are no carries anywhere in this file.

// binAdd returns a + b, which in GF(2) is a XOR b.
func binAdd(a, b *big.Int) *big.Int { return new(big.Int).Xor(a, b) }

// binMul returns the carry-less product of a and b.
func binMul(a, b *big.Int) *big.Int {
	result := new(big.Int)
	shifted := new(big.Int).Set(a)
	for i := 0; i < b.BitLen(); i++ {
		if b.Bit(i) == 1 {
			result.Xor(result, shifted)
		}
		shifted = new(big.Int).Lsh(shifted, 1)
	}
	return result
}

// binSquare returns a*a, which spreads the bits of a to even positions.
func binSquare(a *big.Int) *big.Int {
	result := new(big.Int)
	for i := 0; i < a.BitLen(); i++ {
		if a.Bit(i) == 1 {
			result.SetBit(result, 2*i, 1)
		}
	}
	return result
}

// binMod reduces a modulo the polynomial m.
func binMod(a, m *big.Int) *big.Int {
	degM := m.BitLen() - 1
	if degM <= 0 {
		return new(big.Int).Set(a)
	}
	r := new(big.Int).Set(a)
	for degR := r.BitLen() - 1; degR >= degM; degR = r.BitLen() - 1 {
		r.Xor(r, new(big.Int).Lsh(m, uint(degR-degM)))
	}
	return r
}

// binQuo returns the quotient of the polynomial division a / m.
func binQuo(a, m *big.Int) *big.Int {
	degM := m.BitLen() - 1
	q := new(big.Int)
	r := new(big.Int).Set(a)
	for degR := r.BitLen() - 1; degR >= degM && r.Sign() != 0; degR = r.BitLen() - 1 {
		shift := uint(degR - degM)
		q.SetBit(q, int(shift), 1)
		r.Xor(r, new(big.Int).Lsh(m, shift))
	}
	return q
}

// binInverse returns a^-1 mod m using the extended Euclidean algorithm over
// GF(2). It returns nil when a is not invertible.
func binInverse(a, m *big.Int) *big.Int {
	x := new(big.Int).Set(a)
	y := new(big.Int).Set(m)
	p1 := big.NewInt(1)
	p2 := new(big.Int)

	one := big.NewInt(1)
	for y.Cmp(one) != 0 {
		if y.Sign() == 0 {
			return nil
		}
		q := binQuo(x, y)
		r := binMod(x, y)
		x, y = y, r
		pa := new(big.Int).Xor(p1, binMul(q, p2))
		p1, p2 = p2, pa
	}
	return p2
}

// binDivide returns a * b^-1 mod m.
func binDivide(a, b, m *big.Int) *big.Int {
	inv := binInverse(b, m)
	if inv == nil {
		return nil
	}
	return binMod(binMul(a, inv), m)
}

// binExp returns a^e mod m for a small non-negative exponent e.
func binExp(a *big.Int, e int, m *big.Int) *big.Int {
	result := big.NewInt(1)
	base := binMod(a, m)
	for e > 0 {
		if e&1 == 1 {
			result = binMod(binMul(base, result), m)
		}
		base = binMod(binSquare(base), m)
		e >>= 1
	}
	return result
}
