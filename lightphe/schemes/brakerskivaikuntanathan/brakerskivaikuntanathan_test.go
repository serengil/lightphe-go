package brakerskivaikuntanathan

import (
	"math/big"
	"testing"

	"github.com/serengil/lightphe-go/lightphe/internal/mathutil"
)

// negacyclicProduct is the schoolbook product in Z_q[x] / (x^d + 1).
func negacyclicProduct(p1, p2 []*big.Int) []*big.Int {
	d := len(p1)
	result := make([]*big.Int, d)
	for i := range result {
		result[i] = new(big.Int)
	}
	for i := 0; i < d; i++ {
		for j := 0; j < d; j++ {
			term := new(big.Int).Mul(p1[i], p2[j])
			if i+j < d {
				result[i+j].Add(result[i+j], term)
			} else {
				result[i+j-d].Sub(result[i+j-d], term)
			}
		}
	}
	for _, x := range result {
		x.Mod(x, Q)
	}
	return result
}

func TestPolynomialMultiplication(t *testing.T) {
	for _, d := range []int{8, 64} {
		for i := 0; i < 10; i++ {
			p1, p2 := make([]*big.Int, d), make([]*big.Int, d)
			for j := 0; j < d; j++ {
				p1[j], _ = mathutil.RandBelow(Q)
				p2[j], _ = mathutil.RandBelow(Q)
			}
			got, want := polyMul(p1, p2, d), negacyclicProduct(p1, p2)
			for j := range got {
				if got[j].Cmp(want[j]) != 0 {
					t.Fatalf("degree %d: coefficient %d is %s, want %s", d, j, got[j], want[j])
				}
			}
		}
	}
}

func TestKeysAreWellFormed(t *testing.T) {
	cs, err := Generate(64, nil)
	if err != nil {
		t.Fatalf("generating keys: %v", err)
	}
	keys := cs.Keys()
	d, tt := len(keys.PublicKey.B), keys.PublicKey.T
	a := expand(keys.PublicKey.Seed, d)
	aS := negacyclicProduct(a, toModQ(keys.PrivateKey.S))

	// b = -(a s + t e) where e is small
	half := new(big.Int).Rsh(Q, 1)
	for i, b := range keys.PublicKey.B {
		te := new(big.Int).Add(aS[i], b)
		te.Neg(te).Mod(te, Q)
		if te.Cmp(half) > 0 {
			te.Sub(te, Q)
		}
		e, rem := new(big.Int).QuoRem(te, tt, new(big.Int))
		if rem.Sign() != 0 || e.CmpAbs(big.NewInt(eta)) > 0 {
			t.Fatalf("coefficient %d of the error is not small", i)
		}
	}
}
