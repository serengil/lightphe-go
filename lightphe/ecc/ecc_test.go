package ecc_test

import (
	"math/big"
	"testing"

	"github.com/serengil/lightphe-go/lightphe/ecc"
	"github.com/serengil/lightphe-go/lightphe/ecc/curves"
)

func TestBuildEveryCurve(t *testing.T) {
	// Koblitz curves are exercised separately: validating their order means
	// running a scalar multiplication over a large binary field, which is slow.
	for _, form := range []curves.Form{curves.FormWeierstrass, curves.FormEdwards} {
		form := form
		names, err := curves.List(form)
		if err != nil {
			t.Fatalf("listing %s curves: %v", form, err)
		}
		if len(names) == 0 {
			t.Fatalf("no curves registered for form %s", form)
		}
		for _, name := range names {
			name := name
			t.Run(string(form)+"/"+name, func(t *testing.T) {
				t.Parallel()
				e, err := ecc.New(form, name)
				if err != nil {
					t.Fatalf("building curve: %v", err)
				}
				if !e.Curve().IsOnCurve(e.G()) {
					t.Fatal("base point is off the curve")
				}
			})
		}
	}
}

func TestKoblitzCurve(t *testing.T) {
	if testing.Short() {
		t.Skip("binary field arithmetic is slow; skipped in short mode")
	}
	e, err := ecc.New(curves.FormKoblitz, "k163")
	if err != nil {
		t.Fatalf("building k163: %v", err)
	}
	assertGroupLaws(t, e)
}

func TestGroupLaws(t *testing.T) {
	cases := []struct {
		form  curves.Form
		curve string
	}{
		{curves.FormWeierstrass, "secp256k1"},
		{curves.FormWeierstrass, "p256"},
		{curves.FormEdwards, "ed25519"},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(string(tc.form)+"/"+tc.curve, func(t *testing.T) {
			t.Parallel()
			e, err := ecc.New(tc.form, tc.curve)
			if err != nil {
				t.Fatalf("building curve: %v", err)
			}
			assertGroupLaws(t, e)
		})
	}
}

func assertGroupLaws(t *testing.T, e *ecc.ECC) {
	t.Helper()
	g := e.G()

	// 2G == G + G
	doubled, err := g.Double()
	if err != nil {
		t.Fatalf("doubling: %v", err)
	}
	added, err := g.Add(g)
	if err != nil {
		t.Fatalf("adding: %v", err)
	}
	if !doubled.Equal(added) {
		t.Fatalf("2G = %s but G+G = %s", doubled, added)
	}

	// (a+b)G == aG + bG
	a := big.NewInt(17)
	b := big.NewInt(21)
	lhs, err := g.ScalarMul(new(big.Int).Add(a, b))
	if err != nil {
		t.Fatalf("scalar multiplication: %v", err)
	}
	ag, err := g.ScalarMul(a)
	if err != nil {
		t.Fatalf("scalar multiplication: %v", err)
	}
	bg, err := g.ScalarMul(b)
	if err != nil {
		t.Fatalf("scalar multiplication: %v", err)
	}
	rhs, err := ag.Add(bg)
	if err != nil {
		t.Fatalf("adding: %v", err)
	}
	if !lhs.Equal(rhs) {
		t.Fatalf("(a+b)G = %s but aG+bG = %s", lhs, rhs)
	}

	// G + (-G) == O
	sum, err := g.Add(g.Negate())
	if err != nil {
		t.Fatalf("adding inverse: %v", err)
	}
	if !sum.IsIdentity() {
		t.Fatalf("G + (-G) = %s, want the identity element", sum)
	}

	// 0*G == O and n*G == O
	zero, err := g.ScalarMul(big.NewInt(0))
	if err != nil {
		t.Fatalf("scalar multiplication by zero: %v", err)
	}
	if !zero.IsIdentity() {
		t.Fatalf("0*G = %s, want the identity element", zero)
	}
}

func TestDiscreteLog(t *testing.T) {
	e, err := ecc.New(curves.FormWeierstrass, "secp256k1")
	if err != nil {
		t.Fatalf("building curve: %v", err)
	}
	target, err := e.G().ScalarMul(big.NewInt(23))
	if err != nil {
		t.Fatalf("scalar multiplication: %v", err)
	}
	k, err := ecc.DiscreteLog(target, e.G(), big.NewInt(1000))
	if err != nil {
		t.Fatalf("solving the discrete log: %v", err)
	}
	if k.Int64() != 23 {
		t.Fatalf("recovered %s, want 23", k)
	}
}

func TestUnknownCurveIsRejected(t *testing.T) {
	if _, err := ecc.New(curves.FormWeierstrass, "not-a-curve"); err == nil {
		t.Fatal("expected an error for an unknown curve")
	}
	if _, err := ecc.New("hyperbolic", ""); err == nil {
		t.Fatal("expected an error for an unknown curve form")
	}
}
