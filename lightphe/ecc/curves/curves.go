// Package curves holds the standard elliptic curve parameter sets that ship
// with the library, grouped by curve form. The tables are ported from the
// LightECC project and are read-only: lookups always hand back a fresh copy so
// callers cannot corrupt the inventory for everyone else.
package curves

import (
	"fmt"
	"math/big"
	"sort"
)

// Form names the shape of the curve equation.
type Form string

// Supported curve forms.
const (
	FormWeierstrass Form = "weierstrass"
	FormEdwards     Form = "edwards"
	FormKoblitz     Form = "koblitz"
)

// Default curves for each form.
const (
	DefaultWeierstrassCurve = "secp256k1"
	DefaultEdwardsCurve     = "ed25519"
	DefaultKoblitzCurve     = "k163"
)

// Forms lists every supported curve form.
func Forms() []Form { return []Form{FormWeierstrass, FormEdwards, FormKoblitz} }

// DefaultCurve returns the curve used when a form is selected without naming a
// specific curve.
func DefaultCurve(form Form) (string, error) {
	switch form {
	case FormWeierstrass:
		return DefaultWeierstrassCurve, nil
	case FormEdwards:
		return DefaultEdwardsCurve, nil
	case FormKoblitz:
		return DefaultKoblitzCurve, nil
	default:
		return "", fmt.Errorf("curves: unsupported curve form %q", form)
	}
}

// Weierstrass carries the parameters of y^2 = x^3 + a*x + b over F_p.
type Weierstrass struct {
	Name   string
	A, B   *big.Int
	P      *big.Int
	Gx, Gy *big.Int
	N      *big.Int
}

// Edwards carries the parameters of a*x^2 + y^2 = 1 + d*x^2*y^2 over F_p.
type Edwards struct {
	Name   string
	A, D   *big.Int
	P      *big.Int
	Gx, Gy *big.Int
	N      *big.Int
}

// Koblitz carries the parameters of y^2 + x*y = x^3 + a*x^2 + b over F_{2^m}.
// Coefficients lists the exponents of the set bits of the reduction polynomial,
// most significant first.
type Koblitz struct {
	Name         string
	M            int
	Coefficients []int
	A, B         *big.Int
	Gx, Gy       *big.Int
	N            *big.Int
}

// entry types for the generated tables. Parameters are stored as decimal
// strings and parsed on lookup, which keeps the generated files diffable.
type weierstrassEntry struct {
	name               string
	a, b, p, gx, gy, n string
}

type edwardsEntry struct {
	name               string
	a, d, p, gx, gy, n string
}

type koblitzEntry struct {
	name            string
	m               int
	coefficients    []int
	a, b, gx, gy, n string
}

func mustInt(s string) *big.Int {
	v, ok := new(big.Int).SetString(s, 10)
	if !ok {
		panic("curves: malformed curve parameter " + s)
	}
	return v
}

// LookupWeierstrass returns the named short Weierstrass curve.
func LookupWeierstrass(name string) (*Weierstrass, error) {
	for i := range weierstrassTable {
		e := &weierstrassTable[i]
		if e.name != name {
			continue
		}
		return &Weierstrass{
			Name: e.name,
			A:    mustInt(e.a),
			B:    mustInt(e.b),
			P:    mustInt(e.p),
			Gx:   mustInt(e.gx),
			Gy:   mustInt(e.gy),
			N:    mustInt(e.n),
		}, nil
	}
	return nil, fmt.Errorf("curves: unsupported weierstrass curve %q", name)
}

// LookupEdwards returns the named twisted Edwards curve.
func LookupEdwards(name string) (*Edwards, error) {
	for i := range edwardsTable {
		e := &edwardsTable[i]
		if e.name != name {
			continue
		}
		return &Edwards{
			Name: e.name,
			A:    mustInt(e.a),
			D:    mustInt(e.d),
			P:    mustInt(e.p),
			Gx:   mustInt(e.gx),
			Gy:   mustInt(e.gy),
			N:    mustInt(e.n),
		}, nil
	}
	return nil, fmt.Errorf("curves: unsupported edwards curve %q", name)
}

// LookupKoblitz returns the named Koblitz curve over a binary field.
func LookupKoblitz(name string) (*Koblitz, error) {
	for i := range koblitzTable {
		e := &koblitzTable[i]
		if e.name != name {
			continue
		}
		coeffs := make([]int, len(e.coefficients))
		copy(coeffs, e.coefficients)
		return &Koblitz{
			Name:         e.name,
			M:            e.m,
			Coefficients: coeffs,
			A:            mustInt(e.a),
			B:            mustInt(e.b),
			Gx:           mustInt(e.gx),
			Gy:           mustInt(e.gy),
			N:            mustInt(e.n),
		}, nil
	}
	return nil, fmt.Errorf("curves: unsupported koblitz curve %q", name)
}

// List returns the sorted names of every curve available for a form.
func List(form Form) ([]string, error) {
	var names []string
	switch form {
	case FormWeierstrass:
		names = make([]string, len(weierstrassTable))
		for i := range weierstrassTable {
			names[i] = weierstrassTable[i].name
		}
	case FormEdwards:
		names = make([]string, len(edwardsTable))
		for i := range edwardsTable {
			names[i] = edwardsTable[i].name
		}
	case FormKoblitz:
		names = make([]string, len(koblitzTable))
		for i := range koblitzTable {
			names[i] = koblitzTable[i].name
		}
	default:
		return nil, fmt.Errorf("curves: unsupported curve form %q", form)
	}
	sort.Strings(names)
	return names, nil
}
