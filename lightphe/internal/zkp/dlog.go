package zkp

import (
	"math/big"

	"github.com/serengil/lightphe-go/lightphe/internal/mathutil"
	"github.com/serengil/lightphe-go/lightphe/phe"
)

// Proofs about discrete logarithms in groups of a known prime order.

// ProveDLEQ is the Chaum-Pedersen proof that log_g1(h1) = log_g2(h2) = x
// without revealing x. Context is extra public data bound to the proof.
func ProveDLEQ(group Group, g1, h1, g2, h2 Element, x *big.Int, domain string, context interface{}) (*phe.ZKProof, error) {
	q := group.Order()
	w, err := randomExponent(q)
	if err != nil {
		return nil, err
	}
	a1, err := group.Exp(g1, w)
	if err != nil {
		return nil, err
	}
	a2, err := group.Exp(g2, w)
	if err != nil {
		return nil, err
	}
	e := Challenge(domain, q, append([]interface{}{context}, encodeAll(group, g1, h1, g2, h2, a1, a2)...)...)
	z := new(big.Int).Mul(e, x)
	z.Add(z, w).Mod(z, q)
	return &phe.ZKProof{Challenge: e, Response: z}, nil
}

// VerifyDLEQ verifies a Chaum-Pedersen proof that log_g1(h1) = log_g2(h2).
func VerifyDLEQ(group Group, g1, h1, g2, h2 Element, proof *phe.ZKProof, domain string, context interface{}) bool {
	if proof == nil {
		return false
	}
	q := group.Order()
	e, z := proof.Challenge, proof.Response
	if !inRange(e, q) || !inRange(z, q) {
		return false
	}

	// soundness requires all elements to be in the group of prime order
	for _, element := range []Element{g1, h1, g2, h2} {
		if !group.IsMember(element) {
			return false
		}
	}

	a1, err := commitment(group, g1, h1, z, e)
	if err != nil {
		return false
	}
	a2, err := commitment(group, g2, h2, z, e)
	if err != nil {
		return false
	}
	expected := Challenge(domain, q, append([]interface{}{context}, encodeAll(group, g1, h1, g2, h2, a1, a2)...)...)
	return e.Cmp(expected) == 0
}

// ProveDLEQOr is the disjunctive Chaum-Pedersen proof that log_g1(h1) =
// log_g2(h2) for at least one h2 in h2s, without revealing which one.
// h2s[index] = g2^x, and proofs of other items are simulated.
func ProveDLEQOr(group Group, g1, h1, g2 Element, h2s []Element, x *big.Int, index int, domain string,
	context interface{}) (*phe.ZKProof, error) {
	q := group.Order()
	challenges := make([]*big.Int, len(h2s))
	responses := make([]*big.Int, len(h2s))
	commitments := make([]Element, 0, 2*len(h2s))
	w, err := randomExponent(q)
	if err != nil {
		return nil, err
	}
	for i, h2 := range h2s {
		if i == index {
			challenges[i], responses[i] = new(big.Int), new(big.Int)
			a1, err := group.Exp(g1, w)
			if err != nil {
				return nil, err
			}
			a2, err := group.Exp(g2, w)
			if err != nil {
				return nil, err
			}
			commitments = append(commitments, a1, a2)
			continue
		}
		// simulated proof for a false statement
		if challenges[i], err = mathutil.RandBelow(q); err != nil {
			return nil, err
		}
		if responses[i], err = mathutil.RandBelow(q); err != nil {
			return nil, err
		}
		a1, err := commitment(group, g1, h1, responses[i], challenges[i])
		if err != nil {
			return nil, err
		}
		a2, err := commitment(group, g2, h2, responses[i], challenges[i])
		if err != nil {
			return nil, err
		}
		commitments = append(commitments, a1, a2)
	}

	e := Challenge(domain, q, disjunctionItems(group, context, g1, h1, g2, h2s, commitments)...)

	// challenge of the true statement completes the sum
	sum := new(big.Int)
	for _, c := range challenges {
		sum.Add(sum, c)
	}
	challenges[index] = new(big.Int).Sub(e, sum)
	challenges[index].Mod(challenges[index], q)
	z := new(big.Int).Mul(challenges[index], x)
	responses[index] = z.Add(z, w).Mod(z, q)
	return &phe.ZKProof{Challenges: challenges, Responses: responses}, nil
}

// VerifyDLEQOr verifies a disjunctive Chaum-Pedersen proof.
func VerifyDLEQOr(group Group, g1, h1, g2 Element, h2s []Element, proof *phe.ZKProof, domain string,
	context interface{}) bool {
	if proof == nil || len(proof.Challenges) != len(h2s) || len(proof.Responses) != len(h2s) {
		return false
	}
	q := group.Order()
	for i := range h2s {
		if !inRange(proof.Challenges[i], q) || !inRange(proof.Responses[i], q) {
			return false
		}
	}

	// soundness requires all elements to be in the group of prime order
	for _, element := range append([]Element{g1, h1, g2}, h2s...) {
		if !group.IsMember(element) {
			return false
		}
	}

	commitments := make([]Element, 0, 2*len(h2s))
	sum := new(big.Int)
	for i, h2 := range h2s {
		a1, err := commitment(group, g1, h1, proof.Responses[i], proof.Challenges[i])
		if err != nil {
			return false
		}
		a2, err := commitment(group, g2, h2, proof.Responses[i], proof.Challenges[i])
		if err != nil {
			return false
		}
		commitments = append(commitments, a1, a2)
		sum.Add(sum, proof.Challenges[i])
	}

	e := Challenge(domain, q, disjunctionItems(group, context, g1, h1, g2, h2s, commitments)...)
	return sum.Mod(sum, q).Cmp(e) == 0
}

func disjunctionItems(group Group, context interface{}, g1, h1, g2 Element, h2s, commitments []Element) []interface{} {
	elements := append([]Element{g1, h1, g2}, h2s...)
	elements = append(elements, commitments...)
	return append([]interface{}{context}, encodeAll(group, elements...)...)
}

// ProveDLog is the Schnorr proof of knowledge of x = log_g(h) without
// revealing x.
func ProveDLog(group Group, g, h Element, x *big.Int, domain string, context interface{}) (*phe.ZKProof, error) {
	q := group.Order()
	w, err := randomExponent(q)
	if err != nil {
		return nil, err
	}
	a, err := group.Exp(g, w)
	if err != nil {
		return nil, err
	}
	e := Challenge(domain, q, append([]interface{}{context}, encodeAll(group, g, h, a)...)...)
	z := new(big.Int).Mul(e, x)
	z.Add(z, w).Mod(z, q)
	return &phe.ZKProof{Challenge: e, Response: z}, nil
}

// VerifyDLog verifies a Schnorr proof of knowledge of log_g(h).
func VerifyDLog(group Group, g, h Element, proof *phe.ZKProof, domain string, context interface{}) bool {
	if proof == nil {
		return false
	}
	q := group.Order()
	e, z := proof.Challenge, proof.Response
	if !inRange(e, q) || !inRange(z, q) {
		return false
	}
	if !group.IsMember(g) || !group.IsMember(h) {
		return false
	}
	a, err := commitment(group, g, h, z, e)
	if err != nil {
		return false
	}
	expected := Challenge(domain, q, append([]interface{}{context}, encodeAll(group, g, h, a)...)...)
	return e.Cmp(expected) == 0
}
