package zkp

import (
	"fmt"
	"math/big"

	"github.com/serengil/lightphe-go/lightphe/internal/mathutil"
	"github.com/serengil/lightphe-go/lightphe/phe"
)

// Proofs about Paillier and Damgard-Jurik ciphertexts, whose groups have a
// secret order.

// ChallengeBits is the challenge length of proofs in groups of unknown order.
const ChallengeBits = 128

// StatisticalBits is the statistical hiding of responses in groups of unknown
// order.
const StatisticalBits = 80

var one = big.NewInt(1)

// ProvePaillierDecryption proves the decryption of a Paillier or
// Damgard-Jurik ciphertext. A ciphertext is g^m r^n, and this is one to one
// for m in Z_n and r in Z*_n, so revealing r proves m without a
// zero-knowledge proof. Only the private key owner can recover r, and it
// reveals nothing about other ciphertexts.
func ProvePaillierDecryption(ciphertext, plaintext, n, phi *big.Int) (*phe.ZKProof, error) {
	if !mathutil.IsCoprime(n, phi) {
		return nil, fmt.Errorf("zkp: randomness cannot be recovered because gcd(n, phi) != 1")
	}
	n2 := new(big.Int).Mul(n, n)
	g := new(big.Int).Add(n, one)

	// c g^-m = r^n mod n^2, and r^n mod n is enough to find r mod n
	gm := new(big.Int).Exp(g, plaintext, n2)
	gmInverse, err := mathutil.ModInverse(gm, n2)
	if err != nil {
		return nil, err
	}
	rn := new(big.Int).Mul(ciphertext, gmInverse)
	rn.Mod(rn, n2).Mod(rn, n)
	exponent, err := mathutil.ModInverse(n, phi)
	if err != nil {
		return nil, err
	}
	return &phe.ZKProof{Randomness: new(big.Int).Exp(rn, exponent, n)}, nil
}

// VerifyPaillierDecryption verifies a proof of decryption of a Paillier or
// Damgard-Jurik ciphertext.
func VerifyPaillierDecryption(ciphertext, plaintext *big.Int, proof *phe.ZKProof, n *big.Int) bool {
	if proof == nil || plaintext == nil || ciphertext == nil {
		return false
	}
	r := proof.Randomness
	if r == nil || r.Sign() <= 0 || r.Cmp(n) >= 0 || !mathutil.IsCoprime(r, n) || !mathutil.IsCoprime(ciphertext, n) {
		return false
	}
	if !inRange(plaintext, n) {
		return false
	}
	n2 := new(big.Int).Mul(n, n)
	expected := new(big.Int).Exp(new(big.Int).Add(n, one), plaintext, n2)
	expected.Mul(expected, new(big.Int).Exp(r, n, n2)).Mod(expected, n2)
	return new(big.Int).Mod(ciphertext, n2).Cmp(expected) == 0
}

// NthPowerChallengeBits is the challenge length of proofs of n-th powers.
// Challenges must be smaller than the smallest prime factor of n for
// soundness.
func NthPowerChallengeBits(n *big.Int) int {
	bits := n.BitLen()/2 - 2
	if bits > ChallengeBits {
		bits = ChallengeBits
	}
	if bits < 1 {
		bits = 1
	}
	return bits
}

func nthPowerBound(n *big.Int) *big.Int {
	return new(big.Int).Lsh(one, uint(NthPowerChallengeBits(n)))
}

// RandomUnit returns a random element of the multiplicative group of modulo,
// a power of n.
func RandomUnit(n, modulo *big.Int) (*big.Int, error) {
	for i := 0; i < 10000; i++ {
		r, err := mathutil.RandRange(one, new(big.Int).Sub(modulo, one))
		if err != nil {
			return nil, err
		}
		if mathutil.IsCoprime(r, n) {
			return r, nil
		}
	}
	return nil, fmt.Errorf("zkp: no unit found modulo %s", modulo)
}

// isUnit reports whether 0 < x < modulo and gcd(x, n) = 1.
func isUnit(x, n, modulo *big.Int) bool {
	return x != nil && x.Sign() > 0 && x.Cmp(modulo) < 0 && mathutil.IsCoprime(x, n)
}

// powSigned returns base^k mod modulo for a possibly negative k.
func powSigned(base, k, modulo *big.Int) (*big.Int, error) {
	if k.Sign() >= 0 {
		return new(big.Int).Exp(base, k, modulo), nil
	}
	inverse, err := mathutil.ModInverse(base, modulo)
	if err != nil {
		return nil, err
	}
	return new(big.Int).Exp(inverse, new(big.Int).Neg(k), modulo), nil
}

// ProveNthPowerOr proves that at least one of us is an n-th power in modulo
// n^(s+1), without revealing which. This is the 1-out-of-k proof of Damgard
// and Jurik, showing that a ciphertext c encrypts one of k values v, where us
// are c g^-v. us[index] = r^n.
func ProveNthPowerOr(n, modulo *big.Int, us []*big.Int, r *big.Int, index int, domain string,
	context interface{}) (*phe.ZKProof, error) {
	bound := nthPowerBound(n)
	challenges := make([]*big.Int, len(us))
	responses := make([]*big.Int, len(us))
	commitments := make([]*big.Int, len(us))
	rho, err := RandomUnit(n, modulo)
	if err != nil {
		return nil, err
	}
	for i, u := range us {
		if i == index {
			challenges[i], responses[i] = new(big.Int), new(big.Int)
			commitments[i] = new(big.Int).Exp(rho, n, modulo)
			continue
		}
		// simulated proof for a false statement
		if challenges[i], err = mathutil.RandBelow(bound); err != nil {
			return nil, err
		}
		if responses[i], err = RandomUnit(n, modulo); err != nil {
			return nil, err
		}
		if commitments[i], err = nthPowerCommitment(n, modulo, u, challenges[i], responses[i]); err != nil {
			return nil, err
		}
	}

	e := Challenge(domain, bound, context, n, modulo, us, commitments)

	// challenge of the true statement completes the sum
	sum := new(big.Int)
	for _, c := range challenges {
		sum.Add(sum, c)
	}
	challenges[index] = sum.Sub(e, sum).Mod(sum, bound)
	z := new(big.Int).Exp(r, challenges[index], modulo)
	responses[index] = z.Mul(z, rho).Mod(z, modulo)
	return &phe.ZKProof{Challenges: challenges, Responses: responses}, nil
}

// VerifyNthPowerOr verifies a proof that at least one of us is an n-th power
// in modulo.
func VerifyNthPowerOr(n, modulo *big.Int, us []*big.Int, proof *phe.ZKProof, domain string, context interface{}) bool {
	if proof == nil || len(proof.Challenges) != len(us) || len(proof.Responses) != len(us) {
		return false
	}
	bound := nthPowerBound(n)
	for _, e := range proof.Challenges {
		if !inRange(e, bound) {
			return false
		}
	}
	for _, x := range append(append([]*big.Int{}, proof.Responses...), us...) {
		if !isUnit(x, n, modulo) {
			return false
		}
	}

	commitments := make([]*big.Int, len(us))
	sum := new(big.Int)
	for i, u := range us {
		var err error
		if commitments[i], err = nthPowerCommitment(n, modulo, u, proof.Challenges[i], proof.Responses[i]); err != nil {
			return false
		}
		sum.Add(sum, proof.Challenges[i])
	}
	e := Challenge(domain, bound, context, n, modulo, us, commitments)
	return sum.Mod(sum, bound).Cmp(e) == 0
}

// nthPowerCommitment returns z^n u^-e, the commitment of an honest prover.
func nthPowerCommitment(n, modulo, u, e, z *big.Int) (*big.Int, error) {
	ue, err := powSigned(u, new(big.Int).Neg(e), modulo)
	if err != nil {
		return nil, err
	}
	out := new(big.Int).Exp(z, n, modulo)
	return out.Mul(out, ue).Mod(out, modulo), nil
}

// PaillierMembershipCandidates returns c g^-v for each value v. A ciphertext
// encrypts v if and only if its candidate is an n-th power, i.e. an
// encryption of 0.
func PaillierMembershipCandidates(ciphertext *big.Int, values []*big.Int, n, modulo *big.Int) ([]*big.Int, error) {
	g := new(big.Int).Add(n, one)
	out := make([]*big.Int, len(values))
	for i, v := range values {
		gv, err := powSigned(g, new(big.Int).Neg(v), modulo)
		if err != nil {
			return nil, err
		}
		out[i] = gv.Mul(gv, ciphertext).Mod(gv, modulo)
	}
	return out, nil
}

// ProvePaillierKnowledge proves knowledge of the plaintext m and the
// randomness r of a Paillier or Damgard-Jurik ciphertext c = g^m r^n mod
// n^(s+1) without revealing them.
func ProvePaillierKnowledge(ciphertext, plaintext, r, n, modulo *big.Int, domain string,
	context interface{}) (*phe.ZKProof, error) {
	g := new(big.Int).Add(n, one)
	bound := nthPowerBound(n)
	a, err := mathutil.RandBelow(n)
	if err != nil {
		return nil, err
	}
	b, err := RandomUnit(n, modulo)
	if err != nil {
		return nil, err
	}
	t := new(big.Int).Exp(g, a, modulo)
	t.Mul(t, new(big.Int).Exp(b, n, modulo)).Mod(t, modulo)
	e := Challenge(domain, bound, context, n, modulo, ciphertext, t)

	// a + e m = z_m + carry n, and g^(carry n) is moved into the n-th power
	total := new(big.Int).Mul(e, plaintext)
	total.Add(total, a)
	carry, zm := new(big.Int).DivMod(total, n, new(big.Int))
	zr := new(big.Int).Exp(r, e, modulo)
	zr.Mul(zr, b).Mod(zr, modulo)
	zr.Mul(zr, new(big.Int).Exp(g, carry, modulo)).Mod(zr, modulo)
	return &phe.ZKProof{Challenge: e, PlaintextResponse: zm, RandomnessResponse: zr}, nil
}

// VerifyPaillierKnowledge verifies a proof of knowledge of the plaintext and
// the randomness of a Paillier or Damgard-Jurik ciphertext.
func VerifyPaillierKnowledge(ciphertext *big.Int, proof *phe.ZKProof, n, modulo *big.Int, domain string,
	context interface{}) bool {
	if proof == nil || ciphertext == nil {
		return false
	}
	e, zm, zr := proof.Challenge, proof.PlaintextResponse, proof.RandomnessResponse
	bound := nthPowerBound(n)
	if !inRange(e, bound) || !inRange(zm, n) {
		return false
	}
	if !isUnit(ciphertext, n, modulo) || !isUnit(zr, n, modulo) {
		return false
	}

	// t = g^z_m z_r^n c^-e is the commitment of an honest prover
	g := new(big.Int).Add(n, one)
	ce, err := powSigned(ciphertext, new(big.Int).Neg(e), modulo)
	if err != nil {
		return false
	}
	t := new(big.Int).Exp(g, zm, modulo)
	t.Mul(t, new(big.Int).Exp(zr, n, modulo)).Mod(t, modulo)
	t.Mul(t, ce).Mod(t, modulo)
	return e.Cmp(Challenge(domain, bound, context, n, modulo, ciphertext, t)) == 0
}

// DLEQUnknownOrderBits is the bit length of random values of proofs in
// groups of unknown order, so that responses hide the secret statistically.
func DLEQUnknownOrderBits(n, modulo *big.Int, xBits int) int {
	bits := modulo.BitLen()
	if xBits > bits {
		bits = xBits
	}
	return bits + NthPowerChallengeBits(n) + StatisticalBits
}

// ProveDLEQUnknownOrder proves that log_g1(h1) = log_g2(h2) = x in the group
// of squares modulo n^(s+1), whose order is secret. Response is computed over
// the integers and hides x statistically. This is the proof of correct
// partial decryption of Shoup and Damgard-Jurik.
func ProveDLEQUnknownOrder(n, modulo, g1, h1, g2, h2, x *big.Int, xBits int, domain string,
	context interface{}) (*phe.ZKProof, error) {
	w, err := mathutil.RandBits(DLEQUnknownOrderBits(n, modulo, xBits))
	if err != nil {
		return nil, err
	}
	a1 := new(big.Int).Exp(g1, w, modulo)
	a2 := new(big.Int).Exp(g2, w, modulo)
	e := Challenge(domain, nthPowerBound(n), context, modulo, g1, h1, g2, h2, a1, a2)
	z := new(big.Int).Mul(e, x)
	return &phe.ZKProof{Challenge: e, Response: z.Add(z, w)}, nil
}

// VerifyDLEQUnknownOrder verifies a proof that log_g1(h1) = log_g2(h2) in the
// group of squares modulo n^(s+1).
func VerifyDLEQUnknownOrder(n, modulo, g1, h1, g2, h2 *big.Int, proof *phe.ZKProof, xBits int, domain string,
	context interface{}) bool {
	if proof == nil {
		return false
	}
	e, z := proof.Challenge, proof.Response
	bound := nthPowerBound(n)
	if !inRange(e, bound) {
		return false
	}
	if !inRange(z, new(big.Int).Lsh(one, uint(DLEQUnknownOrderBits(n, modulo, xBits)+1))) {
		return false
	}
	for _, element := range []*big.Int{g1, h1, g2, h2} {
		if !isUnit(element, n, modulo) {
			return false
		}
	}

	// a = g^z h^-e is the commitment of an honest prover
	a1, err := nthCommitment(g1, h1, z, e, modulo)
	if err != nil {
		return false
	}
	a2, err := nthCommitment(g2, h2, z, e, modulo)
	if err != nil {
		return false
	}
	return e.Cmp(Challenge(domain, bound, context, modulo, g1, h1, g2, h2, a1, a2)) == 0
}

func nthCommitment(g, h, z, e, modulo *big.Int) (*big.Int, error) {
	he, err := powSigned(h, new(big.Int).Neg(e), modulo)
	if err != nil {
		return nil, err
	}
	out := new(big.Int).Exp(g, z, modulo)
	return out.Mul(out, he).Mod(out, modulo), nil
}
