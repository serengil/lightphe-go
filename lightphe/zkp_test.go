package lightphe_test

import (
	"encoding/json"
	"errors"
	"math/big"
	"strings"
	"testing"

	"github.com/serengil/lightphe-go/lightphe"
	"github.com/serengil/lightphe-go/lightphe/encrypted"
	"github.com/serengil/lightphe-go/lightphe/internal/zkp"
	"github.com/serengil/lightphe-go/lightphe/phe"
	"github.com/serengil/lightphe-go/lightphe/schemes/ecelgamal"
	"github.com/serengil/lightphe-go/lightphe/schemes/elgamal"
)

type proofCase struct {
	alg  phe.Algorithm
	opts []lightphe.Option
}

var (
	elgamalCase      = proofCase{phe.ElGamal, []lightphe.Option{lightphe.WithKeySize(128), lightphe.WithPrimeOrder(true)}}
	expElgamalCase   = proofCase{phe.ExponentialElGamal, []lightphe.Option{lightphe.WithKeySize(128), lightphe.WithPrimeOrder(true)}}
	ecElgamalCase    = proofCase{phe.EllipticCurveElGamal, nil}
	paillierCase     = proofCase{phe.Paillier, []lightphe.Option{lightphe.WithKeySize(128)}}
	damgardJurikCase = proofCase{phe.DamgardJurik, []lightphe.Option{lightphe.WithKeySize(128)}}

	knowledgeCases  = []proofCase{elgamalCase, expElgamalCase, ecElgamalCase, paillierCase, damgardJurikCase}
	membershipCases = []proofCase{expElgamalCase, ecElgamalCase, paillierCase, damgardJurikCase}
)

// compute combines two encrypted values homomorphically, and returns the
// expected plaintext.
func compute(t *testing.T, cs *lightphe.Cryptosystem, m1, m2 int64) (*encrypted.Ciphertext, int64) {
	t.Helper()
	if cs.Algorithm() == phe.ElGamal {
		return cfMul(t, mustEncrypt(t, cs, m1), mustEncrypt(t, cs, m2)), m1 * m2
	}
	return cfAdd(t, mustEncrypt(t, cs, m1), mustEncrypt(t, cs, m2)), m1 + m2
}

// tamper adds 1 to the first field of a proof.
func tamper(proof *lightphe.ZKProof) *lightphe.ZKProof {
	data, _ := json.Marshal(proof)
	var tampered lightphe.ZKProof
	_ = json.Unmarshal(data, &tampered)
	inc := func(x *big.Int) { x.Add(x, big.NewInt(1)) }
	switch {
	case tampered.Challenge != nil:
		inc(tampered.Challenge)
	case tampered.Challenges != nil:
		inc(tampered.Challenges[0])
	case tampered.Randomness != nil:
		inc(tampered.Randomness)
	}
	return &tampered
}

// roundTrip passes a value through JSON.
func roundTrip(t *testing.T, in, out interface{}) {
	t.Helper()
	data, err := json.Marshal(in)
	if err != nil {
		t.Fatalf("marshaling: %v", err)
	}
	if err := json.Unmarshal(data, out); err != nil {
		t.Fatalf("unmarshaling: %v", err)
	}
}

func publicOf(t *testing.T, cs *lightphe.Cryptosystem) *lightphe.Cryptosystem {
	t.Helper()
	keys, err := cs.Keys(true)
	if err != nil {
		t.Fatalf("exporting: %v", err)
	}
	return mustBuild(t, cs.Algorithm(), lightphe.WithKeys(keys))
}

func assertValid(t *testing.T, what string, valid bool, err error, want bool) {
	t.Helper()
	if err != nil {
		t.Fatalf("%s: %v", what, err)
	}
	if valid != want {
		t.Fatalf("%s: valid = %v, want %v", what, valid, want)
	}
}

func TestProofOfCorrectDecryption(t *testing.T) {
	for _, tc := range knowledgeCases {
		tc := tc
		t.Run(tc.alg.String(), func(t *testing.T) {
			t.Parallel()
			cs := mustBuild(t, tc.alg, tc.opts...)
			c, expected := compute(t, cs, 17, 3)

			plaintext, proof, err := cs.DecryptWithProof(c)
			if err != nil {
				t.Fatalf("decrypting with a proof: %v", err)
			}
			if plaintext.Int64() != expected {
				t.Fatalf("decrypted %s, want %d", plaintext, expected)
			}

			// verifier has the public key only, and proof survives json round
			// trip
			verifier := publicOf(t, cs)
			var decoded lightphe.ZKProof
			roundTrip(t, proof, &decoded)
			valid, err := verifier.VerifyDecryption(c, plaintext, &decoded)
			assertValid(t, "proof", valid, err, true)

			// wrong plaintext, tampered proof and malformed proof are rejected
			valid, err = verifier.VerifyDecryption(c, new(big.Int).Add(plaintext, big.NewInt(1)), proof)
			assertValid(t, "wrong plaintext", valid, err, false)
			valid, err = verifier.VerifyDecryption(c, plaintext, tamper(proof))
			assertValid(t, "tampered proof", valid, err, false)
			valid, err = verifier.VerifyDecryption(c, plaintext, &lightphe.ZKProof{})
			assertValid(t, "empty proof", valid, err, false)
			valid, err = verifier.VerifyDecryption(c, plaintext, nil)
			assertValid(t, "nil proof", valid, err, false)

			// proof of a ciphertext does not prove another ciphertext of same
			// plaintext
			cPrime, err := cs.RegenerateCiphertext(c)
			if err != nil {
				t.Fatalf("regenerating: %v", err)
			}
			valid, err = verifier.VerifyDecryption(cPrime, plaintext, proof)
			assertValid(t, "proof of another ciphertext", valid, err, false)
			_, proofPrime, err := cs.DecryptWithProof(cPrime)
			if err != nil {
				t.Fatalf("decrypting with a proof: %v", err)
			}
			valid, err = verifier.VerifyDecryption(cPrime, plaintext, proofPrime)
			assertValid(t, "proof of the regenerated ciphertext", valid, err, true)
		})
	}
}

func TestElGamalProofsRequirePrimeOrder(t *testing.T) {
	for _, alg := range []phe.Algorithm{phe.ElGamal, phe.ExponentialElGamal} {
		cs := mustBuild(t, alg, lightphe.WithKeySize(testKeySize))
		c := mustEncrypt(t, cs, 5)
		if _, _, err := cs.DecryptWithProof(c); !errors.Is(err, elgamal.ErrPrimeOrderRequired) {
			t.Fatalf("decrypting with a proof returned %v", err)
		}
		if _, err := cs.VerifyDecryption(c, big.NewInt(5), &lightphe.ZKProof{}); !errors.Is(err, elgamal.ErrPrimeOrderRequired) {
			t.Fatalf("verifying returned %v", err)
		}
		if _, _, err := cs.EncryptWithProofOfKnowledge(big.NewInt(5), nil); !errors.Is(err, elgamal.ErrPrimeOrderRequired) {
			t.Fatalf("proving knowledge returned %v", err)
		}
	}
	cs := mustBuild(t, phe.ExponentialElGamal, lightphe.WithKeySize(testKeySize))
	if _, _, err := cs.EncryptWithProof(big.NewInt(1), nil, nil); !errors.Is(err, elgamal.ErrPrimeOrderRequired) {
		t.Fatalf("proving membership returned %v", err)
	}
}

func TestCiphertextOutOfGroupIsRejected(t *testing.T) {
	cs := mustBuild(t, expElgamalCase.alg, expElgamalCase.opts...)
	c := mustEncrypt(t, cs, 5)
	plaintext, proof, err := cs.DecryptWithProof(c)
	if err != nil {
		t.Fatalf("decrypting with a proof: %v", err)
	}

	// -c1 is not in the subgroup of prime order q
	data, _ := cs.Keys(true)
	var keys struct {
		PublicKey struct{ P *big.Int } `json:"public_key"`
	}
	_ = json.Unmarshal(data, &keys)
	tuple, _ := phe.AsTuple(c.Value)
	c1, _ := phe.AsInt(tuple.Items[0])
	forged := cs.CreateCiphertext(phe.NewTuple(phe.Int{V: new(big.Int).Sub(keys.PublicKey.P, c1)}, tuple.Items[1]))
	valid, err := cs.VerifyDecryption(forged, plaintext, proof)
	assertValid(t, "forged ciphertext", valid, err, false)
}

func TestProofsUnsupportedAlgorithms(t *testing.T) {
	for _, alg := range []phe.Algorithm{phe.RSA, phe.OkamotoUchiyama} {
		cs := mustBuild(t, alg, lightphe.WithKeySize(testKeySize))
		c := mustEncrypt(t, cs, 5)
		_, _, err := cs.DecryptWithProof(c)
		assertUnsupported(t, "decryption proof", err)
		_, err = cs.VerifyDecryption(c, big.NewInt(5), nil)
		assertUnsupported(t, "verifying decryption", err)
		_, _, err = cs.EncryptWithProof(big.NewInt(1), nil, nil)
		assertUnsupported(t, "membership proof", err)
		_, _, err = cs.EncryptWithProofOfKnowledge(big.NewInt(5), nil)
		assertUnsupported(t, "knowledge proof", err)
		_, _, err = cs.EncryptOneHot(0, 2, nil)
		assertUnsupported(t, "one-hot proof", err)
		_, _, err = cs.EncryptWithRangeProof(big.NewInt(1), big.NewInt(0), big.NewInt(3), nil)
		assertUnsupported(t, "range proof", err)
	}

	cs := mustBuild(t, elgamalCase.alg, elgamalCase.opts...)
	if _, _, err := cs.EncryptWithProof(big.NewInt(1), []*big.Int{big.NewInt(1), big.NewInt(2)}, nil); err == nil ||
		!strings.Contains(err.Error(), "use Exponential-ElGamal instead") {
		t.Fatalf("membership proof of ElGamal returned %v", err)
	}
}

func TestVerifiablePartialDecryptions(t *testing.T) {
	for _, tc := range []proofCase{elgamalCase, expElgamalCase, ecElgamalCase} {
		tc := tc
		t.Run(tc.alg.String(), func(t *testing.T) {
			t.Parallel()
			dealer := mustBuild(t, tc.alg, tc.opts...)
			publicKey, shareKeys, err := dealer.GenerateThresholdKeys(threshold, parties)
			if err != nil {
				t.Fatalf("generating threshold keys: %v", err)
			}
			public := mustBuild(t, tc.alg, lightphe.WithKeys(publicKey))
			var shareholders []*lightphe.Cryptosystem
			for _, keys := range shareKeys {
				shareholders = append(shareholders, mustBuild(t, tc.alg, lightphe.WithKeys(keys)))
			}

			c, expected := compute(t, public, 17, 3)
			var partials []*lightphe.PartialDecryption
			roundTrip(t, partialDecrypt(t, shareholders, c, true), &partials)
			for _, partial := range partials {
				valid, err := public.VerifyPartialDecryption(c, partial)
				assertValid(t, "honest partial decryption", valid, err, true)
			}

			// a cheating shareholder sends a wrong value with its old proof
			honest := partials[0]
			forged := *honest
			forged.Value = partials[1].Value
			valid, err := public.VerifyPartialDecryption(c, &forged)
			assertValid(t, "forged value", valid, err, false)

			// a proof cannot be reused under another index or for another
			// ciphertext
			moved := *honest
			moved.Index = 2
			valid, err = public.VerifyPartialDecryption(c, &moved)
			assertValid(t, "another index", valid, err, false)
			moved.Index = parties + 1
			valid, err = public.VerifyPartialDecryption(c, &moved)
			assertValid(t, "unknown index", valid, err, false)
			other, err := public.RegenerateCiphertext(c)
			if err != nil {
				t.Fatalf("regenerating: %v", err)
			}
			valid, err = public.VerifyPartialDecryption(other, honest)
			assertValid(t, "another ciphertext", valid, err, false)
			unproven := *honest
			unproven.Proof = nil
			valid, err = public.VerifyPartialDecryption(c, &unproven)
			assertValid(t, "missing proof", valid, err, false)

			// invalid partial decryptions are discarded if enough valid ones
			// remain
			if m := mustCombine(t, public, c, append([]*lightphe.PartialDecryption{&forged}, partials[1:4]...), true); m.Int64() != expected {
				t.Fatalf("decrypted %s, want %d", m, expected)
			}

			// otherwise combination fails instead of returning a wrong plaintext
			if _, err := public.CombinePartialDecryptions(c, append([]*lightphe.PartialDecryption{&forged}, partials[1:3]...), true); err == nil ||
				!strings.Contains(err.Error(), "valid partial decryptions") {
				t.Fatalf("too few valid partial decryptions returned %v", err)
			}

			// partial decryptions without proofs are discarded if verification
			// is on, and combined otherwise
			plain := partialDecrypt(t, shareholders, c, false)
			if _, err := public.CombinePartialDecryptions(c, plain, true); err == nil {
				t.Fatal("unproven partial decryptions were accepted")
			}
			if m := mustCombine(t, public, c, plain, false); m.Int64() != expected {
				t.Fatalf("decrypted %s, want %d", m, expected)
			}
		})
	}
}

func TestPaillierPartialDecryptionProofsRequireSafePrimes(t *testing.T) {
	for _, alg := range []phe.Algorithm{phe.Paillier, phe.DamgardJurik} {
		public, shareholders := buildThreshold(t, alg, testKeySize)
		c := mustEncrypt(t, public, 5)

		// regular keys still decrypt without proofs
		partials := partialDecrypt(t, shareholders, c, false)
		if m := mustCombine(t, public, c, partials, false); m.Int64() != 5 {
			t.Fatalf("decrypted %s, want 5", m)
		}

		if _, err := shareholders[0].PartialDecrypt(c, true); err == nil || !strings.Contains(err.Error(), "safe primes") {
			t.Fatalf("proving returned %v", err)
		}
		if _, err := public.VerifyPartialDecryption(c, partials[0]); err == nil || !strings.Contains(err.Error(), "safe primes") {
			t.Fatalf("verifying returned %v", err)
		}
		if _, err := public.CombinePartialDecryptions(c, partials, true); err == nil || !strings.Contains(err.Error(), "safe primes") {
			t.Fatalf("combining with verification returned %v", err)
		}
	}
}

func TestVerifiablePaillierPartialDecryptions(t *testing.T) {
	for _, alg := range []phe.Algorithm{phe.Paillier, phe.DamgardJurik} {
		alg := alg
		t.Run(alg.String(), func(t *testing.T) {
			t.Parallel()
			dealer := mustBuild(t, alg, lightphe.WithKeySize(128), lightphe.WithSafePrimes(true))

			// safe prime keys work as regular keys
			c := cfAdd(t, mustEncrypt(t, dealer, 100), mustEncrypt(t, dealer, 50))
			assertDecrypts(t, dealer, c, 150)
			assertDecrypts(t, dealer, cfScale(t, c, big.NewInt(3)), 450)

			publicKey, shareKeys, err := dealer.GenerateThresholdKeys(threshold, parties)
			if err != nil {
				t.Fatalf("generating threshold keys: %v", err)
			}
			public := mustBuild(t, alg, lightphe.WithKeys(publicKey))
			var shareholders []*lightphe.Cryptosystem
			for _, keys := range shareKeys {
				shareholders = append(shareholders, mustBuild(t, alg, lightphe.WithKeys(keys)))
			}

			var partials []*lightphe.PartialDecryption
			roundTrip(t, partialDecrypt(t, shareholders, c, true), &partials)
			for _, partial := range partials {
				valid, err := public.VerifyPartialDecryption(c, partial)
				assertValid(t, "honest partial decryption", valid, err, true)
			}
			if m := mustCombine(t, public, c, partials, true); m.Int64() != 150 {
				t.Fatalf("decrypted %s, want 150", m)
			}

			// partial decryptions without proofs are combined if verification
			// is off
			plain := partialDecrypt(t, shareholders, c, false)
			if m := mustCombine(t, public, c, plain, false); m.Int64() != 150 {
				t.Fatalf("decrypted %s, want 150", m)
			}
			if _, err := public.CombinePartialDecryptions(c, plain, true); err == nil {
				t.Fatal("unproven partial decryptions were accepted")
			}

			// a cheating shareholder multiplies its partial decryption with
			// (1 + n)
			honest := partials[0]
			value, _ := phe.AsInt(honest.Value)
			n := public.PlaintextModulo()
			modulo := public.Scheme().CiphertextModulo()
			shifted := new(big.Int).Mul(value, new(big.Int).Add(n, big.NewInt(1)))
			forged := *honest
			forged.Value = phe.Int{V: shifted.Mod(shifted, modulo)}
			valid, err := public.VerifyPartialDecryption(c, &forged)
			assertValid(t, "forged value", valid, err, false)

			moved := *honest
			moved.Index = 2
			valid, err = public.VerifyPartialDecryption(c, &moved)
			assertValid(t, "another index", valid, err, false)
			tampered := *honest
			tampered.Proof = tamper(honest.Proof)
			valid, err = public.VerifyPartialDecryption(c, &tampered)
			assertValid(t, "tampered proof", valid, err, false)

			if m := mustCombine(t, public, c, append([]*lightphe.PartialDecryption{&forged}, partials[1:4]...), true); m.Int64() != 150 {
				t.Fatalf("decrypted %s, want 150", m)
			}
			if _, err := public.CombinePartialDecryptions(c, append([]*lightphe.PartialDecryption{&forged}, partials[1:3]...), true); err == nil {
				t.Fatal("too few valid partial decryptions were accepted")
			}
		})
	}
}

func bigs(values ...int64) []*big.Int {
	out := make([]*big.Int, len(values))
	for i, v := range values {
		out[i] = big.NewInt(v)
	}
	return out
}

func TestProofOfMembership(t *testing.T) {
	for _, tc := range membershipCases {
		tc := tc
		t.Run(tc.alg.String(), func(t *testing.T) {
			t.Parallel()
			cs := mustBuild(t, tc.alg, tc.opts...)

			// voter has the public key only
			voter := publicOf(t, cs)
			for vote := int64(0); vote <= 1; vote++ {
				ballot, proof, err := voter.EncryptWithProof(big.NewInt(vote), nil, "voter-42")
				if err != nil {
					t.Fatalf("encrypting with a proof: %v", err)
				}
				var decoded lightphe.ZKProof
				roundTrip(t, proof, &decoded)
				assertDecrypts(t, cs, ballot, vote)
				valid, err := voter.VerifyCiphertext(ballot, &decoded, nil, "voter-42")
				assertValid(t, "ballot", valid, err, true)
				valid, err = voter.VerifyCiphertext(ballot, proof, bigs(0, 1), "voter-42")
				assertValid(t, "ballot with explicit values", valid, err, true)

				// proof is bound to its context, values and ciphertext
				valid, err = voter.VerifyCiphertext(ballot, proof, nil, "voter-43")
				assertValid(t, "another context", valid, err, false)
				valid, err = voter.VerifyCiphertext(ballot, proof, nil, nil)
				assertValid(t, "no context", valid, err, false)
				valid, err = voter.VerifyCiphertext(ballot, proof, bigs(1, 0), "voter-42")
				assertValid(t, "reordered values", valid, err, false)
				valid, err = voter.VerifyCiphertext(cfAdd(t, ballot, ballot), proof, nil, "voter-42")
				assertValid(t, "doubled ballot", valid, err, false)
				valid, err = voter.VerifyCiphertext(ballot, tamper(proof), nil, "voter-42")
				assertValid(t, "tampered proof", valid, err, false)
				valid, err = voter.VerifyCiphertext(ballot, &lightphe.ZKProof{}, nil, "voter-42")
				assertValid(t, "empty proof", valid, err, false)
				valid, err = voter.VerifyCiphertext(ballot, nil, nil, "voter-42")
				assertValid(t, "nil proof", valid, err, false)
			}

			// larger sets of values, e.g. a rating in [1, 5]
			rating, proof, err := voter.EncryptWithProof(big.NewInt(4), bigs(1, 2, 3, 4, 5), nil)
			if err != nil {
				t.Fatalf("encrypting with a proof: %v", err)
			}
			valid, err := voter.VerifyCiphertext(rating, proof, bigs(1, 2, 3, 4, 5), nil)
			assertValid(t, "rating", valid, err, true)
			valid, err = voter.VerifyCiphertext(rating, proof, bigs(1, 2, 3, 5, 6), nil)
			assertValid(t, "rating with other values", valid, err, false)
			assertDecrypts(t, cs, rating, 4)

			// single allowed value
			c, proof, err := voter.EncryptWithProof(big.NewInt(7), bigs(7), nil)
			if err != nil {
				t.Fatalf("encrypting with a proof: %v", err)
			}
			valid, err = voter.VerifyCiphertext(c, proof, bigs(7), nil)
			assertValid(t, "single value", valid, err, true)

			// invalid inputs
			for _, tt := range []struct {
				plaintext int64
				values    []*big.Int
				message   string
			}{
				{2, nil, "one of the allowed values"},
				{1, bigs(0, 1, 1), "distinct"},
				{1, []*big.Int{}, "non-empty"},
			} {
				if _, _, err := voter.EncryptWithProof(big.NewInt(tt.plaintext), tt.values, nil); err == nil ||
					!strings.Contains(err.Error(), tt.message) {
					t.Fatalf("encrypting %d of %v returned %v", tt.plaintext, tt.values, err)
				}
			}
		})
	}
}

func TestCheatingVoterIsRejected(t *testing.T) {
	// a voter encrypts 2 and runs the prover pretending that it encrypts 1
	for _, tc := range membershipCases {
		cs := mustBuild(t, tc.alg, tc.opts...)
		prover := cs.Scheme().(phe.MembershipProver)
		values := bigs(0, 1)
		r, err := prover.GenerateRandomKey()
		if err != nil {
			t.Fatalf("random key: %v", err)
		}
		value, err := prover.EncryptWith(big.NewInt(2), r)
		if err != nil {
			t.Fatalf("encrypting: %v", err)
		}

		var proof *phe.ZKProof
		switch tc.alg {
		case phe.Paillier, phe.DamgardJurik:
			n := cs.PlaintextModulo()
			modulo := cs.Scheme().CiphertextModulo()
			domain := "lightphe/paillier/membership"
			if tc.alg == phe.DamgardJurik {
				domain = "lightphe/damgard-jurik/membership"
			}
			c, _ := phe.AsInt(value)
			us, _ := zkp.PaillierMembershipCandidates(c, values, n, modulo)
			proof, err = zkp.ProveNthPowerOr(n, modulo, us, r, 1, domain, []interface{}{values, nil})
		case phe.ExponentialElGamal:
			var keys elgamal.Keys
			data, _ := cs.Keys(true)
			_ = json.Unmarshal(data, &keys)
			pk := keys.PublicKey
			tuple, _ := phe.AsTuple(value)
			c1, _ := phe.AsInt(tuple.Items[0])
			c2, _ := phe.AsInt(tuple.Items[1])
			var h2s []zkp.Element
			for _, v := range values {
				gv := new(big.Int).Exp(pk.G, new(big.Int).Mod(new(big.Int).Neg(v), pk.Q), pk.P)
				h2s = append(h2s, gv.Mul(gv, c2).Mod(gv, pk.P))
			}
			proof, err = zkp.ProveDLEQOr(zkp.ModularGroup{P: pk.P, Q: pk.Q}, pk.G, c1, pk.Y, h2s, r, 1,
				elgamal.MembershipDomain, []interface{}{pk.P, c2, values, nil})
		case phe.EllipticCurveElGamal:
			ec := cs.Scheme().(*ecelgamal.Cryptosystem).ECC()
			tuple, _ := phe.AsTuple(value)
			p1, _ := phe.AsPoint(tuple.Items[0])
			p2, _ := phe.AsPoint(tuple.Items[1])
			c1, _ := ec.Point(p1.X, p1.Y)
			c2, _ := ec.Point(p2.X, p2.Y)
			qa := cs.Scheme().(*ecelgamal.Cryptosystem).Keys().PublicKey.Qa
			qaPoint, _ := ec.Point(qa.X, qa.Y)
			var h2s []zkp.Element
			for _, v := range values {
				vG, _ := ec.G().ScalarMul(v)
				candidate, _ := c2.Sub(vG)
				h2s = append(h2s, candidate)
			}
			proof, err = zkp.ProveDLEQOr(zkp.EllipticCurveGroup{EC: ec}, ec.G(), c1, qaPoint, h2s, r, 1,
				ecelgamal.MembershipDomain, []interface{}{ec.N(), c2, values, nil})
		}
		if err != nil {
			t.Fatalf("proving: %v", err)
		}

		ballot := cs.CreateCiphertext(value)
		assertDecrypts(t, cs, ballot, 2)
		valid, err := cs.VerifyCiphertext(ballot, proof, nil, nil)
		assertValid(t, string(tc.alg)+" cheating voter", valid, err, false)
	}
}

func TestProofOfKnowledge(t *testing.T) {
	for _, tc := range knowledgeCases {
		tc := tc
		t.Run(tc.alg.String(), func(t *testing.T) {
			t.Parallel()
			cs := mustBuild(t, tc.alg, tc.opts...)

			// prover and verifier have the public key only
			public := publicOf(t, cs)
			c, proof, err := public.EncryptWithProofOfKnowledge(big.NewInt(17), "alice")
			if err != nil {
				t.Fatalf("encrypting with a proof: %v", err)
			}
			var decoded lightphe.ZKProof
			roundTrip(t, proof, &decoded)
			assertDecrypts(t, cs, c, 17)
			valid, err := public.VerifyKnowledge(c, &decoded, "alice")
			assertValid(t, "proof", valid, err, true)

			// proof is bound to its context and ciphertext
			valid, err = public.VerifyKnowledge(c, proof, "bob")
			assertValid(t, "another context", valid, err, false)
			valid, err = public.VerifyKnowledge(c, proof, nil)
			assertValid(t, "no context", valid, err, false)

			// a copied ciphertext cannot be re-randomized or modified with the
			// same proof
			regenerated, err := public.RegenerateCiphertext(c)
			if err != nil {
				t.Fatalf("regenerating: %v", err)
			}
			valid, err = public.VerifyKnowledge(regenerated, proof, "alice")
			assertValid(t, "re-randomized", valid, err, false)
			var modified *encrypted.Ciphertext
			if tc.alg == phe.ElGamal {
				modified = cfMul(t, c, mustEncrypt(t, public, 2))
			} else {
				modified = cfAdd(t, c, mustEncrypt(t, public, 1))
				valid, err = public.VerifyKnowledge(cfScale(t, c, big.NewInt(3)), proof, "alice")
				assertValid(t, "scaled", valid, err, false)
			}
			valid, err = public.VerifyKnowledge(modified, proof, "alice")
			assertValid(t, "modified", valid, err, false)

			// tampered and malformed proofs are rejected
			valid, err = public.VerifyKnowledge(c, tamper(proof), "alice")
			assertValid(t, "tampered", valid, err, false)
			valid, err = public.VerifyKnowledge(c, &lightphe.ZKProof{}, "alice")
			assertValid(t, "empty", valid, err, false)
			valid, err = public.VerifyKnowledge(c, nil, "alice")
			assertValid(t, "nil", valid, err, false)

			// a proof of another ciphertext does not prove this one
			other, otherProof, err := public.EncryptWithProofOfKnowledge(big.NewInt(17), "alice")
			if err != nil {
				t.Fatalf("encrypting with a proof: %v", err)
			}
			valid, err = public.VerifyKnowledge(c, otherProof, "alice")
			assertValid(t, "proof of another ciphertext", valid, err, false)
			valid, err = public.VerifyKnowledge(other, otherProof, "alice")
			assertValid(t, "other proof", valid, err, true)
		})
	}
}

func TestChallengeTranscript(t *testing.T) {
	// transcripts are the compact JSON of Python's json.dumps, so challenges
	// match the Python library's
	e := zkp.Challenge("domain", new(big.Int).Lsh(big.NewInt(1), 512),
		map[string]interface{}{"a": []int{2, 3}, "b": 1}, "ç<>&\n", nil, big.NewInt(5),
		phe.NewPoint(big.NewInt(7), big.NewInt(8)), 1.5)
	want, _ := new(big.Int).SetString("57389078889167865834580437035861919955616059860029798820778319682338900214"+
		"2233142713361454881157207409520438914390977155784026136245824732475176891417830", 10)
	if e.Cmp(want) != 0 {
		t.Fatalf("challenge is %s, want %s", e, want)
	}
}
