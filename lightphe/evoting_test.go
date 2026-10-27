package lightphe_test

import (
	"encoding/json"
	"math/big"
	"strings"
	"testing"

	"github.com/serengil/lightphe-go/lightphe"
	"github.com/serengil/lightphe-go/lightphe/encrypted"
	thresholdutil "github.com/serengil/lightphe-go/lightphe/internal/threshold"
	"github.com/serengil/lightphe-go/lightphe/internal/zkp"
	"github.com/serengil/lightphe-go/lightphe/phe"
)

// Range proofs and e-voting with proofs of allowed values.

func TestRangeProof(t *testing.T) {
	for _, tc := range membershipCases {
		tc := tc
		t.Run(tc.alg.String(), func(t *testing.T) {
			t.Parallel()
			cs := mustBuild(t, tc.alg, tc.opts...)

			// prover and verifier have the public key only
			public := publicOf(t, cs)
			low, high := big.NewInt(10), big.NewInt(200)
			var c *encrypted.Ciphertext
			var proof *lightphe.RangeProof
			for _, plaintext := range []int64{10, 137, 200} {
				var err error
				c, proof, err = public.EncryptWithRangeProof(big.NewInt(plaintext), low, high, "alice")
				if err != nil {
					t.Fatalf("encrypting with a range proof: %v", err)
				}
				assertDecrypts(t, cs, c, plaintext)
				valid, err := public.VerifyRange(c, proof, low, high, "alice")
				assertValid(t, "range proof", valid, err, true)
			}

			// proof is bound to its context, range and ciphertext
			for _, tt := range []struct {
				what      string
				c         *encrypted.Ciphertext
				low, high *big.Int
				context   interface{}
			}{
				{"another context", c, low, high, "bob"},
				{"no context", c, low, high, nil},
				{"another lower bound", c, big.NewInt(9), high, "alice"},
				{"another upper bound", c, low, big.NewInt(201), "alice"},
				{"doubled ciphertext", cfAdd(t, c, c), low, high, "alice"},
			} {
				valid, err := public.VerifyRange(tt.c, proof, tt.low, tt.high, tt.context)
				assertValid(t, tt.what, valid, err, false)
			}
			other, _, err := public.EncryptWithRangeProof(big.NewInt(200), low, high, "alice")
			if err != nil {
				t.Fatalf("encrypting with a range proof: %v", err)
			}
			valid, err := public.VerifyRange(other, proof, low, high, "alice")
			assertValid(t, "another ciphertext", valid, err, false)

			// tampered, reordered, truncated and malformed proofs are rejected
			reordered := &lightphe.RangeProof{
				Ciphertexts: append([]phe.Value{}, proof.Ciphertexts...),
				Proofs:      append([]*lightphe.ZKProof{}, proof.Proofs...),
			}
			reordered.Ciphertexts[1], reordered.Ciphertexts[2] = reordered.Ciphertexts[2], reordered.Ciphertexts[1]
			reordered.Proofs[1], reordered.Proofs[2] = reordered.Proofs[2], reordered.Proofs[1]
			valid, err = public.VerifyRange(c, reordered, low, high, "alice")
			assertValid(t, "reordered", valid, err, false)

			truncated := &lightphe.RangeProof{
				Ciphertexts: proof.Ciphertexts[:len(proof.Ciphertexts)-1],
				Proofs:      proof.Proofs[:len(proof.Proofs)-1],
			}
			valid, err = public.VerifyRange(c, truncated, low, high, "alice")
			assertValid(t, "truncated", valid, err, false)

			tampered := &lightphe.RangeProof{
				Ciphertexts: proof.Ciphertexts,
				Proofs:      append([]*lightphe.ZKProof{}, proof.Proofs...),
			}
			tampered.Proofs[1] = tamper(proof.Proofs[1])
			valid, err = public.VerifyRange(c, tampered, low, high, "alice")
			assertValid(t, "tampered", valid, err, false)

			valid, err = public.VerifyRange(c, &lightphe.RangeProof{}, low, high, "alice")
			assertValid(t, "empty", valid, err, false)
			valid, err = public.VerifyRange(c, nil, low, high, "alice")
			assertValid(t, "nil", valid, err, false)

			// a cheater runs the prover for a value out of the range, or presents
			// the proof of an in-range value next to the ciphertext of an
			// out-of-range value
			outOfRange := mustEncrypt(t, cs, 150)
			_, cheat, err := zkp.ProveRange(cs.Scheme().(zkp.Prover), big.NewInt(150), big.NewInt(0), big.NewInt(100),
				big.NewInt(0), big.NewInt(0), big.NewInt(1), nil)
			if err != nil {
				t.Fatalf("proving: %v", err)
			}
			valid, err = cs.VerifyRange(outOfRange, cheat, big.NewInt(0), big.NewInt(100), nil)
			assertValid(t, "out of range", valid, err, false)
			_, inRange, err := cs.EncryptWithRangeProof(big.NewInt(50), big.NewInt(0), big.NewInt(100), nil)
			if err != nil {
				t.Fatalf("encrypting with a range proof: %v", err)
			}
			valid, err = cs.VerifyRange(outOfRange, inRange, big.NewInt(0), big.NewInt(100), nil)
			assertValid(t, "proof of another value", valid, err, false)
		})
	}
}

func TestRangeProofEdgeRanges(t *testing.T) {
	cs := mustBuild(t, phe.Paillier, lightphe.WithKeySize(128))
	modulo := cs.PlaintextModulo()
	prove := func(plaintext, low, high int64) {
		t.Helper()
		c, proof, err := cs.EncryptWithRangeProof(big.NewInt(plaintext), big.NewInt(low), big.NewInt(high), nil)
		if err != nil {
			t.Fatalf("encrypting %d in [%d, %d]: %v", plaintext, low, high, err)
		}
		valid, err := cs.VerifyRange(c, proof, big.NewInt(low), big.NewInt(high), nil)
		assertValid(t, "range proof", valid, err, true)
		assertDecryptsBig(t, cs, c, new(big.Int).Mod(big.NewInt(plaintext), modulo))
	}

	// single value range, negative values and power of two widths
	prove(7, 7, 7)
	prove(-30, -100, 100)
	for _, high := range []int64{1, 2, 255, 256} {
		prove(high, 0, high)
	}

	// invalid inputs
	for _, tt := range []struct {
		plaintext, low, high *big.Int
		message              string
	}{
		{big.NewInt(101), big.NewInt(0), big.NewInt(100), "must be in"},
		{big.NewInt(-1), big.NewInt(0), big.NewInt(100), "must be in"},
		{big.NewInt(5), big.NewInt(10), big.NewInt(0), "must not be greater"},
		{big.NewInt(5), big.NewInt(0), modulo, "narrower"},
	} {
		if _, _, err := cs.EncryptWithRangeProof(tt.plaintext, tt.low, tt.high, nil); err == nil ||
			!strings.Contains(err.Error(), tt.message) {
			t.Fatalf("%s in [%s, %s] returned %v", tt.plaintext, tt.low, tt.high, err)
		}
	}

	// range proofs survive a json round trip of their proofs
	c, proof, err := cs.EncryptWithRangeProof(big.NewInt(5), big.NewInt(0), big.NewInt(10), "x")
	if err != nil {
		t.Fatalf("encrypting: %v", err)
	}
	data, _ := json.Marshal(proof)
	if !strings.Contains(string(data), `"ciphertexts":[`) || !strings.Contains(string(data), `"proofs":[`) {
		t.Fatalf("range proof marshals to %s", data)
	}
	valid, err := cs.VerifyRange(c, proof, big.NewInt(0), big.NewInt(10), "x")
	assertValid(t, "range proof", valid, err, true)
}

func TestSalarySurvey(t *testing.T) {
	// employees submit encrypted salaries with proofs that they are in
	// [0, 500000], so nobody can skew the average
	authority := mustBuild(t, phe.Paillier, lightphe.WithKeySize(128))
	public := publicOf(t, authority)
	low, high := big.NewInt(0), big.NewInt(500000)

	type submission struct {
		c     *encrypted.Ciphertext
		proof *lightphe.RangeProof
	}
	salaries := map[string]int64{"alice": 85000, "bob": 62000, "carol": 120000, "dave": 47000}
	submissions := map[string]submission{}
	for employee, salary := range salaries {
		c, proof, err := public.EncryptWithRangeProof(big.NewInt(salary), low, high, employee)
		if err != nil {
			t.Fatalf("encrypting: %v", err)
		}
		submissions[employee] = submission{c, proof}
	}

	// mallory copies alice's submission
	submissions["mallory"] = submissions["alice"]

	// oscar cannot prove a huge salary, and cannot reuse a proof of a valid
	// salary
	if _, _, err := public.EncryptWithRangeProof(big.NewInt(1e9), low, high, "oscar"); err == nil {
		t.Fatal("a huge salary was proven")
	}
	_, oscarProof, err := public.EncryptWithRangeProof(big.NewInt(50000), low, high, "oscar")
	if err != nil {
		t.Fatalf("encrypting: %v", err)
	}
	submissions["oscar"] = submission{mustEncrypt(t, public, 1e9), oscarProof}

	// trent cannot submit a negative salary either
	_, trentProof, err := public.EncryptWithRangeProof(big.NewInt(0), low, high, "trent")
	if err != nil {
		t.Fatalf("encrypting: %v", err)
	}
	submissions["trent"] = submission{mustEncrypt(t, public, -1e6), trentProof}

	var total *encrypted.Ciphertext
	count := 0
	for employee, s := range submissions {
		valid, err := public.VerifyRange(s.c, s.proof, low, high, employee)
		if err != nil {
			t.Fatalf("verifying: %v", err)
		}
		if _, honest := salaries[employee]; valid != honest {
			t.Fatalf("submission of %s is valid = %v", employee, valid)
		}
		if !valid {
			continue
		}
		count++
		if total == nil {
			total = s.c
		} else {
			total = cfAdd(t, total, s.c)
		}
	}

	// authority decrypts the total only with a proof, and anyone verifies it
	result, proof, err := authority.DecryptWithProof(total)
	if err != nil {
		t.Fatalf("decrypting: %v", err)
	}
	valid, err := public.VerifyDecryption(total, result, proof)
	assertValid(t, "total", valid, err, true)
	if result.Int64()/int64(count) != 78500 {
		t.Fatalf("average salary is %d, want 78500", result.Int64()/int64(count))
	}
}

func TestEncryptedVoting(t *testing.T) {
	// voters cast 0/1 ballots with proofs, valid ones are tallied
	// homomorphically, and trustees threshold-decrypt the tally with proofs
	authority := mustBuild(t, phe.ExponentialElGamal, lightphe.WithKeySize(128), lightphe.WithPrimeOrder(true))
	publicKey, shareKeys, err := authority.GenerateThresholdKeys(2, 3)
	if err != nil {
		t.Fatalf("generating threshold keys: %v", err)
	}
	public := mustBuild(t, phe.ExponentialElGamal, lightphe.WithKeys(publicKey))

	votes := map[string]int64{"alice": 1, "bob": 0, "carol": 1, "dave": 1}
	type ballot struct {
		c     *encrypted.Ciphertext
		proof *lightphe.ZKProof
	}
	ballots := map[string]ballot{}
	for voter, vote := range votes {
		c, proof, err := public.EncryptWithProof(big.NewInt(vote), nil, voter)
		if err != nil {
			t.Fatalf("encrypting: %v", err)
		}
		ballots[voter] = ballot{c, proof}
	}

	// mallory copies alice's ballot
	ballots["mallory"] = ballots["alice"]

	var tally *encrypted.Ciphertext
	for voter, b := range ballots {
		valid, err := public.VerifyCiphertext(b.c, b.proof, nil, voter)
		if err != nil {
			t.Fatalf("verifying: %v", err)
		}
		if _, honest := votes[voter]; valid != honest {
			t.Fatalf("ballot of %s is valid = %v", voter, valid)
		}
		if !valid {
			continue
		}
		if tally == nil {
			tally = b.c
		} else {
			tally = cfAdd(t, tally, b.c)
		}
	}

	var partials []*lightphe.PartialDecryption
	for _, keys := range shareKeys[:2] {
		partial, err := mustBuild(t, phe.ExponentialElGamal, lightphe.WithKeys(keys)).PartialDecrypt(tally, true)
		if err != nil {
			t.Fatalf("partial decryption: %v", err)
		}
		partials = append(partials, partial)
	}
	if m := mustCombine(t, public, tally, partials, true); m.Int64() != 3 {
		t.Fatalf("tally is %s, want 3", m)
	}
}

func partyValues(parties int, base int64) []*big.Int {
	values := make([]*big.Int, parties)
	for k := range values {
		values[k] = new(big.Int).Exp(big.NewInt(base), big.NewInt(int64(k)), nil)
	}
	return values
}

func countVotes(result *big.Int, parties []string, base int64) map[string]int64 {
	counts := map[string]int64{}
	digits := new(big.Int).Set(result)
	for _, party := range parties {
		digit := new(big.Int)
		digits.DivMod(digits, big.NewInt(base), digit)
		counts[party] = digit.Int64()
	}
	return counts
}

func assertCounts(t *testing.T, got, want map[string]int64) {
	t.Helper()
	for party, count := range want {
		if got[party] != count {
			t.Fatalf("votes are %v, want %v", got, want)
		}
	}
}

func TestEncryptedElectionOfParties(t *testing.T) {
	// a vote for party k is encrypted as base^k, so the tally keeps the count
	// of each party in its own digit in base 100
	authority := mustBuild(t, phe.Paillier, lightphe.WithKeySize(128))
	public := publicOf(t, authority)
	parties := []string{"red", "green", "blue"}
	values := partyValues(len(parties), 100)
	index := map[string]int{"red": 0, "green": 1, "blue": 2}

	votes := map[string]string{"alice": "red", "bob": "blue", "carol": "red", "dave": "red", "erin": "blue"}
	type ballot struct {
		c     *encrypted.Ciphertext
		proof *lightphe.ZKProof
	}
	ballots := map[string]ballot{}
	for voter, party := range votes {
		c, proof, err := public.EncryptWithProof(values[index[party]], values, voter)
		if err != nil {
			t.Fatalf("encrypting: %v", err)
		}
		ballots[voter] = ballot{c, proof}
	}

	// mallory copies alice's ballot
	ballots["mallory"] = ballots["alice"]

	// oscar cannot vote twice for a party, nor reuse a proof of a single vote
	// for a doubled ballot
	if _, _, err := public.EncryptWithProof(new(big.Int).Mul(values[1], big.NewInt(2)), values, "oscar"); err == nil ||
		!strings.Contains(err.Error(), "one of the allowed values") {
		t.Fatalf("a double vote returned %v", err)
	}
	oscar, oscarProof, err := public.EncryptWithProof(values[1], values, "oscar")
	if err != nil {
		t.Fatalf("encrypting: %v", err)
	}
	ballots["oscar"] = ballot{cfAdd(t, oscar, oscar), oscarProof}

	var tally *encrypted.Ciphertext
	for voter, b := range ballots {
		valid, err := public.VerifyCiphertext(b.c, b.proof, values, voter)
		if err != nil {
			t.Fatalf("verifying: %v", err)
		}
		if _, honest := votes[voter]; valid != honest {
			t.Fatalf("ballot of %s is valid = %v", voter, valid)
		}
		if !valid {
			continue
		}
		if tally == nil {
			tally = b.c
		} else {
			tally = cfAdd(t, tally, b.c)
		}
	}

	// authority decrypts the tally with a proof, and anyone verifies it
	result, proof, err := authority.DecryptWithProof(tally)
	if err != nil {
		t.Fatalf("decrypting: %v", err)
	}
	valid, err := public.VerifyDecryption(tally, result, proof)
	assertValid(t, "tally", valid, err, true)
	assertCounts(t, countVotes(result, parties, 100), map[string]int64{"red": 3, "green": 0, "blue": 2})
}

func TestTrusteesTallyElectionOfParties(t *testing.T) {
	// a cheating trustee shifts its partial decryption to add 50 votes to its
	// own party. Without proofs, the forged tally is accepted silently. With
	// proofs, it is discarded.
	authority := mustBuild(t, phe.Paillier, lightphe.WithKeySize(128), lightphe.WithSafePrimes(true))
	publicKey, shareKeys, err := authority.GenerateThresholdKeys(2, 3)
	if err != nil {
		t.Fatalf("generating threshold keys: %v", err)
	}
	public := mustBuild(t, phe.Paillier, lightphe.WithKeys(publicKey))
	var trustees []*lightphe.Cryptosystem
	for _, keys := range shareKeys {
		trustees = append(trustees, mustBuild(t, phe.Paillier, lightphe.WithKeys(keys)))
	}

	parties := []string{"red", "green", "blue"}
	values := partyValues(len(parties), 100)
	var tally *encrypted.Ciphertext
	for i, party := range []int{0, 2, 0, 1, 0} {
		c, proof, err := public.EncryptWithProof(values[party], values, i)
		if err != nil {
			t.Fatalf("encrypting: %v", err)
		}
		valid, err := public.VerifyCiphertext(c, proof, values, i)
		assertValid(t, "ballot", valid, err, true)
		if tally == nil {
			tally = c
		} else {
			tally = cfAdd(t, tally, c)
		}
	}

	partials := partialDecrypt(t, trustees, tally, true)
	assertCounts(t, countVotes(mustCombine(t, public, tally, partials[:2], true), parties, 100),
		map[string]int64{"red": 3, "green": 1, "blue": 1})

	// trustee 1 of blue party knows that trustee 2 joins the decryption, so it
	// finds the shift adding 50 votes to blue from public lagrange coefficients
	n := public.PlaintextModulo()
	modulo := public.Scheme().CiphertextModulo()
	delta := big.NewInt(6)
	coefficient := thresholdutil.ScaledLagrangeCoefficient(1, []int{1, 2}, delta)
	shift := new(big.Int).Mul(big.NewInt(50), values[2])
	shift.Mul(shift, big.NewInt(4)).Mul(shift, delta).Mul(shift, delta)
	shift.Mul(shift, new(big.Int).ModInverse(new(big.Int).Mod(new(big.Int).Mul(big.NewInt(2), coefficient), n), n)).Mod(shift, n)
	value, _ := phe.AsInt(partials[0].Value)
	forgedValue := new(big.Int).Exp(new(big.Int).Add(n, big.NewInt(1)), shift, modulo)
	forgedValue.Mul(forgedValue, value).Mod(forgedValue, modulo)
	forged := *partials[0]
	forged.Value = phe.Int{V: forgedValue}

	// without proofs, blue gets 50 more votes silently
	assertCounts(t, countVotes(mustCombine(t, public, tally, []*lightphe.PartialDecryption{&forged, partials[1]}, false), parties, 100),
		map[string]int64{"red": 3, "green": 1, "blue": 51})

	// with proofs, the forged partial decryption is discarded
	assertCounts(t, countVotes(mustCombine(t, public, tally, []*lightphe.PartialDecryption{&forged, partials[1], partials[2]}, true), parties, 100),
		map[string]int64{"red": 3, "green": 1, "blue": 1})
}

func TestOneHotElection(t *testing.T) {
	// voters cast one-hot ballots, slots are summed homomorphically, and
	// trustees decrypt the count of each party with proofs
	authority := mustBuild(t, phe.ExponentialElGamal, lightphe.WithKeySize(128), lightphe.WithPrimeOrder(true))
	publicKey, shareKeys, err := authority.GenerateThresholdKeys(2, 3)
	if err != nil {
		t.Fatalf("generating threshold keys: %v", err)
	}
	public := mustBuild(t, phe.ExponentialElGamal, lightphe.WithKeys(publicKey))
	trustees := []*lightphe.Cryptosystem{
		mustBuild(t, phe.ExponentialElGamal, lightphe.WithKeys(shareKeys[0])),
		mustBuild(t, phe.ExponentialElGamal, lightphe.WithKeys(shareKeys[1])),
	}

	parties := []string{"red", "green", "blue", "yellow", "purple", "orange", "black", "white"}
	index := map[string]int{}
	for i, party := range parties {
		index[party] = i
	}
	votes := map[string]string{"alice": "red", "bob": "blue", "carol": "red", "dave": "white", "erin": "blue", "frank": "red"}
	type ballot struct {
		slots []*encrypted.Ciphertext
		proof *lightphe.OneHotProof
	}
	ballots := map[string]ballot{}
	for voter, party := range votes {
		slots, proof, err := public.EncryptOneHot(index[party], len(parties), voter)
		if err != nil {
			t.Fatalf("encrypting: %v", err)
		}
		ballots[voter] = ballot{slots, proof}
	}

	// mallory copies alice's ballot, and oscar reorders bob's slots to vote
	// for another party
	ballots["mallory"] = ballots["alice"]
	bob := ballots["bob"]
	ballots["oscar"] = ballot{append(append([]*encrypted.Ciphertext{}, bob.slots[1:]...), bob.slots[0]), bob.proof}

	var tally []*encrypted.Ciphertext
	for voter, b := range ballots {
		valid, err := public.VerifyOneHot(b.slots, b.proof, voter)
		if err != nil {
			t.Fatalf("verifying: %v", err)
		}
		if _, honest := votes[voter]; valid != honest {
			t.Fatalf("ballot of %s is valid = %v", voter, valid)
		}
		if !valid {
			continue
		}
		if tally == nil {
			tally = b.slots
			continue
		}
		for i := range tally {
			tally[i] = cfAdd(t, tally[i], b.slots[i])
		}
	}

	want := map[string]int64{"red": 3, "blue": 2, "white": 1}
	for i, party := range parties {
		m := mustCombine(t, public, tally[i], partialDecrypt(t, trustees, tally[i], true), true)
		if m.Int64() != want[party] {
			t.Fatalf("%s has %s votes, want %d", party, m, want[party])
		}
	}
}

func TestCheatingOneHotBallotsAreRejected(t *testing.T) {
	// a cheating voter builds its ballot slot by slot, proving whatever it can
	for _, tc := range membershipCases {
		cs := mustBuild(t, tc.alg, tc.opts...)
		prover := cs.Scheme().(zkp.Prover)
		const options = 3
		context := func(slot interface{}) []interface{} { return []interface{}{"one-hot", options, slot, nil} }

		cheat := func(slots []int64) ([]*encrypted.Ciphertext, *lightphe.OneHotProof) {
			var ciphertexts []*encrypted.Ciphertext
			var randomKeys []*big.Int
			proof := &lightphe.OneHotProof{}
			var total phe.Value
			for slot, plaintext := range slots {
				r, _ := prover.GenerateRandomKey()
				value, err := prover.EncryptWith(big.NewInt(plaintext), r)
				if err != nil {
					t.Fatalf("encrypting: %v", err)
				}
				// a slot of 2 cannot be proven to be 0 or 1, so prove it as 1
				claimed := plaintext
				if claimed > 1 {
					claimed = 1
				}
				slotProof, err := prover.ProveMembership(value, big.NewInt(claimed), r, bigs(0, 1), context(slot))
				if err != nil {
					t.Fatalf("proving: %v", err)
				}
				proof.Slots = append(proof.Slots, slotProof)
				ciphertexts = append(ciphertexts, cs.CreateCiphertext(value))
				randomKeys = append(randomKeys, r)
				if total == nil {
					total = value
				} else if total, err = prover.Add(total, value); err != nil {
					t.Fatalf("adding: %v", err)
				}
			}
			// claim that the sum is 1 although it is not
			sumProof, err := prover.ProveMembership(total, big.NewInt(1), prover.CombineRandomKeys(randomKeys), bigs(1), context("sum"))
			if err != nil {
				t.Fatalf("proving: %v", err)
			}
			proof.Sum = sumProof
			return ciphertexts, proof
		}

		// an honest ballot built in the same way is valid
		slots, proof := cheat([]int64{0, 1, 0})
		valid, err := cs.VerifyOneHot(slots, proof, nil)
		assertValid(t, string(tc.alg)+" honest ballot", valid, err, true)

		// voting for two parties, voting twice for a party, or abstaining is
		// rejected
		for _, cheated := range [][]int64{{1, 1, 0}, {2, 0, 0}, {0, 0, 0}} {
			slots, proof := cheat(cheated)
			valid, err := cs.VerifyOneHot(slots, proof, nil)
			assertValid(t, string(tc.alg)+" cheating ballot", valid, err, false)
		}
	}
}

func TestOneHotInvalidInputs(t *testing.T) {
	cs := mustBuild(t, phe.Paillier, lightphe.WithKeySize(128))
	if _, _, err := cs.EncryptOneHot(3, 3, nil); err == nil || !strings.Contains(err.Error(), "choice must be in") {
		t.Fatalf("choice out of range returned %v", err)
	}
	if _, _, err := cs.EncryptOneHot(0, 0, nil); err == nil || !strings.Contains(err.Error(), "at least 1") {
		t.Fatalf("no options returned %v", err)
	}

	slots, proof, err := cs.EncryptOneHot(0, 1, nil)
	if err != nil {
		t.Fatalf("encrypting: %v", err)
	}
	valid, err := cs.VerifyOneHot(slots, proof, nil)
	assertValid(t, "single option", valid, err, true)
	valid, err = cs.VerifyOneHot(nil, proof, nil)
	assertValid(t, "no slots", valid, err, false)
	valid, err = cs.VerifyOneHot(slots, &lightphe.OneHotProof{}, nil)
	assertValid(t, "empty proof", valid, err, false)
	valid, err = cs.VerifyOneHot(slots, nil, nil)
	assertValid(t, "nil proof", valid, err, false)
}
