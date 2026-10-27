package lightphe_test

import (
	"encoding/json"
	"errors"
	"math"
	"math/big"
	"strings"
	"testing"

	"github.com/serengil/lightphe-go/lightphe"
	"github.com/serengil/lightphe-go/lightphe/encrypted"
	"github.com/serengil/lightphe-go/lightphe/phe"
)

const (
	threshold = 3
	parties   = 5
)

var thresholdAlgorithms = []struct {
	alg     phe.Algorithm
	keySize int
}{
	{phe.ExponentialElGamal, testKeySize},
	{phe.EllipticCurveElGamal, 0},
	{phe.Paillier, testKeySize},
	{phe.DamgardJurik, testKeySize},
}

// buildThreshold builds a dealer, splits its private key, and returns the
// public cryptosystem having threshold parameters and the shareholders.
func buildThreshold(t *testing.T, alg phe.Algorithm, keySize int, opts ...lightphe.Option) (
	*lightphe.Cryptosystem, []*lightphe.Cryptosystem) {
	t.Helper()
	opts = append([]lightphe.Option{lightphe.WithKeySize(keySize)}, opts...)
	if alg == phe.ElGamal || alg == phe.ExponentialElGamal {
		opts = append(opts, lightphe.WithPrimeOrder(true))
	}
	dealer := mustBuild(t, alg, opts...)
	publicKey, shareKeys, err := dealer.GenerateThresholdKeys(threshold, parties)
	if err != nil {
		t.Fatalf("generating threshold keys: %v", err)
	}
	shareholders := make([]*lightphe.Cryptosystem, len(shareKeys))
	for i, keys := range shareKeys {
		shareholders[i] = mustBuild(t, alg, lightphe.WithKeys(keys))
	}
	return mustBuild(t, alg, lightphe.WithKeys(publicKey)), shareholders
}

func partialDecrypt(t *testing.T, shareholders []*lightphe.Cryptosystem, c *encrypted.Ciphertext, prove bool) []*lightphe.PartialDecryption {
	t.Helper()
	out := make([]*lightphe.PartialDecryption, len(shareholders))
	for i, shareholder := range shareholders {
		partial, err := shareholder.PartialDecrypt(c, prove)
		if err != nil {
			t.Fatalf("partial decryption: %v", err)
		}
		out[i] = partial
	}
	return out
}

func mustCombine(t *testing.T, cs *lightphe.Cryptosystem, c *encrypted.Ciphertext, partials []*lightphe.PartialDecryption,
	verify bool) *big.Int {
	t.Helper()
	m, err := cs.CombinePartialDecryptions(c, partials, verify)
	if err != nil {
		t.Fatalf("combining partial decryptions: %v", err)
	}
	return m
}

// subsets returns every subset of size k of [0, n).
func subsets(n, k int) [][]int {
	if k == 0 {
		return [][]int{{}}
	}
	var out [][]int
	for first := 0; first <= n-k; first++ {
		for _, rest := range subsets(n-first-1, k-1) {
			subset := []int{first}
			for _, i := range rest {
				subset = append(subset, first+1+i)
			}
			out = append(out, subset)
		}
	}
	return out
}

func TestAdditiveThresholdDecryption(t *testing.T) {
	for _, tc := range thresholdAlgorithms {
		tc := tc
		t.Run(tc.alg.String(), func(t *testing.T) {
			t.Parallel()
			public, shareholders := buildThreshold(t, tc.alg, tc.keySize)

			const m1, m2, k = 17, 21, 3
			c1, c2 := mustEncrypt(t, public, m1), mustEncrypt(t, public, m2)

			// homomorphic operations before threshold decryption
			for _, tt := range []struct {
				c    *encrypted.Ciphertext
				want int64
			}{{c1, m1}, {cfAdd(t, c1, c2), m1 + m2}, {cfScale(t, c1, big.NewInt(k)), m1 * k}} {
				partials := partialDecrypt(t, shareholders, tt.c, false)

				// any threshold many shareholders can decrypt
				for _, subset := range subsets(parties, threshold) {
					selected := make([]*lightphe.PartialDecryption, len(subset))
					for i, index := range subset {
						selected[i] = partials[index]
					}
					if m := mustCombine(t, public, tt.c, selected, false); m.Int64() != tt.want {
						t.Fatalf("subset %v decrypted %s, want %d", subset, m, tt.want)
					}
				}

				// more than threshold many partial decryptions are fine as well
				if m := mustCombine(t, public, tt.c, partials, false); m.Int64() != tt.want {
					t.Fatalf("all partial decryptions decrypted %s, want %d", m, tt.want)
				}

				// less than threshold many partial decryptions are rejected
				if _, err := public.CombinePartialDecryptions(tt.c, partials[:threshold-1], false); err == nil ||
					!strings.Contains(err.Error(), "at least") {
					t.Fatalf("too few partial decryptions returned %v", err)
				}
			}

			// regenerated ciphertexts are decrypted as well
			c3, err := public.RegenerateCiphertext(c1)
			if err != nil {
				t.Fatalf("regenerating: %v", err)
			}
			if m := mustCombine(t, public, c3, partialDecrypt(t, shareholders[:threshold], c3, false), false); m.Int64() != m1 {
				t.Fatalf("regenerated ciphertext decrypted %s", m)
			}
		})
	}
}

func TestMultiplicativeElGamalThresholdDecryption(t *testing.T) {
	public, shareholders := buildThreshold(t, phe.ElGamal, testKeySize)
	c := cfMul(t, mustEncrypt(t, public, 17), mustEncrypt(t, public, 21))
	partials := partialDecrypt(t, shareholders, c, false)
	for _, subset := range subsets(parties, threshold) {
		selected := []*lightphe.PartialDecryption{partials[subset[0]], partials[subset[1]], partials[subset[2]]}
		if m := mustCombine(t, public, c, selected, false); m.Int64() != 17*21 {
			t.Fatalf("decrypted %s, want %d", m, 17*21)
		}
	}
}

func TestThresholdNegativeAndFloatValues(t *testing.T) {
	for _, alg := range []phe.Algorithm{phe.Paillier, phe.DamgardJurik} {
		public, shareholders := buildThreshold(t, alg, testKeySize)
		modulo := public.PlaintextModulo()

		c := mustEncrypt(t, public, -5)
		want := new(big.Int).Sub(modulo, big.NewInt(5))
		if m := mustCombine(t, public, c, partialDecrypt(t, shareholders[:threshold], c, false), false); m.Cmp(want) != 0 {
			t.Fatalf("%s decrypted %s, want %s", alg, m, want)
		}

		// float is restored as dividend * divisor^-1 mod modulo, same as decrypt
		c, err := public.EncryptFloat(1.5)
		if err != nil {
			t.Fatalf("encrypting a float: %v", err)
		}
		want = new(big.Int).ModInverse(big.NewInt(10), modulo)
		want.Mul(want, big.NewInt(15)).Mod(want, modulo)
		if m := mustCombine(t, public, c, partialDecrypt(t, shareholders[:threshold], c, false), false); m.Cmp(want) != 0 {
			t.Fatalf("%s decrypted %s, want %s", alg, m, want)
		}
	}
}

func TestThresholdTensors(t *testing.T) {
	public, shareholders := buildThreshold(t, phe.Paillier, 128)
	tensor := []float64{1.005, 2.05, -3.5, 4, 0}
	encryptedTensor, err := public.EncryptTensor(tensor)
	if err != nil {
		t.Fatalf("encrypting a tensor: %v", err)
	}

	var partials [][]lightphe.TensorPartialDecryption
	for _, shareholder := range shareholders[1:4] {
		p, err := shareholder.PartialDecryptTensor(encryptedTensor, false)
		if err != nil {
			t.Fatalf("partial decryption: %v", err)
		}
		partials = append(partials, p)
	}
	restored, err := public.CombineTensorPartialDecryptions(encryptedTensor, partials, false)
	if err != nil {
		t.Fatalf("combining: %v", err)
	}
	for i, x := range tensor {
		if math.Abs(restored[i]-x) > 1e-3 {
			t.Fatalf("element %d is %v, want %v", i, restored[i], x)
		}
	}
}

func TestThresholdKeysDoNotHavePrivateKey(t *testing.T) {
	dealer := mustBuild(t, phe.Paillier, lightphe.WithKeySize(testKeySize))
	publicKey, shareKeys, err := dealer.GenerateThresholdKeys(threshold, parties)
	if err != nil {
		t.Fatalf("generating threshold keys: %v", err)
	}
	for _, keys := range append([][]byte{publicKey}, shareKeys...) {
		if strings.Contains(string(keys), "private_key") || strings.Contains(string(keys), "phi") {
			t.Fatalf("keys leak the private key: %s", keys)
		}
	}
	if strings.Contains(string(publicKey), "threshold_key") {
		t.Fatal("public key has a share")
	}

	// shareholders cannot decrypt alone
	public := mustBuild(t, phe.Paillier, lightphe.WithKeys(publicKey))
	c := mustEncrypt(t, public, 42)
	shareholders := make([]*lightphe.Cryptosystem, len(shareKeys))
	for i, keys := range shareKeys {
		shareholders[i] = mustBuild(t, phe.Paillier, lightphe.WithKeys(keys))
		if _, err := shareholders[i].Decrypt(c); !errors.Is(err, phe.ErrMissingPrivateKey) {
			t.Fatalf("shareholder decrypted alone: %v", err)
		}
	}

	// a cryptosystem without a share cannot decrypt partially
	if _, err := public.PartialDecrypt(c, false); err == nil || !strings.Contains(err.Error(), "threshold key") {
		t.Fatalf("partial decryption without a share returned %v", err)
	}

	// keys of shareholders and partial decryptions survive a json round trip,
	// and exporting public keys drops shares
	exported, err := shareholders[0].Keys(false)
	if err != nil {
		t.Fatalf("exporting: %v", err)
	}
	publicOnly, err := shareholders[0].Keys(true)
	if err != nil {
		t.Fatalf("exporting: %v", err)
	}
	if strings.Contains(string(publicOnly), "threshold_key") {
		t.Fatal("exported public key has a share")
	}
	restored := mustBuild(t, phe.Paillier, lightphe.WithKeys(exported))
	partials := append([]*lightphe.PartialDecryption{}, partialDecrypt(t, []*lightphe.Cryptosystem{restored}, c, false)...)
	partials = append(partials, partialDecrypt(t, shareholders[1:threshold], c, false)...)
	data, err := json.Marshal(partials)
	if err != nil {
		t.Fatalf("marshaling: %v", err)
	}
	var decoded []*lightphe.PartialDecryption
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshaling: %v", err)
	}
	if m := mustCombine(t, public, c, decoded, false); m.Int64() != 42 {
		t.Fatalf("decrypted %s, want 42", m)
	}
}

func TestThresholdInvalidInputs(t *testing.T) {
	public, shareholders := buildThreshold(t, phe.Paillier, testKeySize)
	c := mustEncrypt(t, public, 7)
	partials := partialDecrypt(t, shareholders, c, false)

	// same party counted once
	if _, err := public.CombinePartialDecryptions(c, []*lightphe.PartialDecryption{partials[0], partials[0], partials[0]}, false); err == nil ||
		!strings.Contains(err.Error(), "distinct") {
		t.Fatalf("repeated partial decryptions returned %v", err)
	}

	// conflicting partial decryptions of same party
	value, _ := phe.AsInt(partials[0].Value)
	forged := &lightphe.PartialDecryption{Index: partials[0].Index, Value: phe.Int{V: new(big.Int).Add(value, big.NewInt(1))}}
	if _, err := public.CombinePartialDecryptions(c, []*lightphe.PartialDecryption{partials[0], forged, partials[1]}, false); err == nil ||
		!strings.Contains(err.Error(), "conflicting") {
		t.Fatalf("conflicting partial decryptions returned %v", err)
	}

	// unknown party
	unknown := &lightphe.PartialDecryption{Index: parties + 1, Value: phe.Int{V: big.NewInt(1)}}
	if _, err := public.CombinePartialDecryptions(c, []*lightphe.PartialDecryption{partials[0], partials[1], unknown}, false); err == nil ||
		!strings.Contains(err.Error(), "index") {
		t.Fatalf("an unknown party returned %v", err)
	}

	for _, tt := range [][2]int{{0, 5}, {6, 5}} {
		cs := mustBuild(t, phe.Paillier, lightphe.WithKeySize(testKeySize))
		if _, _, err := cs.GenerateThresholdKeys(tt[0], tt[1]); err == nil {
			t.Fatalf("threshold %d of %d parties was accepted", tt[0], tt[1])
		}
	}

	// dealer must have the private key
	if _, _, err := public.GenerateThresholdKeys(threshold, parties); !errors.Is(err, phe.ErrMissingPrivateKey) {
		t.Fatalf("generating threshold keys without a private key returned %v", err)
	}
}

func TestThresholdOfOneAndAllParties(t *testing.T) {
	for _, tt := range [][2]int{{1, 3}, {3, 3}} {
		dealer := mustBuild(t, phe.ExponentialElGamal, lightphe.WithKeySize(testKeySize), lightphe.WithPrimeOrder(true))
		publicKey, shareKeys, err := dealer.GenerateThresholdKeys(tt[0], tt[1])
		if err != nil {
			t.Fatalf("generating threshold keys: %v", err)
		}
		public := mustBuild(t, phe.ExponentialElGamal, lightphe.WithKeys(publicKey))
		c := mustEncrypt(t, public, 10)
		var partials []*lightphe.PartialDecryption
		for _, keys := range shareKeys {
			partial, err := mustBuild(t, phe.ExponentialElGamal, lightphe.WithKeys(keys)).PartialDecrypt(c, false)
			if err != nil {
				t.Fatalf("partial decryption: %v", err)
			}
			partials = append(partials, partial)
		}
		if m := mustCombine(t, public, c, partials[:tt[0]], false); m.Int64() != 10 {
			t.Fatalf("decrypted %s, want 10", m)
		}
	}
}

func TestElGamalKeysWithoutPrimeOrderAreRejected(t *testing.T) {
	for _, alg := range []phe.Algorithm{phe.ElGamal, phe.ExponentialElGamal} {
		cs := mustBuild(t, alg, lightphe.WithKeySize(testKeySize))
		keys, _ := cs.Keys(true)
		if strings.Contains(string(keys), `"q"`) {
			t.Fatal("default keys have q")
		}
		if _, _, err := cs.GenerateThresholdKeys(threshold, parties); err == nil || !strings.Contains(err.Error(), "prime order") {
			t.Fatalf("%s threshold keys without a prime order returned %v", alg, err)
		}
		assertDecrypts(t, cs, mustEncrypt(t, cs, 2), 2)
	}
}

func TestPrimeOrderElGamalKeys(t *testing.T) {
	for _, alg := range []phe.Algorithm{phe.ElGamal, phe.ExponentialElGamal} {
		cs := mustBuild(t, alg, lightphe.WithKeySize(testKeySize), lightphe.WithPrimeOrder(true))
		data, _ := cs.Keys(true)
		var keys struct {
			PublicKey struct{ P, G, Q *big.Int } `json:"public_key"`
		}
		if err := json.Unmarshal(data, &keys); err != nil {
			t.Fatalf("decoding keys: %v", err)
		}
		p, g, q := keys.PublicKey.P, keys.PublicKey.G, keys.PublicKey.Q
		if new(big.Int).Mod(new(big.Int).Sub(p, big.NewInt(1)), q).Sign() != 0 {
			t.Fatal("q does not divide p - 1")
		}
		if g.Cmp(big.NewInt(1)) == 0 || new(big.Int).Exp(g, q, p).Cmp(big.NewInt(1)) != 0 {
			t.Fatal("g does not have order q")
		}

		// classic usage works with prime order keys as well
		c1, c2 := mustEncrypt(t, cs, 17), mustEncrypt(t, cs, 21)
		if alg == phe.ElGamal {
			assertDecrypts(t, cs, cfMul(t, c1, c2), 17*21)
		} else {
			assertDecrypts(t, cs, cfAdd(t, c1, c2), 17+21)
			assertDecrypts(t, cs, cfScale(t, c1, big.NewInt(3)), 17*3)
		}
	}
}

func TestThresholdUnsupportedAlgorithms(t *testing.T) {
	for _, alg := range []phe.Algorithm{phe.RSA, phe.OkamotoUchiyama, phe.GoldwasserMicali} {
		cs := mustBuild(t, alg, lightphe.WithKeySize(testKeySize))
		_, _, err := cs.GenerateThresholdKeys(threshold, parties)
		assertUnsupported(t, string(alg), err)
	}

	// ciphertexts supporting multiplication cannot be decrypted partially
	public, shareholders := buildThreshold(t, phe.Paillier, testKeySize)
	keys, _ := public.Keys(true)
	boosted := mustBuild(t, phe.Paillier, lightphe.WithKeys(keys), lightphe.WithBoost(lightphe.CatalanoFiore))
	if _, err := shareholders[0].PartialDecrypt(mustEncrypt(t, boosted, 1), false); !errors.Is(err, lightphe.ErrBoostedThreshold) {
		t.Fatalf("partial decryption of a boosted ciphertext returned %v", err)
	}
}

func TestSealedBidAuction(t *testing.T) {
	for _, tc := range []struct {
		alg  phe.Algorithm
		opts []lightphe.Option
	}{
		{phe.ExponentialElGamal, []lightphe.Option{lightphe.WithKeySize(128), lightphe.WithPrimeOrder(true)}},
		{phe.Paillier, []lightphe.Option{lightphe.WithKeySize(128)}},
	} {
		// bidders submit encrypted bids with proofs of knowledge, so a bidder
		// copying someone else's bid cannot outbid without knowing it
		auctioneer := mustBuild(t, tc.alg, tc.opts...)
		publicKey, _ := auctioneer.Keys(true)
		public := mustBuild(t, tc.alg, lightphe.WithKeys(publicKey))

		type submission struct {
			bid   *encrypted.Ciphertext
			proof *lightphe.ZKProof
		}
		bids := map[string]int64{"alice": 950, "bob": 870, "carol": 910}
		submissions := map[string]submission{}
		for bidder, bid := range bids {
			c, proof, err := public.EncryptWithProofOfKnowledge(big.NewInt(bid), bidder)
			if err != nil {
				t.Fatalf("encrypting with a proof: %v", err)
			}
			submissions[bidder] = submission{c, proof}
		}

		// mallory adds 1 to alice's bid and reuses her proof
		submissions["mallory"] = submission{cfAdd(t, submissions["alice"].bid, mustEncrypt(t, public, 1)), submissions["alice"].proof}

		// oscar re-randomizes bob's bid
		rerandomized, err := public.RegenerateCiphertext(submissions["bob"].bid)
		if err != nil {
			t.Fatalf("regenerating: %v", err)
		}
		submissions["oscar"] = submission{rerandomized, submissions["bob"].proof}

		// trent copies carol's submission as is
		submissions["trent"] = submissions["carol"]

		opened := map[string]int64{}
		for bidder, s := range submissions {
			valid, err := public.VerifyKnowledge(s.bid, s.proof, bidder)
			if err != nil {
				t.Fatalf("verifying: %v", err)
			}
			if _, honest := bids[bidder]; valid != honest {
				t.Fatalf("%s: proof of %s is valid = %v", tc.alg, bidder, valid)
			}
			if !valid {
				continue
			}
			// auctioneer decrypts valid bids with proofs, and anyone verifies
			// them
			amount, proof, err := auctioneer.DecryptWithProof(s.bid)
			if err != nil {
				t.Fatalf("decrypting with a proof: %v", err)
			}
			if ok, err := public.VerifyDecryption(s.bid, amount, proof); err != nil || !ok {
				t.Fatalf("proof of decryption is rejected: %v", err)
			}
			opened[bidder] = amount.Int64()
		}
		for bidder, bid := range bids {
			if opened[bidder] != bid {
				t.Fatalf("bid of %s is %d, want %d", bidder, opened[bidder], bid)
			}
		}
	}
}
