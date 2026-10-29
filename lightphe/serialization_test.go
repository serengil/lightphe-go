package lightphe_test

import (
	"encoding/json"
	"errors"
	"math"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/serengil/lightphe-go/lightphe"
	"github.com/serengil/lightphe-go/lightphe/encrypted"
	"github.com/serengil/lightphe-go/lightphe/phe"
)

// publicParty builds a cryptosystem having the public key of cs only.
func publicParty(t *testing.T, cs *lightphe.Cryptosystem, opts ...lightphe.Option) *lightphe.Cryptosystem {
	t.Helper()
	keys, err := cs.Keys(true)
	if err != nil {
		t.Fatalf("exporting the public key: %v", err)
	}
	return mustBuild(t, cs.Algorithm(), append([]lightphe.Option{lightphe.WithKeys(keys)}, opts...)...)
}

func mustSerialize(t *testing.T, cs *lightphe.Cryptosystem, item interface{}) []byte {
	t.Helper()
	data, err := cs.Serialize(item)
	if err != nil {
		t.Fatalf("serializing: %v", err)
	}
	return data
}

func mustDeserialize(t *testing.T, cs *lightphe.Cryptosystem, data []byte, target interface{}) {
	t.Helper()
	if err := cs.Deserialize(data, target); err != nil {
		t.Fatalf("deserializing: %v", err)
	}
}

// transfer serializes item on sender side and deserializes it into target on
// receiver side.
func transfer(t *testing.T, sender, receiver *lightphe.Cryptosystem, item, target interface{}) {
	t.Helper()
	mustDeserialize(t, receiver, mustSerialize(t, sender, item), target)
}

func TestSerializationRoundTripThroughUntrustedParty(t *testing.T) {
	for _, tc := range restoreCases() {
		tc := tc
		t.Run(tc.alg.String(), func(t *testing.T) {
			t.Parallel()
			owner := mustBuild(t, tc.alg, tc.opts...)
			cloud := publicParty(t, owner)

			// owner sends ciphertexts, and cloud computes on them with the public key only
			c1, c2 := mustEncrypt(t, owner, restoreM1), mustEncrypt(t, owner, restoreM2)
			data := mustSerialize(t, owner, c1)
			if strings.Contains(string(data), "private") {
				t.Fatal("serialized ciphertext has private key")
			}
			var restored1, restored2 *encrypted.Ciphertext
			mustDeserialize(t, cloud, data, &restored1)
			transfer(t, owner, cloud, c2, &restored2)
			if !restored1.Value.Equal(c1.Value) {
				t.Fatalf("restored %s, want %s", restored1.Value, c1.Value)
			}
			if restored1.Scheme().HasPrivateKey() {
				t.Fatal("restored ciphertext has private key")
			}

			result, err := tc.evaluate(restored1, restored2)
			if err != nil {
				t.Fatalf("evaluating: %v", err)
			}

			// cloud sends the result back to the owner
			var received *encrypted.Ciphertext
			transfer(t, cloud, owner, result, &received)
			want := tc.want(owner.PlaintextModulo())
			if got := mustDecrypt(t, owner, received); got.Cmp(want) != 0 {
				t.Fatalf("decrypted %s, want %s", got, want)
			}
		})
	}
}

func TestSerializedMultipliedCiphertexts(t *testing.T) {
	// multiplied ciphertexts of these algorithms have other shapes, e.g. a
	// point on the curve for Boneh-Goh-Nissim becomes an element of F_p^2
	for _, tc := range []struct {
		alg  phe.Algorithm
		opts []lightphe.Option
	}{
		{phe.BonehGohNissim, []lightphe.Option{lightphe.WithKeySize(64)}},
		{phe.FreemanBonehGohNissim, []lightphe.Option{lightphe.WithKeySize(64)}},
		{phe.BrakerskiVaikuntanathan, []lightphe.Option{lightphe.WithKeySize(64)}},
	} {
		owner := mustBuild(t, tc.alg, tc.opts...)
		cloud := publicParty(t, owner)

		var c1, c2 *encrypted.Ciphertext
		transfer(t, owner, cloud, mustEncrypt(t, owner, 3), &c1)
		transfer(t, owner, cloud, mustEncrypt(t, owner, 4), &c2)
		product, err := c1.Multiply(c2)
		if err != nil {
			t.Fatalf("%s: multiplying: %v", tc.alg, err)
		}
		var received *encrypted.Ciphertext
		transfer(t, cloud, owner, product, &received)
		if !received.Value.Equal(product.Value) {
			t.Fatalf("%s: restored %T, want %T", tc.alg, received.Value, product.Value)
		}
		assertDecrypts(t, owner, received, 12)
	}
}

func TestSerializedStructuresArePreserved(t *testing.T) {
	cs := mustBuild(t, phe.Paillier, lightphe.WithKeySize(testKeySize))
	c := mustEncrypt(t, cs, 5)

	type message struct {
		Ciphertexts []*encrypted.Ciphertext            `json:"ciphertexts"`
		ByIndex     map[int]*encrypted.Ciphertext      `json:"by_index"`
		Pairs       [][2]encrypted.Ciphertext          `json:"pairs"`
		Named       map[string][]*encrypted.Ciphertext `json:"named"`
		Missing     *encrypted.Ciphertext              `json:"missing"`
		Text        string                             `json:"text"`
	}
	item := message{
		Ciphertexts: []*encrypted.Ciphertext{c, c},
		ByIndex:     map[int]*encrypted.Ciphertext{1: c, 2: c},
		Pairs:       [][2]encrypted.Ciphertext{{*c, *c}},
		Named:       map[string][]*encrypted.Ciphertext{"x": {c}},
		Text:        "plain",
	}
	var restored message
	transfer(t, cs, cs, item, &restored)

	assertDecrypts(t, cs, restored.Ciphertexts[1], 5)
	assertDecrypts(t, cs, restored.ByIndex[2], 5)
	assertDecrypts(t, cs, &restored.Pairs[0][1], 5)
	assertDecrypts(t, cs, restored.Named["x"][0], 5)
	if restored.Missing != nil || restored.Text != "plain" {
		t.Fatalf("restored %v and %q", restored.Missing, restored.Text)
	}
}

func TestSerializedTensors(t *testing.T) {
	cs := mustBuild(t, phe.Paillier, lightphe.WithKeySize(128), lightphe.WithPrecision(3))
	cloud := publicParty(t, cs, lightphe.WithPrecision(3))

	signed, err := cs.EncryptTensor([]float64{1.5, -2.25, 3})
	if err != nil {
		t.Fatalf("encrypting: %v", err)
	}
	var restoredSigned *encrypted.Tensor
	transfer(t, cs, cs, signed, &restoredSigned)
	assertFloats(t, cs, restoredSigned, []float64{1.5, -2.25, 3})

	tensor, err := cs.EncryptTensor([]float64{1.5, 2.25, 3})
	if err != nil {
		t.Fatalf("encrypting: %v", err)
	}
	var restored *encrypted.Tensor
	transfer(t, cs, cloud, tensor, &restored)
	if restored.Scheme().HasPrivateKey() || restored.Precision() != 3 {
		t.Fatal("restored tensor has private key or another precision")
	}

	// cloud multiplies the encrypted tensor with a plain tensor and sends it back
	product, err := restored.MultiplyByPlain([]float64{2, 2, 2})
	if err != nil {
		t.Fatalf("multiplying: %v", err)
	}
	var received *encrypted.Tensor
	transfer(t, cloud, cs, product, &received)
	assertFloats(t, cs, received, []float64{3, 4.5, 6})
}

func assertFloats(t *testing.T, cs *lightphe.Cryptosystem, tensor *encrypted.Tensor, want []float64) {
	t.Helper()
	got, err := cs.DecryptTensor(tensor)
	if err != nil {
		t.Fatalf("decrypting: %v", err)
	}
	for i := range want {
		if math.Abs(got[i]-want[i]) > 1e-6 {
			t.Fatalf("decrypted %v, want %v", got, want)
		}
	}
}

func TestSerializedProofs(t *testing.T) {
	for _, alg := range []phe.Algorithm{phe.Paillier, phe.EllipticCurveElGamal} {
		prover := mustBuild(t, alg, lightphe.WithKeySize(128))
		verifier := publicParty(t, prover)
		low, high := big.NewInt(0), big.NewInt(100)

		type rangeMessage struct {
			Ciphertext *encrypted.Ciphertext `json:"ciphertext"`
			Proof      *lightphe.RangeProof  `json:"proof"`
		}
		ciphertext, proof, err := prover.EncryptWithRangeProof(big.NewInt(17), low, high, "employee")
		if err != nil {
			t.Fatalf("%s: proving range: %v", alg, err)
		}
		var rm rangeMessage
		transfer(t, prover, verifier, rangeMessage{ciphertext, proof}, &rm)
		if ok, err := verifier.VerifyRange(rm.Ciphertext, rm.Proof, low, high, "employee"); err != nil || !ok {
			t.Fatalf("%s: range proof is rejected: %v", alg, err)
		}

		type oneHotMessage struct {
			Ciphertexts []*encrypted.Ciphertext `json:"ciphertexts"`
			Proof       *lightphe.OneHotProof   `json:"proof"`
		}
		slots, oneHot, err := prover.EncryptOneHot(1, 3, nil)
		if err != nil {
			t.Fatalf("%s: proving one-hot: %v", alg, err)
		}
		var om oneHotMessage
		transfer(t, prover, verifier, oneHotMessage{slots, oneHot}, &om)
		if ok, err := verifier.VerifyOneHot(om.Ciphertexts, om.Proof, nil); err != nil || !ok {
			t.Fatalf("%s: one-hot proof is rejected: %v", alg, err)
		}

		type decryptionMessage struct {
			Ciphertext *encrypted.Ciphertext `json:"ciphertext"`
			Plaintext  *big.Int              `json:"plaintext"`
			Proof      *lightphe.ZKProof     `json:"proof"`
		}
		plaintext, decryption, err := prover.DecryptWithProof(ciphertext)
		if err != nil {
			t.Fatalf("%s: proving decryption: %v", alg, err)
		}
		var dm decryptionMessage
		transfer(t, prover, verifier, decryptionMessage{ciphertext, plaintext, decryption}, &dm)
		if ok, err := verifier.VerifyDecryption(dm.Ciphertext, dm.Plaintext, dm.Proof); err != nil || !ok {
			t.Fatalf("%s: decryption proof is rejected: %v", alg, err)
		}
	}
}

func TestThresholdDecryptionOverNetwork(t *testing.T) {
	for _, alg := range []phe.Algorithm{phe.Paillier, phe.EllipticCurveElGamal} {
		combiner, shareholders := buildThreshold(t, alg, 256, lightphe.WithSafePrimes(alg == phe.Paillier))
		ciphertext := mustEncrypt(t, combiner, 42)
		data := mustSerialize(t, combiner, ciphertext)

		// every shareholder receives the ciphertext, and sends its partial decryption back
		var partials []*lightphe.PartialDecryption
		for _, shareholder := range shareholders[:threshold] {
			var received *encrypted.Ciphertext
			mustDeserialize(t, shareholder, data, &received)
			partial, err := shareholder.PartialDecrypt(received, true)
			if err != nil {
				t.Fatalf("%s: partial decryption: %v", alg, err)
			}
			var restored *lightphe.PartialDecryption
			transfer(t, shareholder, combiner, partial, &restored)
			partials = append(partials, restored)
		}
		if got := mustCombine(t, combiner, ciphertext, partials, true); got.Int64() != 42 {
			t.Fatalf("%s: combined %s, want 42", alg, got)
		}
	}
}

func TestSecureAggregationOverNetwork(t *testing.T) {
	owner := mustBuild(t, phe.Paillier, lightphe.WithKeySize(256))
	server := publicParty(t, owner)
	updates := [][]float64{{0.5, -0.25, 1}, {-1, 0.75, 0.125}, {0.25, 0.25, -0.5}}

	var received []*lightphe.EncryptedUpdate
	for _, update := range updates {
		client := publicParty(t, owner)
		e, err := client.EncryptUpdate(update, 1, 10)
		if err != nil {
			t.Fatalf("encrypting the update: %v", err)
		}
		var r *lightphe.EncryptedUpdate
		transfer(t, client, server, e, &r)
		received = append(received, r)
	}
	sum, err := server.AggregateUpdates(received)
	if err != nil {
		t.Fatalf("aggregating: %v", err)
	}
	var encryptedSum *lightphe.EncryptedUpdate
	transfer(t, server, owner, sum, &encryptedSum)
	result, err := owner.DecryptAggregate(encryptedSum)
	if err != nil {
		t.Fatalf("decrypting: %v", err)
	}
	if result.Count != 3 {
		t.Fatalf("count is %d, want 3", result.Count)
	}
	for i := range updates[0] {
		want := updates[0][i] + updates[1][i] + updates[2][i]
		if math.Abs(result.Sum[i]-want) > 1e-4 {
			t.Fatalf("sum is %v at %d, want %v", result.Sum[i], i, want)
		}
	}
}

func TestKNNOverNetwork(t *testing.T) {
	client := mustBuild(t, phe.DamgardGeislerKroigaard, lightphe.WithKeySize(512))
	server := publicParty(t, client)

	network := func(message lightphe.ArgmaxMessage) ([]*big.Int, error) {
		// server serializes its message, client answers it, and server restores the answer
		var received lightphe.ArgmaxMessage
		transfer(t, server, client, message, &received)
		answer, err := client.AnswerKNN(received)
		if err != nil {
			return nil, err
		}
		var restored []*big.Int
		transfer(t, client, server, answer, &restored)
		return restored, nil
	}

	database := [][]int64{{1, 2}, {5, 5}, {0, 0}, {9, 1}}
	query, err := client.EncryptKNNQuery([]int64{1, 1})
	if err != nil {
		t.Fatalf("encrypting the query: %v", err)
	}
	var receivedQuery *lightphe.EncryptedQuery
	transfer(t, client, server, query, &receivedQuery)
	result, err := server.EvaluateKNN(receivedQuery, database, 2, 8, network, nil)
	if err != nil {
		t.Fatalf("searching: %v", err)
	}
	var received *lightphe.KNNResult
	transfer(t, server, client, result, &received)
	for i, want := range []int64{0, 2} {
		assertDecrypts(t, client, received.Indices[i], want)
	}
}

func TestSerializedCatalanoFiore(t *testing.T) {
	owner := mustBuild(t, phe.Paillier, lightphe.WithKeySize(128), lightphe.WithBoost(lightphe.CatalanoFiore))
	cloud := publicParty(t, owner, lightphe.WithBoost(lightphe.CatalanoFiore))
	encryptVector := func(vector []int64) []*encrypted.Ciphertext {
		var out []*encrypted.Ciphertext
		for _, x := range vector {
			out = append(out, mustEncrypt(t, owner, x))
		}
		return out
	}

	database := [][]int64{{1, 2, 3}, {4, 4, 4}, {0, 1, 2}}
	var encryptedDatabase [][]*encrypted.Ciphertext
	for _, vector := range database {
		encryptedDatabase = append(encryptedDatabase, encryptVector(vector))
	}
	var receivedDatabase [][]*encrypted.Ciphertext
	var receivedQuery []*encrypted.Ciphertext
	transfer(t, owner, cloud, encryptedDatabase, &receivedDatabase)
	transfer(t, owner, cloud, encryptVector([]int64{1, 1, 1}), &receivedQuery)

	distances, err := cloud.EvaluateKNNDistances(receivedQuery, receivedDatabase)
	if err != nil {
		t.Fatalf("computing distances: %v", err)
	}
	var receivedDistances []*encrypted.Ciphertext
	transfer(t, cloud, owner, distances, &receivedDistances)
	result, err := owner.DecryptKNN(receivedDistances, 2)
	if err != nil {
		t.Fatalf("decrypting: %v", err)
	}
	if result.Indices[0] != 2 || result.Indices[1] != 0 || result.Distances[0].Int64() != 2 || result.Distances[1].Int64() != 5 {
		t.Fatalf("nearest vectors are %v with %v", result.Indices, result.Distances)
	}

	// a party without the boost restores Catalano-Fiore ciphertexts as well
	product := cfMul(t, mustEncrypt(t, owner, 6), mustEncrypt(t, owner, 7))
	var restored *encrypted.Ciphertext
	transfer(t, owner, publicParty(t, owner), product, &restored)
	assertDecrypts(t, owner, restored, 42)
	plain := mustBuild(t, phe.Paillier, lightphe.WithKeys(mustKeys(t, owner)))
	assertDecrypts(t, plain, restored, 42)
}

func mustKeys(t *testing.T, cs *lightphe.Cryptosystem) []byte {
	t.Helper()
	keys, err := cs.Keys(false)
	if err != nil {
		t.Fatalf("exporting keys: %v", err)
	}
	return keys
}

// mutate decodes a serialized ciphertext into a generic json object, applies
// change and encodes it again.
func mutate(t *testing.T, data []byte, change func(doc map[string]interface{})) []byte {
	t.Helper()
	var doc map[string]interface{}
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.UseNumber()
	if err := decoder.Decode(&doc); err != nil {
		t.Fatalf("decoding: %v", err)
	}
	change(doc)
	out, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("encoding: %v", err)
	}
	return out
}

func assertDeserializeFails(t *testing.T, cs *lightphe.Cryptosystem, data []byte, message string) {
	t.Helper()
	var c *encrypted.Ciphertext
	err := cs.Deserialize(data, &c)
	if err == nil || !strings.Contains(err.Error(), message) || !errors.Is(err, lightphe.ErrInvalidCiphertext) {
		t.Fatalf("got %v, want an invalid ciphertext error containing %q", err, message)
	}
}

func TestSerializationInvalidInputs(t *testing.T) {
	cs := mustBuild(t, phe.Paillier, lightphe.WithKeySize(testKeySize))
	data := mustSerialize(t, cs, mustEncrypt(t, cs, 5))

	other := mustBuild(t, phe.DamgardJurik, lightphe.WithKeySize(testKeySize))
	assertDeserializeFails(t, other, data, "belongs to Paillier")
	assertDeserializeFails(t, cs, []byte("{not json"), "not a valid json")

	for _, value := range []interface{}{"123", true, nil, map[string]interface{}{"x": 1}, []interface{}{1, "2"}, 1.5} {
		assertDeserializeFails(t, cs, mutate(t, data, func(doc map[string]interface{}) { doc["value"] = value }),
			"must consist of integers")
	}
	assertDeserializeFails(t, cs, mutate(t, data, func(doc map[string]interface{}) { doc["version"] = 999 }), "version")
	assertDeserializeFails(t, cs, []byte(`{"__lightphe__": "something"}`), "serialized object is something")

	// unbound ciphertexts are rejected until they are restored
	var unbound *encrypted.Ciphertext
	if err := json.Unmarshal(data, &unbound); err != nil {
		t.Fatalf("decoding: %v", err)
	}
	if _, err := unbound.Add(unbound); !errors.Is(err, encrypted.ErrUnbound) {
		t.Fatalf("adding unbound ciphertexts returned %v", err)
	}
	if _, err := cs.Decrypt(unbound); !errors.Is(err, encrypted.ErrUnbound) {
		t.Fatalf("decrypting an unbound ciphertext returned %v", err)
	}
	if err := cs.Restore(&unbound); err != nil {
		t.Fatalf("restoring: %v", err)
	}
	assertDecrypts(t, cs, unbound, 5)

	// points must be on the curve
	bgn := mustBuild(t, phe.BonehGohNissim, lightphe.WithKeySize(64))
	pointData := mustSerialize(t, bgn, mustEncrypt(t, bgn, 1))
	offCurve := mutate(t, pointData, func(doc map[string]interface{}) {
		point := doc["value"].(map[string]interface{})
		y, _ := new(big.Int).SetString(point["y"].(json.Number).String(), 10)
		point["y"] = json.Number(y.Add(y, big.NewInt(1)).String())
	})
	assertDeserializeFails(t, bgn, offCurve, "not on the curve")
	assertDeserializeFails(t, cs, mutate(t, data, func(doc map[string]interface{}) {
		doc["value"] = map[string]interface{}{encrypted.Tag: "point", "x": 1, "y": 2}
	}), "not elliptic curve points")

	// Catalano-Fiore ciphertexts must be well formed
	boosted := mustBuild(t, phe.Paillier, lightphe.WithKeys(mustKeys(t, cs)), lightphe.WithBoost(lightphe.CatalanoFiore))
	cfData := mustSerialize(t, boosted, mustEncrypt(t, boosted, 5))
	assertDeserializeFails(t, cs, mutate(t, cfData, func(doc map[string]interface{}) {
		doc["a"] = json.Number(cs.PlaintextModulo().String())
	}), "must be in")
	assertDeserializeFails(t, cs, mutate(t, cfData, func(doc map[string]interface{}) {
		doc["pairs"] = []interface{}{[]interface{}{doc["beta"], doc["beta"]}}
	}), "a and beta only")
	assertDeserializeFails(t, cs, mutate(t, cfData, func(doc map[string]interface{}) { doc["alpha"] = doc["beta"] }),
		"alpha and pairs only")
	assertDeserializeFails(t, cs, mutate(t, cfData, func(doc map[string]interface{}) { doc["beta"] = cfData }),
		"must consist of ciphertexts")
	assertDeserializeFails(t, other, cfData, "belongs to Paillier")
}

func TestMalformedKeyFileIsRejected(t *testing.T) {
	keyFile := filepath.Join(t.TempDir(), "malicious.json")
	payload := "__import__('pathlib').Path('pwned.txt').write_text('pwned')"
	if err := os.WriteFile(keyFile, []byte(payload), 0600); err != nil {
		t.Fatalf("writing: %v", err)
	}
	if _, err := lightphe.New(phe.RSA, lightphe.WithKeyFile(keyFile)); !errors.Is(err, lightphe.ErrInvalidKeys) {
		t.Fatalf("a key file that is not json returned %v", err)
	}
}
