package lightphe_test

import (
	"math"
	"math/big"
	"math/rand"
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/serengil/lightphe-go/lightphe"
	"github.com/serengil/lightphe-go/lightphe/encrypted"
	"github.com/serengil/lightphe-go/lightphe/phe"
	"github.com/serengil/lightphe-go/lightphe/schemes/damgardgeislerkroigaard"
)

// 512-bit keys have the same 32-bit plaintext space as 1024-bit keys, but are
// faster. They are not secure, and are for testing only.
var (
	classifierOnce   sync.Once
	classifierClient *lightphe.Cryptosystem
	classifierServer *lightphe.Cryptosystem
)

func classifierParties(t *testing.T) (*lightphe.Cryptosystem, *lightphe.Cryptosystem) {
	t.Helper()
	classifierOnce.Do(func() {
		client, err := lightphe.New(phe.DamgardGeislerKroigaard, lightphe.WithKeySize(512))
		if err != nil {
			t.Fatalf("building the client: %v", err)
		}
		keys, err := client.Keys(true)
		if err != nil {
			t.Fatalf("exporting the public key: %v", err)
		}
		server, err := lightphe.New(phe.DamgardGeislerKroigaard, lightphe.WithKeys(keys))
		if err != nil {
			t.Fatalf("building the server: %v", err)
		}
		classifierClient, classifierServer = client, server
	})
	if classifierClient == nil {
		t.Fatal("parties could not be built")
	}
	return classifierClient, classifierServer
}

func squaredDistance(a, b []int64) int64 {
	var d int64
	for i := range a {
		d += (a[i] - b[i]) * (a[i] - b[i])
	}
	return d
}

func plainKNN(query []int64, database [][]int64, k int) []int64 {
	indices := make([]int64, len(database))
	for i := range indices {
		indices[i] = int64(i)
	}
	// earlier index first on ties
	sort.SliceStable(indices, func(a, b int) bool {
		return squaredDistance(query, database[indices[a]]) < squaredDistance(query, database[indices[b]])
	})
	return indices[:k]
}

func search(t *testing.T, query []int64, database [][]int64, k, bitLength int, labels []int64,
	client lightphe.ArgmaxClient) ([]int64, []int64) {
	t.Helper()
	clientCs, serverCs := classifierParties(t)
	encryptedQuery, err := clientCs.EncryptKNNQuery(query)
	if err != nil {
		t.Fatalf("encrypting the query: %v", err)
	}
	if client == nil {
		client = clientCs.AnswerKNN
	}
	result, err := serverCs.EvaluateKNN(encryptedQuery, database, k, bitLength, client, labels)
	if err != nil {
		t.Fatalf("evaluating: %v", err)
	}
	decrypt := func(cs []*encrypted.Ciphertext) []int64 {
		var out []int64
		for _, c := range cs {
			out = append(out, mustDecrypt(t, clientCs, c).Int64())
		}
		return out
	}
	return decrypt(result.Indices), decrypt(result.Labels)
}

func assertInts(t *testing.T, what string, got, want []int64) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("%s are %v, want %v", what, got, want)
	}
	for i := range got {
		if got[i] != want[i] {
			t.Fatalf("%s are %v, want %v", what, got, want)
		}
	}
}

func randomVectors(rng *rand.Rand, count, dimension int, lo, hi int64) [][]int64 {
	out := make([][]int64, count)
	for i := range out {
		out[i] = make([]int64, dimension)
		for j := range out[i] {
			out[i][j] = lo + rng.Int63n(hi-lo+1)
		}
	}
	return out
}

func TestKNNMatchesPlainKNN(t *testing.T) {
	rng := rand.New(rand.NewSource(7))
	for i := 0; i < 2; i++ {
		database := randomVectors(rng, 10, 8, -50, 50)
		labels := make([]int64, len(database))
		for j := range labels {
			labels[j] = 1 + rng.Int63n(1e6)
		}
		query := randomVectors(rng, 1, 8, -50, 50)[0]

		indices, found := search(t, query, database, 3, 17, labels, nil)
		expected := plainKNN(query, database, 3)
		assertInts(t, "indices", indices, expected)
		assertInts(t, "labels", found, []int64{labels[expected[0]], labels[expected[1]], labels[expected[2]]})
	}
}

func TestKNNOfOneAndFullRanking(t *testing.T) {
	rng := rand.New(rand.NewSource(11))
	database := randomVectors(rng, 5, 4, 0, 20)
	query := randomVectors(rng, 1, 4, 0, 20)[0]

	indices, labels := search(t, query, database, 1, 12, nil, nil)
	assertInts(t, "indices", indices, plainKNN(query, database, 1))
	if len(labels) != 0 {
		t.Fatalf("labels are %v without labels", labels)
	}
	indices, _ = search(t, query, database, 5, 12, nil, nil)
	assertInts(t, "indices", indices, plainKNN(query, database, 5))
}

func TestKNNTiesReturnEarlierIndexFirst(t *testing.T) {
	indices, _ := search(t, []int64{0, 0}, [][]int64{{3, 4}, {0, 0}, {3, 4}, {0, 0}, {9, 9}}, 4, 8, nil, nil)
	assertInts(t, "indices", indices, []int64{1, 3, 0, 2})
}

func TestKNNClientSeesOneZeroInShuffledPositions(t *testing.T) {
	clientCs, _ := classifierParties(t)
	dgk := clientCs.Scheme().(*damgardgeislerkroigaard.Cryptosystem)
	database := make([][]int64, 6)
	for i := range database {
		database[i] = []int64{int64(i), int64(2 * i)}
	}

	var seen [][]bool
	recording := func(message lightphe.ArgmaxMessage) ([]*big.Int, error) {
		if message.Type == phe.ArgmaxEquality {
			var round []bool
			for _, c := range message.Payload {
				zero, err := dgk.IsZero(c)
				if err != nil {
					return nil, err
				}
				round = append(round, zero)
			}
			seen = append(seen, round)
		}
		return clientCs.AnswerKNN(message)
	}
	indices, _ := search(t, []int64{0, 0}, database, 3, 8, nil, recording)
	assertInts(t, "indices", indices, []int64{0, 1, 2})

	// one equality round per found vector except the last one, each having a
	// single zero
	if len(seen) != 2 {
		t.Fatalf("client saw %d equality rounds, want 2", len(seen))
	}
	for _, round := range seen {
		zeros := 0
		for _, zero := range round {
			if zero {
				zeros++
			}
		}
		if zeros != 1 || len(round) != len(database) {
			t.Fatalf("client saw %v", round)
		}
	}
}

func TestFaceSearchWithQuantizedEmbeddings(t *testing.T) {
	// gallery of 8 people with 32-dimensional embeddings in [-1, 1]
	rng := rand.New(rand.NewSource(5))
	gallery := make([][]float64, 8)
	for i := range gallery {
		gallery[i] = make([]float64, 32)
		for j := range gallery[i] {
			gallery[i][j] = rng.Float64()*2 - 1
		}
	}
	people := []int64{101, 102, 103, 104, 105, 106, 107, 108}

	// query is a noisy capture of person 105
	query := make([]float64, 32)
	for j, x := range gallery[4] {
		query[j] = x + rng.NormFloat64()*0.05
	}

	// embeddings are quantized to 8-bit integers, so squared distances are
	// less than 2^21
	quantize := func(vector []float64) []int64 {
		out := make([]int64, len(vector))
		for i, x := range vector {
			out[i] = int64(math.Max(-127, math.Min(127, math.Round(x*127))))
		}
		return out
	}
	database := make([][]int64, len(gallery))
	for i, v := range gallery {
		database[i] = quantize(v)
	}
	_, labels := search(t, quantize(query), database, 1, 21, people, nil)
	assertInts(t, "labels", labels, []int64{105})
}

func TestKNNInvalidInputs(t *testing.T) {
	clientCs, serverCs := classifierParties(t)
	query, err := clientCs.EncryptKNNQuery([]int64{1, 2})
	if err != nil {
		t.Fatalf("encrypting: %v", err)
	}
	database := [][]int64{{1, 2}, {3, 4}}

	for _, tt := range []struct {
		query     *lightphe.EncryptedQuery
		database  [][]int64
		k         int
		bitLength int
		labels    []int64
		message   string
	}{
		{query, [][]int64{{1, 2, 3}}, 1, 8, nil, "list of 2 integers"},
		{query, database, 0, 8, nil, "k must be in"},
		{query, database, 3, 8, nil, "k must be in"},
		{query, database, 1, 8, []int64{1}, "one for each vector"},
		{query, database, 1, 4, nil, "does not fit"},
		{query, database, 1, 40, nil, "too small for argmax"},
		{&lightphe.EncryptedQuery{}, database, 1, 8, nil, "output of EncryptKNNQuery"},
	} {
		if _, err := serverCs.EvaluateKNN(tt.query, tt.database, tt.k, tt.bitLength, clientCs.AnswerKNN, tt.labels); err == nil ||
			!strings.Contains(err.Error(), tt.message) {
			t.Fatalf("expected %q, got %v", tt.message, err)
		}
	}
	if _, err := clientCs.EncryptKNNQuery(nil); err == nil {
		t.Fatal("an empty query was accepted")
	}
	if _, err := serverCs.AnswerKNN(lightphe.ArgmaxMessage{Type: phe.ArgmaxEquality}); err == nil ||
		!strings.Contains(err.Error(), "private key") {
		t.Fatalf("answering without the private key returned %v", err)
	}

	paillier := mustBuild(t, phe.Paillier, lightphe.WithKeySize(64))
	_, err = paillier.EncryptKNNQuery([]int64{1, 2})
	assertUnsupported(t, "nearest neighbor search", err)
}

func TestEncryptedDatabaseInCloud(t *testing.T) {
	// owner stores its encrypted database in an untrusted cloud
	owner := mustBuild(t, phe.Paillier, lightphe.WithKeySize(256), lightphe.WithBoost(lightphe.CatalanoFiore))
	keys, _ := owner.Keys(true)
	cloud := mustBuild(t, phe.Paillier, lightphe.WithKeys(keys), lightphe.WithBoost(lightphe.CatalanoFiore))

	rng := rand.New(rand.NewSource(13))
	database := randomVectors(rng, 8, 6, -100, 100)
	query := randomVectors(rng, 1, 6, -100, 100)[0]
	encryptVector := func(vector []int64) []*encrypted.Ciphertext {
		var out []*encrypted.Ciphertext
		for _, x := range vector {
			out = append(out, mustEncrypt(t, owner, x))
		}
		return out
	}

	// owner encrypts its database once and uploads it, then encrypts queries
	var encryptedDatabase [][]*encrypted.Ciphertext
	for _, vector := range database {
		encryptedDatabase = append(encryptedDatabase, encryptVector(vector))
	}

	// cloud computes encrypted distances with the public key only
	distances, err := cloud.EvaluateKNNDistances(encryptVector(query), encryptedDatabase)
	if err != nil {
		t.Fatalf("computing distances: %v", err)
	}
	if _, err := cloud.DecryptKNN(distances, 3); err == nil || !strings.Contains(err.Error(), "private key") {
		t.Fatalf("cloud decrypted distances: %v", err)
	}

	// owner decrypts them and finds the nearest vectors locally
	result, err := owner.DecryptKNN(distances, 3)
	if err != nil {
		t.Fatalf("decrypting: %v", err)
	}
	expected := plainKNN(query, database, 3)
	for i, index := range result.Indices {
		if int64(index) != expected[i] || result.Distances[i].Int64() != squaredDistance(query, database[index]) {
			t.Fatalf("nearest vectors are %v with %v, want %v", result.Indices, result.Distances, expected)
		}
	}

	// invalid inputs
	q := encryptVector([]int64{1, 2})
	db := [][]*encrypted.Ciphertext{encryptVector([]int64{3, 4})}
	if _, err := cloud.EvaluateKNNDistances(q, [][]*encrypted.Ciphertext{encryptVector([]int64{1})}); err == nil ||
		!strings.Contains(err.Error(), "list of 2 encrypted integers") {
		t.Fatalf("a short vector returned %v", err)
	}
	// products cannot be multiplied again
	if _, err := cloud.EvaluateKNNDistances([]*encrypted.Ciphertext{cfMul(t, q[0], q[1]), q[1]}, db); err == nil ||
		!strings.Contains(err.Error(), "non-empty list of encrypted integers") {
		t.Fatalf("a product returned %v", err)
	}
	d, err := cloud.EvaluateKNNDistances(q, db)
	if err != nil {
		t.Fatalf("computing distances: %v", err)
	}
	for _, k := range []int{0, 2} {
		if _, err := owner.DecryptKNN(d, k); err == nil || !strings.Contains(err.Error(), "k must be in") {
			t.Fatalf("k = %d returned %v", k, err)
		}
	}
	plain := mustBuild(t, phe.Paillier, lightphe.WithKeySize(64))
	_, err = plain.EvaluateKNNDistances(q, db)
	assertUnsupported(t, "distances without the boost", err)
}
