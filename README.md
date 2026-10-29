# lightphe-go

<div align="center">

[![Stars](https://img.shields.io/github/stars/serengil/lightphe-go?color=yellow&style=flat&label=%E2%AD%90%20stars)](https://github.com/serengil/lightphe-go/stargazers)
[![License](http://img.shields.io/:license-MIT-green.svg?style=flat)](https://github.com/serengil/lightphe-go/blob/main/LICENSE)
[![DOI](http://img.shields.io/:DOI-10.3390/sym18050832-blue.svg?style=flat)](https://www.mdpi.com/2073-8994/18/5/832)

</div>

<p align="center"><img src="https://raw.githubusercontent.com/serengil/lightphe-go/main/images/lightphe-go-mascot.jpg" width="30%"></p>

`lightphe-go` is a lightweight homomorphic encryption library for Go supporting various partially
and somewhat homomorphic encryption schemes such as
[`RSA`](https://sefiks.com/2023/03/06/a-step-by-step-partially-homomorphic-encryption-example-with-rsa-in-python/),
[`ElGamal`](https://sefiks.com/2023/03/27/a-step-by-step-partially-homomorphic-encryption-example-with-elgamal-in-python/),
[`Exponential ElGamal`](https://sefiks.com/2023/03/27/a-step-by-step-partially-homomorphic-encryption-example-with-elgamal-in-python/),
[`Elliptic Curve ElGamal`](https://sefiks.com/2018/08/21/elliptic-curve-elgamal-encryption/)
([`Weierstrass`](https://sefiks.com/2016/03/13/the-math-behind-elliptic-curve-cryptography/),
[`Koblitz`](https://sefiks.com/2016/03/13/the-math-behind-elliptic-curves-over-binary-field/) and
[`Edwards`](https://sefiks.com/2018/12/19/a-gentle-introduction-to-edwards-curves/) forms),
[`Paillier`](https://sefiks.com/2023/04/03/a-step-by-step-partially-homomorphic-encryption-example-with-paillier-in-python/),
[`Damgard-Jurik`](https://sefiks.com/2023/10/20/a-step-by-step-partially-homomorphic-encryption-example-with-damgard-jurik-in-python/),
[`Okamoto–Uchiyama`](https://sefiks.com/2023/10/20/a-step-by-step-partially-homomorphic-encryption-example-with-okamoto-uchiyama-in-python/),
[`Benaloh`](https://sefiks.com/2023/10/06/a-step-by-step-partially-homomorphic-encryption-example-with-benaloh-in-python-from-scratch/),
[`Naccache–Stern`](https://sefiks.com/2023/10/26/a-step-by-step-partially-homomorphic-encryption-example-with-naccache-stern-in-python/),
[`Goldwasser–Micali`](https://sefiks.com/2023/10/27/a-step-by-step-partially-homomorphic-encryption-example-with-goldwasser-micali-in-python/),
[`Sander-Young-Yung`](https://sefiks.com/2026/04/02/a-step-by-step-partially-homomorphic-sander-young-yung-example-in-python/),
[`Boneh-Goh-Nissim`](https://sefiks.com/2026/04/02/a-step-by-step-somewhat-homomorphic-encryption-example-with-boneh-goh-nissim-in-python/),
`Joye-Libert`, `Castagnos-Laguillaumie`, `Ishai-Paskin`, `Damgard-Geisler-Kroigaard`,
`Bresson-Catalano-Pointcheval`, `Camenisch-Shoup`, `Elliptic Curve Paillier`, `Regev`,
`Lyubashevsky-Peikert-Regev`, `ML-KEM`, `Brakerski-Vaikuntanathan`, `Freeman-Boneh-Goh-Nissim`,
`Gentry-Halevi-Vaikuntanathan`, `Gentry-Sahai-Waters`.
It also supports [`Catalano-Fiore`](#adding-multiplication-support-to-additive-algorithms) transform to add one multiplication to additively homomorphic ones.

It is a pure Go port of [LightPHE](https://github.com/serengil/LightPHE), with the elliptic curve
arithmetic of [LightECC](https://github.com/serengil/LightECC) folded in.

Homomorphic encryption lets a party compute on ciphertexts without ever seeing the plaintexts or
holding the private key. That is what makes it possible to offload work to a cloud you do not
trust: the cloud adds, multiplies or combines encrypted values, and only you can read the result.

## Partially vs fully homomorphic encryption

Fully homomorphic encryption (FHE) can evaluate arbitrary circuits, but it pays for that
generality in speed, ciphertext size and memory. When your task only needs one kind of operation —
summing salaries, multiplying scores, computing a dot product — partial homomorphism does the job
and does it far more cheaply:

- 🏎️ Notably faster
- 💻 Demands fewer computational resources
- 📏 Generating much smaller ciphertexts
- 🔑 Distributing much smaller keys
- 🧠 Well-suited for memory-constrained environments
- ⚖️ Strikes a favorable balance for practical use cases

## Installation

```shell
go get github.com/serengil/lightphe-go
```

```go
import "github.com/serengil/lightphe-go/lightphe"
```

That single import is all you need. The algorithm constants, the sentinel errors and the encrypted
value types are all re-exported by `lightphe`, so `lightphe.Paillier`, `lightphe.Ciphertext` and
`lightphe.ErrUnsupportedOperation` work without pulling in a second package.

`lightphe.New` returns a `*lightphe.Cryptosystem`, which is what every example below calls `cs`.

Requires Go 1.17 or newer.

## Supported cryptosystems

| Algorithm | Multiplicatively<br>Homomorphic | Additively<br>Homomorphic | Scalar Multiplication | Bitwise-XOR Homomorphic | Bitwise-AND Homomorphic | Regeneration<br>of Ciphertext | Decision Tree<br>Evaluation | Secure<br>Comparison | Encrypted<br>Argmax | Threshold<br>Decryption | Zero-Knowledge<br>Proofs |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| RSA | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| ElGamal | ✅ | ❌ | ❌ | ❌ | ❌ | ✅ | ❌ | ❌ | ❌ | ✅ | ✅ |
| ExponentialElGamal | ❌ | ✅ | ✅ | ❌ | ❌ | ✅ | ❌ | ❌ | ❌ | ✅ | ✅ |
| EllipticCurveElGamal | ❌ | ✅ | ✅ | ❌ | ❌ | ✅ | ❌ | ❌ | ❌ | ✅ | ✅ |
| Paillier | ❌ | ✅ | ✅ | ❌ | ❌ | ✅ | ❌ | ❌ | ❌ | ✅ | ✅ |
| EllipticCurvePaillier | ❌ | ✅ | ✅ | ❌ | ❌ | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ |
| DamgardJurik | ❌ | ✅ | ✅ | ❌ | ❌ | ✅ | ❌ | ❌ | ❌ | ✅ | ✅ |
| Benaloh | ❌ | ✅ | ✅ | ❌ | ❌ | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ |
| NaccacheStern | ❌ | ✅ | ✅ | ❌ | ❌ | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ |
| OkamotoUchiyama | ❌ | ✅ | ✅ | ❌ | ❌ | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ |
| JoyeLibert | ❌ | ✅ | ✅ | ❌ | ❌ | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ |
| CastagnosLaguillaumie | ❌ | ✅ | ✅ | ❌ | ❌ | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ |
| DamgardGeislerKroigaard | ❌ | ✅ | ✅ | ❌ | ❌ | ✅ | ✅ | ✅ | ✅ | ❌ | ❌ |
| BressonCatalanoPointcheval | ❌ | ✅ | ✅ | ❌ | ❌ | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ |
| CamenischShoup | ❌ | ✅ | ✅ | ❌ | ❌ | ✅ | ❌ | ❌ | ❌ | ❌ | ✅ |
| IshaiPaskin | ❌ | ✅ | ✅ | ❌ | ❌ | ✅ | ✅ | ❌ | ❌ | ❌ | ❌ |
| Regev | ❌ | ✅ | ✅ | ❌ | ❌ | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ |
| LyubashevskyPeikertRegev | ❌ | ✅ | ✅ | ❌ | ❌ | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ |
| MLKEM | ❌ | ❌ | ❌ | ✅ | ❌ | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ |
| GoldwasserMicali | ❌ | ❌ | ❌ | ✅ | ❌ | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ |
| SanderYoungYung | ❌ | ❌ | ❌ | ❌ | ✅ | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ |
| BonehGohNissim | 1️⃣ | ✅ | ✅ | ❌ | ❌ | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ |
| FreemanBonehGohNissim | 1️⃣ | ✅ | ✅ | ❌ | ❌ | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ |
| BrakerskiVaikuntanathan | 1️⃣ | ✅ | ✅ | ❌ | ❌ | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ |
| GentryHaleviVaikuntanathan | 1️⃣ | ✅ | ✅ | ❌ | ❌ | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ |
| GentrySahaiWaters | ✅ | ❌ | ❌ | ✅ | ✅ | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ |

1️⃣ Boneh-Goh-Nissim, Freeman-Boneh-Goh-Nissim, Brakerski-Vaikuntanathan and
Gentry-Halevi-Vaikuntanathan support one multiplication natively. Gentry-Sahai-Waters supports
multiplications of encrypted bits up to a small depth. Most additively homomorphic
algorithms can support one multiplication with
[Catalano-Fiore transform](#adding-multiplication-support-to-additive-algorithms) as well.

## Building a cryptosystem

`New` generates a fresh key pair. Options tune the key size and the scheme-specific parameters.

```go
// default key size
cs, err := lightphe.New(lightphe.Paillier)

// or an explicit key size
cs, err = lightphe.New(lightphe.Paillier, lightphe.WithKeySize(2048))
```

Every algorithm is listed by `lightphe.Algorithms()`.

## Homomorphic operations

The workflow below is the whole point of the library. Keys are generated on premises; encryption
and evaluation need only the public key and can be handed to an untrusted party; decryption comes
home.

```go
  const (
      m1 = 10000 // base salary
      m2 = 500   // wage increase amount
      k  = 1.05  // wage increase percentage (5%)
  )

  // Build an additively homomorphic cryptosystem on premises.
  cs, _ := lightphe.New(lightphe.Paillier)

  // Encrypt - no private key required.
  salary, _ := cs.EncryptInt(m1)
  raise, _ := cs.EncryptInt(m2)
  
  // Homomorphic addition - no private key required.
  total, _ := salary.Add(raise)

  // Scalar multiplication - no private key required.
  increased, _ := salary.MultiplyByFloat(k)

  // Decryption - private key required.
  sum, _ := cs.Decrypt(total)
  scaled, _ := cs.Decrypt(increased)

  // Decrypt returns *big.Int, so compare with Int64 (or Cmp for large values).
  if sum.Int64() != m1+m2 {
      panic("homomorphic addition failed")
  }
  if scaled.Int64() != int64(m1*k) {
      panic("homomorphic scalar multiplication failed")
  }
```

With a multiplicatively homomorphic cryptosystem you multiply ciphertexts instead:

```go
	const (
		m1 = 17
		m2 = 21
	)

	// Build a multiplicatively homomorphic cryptosystem on premises.
	cs, _ := lightphe.New(lightphe.RSA)

	// Encrypt - no private key required.
	c1, _ := cs.EncryptInt(m1)
	c2, _ := cs.EncryptInt(m2)

	// Homomorphic multiplication - no private key required.
	product, _ := c1.Multiply(c2)

	// Decryption - private key required.
	m, _ := cs.Decrypt(product)

	// Assert decrypted value against expected calculation
	if m.Int64() != m1*m2 {
		panic("Homomorphic multiplication failed")
	}

	// Asking a scheme for an operation it does not support returns an error you can test for
	_, err := c1.Add(c2)
	if !errors.Is(err, lightphe.ErrUnsupportedOperation) {
		panic("Expected ErrUnsupportedOperation for addition in RSA")
	}
```

### Ciphertext regeneration

Most schemes can re-randomise a ciphertext without changing the plaintext behind it, which makes
observations harder to correlate.

```go
refreshed, _ := cs.RegenerateCiphertext(c1)
// refreshed.Value differs from c1.Value, but both decrypt to the same message
```

### Split trust: encrypt and evaluate without the private key

Export the public key, hand it to the evaluator, and keep the private key at home.

```go
	// On premises.
	cs, _ := lightphe.New(lightphe.Paillier)
	_ = cs.ExportKeys("public.json", true)   // public key only
	_ = cs.ExportKeys("private.json", false) // includes the private key - protect it

	// On the evaluator.
	cloud, _ := lightphe.New(lightphe.Paillier, lightphe.WithKeyFile("public.json"))
	c1, _ := cloud.EncryptInt(10000)
	c2, _ := cloud.EncryptInt(500)
	result, _ := c1.Add(c2)

	// The evaluator holds no private key, so it cannot read what it just computed.
	_, err := cloud.Decrypt(result)
	if !errors.Is(err, lightphe.ErrMissingPrivateKey) {
		panic("expected ErrMissingPrivateKey")
	}

	// Back on premises.
	onprem, _ := lightphe.New(lightphe.Paillier, lightphe.WithKeyFile("private.json"))
	m, _ := onprem.Decrypt(result)
	if m.Int64() != 10500 {
		panic("homomorphic addition failed")
	}
```

### Sending ciphertexts over network

Ciphertexts, proofs and messages of interactive protocols can be serialized into json to be sent to
another party. Keys are never serialized, the receiver restores ciphertexts with its own public key.
`Deserialize` fills any target having ciphertexts in it, e.g. a ciphertext with its proof, an encrypted
update for secure aggregation, or a message sent to the `client` callback of encrypted argmax and
nearest neighbor search. Ciphertexts are encoded in the format of the Python library, so a Go party
and a Python party can talk to each other.

```go
	// client encrypts its value and sends it to the server
	clientCs, _ := lightphe.New(lightphe.Paillier)
	c, _ := clientCs.EncryptInt(17)
	data, _ := clientCs.Serialize(c)

	// server restores the ciphertext with the client's public key only, and computes on it
	publicKey, _ := clientCs.Keys(true)
	serverCs, _ := lightphe.New(lightphe.Paillier, lightphe.WithKeys(publicKey))
	var received *lightphe.Ciphertext
	_ = serverCs.Deserialize(data, &received)
	c25, _ := serverCs.EncryptInt(25)
	sum, _ := received.Add(c25)
	response, _ := serverCs.Serialize(sum)

	// client decrypts the response
	var result *lightphe.Ciphertext
	_ = clientCs.Deserialize(response, &result)
	m, _ := clientCs.Decrypt(result)
	if m.Int64() != 42 {
		panic("homomorphic addition failed")
	}
```

`Ciphertext` and `Tensor` implement `json.Marshaler`, so they can be a part of any message. A message
decoded with `json.Unmarshal` elsewhere, e.g. by a web framework, has its ciphertexts bound to the
receiver's public key with `Restore`. To run an interactive protocol across machines, wrap the network
call with the `client` callback:

```go
	client := func(message lightphe.ArgmaxMessage) ([]*big.Int, error) {
		// e.g. an http request to the client, which answers with
		// clientCs.Serialize(clientCs.AnswerKNN(message))
		body, _ := serverCs.Serialize(message)
		resp, err := http.Post(clientURL, "application/json", bytes.NewReader(body))
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()
		answer, _ := io.ReadAll(resp.Body)
		var out []*big.Int
		return out, serverCs.Deserialize(answer, &out)
	}

	result, _ := serverCs.EvaluateKNN(encryptedQuery, gallery, 2, 16, client, nil)
```

### Elliptic curve cryptography

The `ecc` package implements curve arithmetic over prime and binary fields in three forms —
Weierstrass, twisted Edwards and Koblitz — across 100+ standard curves, plus the Weil and modified
Tate pairings. Elliptic curve ElGamal builds on it:

```go
cs, err := lightphe.New(lightphe.EllipticCurveElGamal,
    lightphe.WithCurve("edwards", "ed25519"),
)
```

An empty form defaults to `weierstrass`, and an empty curve name to that form's standard curve
(`secp256k1`, `ed25519`, `k163`). `curves.List` enumerates what is available:

```go
import "github.com/serengil/lightphe-go/lightphe/ecc/curves"

names, err := curves.List(curves.FormWeierstrass)
```

The order of the curve is the main lever on security: a larger order means a stronger system and a
slower one. Pick it for your threat model, not by default.

Note that elliptic curve ElGamal decrypts by solving an elliptic curve discrete logarithm, so it
is only practical for small plaintexts. The same caveat applies to exponential ElGamal, Benaloh
and Naccache-Stern.

See [`curves`](https://github.com/serengil/LightECC#supported-curves) page for a list of all supported forms, curves and their details.

### Decision trees

lightphe-go can evaluate decision trees privately. Suppose a bank has a secret decision tree that
decides a customer's credit limit, and a customer has private data. The bank does not want to
reveal its tree, and the customer does not want to reveal their data. The customer sends encrypted
data, the bank runs its tree on it without seeing it, and only the customer can decrypt the
result. The customer learns the credit limit but not the rest of the tree. Two cryptosystems
support this: Ishai-Paskin for trees on yes / no answers, and Damgard-Geisler-Kroigaard for trees
on numeric features.

#### Decision trees with nominal decisions

Ishai-Paskin evaluates trees whose questions have yes / no answers, in a single round: the
customer sends encrypted answers, and the bank sends back the encrypted result.

Let the bank's tree be the following, where questions are numbered 0, 1 and 2 and leaves are
credit limits in thousand dollars.

```
                  Q0: has stable income?
                 /no                    \yes
     Q2: owns a house?              Q1: has existing debt?
       /no        \yes               /no           \yes
      0            5               20         Q2: owns a house?
                                                /no       \yes
                                               5          10
```

Each question is written as `Node(question number, what to do if no, what to do if yes)`, and
leaves are `Leaf(value)`. So, the tree above becomes:

```go
leaf, node := lightphe.Leaf, lightphe.Node

creditLimitTree := node(0,
    node(2, leaf(0), leaf(5)),
    node(1, leaf(20), node(2, leaf(5), leaf(10))),
)
```

Then, the customer and the bank run the following steps.

```go
// customer builds the cryptosystem and keeps the private key
customerCs, _ := lightphe.New(lightphe.IshaiPaskin)

// customer shares only the public key with the bank
_ = customerCs.ExportKeys("public.txt", true)

// customer's answers: stable income = yes, existing debt = yes, owns a house = no
answers := []int{1, 1, 0}

// customer encrypts the answers and sends them to the bank. depth is the maximum
// number of questions on a path of the tree, the bank should share this value
encryptedAnswers, _ := customerCs.EncryptDecisionTreeInput(answers, 3)

// bank builds its own cryptosystem with the customer's public key
bankCs, _ := lightphe.New(lightphe.IshaiPaskin, lightphe.WithKeyFile("public.txt"))

// bank runs its tree on encrypted answers and sends the result back to the customer
encryptedLimit, _ := bankCs.EvaluateDecisionTree(creditLimitTree, encryptedAnswers)

// customer decrypts the result - only the customer has the private key
limit, _ := customerCs.Decrypt(encryptedLimit)
if limit.Int64() != 5 {
    panic("decision tree evaluation failed")
}
```

The size of the result grows with the depth of the tree, not with the number of its nodes. Still,
each extra level makes the computation noticeably slower, so this is practical for shallow trees.

#### Decision trees with numeric decisions

Damgard-Geisler-Kroigaard evaluates decision trees with numeric thresholds instead of yes / no
answers, using the secure comparison protocol below at each node. It requires a few rounds of
interaction between the customer and the bank, but its cost grows linearly with the number of
nodes.

Let the bank's tree be the following, where features are numbered 0 (age), 1 (income in thousand
dollars) and 2 (number of open loans), and leaves are credit limits in thousand dollars.

```
                  F1: income <= 40?
                 /yes                \no
       F0: age <= 25?          F2: open loans <= 2?
        /yes      \no            /yes           \no
       0           5            20              10
```

Each decision node is written as `NumericNode(feature index, threshold, what to do if
feature <= threshold, what to do otherwise)`, and leaves are `NumericLeaf(value)`. So, the tree
above becomes:

```go
leaf, node := lightphe.NumericLeaf, lightphe.NumericNode

creditLimitTree := node(1, 40,
    node(0, 25, leaf(0), leaf(5)),
    node(2, 2, leaf(20), leaf(10)),
)
```

Then, the customer and the bank run the following steps.

```go
// customer: age = 30, income = 75 and open loans = 1
// so, the expected path is income > 40 -> open loans <= 2 -> credit limit of 20
customerCs, _ := lightphe.New(lightphe.DamgardGeislerKroigaard)
_ = customerCs.ExportKeys("public.txt", true)
encryptedFeatures, _ := customerCs.EncryptDecisionTreeFeatures([]int64{30, 75, 1}, 8)

// bank, having the customer's public key only
bankCs, _ := lightphe.New(lightphe.DamgardGeislerKroigaard, lightphe.WithKeyFile("public.txt"))
encryptedComparisons, bankState, _ := bankCs.EvaluateDecisionTreeComparisons(creditLimitTree, encryptedFeatures)

// customer answers randomly flipped comparisons, so cannot follow the path in the tree
encryptedAnswers, _ := customerCs.AnswerDecisionTreeComparisons(encryptedComparisons)

// bank keeps bankState secret and finds the reached leaf in encrypted form
encryptedLeaves, _ := bankCs.EvaluateDecisionTreeLeaves(bankState, encryptedAnswers)

// customer learns only the credit limit
limit, _ := customerCs.DecryptDecisionTreeOutput(encryptedLeaves)
if limit.Int64() != 20 {
    panic("decision tree evaluation failed")
}
```

### Secure comparison

Damgard-Geisler-Kroigaard lets a client and a server find out whether the client's private value
is less than or equal to the server's private value, without revealing the values to each other.
For instance, a bidder can check whether their bid beats the reserve price of an auction.

```go
// client encrypts its value bit by bit
clientCs, _ := lightphe.New(lightphe.DamgardGeislerKroigaard)
_ = clientCs.ExportKeys("public.txt", true)
encryptedBid, _ := clientCs.EncryptComparisonInput(120, 16)

// server compares it with its own value having the client's public key only
serverCs, _ := lightphe.New(lightphe.DamgardGeislerKroigaard, lightphe.WithKeyFile("public.txt"))
encryptedResult, _ := serverCs.EvaluateComparison(encryptedBid, 150)

// client learns only whether bid <= reserve price
lessOrEqual, _ := clientCs.DecryptComparison(encryptedResult)
if !lessOrEqual {
    panic("secure comparison failed")
}
```

### Encrypted argmax

Damgard-Geisler-Kroigaard can also find the index of the maximum among encrypted values. For
instance, a server can compute encrypted class scores of a linear classifier on a client's
encrypted features, and then find the predicted class. The client learns only the index, neither
the scores nor the intermediate comparisons, and the server learns nothing. The protocol needs a
few round trips per value, so the server talks to the client through a callback. Locally, it can
be the client's `AnswerArgmax` directly. Otherwise, wrap your network call with it.

```go
// client encrypts its features
clientCs, _ := lightphe.New(lightphe.DamgardGeislerKroigaard)
_ = clientCs.ExportKeys("public.txt", true)
var encryptedFeatures []*lightphe.Ciphertext
for _, feature := range []int64{3, 1, 4} {
    c, _ := clientCs.EncryptInt(feature)
    encryptedFeatures = append(encryptedFeatures, c)
}

// server computes class scores with its private weights homomorphically
serverCs, _ := lightphe.New(lightphe.DamgardGeislerKroigaard, lightphe.WithKeyFile("public.txt"))
weights := [][]int64{{1, 2, 0}, {0, 1, 3}, {2, 0, 1}}
var encryptedScores []*lightphe.Ciphertext
for _, classWeights := range weights {
    score, _ := encryptedFeatures[0].MultiplyByInt(classWeights[0])
    for i := 1; i < len(classWeights); i++ {
        term, _ := encryptedFeatures[i].MultiplyByInt(classWeights[i])
        score, _ = score.Add(term)
    }
    encryptedScores = append(encryptedScores, score)
}

// server finds the argmax with the client's help - scores must fit into 8 bits
encryptedClass, _ := serverCs.EvaluateArgmax(encryptedScores, 8, clientCs.AnswerArgmax)

// client learns only the predicted class
class, _ := clientCs.Decrypt(encryptedClass)
if class.Int64() != 1 {
    panic("encrypted argmax failed")
}
```

### Hyperplane and naive Bayes classifiers

Together with [decision trees](#decision-trees), Damgard-Geisler-Kroigaard supports the
classifiers of Bost et al. over encrypted data: hyperplane classifiers, e.g. logistic regression or
linear SVM, and naive Bayes. The client encrypts its features, the server evaluates its private
model on them, and finds the predicted class with [encrypted argmax](#encrypted-argmax). The client
learns only the predicted class, and the server learns nothing about the features. Scores of
classes must fit into about 30 bits, so floats must be quantized to integers.

```go
// client encrypts its features: income and debt in thousands, years of employment, late payments
clientCs, _ := lightphe.New(lightphe.DamgardGeislerKroigaard)
_ = clientCs.ExportKeys("public.txt", true)
var encryptedFeatures []*lightphe.Ciphertext
for _, feature := range []int64{85, 20, 6, 0} {
    c, _ := clientCs.EncryptInt(feature)
    encryptedFeatures = append(encryptedFeatures, c)
}

// bank's logistic regression model, quantized by 1000: class 1 approves the loan
serverCs, _ := lightphe.New(lightphe.DamgardGeislerKroigaard, lightphe.WithKeyFile("public.txt"))
weights := [][]int64{{0, 0, 0, 0}, {42, -65, 310, -900}}
biases := []int64{0, -1200}

// absolute values of scores must be less than 2^16
encryptedClass, _ := serverCs.EvaluateHyperplane(encryptedFeatures, weights, 16, clientCs.AnswerArgmax, biases)
approved, _ := clientCs.Decrypt(encryptedClass) // 1
```

Naive Bayes works with categorical features, which the client encrypts as one-hot vectors. The
server quantizes the logarithms of its probabilities, which must be positive, e.g. smoothed with
Laplace smoothing.

```go
// continuing with clientCs and serverCs above
// patient encrypts symptoms: fever (no, yes), cough (none, dry, wet), fatigue (no, yes)
encryptedSymptoms, _ := clientCs.EncryptNaiveBayesInput([]int{1, 1, 1}, []int{2, 3, 2})

// clinic's model: P(diagnosis) and P(symptom | diagnosis) for cold, flu and allergy
priors := []float64{0.36, 0.36, 0.28}
likelihoods := [][][]float64{
    {{0.71, 0.29}, {0.12, 0.25, 0.63}, {0.71, 0.29}},
    {{0.29, 0.71}, {0.12, 0.63, 0.25}, {0.29, 0.71}},
    {{0.83, 0.17}, {0.57, 0.29, 0.14}, {0.67, 0.33}},
}

// log probabilities are quantized with 3 decimal digits
encryptedDiagnosis, _ := serverCs.EvaluateNaiveBayes(encryptedSymptoms, priors, likelihoods, clientCs.AnswerArgmax, 3)

// patient learns only the most likely diagnosis: flu
diagnosis, _ := clientCs.Decrypt(encryptedDiagnosis) // 1
```

Scenarios:

- A customer applies for a loan from a mobile app, and the bank runs its credit scoring model on
  the encrypted income and debts, so the customer learns only whether the loan is approved, and
  the bank neither reveals its model nor sees the financial details before the customer agrees to
  share them.
- A patient checks symptoms with an online clinic, whose diagnosis model was trained on years of
  patient records, so the patient learns the most likely diagnosis without revealing the symptoms,
  and the clinic does not give away its model.
- An email client asks a spam filtering service whether a message is spam, and the service
  classifies the encrypted word counts of the message, so it never reads the email.

### Encrypted nearest neighbor search

lightphe-go can find the k nearest vectors to an encrypted query, e.g. searching a face embedding
in a gallery, without revealing the query. Embeddings must be quantized to integers first, e.g. by
scaling and rounding. There are two settings.

If the server owns the gallery in plain, the client encrypts its query with
Damgard-Geisler-Kroigaard, and the server finds the nearest vectors with
[encrypted argmax](#encrypted-argmax). The server learns neither the query nor the result, and the
client learns only the indices or labels of the k nearest vectors, neither the distances nor the
other vectors. It needs about 0.15 seconds per vector of the gallery and per nearest vector to
find with 1024-bit keys.

```go
// client encrypts its face embedding, quantized to integers
clientCs, _ := lightphe.New(lightphe.DamgardGeislerKroigaard)
_ = clientCs.ExportKeys("public.txt", true)
encryptedQuery, _ := clientCs.EncryptKNNQuery([]int64{12, -7, 33, 5})

// server finds the 2 nearest vectors of its gallery - squared distances must fit into 16 bits
serverCs, _ := lightphe.New(lightphe.DamgardGeislerKroigaard, lightphe.WithKeyFile("public.txt"))
gallery := [][]int64{{10, -5, 30, 4}, {-40, 22, 1, 9}, {13, -8, 35, 6}}
people := []int64{101, 102, 103}
result, _ := serverCs.EvaluateKNN(encryptedQuery, gallery, 2, 16, clientCs.AnswerKNN, people)

// client learns only who the nearest people are
for _, label := range result.Labels {
    person, _ := clientCs.Decrypt(label)
    fmt.Println(person) // 103, then 101
}
```

If the gallery itself is stored in an untrusted cloud, the owner encrypts both the gallery and its
queries with the [Catalano-Fiore](#adding-multiplication-support-to-additive-algorithms) boost. The
cloud computes encrypted squared distances with the public key only, and the owner decrypts them to
find the nearest vectors. The cloud learns nothing.

```go
// owner encrypts its gallery once, uploads it, and then encrypts queries
ownerCs, _ := lightphe.New(lightphe.Paillier, lightphe.WithBoost(lightphe.CatalanoFiore))
_ = ownerCs.ExportKeys("public.txt", true)
encryptVector := func(vector []int64) []*lightphe.Ciphertext {
    var out []*lightphe.Ciphertext
    for _, x := range vector {
        c, _ := ownerCs.EncryptInt(x)
        out = append(out, c)
    }
    return out
}
var encryptedGallery [][]*lightphe.Ciphertext
for _, vector := range [][]int64{{10, -5, 30, 4}, {-40, 22, 1, 9}, {13, -8, 35, 6}} {
    encryptedGallery = append(encryptedGallery, encryptVector(vector))
}
encryptedQuery := encryptVector([]int64{12, -7, 33, 5})

// cloud computes encrypted distances with the public key only
cloudCs, _ := lightphe.New(lightphe.Paillier, lightphe.WithKeyFile("public.txt"), lightphe.WithBoost(lightphe.CatalanoFiore))
encryptedDistances, _ := cloudCs.EvaluateKNNDistances(encryptedQuery, encryptedGallery)

// owner decrypts them and finds the nearest vectors
nearest, _ := ownerCs.DecryptKNN(encryptedDistances, 2) // nearest.Indices is [2 0]
```

Scenarios:

- A user unlocks a door by face, and the building's server matches the encrypted face embedding
  against its gallery of employees, so the server never sees the user's face and the user learns
  only whether they are recognized, not who else is enrolled.
- A bank checks whether a new customer's encrypted face embedding matches anyone on a sanctions
  list held by a screening provider, so the provider does not learn the customer and the bank does
  not get the list.
- A company keeps the face embeddings of its employees in a public cloud, and searches them with
  encrypted queries, so a breach of the cloud reveals neither the gallery nor the queries.
- A retailer recommends products by finding the nearest items to a user's encrypted preference
  vector, so the server does not learn the user's taste.

### Master key decryption

Bresson-Catalano-Pointcheval has two ways to decrypt a ciphertext. Each user decrypts with its
own private key, while an authority holding the master key decrypts ciphertexts of all users. For
instance, a company can let every employee encrypt with their own key, and still recover the data
if an employee leaves. Keep in mind that the master key holder can read everything by design.

```go
// authority generates the master key and publishes its public key
authorityCs, _ := lightphe.New(lightphe.BressonCatalanoPointcheval)
_ = authorityCs.ExportKeys("public.txt", true)

// each user generates its own key pair with the public key of the authority
publicCs, _ := lightphe.New(lightphe.BressonCatalanoPointcheval, lightphe.WithKeyFile("public.txt"))
aliceKeys, _ := publicCs.GenerateUserKeys()
bobKeys, _ := publicCs.GenerateUserKeys()
aliceCs, _ := lightphe.New(lightphe.BressonCatalanoPointcheval, lightphe.WithKeys(aliceKeys))
bobCs, _ := lightphe.New(lightphe.BressonCatalanoPointcheval, lightphe.WithKeys(bobKeys))

c1, _ := aliceCs.EncryptInt(100)
c2, _ := aliceCs.EncryptInt(50)
aliceCiphertext, _ := c1.Add(c2)
bobCiphertext, _ := bobCs.EncryptInt(200)

// users decrypt their own ciphertexts only
m, _ := aliceCs.Decrypt(aliceCiphertext) // 150
m, _ = aliceCs.Decrypt(bobCiphertext)    // not 200

// authority decrypts ciphertexts of all users
m, _ = authorityCs.DecryptWithMasterKey(aliceCiphertext) // 150
m, _ = authorityCs.DecryptWithMasterKey(bobCiphertext)   // 200
```

`DecryptTensorWithMasterKey` does the same for encrypted tensors.

### Threshold decryption

ElGamal, Exponential ElGamal, Elliptic Curve ElGamal, Paillier and Damgard-Jurik support threshold
decryption. ElGamal and Exponential ElGamal keys must be generated with
`lightphe.WithPrimeOrder(true)` for this. A dealer splits the private key into shares, and any
`threshold` of `parties` shareholders decrypt a ciphertext together, whereas fewer shareholders
learn nothing. For instance, a board of 5 directors can let any 3 of them decrypt the company's
encrypted data, so neither a single director can read it alone nor losing 2 of them blocks access.

```go
// dealer splits the private key into 5 shares, any 3 of them can decrypt
dealerCs, _ := lightphe.New(lightphe.Paillier)
publicKey, shareKeys, _ := dealerCs.GenerateThresholdKeys(3, 5)

// dealer publishes the public key with threshold parameters, and forgets its private key
_ = os.WriteFile("public.txt", publicKey, 0644)

// each share key is sent to its own shareholder secretly
var shareholders []*lightphe.Cryptosystem
for _, keys := range shareKeys {
    shareholder, _ := lightphe.New(lightphe.Paillier, lightphe.WithKeys(keys))
    shareholders = append(shareholders, shareholder)
}

// anyone encrypts and computes homomorphically with the public key
publicCs, _ := lightphe.New(lightphe.Paillier, lightphe.WithKeyFile("public.txt"))
c1, _ := publicCs.EncryptInt(100)
c2, _ := publicCs.EncryptInt(50)
c, _ := c1.Add(c2)

// any 3 shareholders decrypt partially, a single partial decryption reveals nothing
var partials []*lightphe.PartialDecryption
for _, i := range []int{0, 2, 4} {
    partial, _ := shareholders[i].PartialDecrypt(c, false)
    partials = append(partials, partial)
}

// anyone having the public key combines partial decryptions
m, _ := publicCs.CombinePartialDecryptions(c, partials, false) // 150
```

A cryptosystem is immutable, so the dealer's cryptosystem keeps its private key after splitting
it: publish the returned public key instead of the dealer's own, and discard the dealer's keys. The
dealer knows the private key while splitting it, so it must be trusted. Share keys and partial
decryptions marshal to the same JSON as the Python library's. `PartialDecryptTensor` and
`CombineTensorPartialDecryptions` do the same for encrypted tensors. By default, partial
decryptions are not proven, so a cheating shareholder can cause a wrong plaintext silently.
[Proof of partial decryption](#proof-of-partial-decryption) prevents this.

### Secure aggregation for federated learning

In federated learning, clients train a model on their private data and send only model updates to
a server, but updates can still leak the data. lightphe-go lets clients encrypt their updates, the
server sum them without decrypting, and a committee holding shares of the private key decrypt only
the sum with [threshold decryption](#threshold-decryption). Updates are quantized with the precision
of the cryptosystem, and many values are packed into a single ciphertext, so a client encrypts one
ciphertext per chunk instead of one per value. With 1024-bit keys, 40 values fit into a ciphertext,
so an update of 1000 values needs 25 ciphertexts instead of 1000. Paillier and Damgard-Jurik
support this.

```go
// dealer splits the key among a committee of 5, any 3 of them can decrypt
dealerCs, _ := lightphe.New(lightphe.Paillier, lightphe.WithSafePrimes(true))
publicKey, shareKeys, _ := dealerCs.GenerateThresholdKeys(3, 5)
var committee []*lightphe.Cryptosystem
for _, keys := range shareKeys {
    member, _ := lightphe.New(lightphe.Paillier, lightphe.WithKeys(keys))
    committee = append(committee, member)
}

// each client encrypts its update with the public key - values must be in [-1, 1]
clientCs, _ := lightphe.New(lightphe.Paillier, lightphe.WithKeys(publicKey))
updates := [][]float64{{0.12, -0.53, 0.98}, {0.33, 0.21, -0.47}, {-0.25, 0.08, 0.61}}
var encryptedUpdates []*lightphe.EncryptedUpdate
for _, update := range updates {
    encryptedUpdate, _ := clientCs.EncryptUpdate(update, 1, 100)
    encryptedUpdates = append(encryptedUpdates, encryptedUpdate)
}

// server sums encrypted updates without decrypting them
serverCs, _ := lightphe.New(lightphe.Paillier, lightphe.WithKeys(publicKey))
encryptedSum, _ := serverCs.AggregateUpdates(encryptedUpdates)

// any 3 members decrypt the sum only, and prove their partial decryptions
var partials [][]*lightphe.PartialDecryption
for _, member := range committee[:3] {
    memberPartials, _ := member.PartialDecryptAggregate(encryptedSum, true)
    partials = append(partials, memberPartials)
}
result, _ := serverCs.CombineAggregate(encryptedSum, partials, true)
// result.Mean is [0.0667, -0.08, 0.3733] rounded
```

The maximum number of clients, 100 above, reserves room in each slot, so that the sum of that many
updates never overflows into the next value, and the server refuses to sum more. Clients must use
the same key, length, precision, maximum value and maximum number of clients. Updates of dropped
clients are simply not summed, and the sum can still be decrypted if up to 2 committee members drop
out. A single key owner decrypts the sum with `DecryptAggregate` instead.

Scenarios:

- Hospitals train a model to detect tumors on their own scans, and a central server averages their
  encrypted model updates, so neither the server nor the other hospitals see any hospital's update,
  which could leak information about its patients.
- A keyboard app improves next-word prediction from millions of phones, and a committee of
  independent organizations decrypts only the average update of each round, so no single party,
  including the app maker, can inspect the update of a particular phone.
- Banks build a shared fraud detection model, and verified partial decryptions stop a dishonest
  committee member from slipping a manipulated average into the shared model.

### Zero-knowledge proofs

lightphe-go lets you prove facts about ciphertexts and decryptions without revealing the plaintexts
or the private key, and anyone having the public key can verify them. For instance, a voter proves
that a ballot is 0 or 1, an employee proves that an encrypted salary is in a sensible range, and an
authority proves that the announced tally is really what the encrypted tally contains.

| Algorithm | Proof of<br>Decryption | Proof of<br>Partial Decryption | Proof of<br>Knowledge | Proof of<br>Allowed Values | Proof of<br>Range | E-Voting | Verifiable<br>Encryption |
| --- | --- | --- | --- | --- | --- | --- | --- |
| ElGamal | ✅ | ✅ | ✅ | ❌ | ❌ | ❌ | ❌ |
| ExponentialElGamal | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ❌ |
| EllipticCurveElGamal | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ❌ |
| Paillier | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ❌ |
| DamgardJurik | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ❌ |
| CamenischShoup | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ |

ElGamal and Exponential ElGamal keys must be generated with `lightphe.WithPrimeOrder(true)` for
proofs. Paillier and Damgard-Jurik keys must be generated with `lightphe.WithSafePrimes(true)` for
proof of partial decryption. Proofs marshal to the same JSON as the Python library's, and their
Fiat-Shamir challenges hash the same transcripts, so proofs made by one library verify in the
other. A context binds a proof to public data such as the id of the prover. It can be any value
serializable to JSON, or nil.

#### Proof of decryption

The private key owner can prove that a ciphertext decrypts to a plaintext, and anyone can check it
with the public key only. ElGamal family uses a Chaum-Pedersen zero-knowledge proof, so the private
key is never revealed. Paillier and Damgard-Jurik reveal the randomness of the ciphertext instead,
which proves the plaintext and reveals nothing about the private key or other ciphertexts.

```go
// private key owner builds the cryptosystem and publishes its public key
cs, _ := lightphe.New(lightphe.ExponentialElGamal, lightphe.WithPrimeOrder(true))
_ = cs.ExportKeys("public.txt", true)
publicCs, _ := lightphe.New(lightphe.ExponentialElGamal, lightphe.WithKeyFile("public.txt"))

c1, _ := publicCs.EncryptInt(17)
c2, _ := publicCs.EncryptInt(25)
c, _ := c1.Add(c2)

// private key owner decrypts with a proof
plaintext, proof, _ := cs.DecryptWithProof(c) // 42

// anyone verifies it with public key only
valid, _ := publicCs.VerifyDecryption(c, plaintext, proof)                                // true
valid, _ = publicCs.VerifyDecryption(c, new(big.Int).Add(plaintext, big.NewInt(1)), proof) // false
```

Scenarios:

- An election authority announces that 5,000 of 8,000 encrypted ballots are yes, and publishes a
  proof, so every voter can check that the announced result is really what the encrypted tally
  contains without trusting the authority.
- A cloud service computes the average salary over encrypted payroll data of a client company and
  decrypts it with a proof, so an external auditor can confirm that the reported average was not
  altered on its way to the board.
- A bank publishes the decrypted total of a day's encrypted transactions together with a proof, so
  a regulator can verify the total without being given the bank's private key or the individual
  transactions.

#### Proof of partial decryption

In [threshold decryption](#threshold-decryption), a cheating shareholder can send a wrong partial
decryption and cause a wrong plaintext silently. A cheating shareholder can even shift the result
by any amount it chooses, e.g. add 50 votes to a party, because lagrange coefficients of other
shareholders are public. Shareholders can opt in to prove that their partial decryptions are
computed with their own shares, and the combiner can opt in to verify them. Then, invalid or
unproven partial decryptions are discarded. Paillier and Damgard-Jurik keys must be generated with
`lightphe.WithSafePrimes(true)` for this.

```go
// dealer splits the private key into 3 shares, any 2 of them can decrypt
dealerCs, _ := lightphe.New(lightphe.ExponentialElGamal, lightphe.WithPrimeOrder(true))
publicKey, shareKeys, _ := dealerCs.GenerateThresholdKeys(2, 3)
publicCs, _ := lightphe.New(lightphe.ExponentialElGamal, lightphe.WithKeys(publicKey))

c, _ := publicCs.EncryptInt(42)

// shareholders opt in to prove their partial decryptions
var partials []*lightphe.PartialDecryption
for _, keys := range shareKeys {
    shareholder, _ := lightphe.New(lightphe.ExponentialElGamal, lightphe.WithKeys(keys))
    partial, _ := shareholder.PartialDecrypt(c, true)
    partials = append(partials, partial)
}

// anyone verifies a partial decryption with public key only, e.g. to find a cheating shareholder
valid, _ := publicCs.VerifyPartialDecryption(c, partials[0]) // true

// combiner opts in to verify partial decryptions while combining them
m, _ := publicCs.CombinePartialDecryptions(c, partials, true) // 42
```

Scenarios:

- Three trustees nominated by competing parties decrypt an election tally together, so a trustee
  who tries to add 50 votes to its own party by tampering with its partial decryption is detected
  and outvoted by the honest two.
- Five hospitals hold shares of a key protecting encrypted patient statistics, and any three of
  them decrypt the yearly average together, so a single hospital cannot quietly bias the published
  average in its favor.
- Servers of a federated learning committee decrypt the sum of encrypted model updates from
  thousands of phones, so a compromised server cannot slip a poisoned update into the global model
  without being caught.
- Two of three auditors are required to open the total of a company's encrypted transactions, so an
  auditor bribed to hide a loss cannot misreport the total.

#### Proof of knowledge

Anyone having the public key can encrypt a value and prove knowledge of it, without revealing it.
Otherwise, someone could copy another one's ciphertext, re-randomize it or modify it
homomorphically, and submit it as their own without knowing the plaintext. The proof is bound to
the ciphertext and a context such as the id of the encryptor.

```go
cs, _ := lightphe.New(lightphe.Paillier)

// alice submits her sealed bid with a proof of knowledge
aliceBid, aliceProof, _ := cs.EncryptWithProofOfKnowledge(big.NewInt(950), "alice")
valid, _ := cs.VerifyKnowledge(aliceBid, aliceProof, "alice") // true

// mallory outbids alice by adding 1 to her encrypted bid without knowing it, but cannot prove it
one, _ := cs.EncryptInt(1)
malloryBid, _ := aliceBid.Add(one)
valid, _ = cs.VerifyKnowledge(malloryBid, aliceProof, "mallory") // false
```

Scenarios:

- In a sealed-bid auction, Mallory sees Alice's encrypted bid and submits it plus 1 to win by the
  smallest margin without knowing the amount, but she cannot prove knowledge of that bid, so her
  submission is rejected.
- On a crowdfunding platform, a backer cannot copy a large encrypted pledge of another backer and
  scale it to look generous, because each pledge must come with a proof that its owner knows the
  amount.
- In an encrypted employee survey, a participant cannot re-randomize a colleague's encrypted answer
  and submit it as their own to double its weight, because a re-randomized copy cannot be proven.

#### Proof of allowed values

Anyone having the public key can encrypt a value and prove that it is one of the allowed values,
without revealing which one. Nil values allow 0 and 1. The proof is bound to a context such as the
id of the encryptor, so a copied ciphertext with its proof is rejected for another context.

```go
cs, _ := lightphe.New(lightphe.Paillier)
stars := []*big.Int{big.NewInt(1), big.NewInt(2), big.NewInt(3), big.NewInt(4), big.NewInt(5)}

// a customer rates a product from 1 to 5 stars, and proves it without revealing the rating
rating, proof, _ := cs.EncryptWithProof(big.NewInt(4), stars, "customer-42")

// anyone verifies it with public key only
valid, _ := cs.VerifyCiphertext(rating, proof, stars, "customer-42") // true
valid, _ = cs.VerifyCiphertext(rating, proof, stars, "customer-43")  // false
```

Scenarios:

- An online shop collects encrypted product ratings, and each customer proves that the rating is
  between 1 and 5 stars, so nobody can submit a rating of 1,000 to push the average up while
  individual ratings stay private.
- A company runs an anonymous satisfaction survey with answers from 1 (poor) to 4 (excellent), and
  each employee proves that the encrypted answer is one of them, so the average satisfaction is
  computed homomorphically and a malformed answer cannot corrupt it.
- In [e-voting](#e-voting), each voter proves that the ballot is 0 or 1, so nobody can cast a vote
  of 100 in the homomorphic tally without revealing how they voted.

#### Proof of range

Anyone having the public key can encrypt a value and prove that it is in `[low, high]`, without
revealing it. Proof size grows with the bit length of `high - low`.

```go
cs, _ := lightphe.New(lightphe.Paillier)
low, high := big.NewInt(0), big.NewInt(500000)

// an employee proves that the encrypted salary is in [0, 500000], so cannot skew the average
salary, proof, _ := cs.EncryptWithRangeProof(big.NewInt(85000), low, high, "alice")

// anyone verifies it with public key only
valid, _ := cs.VerifyRange(salary, proof, low, high, "alice")             // true
valid, _ = cs.VerifyRange(salary, proof, low, big.NewInt(50000), "alice") // false
```

Scenarios:

- In an industry salary survey, each employee encrypts the salary with a proof that it is between
  0 and 500,000, so a single participant cannot submit a negative or a billion-dollar salary to
  skew the published average.
- A website requires visitors to be adults, and a visitor proves that the encrypted age is between
  18 and 120 without revealing the exact age or birth date.
- In a participatory budget, each citizen allocates up to 1,000 to public projects in encrypted
  form, so allocations are proven to be within the cap while individual preferences stay private.
- A lender accepts an encrypted credit score with a proof that it is between 650 and 850, so the
  applicant shows eligibility without revealing the exact score.

#### E-voting

[Proof of allowed values](#proof-of-allowed-values) makes e-voting possible. Each voter proves that
a ballot is 0 or 1, so cannot cast a vote of 100 in the homomorphic tally. The proof is bound to
the id of the voter, so a copied ballot is rejected. Then, the authority decrypts the tally with a
[proof of decryption](#proof-of-decryption).

```go
// authority builds the cryptosystem and publishes its public key
authorityCs, _ := lightphe.New(lightphe.ExponentialElGamal, lightphe.WithPrimeOrder(true))
_ = authorityCs.ExportKeys("public.txt", true)
publicCs, _ := lightphe.New(lightphe.ExponentialElGamal, lightphe.WithKeyFile("public.txt"))

// each voter encrypts a vote of 0 or 1 with a proof, having the public key only
aliceBallot, aliceProof, _ := publicCs.EncryptWithProof(big.NewInt(1), nil, "alice")
bobBallot, bobProof, _ := publicCs.EncryptWithProof(big.NewInt(0), nil, "bob")

// anyone verifies ballots without decrypting them
valid, _ := publicCs.VerifyCiphertext(aliceBallot, aliceProof, nil, "alice") // true
valid, _ = publicCs.VerifyCiphertext(bobBallot, bobProof, nil, "bob")       // true

// mallory's copy of alice's ballot is rejected
valid, _ = publicCs.VerifyCiphertext(aliceBallot, aliceProof, nil, "mallory") // false

// valid ballots are tallied homomorphically, and the authority decrypts the tally with a proof
tally, _ := aliceBallot.Add(bobBallot)
result, proof, _ := authorityCs.DecryptWithProof(tally)   // 1
valid, _ = publicCs.VerifyDecryption(tally, result, proof) // true
```

For an election of parties, a vote for party `k` can be encrypted as `base^k`, so the tally keeps
the votes of each party in its own digit in that base. The proof guarantees that a voter votes once
for exactly one party. `base` must be greater than the votes a party can get, e.g. 100 allows up to
99 votes per party, and `base^parties` must be less than the modulus. Paillier fits here, as the
tally is a large number.

```go
// authority builds the cryptosystem and publishes its public key
authorityCs, _ := lightphe.New(lightphe.Paillier)
_ = authorityCs.ExportKeys("public.txt", true)
publicCs, _ := lightphe.New(lightphe.Paillier, lightphe.WithKeyFile("public.txt"))

// a vote for party k is encrypted as 100^k, i.e. 1 for red, 100 for green and 10000 for blue
parties := []string{"red", "green", "blue"}
values := []*big.Int{big.NewInt(1), big.NewInt(100), big.NewInt(10000)}

// each voter encrypts a vote for one party with a proof
aliceBallot, aliceProof, _ := publicCs.EncryptWithProof(values[0], values, "alice")
bobBallot, bobProof, _ := publicCs.EncryptWithProof(values[2], values, "bob")
carolBallot, carolProof, _ := publicCs.EncryptWithProof(values[0], values, "carol")

// anyone verifies ballots without decrypting them
valid, _ := publicCs.VerifyCiphertext(aliceBallot, aliceProof, values, "alice") // true
valid, _ = publicCs.VerifyCiphertext(bobBallot, bobProof, values, "bob")       // true
valid, _ = publicCs.VerifyCiphertext(carolBallot, carolProof, values, "carol") // true

// valid ballots are tallied homomorphically, and the authority decrypts the tally with a proof
tally, _ := aliceBallot.Add(bobBallot)
tally, _ = tally.Add(carolBallot)
result, proof, _ := authorityCs.DecryptWithProof(tally)
valid, _ = publicCs.VerifyDecryption(tally, result, proof) // true

// tally is 2 x 1 + 0 x 100 + 1 x 10000 = 10002, read 2 digits at a time from right: 1 | 00 | 02
votes := map[string]int64{}
for _, party := range parties {
    digit := new(big.Int)
    result.DivMod(result, big.NewInt(100), digit)
    votes[party] = digit.Int64() // red: 2, green: 0, blue: 1
}
```

Alternatively, for an election of many parties, each voter casts a one-hot ballot, i.e. one
ciphertext per party where only the chosen party is 1, with a proof that exactly one party is
chosen. Summing ballots slot by slot counts the votes of each party separately, so the number of
parties is not limited.

```go
// authority builds the cryptosystem and publishes its public key
authorityCs, _ := lightphe.New(lightphe.ExponentialElGamal, lightphe.WithPrimeOrder(true))
_ = authorityCs.ExportKeys("public.txt", true)
publicCs, _ := lightphe.New(lightphe.ExponentialElGamal, lightphe.WithKeyFile("public.txt"))

parties := []string{"red", "green", "blue", "yellow"}

// each voter encrypts a vote for one party as a one-hot ballot with a proof
aliceBallot, aliceProof, _ := publicCs.EncryptOneHot(0, len(parties), "alice") // red
bobBallot, bobProof, _ := publicCs.EncryptOneHot(2, len(parties), "bob")       // blue
carolBallot, carolProof, _ := publicCs.EncryptOneHot(0, len(parties), "carol") // red

// anyone verifies ballots without decrypting them
valid, _ := publicCs.VerifyOneHot(aliceBallot, aliceProof, "alice") // true
valid, _ = publicCs.VerifyOneHot(bobBallot, bobProof, "bob")       // true
valid, _ = publicCs.VerifyOneHot(carolBallot, carolProof, "carol") // true

// valid ballots are summed slot by slot, so each party's votes are counted in its own ciphertext
votes := map[string]int64{}
for k, party := range parties {
    count, _ := aliceBallot[k].Add(bobBallot[k])
    count, _ = count.Add(carolBallot[k])

    // authority decrypts the count of each party with a proof
    result, proof, _ := authorityCs.DecryptWithProof(count)
    valid, _ = publicCs.VerifyDecryption(count, result, proof) // true
    votes[party] = result.Int64() // red: 2, green: 0, blue: 1, yellow: 0
}
```

Scenarios:

- A city runs a referendum on a new park, and every resident casts an encrypted yes or no ballot
  with a proof, so the city announces the result with a proof of decryption while nobody, including
  the city, learns how an individual voted.
- A national election of a few parties encrypts a vote for party k as `base^k`, so a single
  homomorphic sum and a single decryption reveal the votes of every party at once.
- A national election of dozens of parties uses one-hot ballots of `EncryptOneHot` and
  `VerifyOneHot`, so each party's votes are counted in its own ciphertext and the number of parties
  is not limited.
- Shareholders of a company vote on the board's proposals, and three independent trustees decrypt
  the tally with [threshold decryption](#threshold-decryption) and
  [proof of partial decryption](#proof-of-partial-decryption), so no single trustee can read or
  alter the result.

#### Verifiable encryption

Camenisch-Shoup lets you encrypt a secret for someone else and prove that the ciphertext really
contains it, without revealing the secret. For instance, Alice can escrow the private key of her
crypto wallet with a trusted third party. A bank, which knows only her public key, verifies that
the escrowed ciphertext contains its private key, and the trusted third party can recover it only
under the conditions written in the label.

```go
import "github.com/serengil/lightphe-go/lightphe/ecc"

// trusted third party builds the cryptosystem and publishes its public key
ttpCs, _ := lightphe.New(lightphe.CamenischShoup)
_ = ttpCs.ExportKeys("public.txt", true)

// alice's wallet key pair on secp256k1
curve, _ := ecc.New("weierstrass", "secp256k1")
privateKey := big.NewInt(123456789)
publicKey, _ := curve.G().ScalarMul(privateKey)

// alice encrypts her private key for the trusted third party with a proof
label := "release only if alice loses access to her wallet"
aliceCs, _ := lightphe.New(lightphe.CamenischShoup, lightphe.WithKeyFile("public.txt"))
escrow, _ := aliceCs.EncryptVerifiably(privateKey, label)

// bank verifies it with public keys only, without learning alice's private key
bankCs, _ := lightphe.New(lightphe.CamenischShoup, lightphe.WithKeyFile("public.txt"))
valid, _ := bankCs.VerifyEncryption(escrow, publicKey, label) // true

// trusted third party recovers the private key under the same label only
recovered, _ := ttpCs.DecryptVerifiableCiphertext(escrow, label) // 123456789
```

Private keys of other curves can be escrowed with `lightphe.WithCurve(form, curve)` while building
the cryptosystem. Verifiable ciphertexts reject any modification, so homomorphic operations are
applied to regular ciphertexts created with `Encrypt`. A `VerifiableCiphertext` marshals to the
same JSON as the Python library's, so proofs made by one library verify in the other.

Scenarios:

- Alice escrows the private key of her crypto wallet with a trusted third party, and her bank
  verifies that the escrow really contains the key before granting her a loan, without ever seeing
  the key.
- A company escrows the encryption keys of its employees with a recovery service, so an auditor can
  verify that every key is recoverable if an employee leaves, while neither the auditor nor the
  service can use the keys under normal conditions.
- A crypto exchange verifies that a customer's key is escrowed under conditions agreed with a
  regulator, e.g. release only with a court order, without learning the key itself.

### Adding multiplication support to additive algorithms

Additively homomorphic algorithms cannot multiply two ciphertexts. Boosting them with
Catalano-Fiore transform adds one multiplication on top of them, without changing the algorithms
themselves. This lets you evaluate degree-2 functions on encrypted data, such as dot products of
two encrypted vectors, variances or squared distances. It supports Paillier, Damgard-Jurik,
Bresson-Catalano-Pointcheval, Camenisch-Shoup, Elliptic Curve Paillier, Joye-Libert,
Castagnos-Laguillaumie, Naccache-Stern, Benaloh and Damgard-Geisler-Kroigaard.

```go
// client builds a boosted cryptosystem, and encrypts its private vectors
clientCs, _ := lightphe.New(lightphe.Paillier, lightphe.WithBoost(lightphe.CatalanoFiore))

x := []int64{3, 1, 4}
y := []int64{1, 5, 9}

// server computes dot product of encrypted vectors - ciphertexts carry the public key only
var dot *lightphe.Ciphertext
for i := range x {
    ex, _ := clientCs.EncryptInt(x[i])
    ey, _ := clientCs.EncryptInt(y[i])
    product, _ := ex.Multiply(ey)
    if dot == nil {
        dot = product
    } else {
        dot, _ = dot.Add(product)
    }
}

// client decrypts the result
m, _ := clientCs.Decrypt(dot) // 44
```

Multiplied ciphertexts can be added and multiplied with constants, but not multiplied with
ciphertexts again. They keep a pair of ciphertexts for every product, so a dot product of length d
grows d times. Only integers are supported.

### Post-quantum security

Most algorithms in lightphe-go rely on factoring or discrete logarithm problems, which a large
enough quantum computer could solve with Shor's algorithm. Regev, Lyubashevsky-Peikert-Regev,
ML-KEM, Brakerski-Vaikuntanathan and Gentry-Sahai-Waters rely on learning with errors problems
instead, which are believed to be hard for quantum computers too.
Their default key sizes give about 128-bit security against quantum attacks.

Regev is additively homomorphic. Its key size is the lattice dimension, and its default is 2048.

```go
cs, _ := lightphe.New(lightphe.Regev)

c1, _ := cs.EncryptInt(1500)
c2, _ := cs.EncryptInt(2500)

sum, _ := c1.Add(c2)             // decrypts to 4000
scaled, _ := c1.MultiplyByInt(3) // decrypts to 4500
```

Lyubashevsky-Peikert-Regev is Regev over a polynomial ring, so its security relies on the ring
learning with errors problem like Brakerski-Vaikuntanathan. Its random matrix is replaced by a
single polynomial, so it generates keys and prepares a public key for encryption in milliseconds
instead of about a second for Regev, with the same key and ciphertext sizes. Its key size is the
degree of its polynomial ring, and its default is 2048.

```go
cs, _ := lightphe.New(lightphe.LyubashevskyPeikertRegev)

c1, _ := cs.EncryptInt(1500)
c2, _ := cs.EncryptInt(2500)

sum, _ := c1.Add(c2)             // decrypts to 4000
scaled, _ := c1.MultiplyByInt(3) // decrypts to 4500
```

ML-KEM uses the parameter sets standardized by NIST in FIPS 203: ML-KEM-512, ML-KEM-768 and
ML-KEM-1024. It is homomorphic with respect to the exclusive or of 256-bit messages like
Goldwasser-Micali. Its key size is the parameter set, and its default is 768. Notice that this is
the CPA secure public key encryption K-PKE inside ML-KEM, without ciphertext compression and
without the transform that makes ML-KEM CCA secure, because a CCA secure scheme cannot be
homomorphic. So, it is not a FIPS 203 compliant ML-KEM implementation, and its keys and
ciphertexts are not interoperable with other ML-KEM libraries. Its modulus is small, so only a few
ciphertexts can be combined: exclusive or of 6 ciphertexts fails with a probability of about 2^-50
for ML-KEM-768.

```go
cs, _ := lightphe.New(lightphe.MLKEM)

m1, _ := new(big.Int).SetString("1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef", 16)
m2, _ := new(big.Int).SetString("fedcba0987654321fedcba0987654321fedcba0987654321fedcba0987654321", 16)

c1, _ := cs.Encrypt(m1)
c2, _ := cs.Encrypt(m2)

c3, _ := c1.Xor(c2) // decrypts to m1 ^ m2
```

Brakerski-Vaikuntanathan additionally supports one multiplication of ciphertexts like
Boneh-Goh-Nissim, but without pairings. Its key size is the degree of its polynomial ring, and its
default is 4096.

```go
cs, _ := lightphe.New(lightphe.BrakerskiVaikuntanathan)

c1, _ := cs.EncryptInt(15)
c2, _ := cs.EncryptInt(25)
c3, _ := cs.EncryptInt(100)

// one multiplication, then additions and multiplications with constants
product, _ := c1.Multiply(c2)
result, _ := product.Add(c3) // decrypts to 475
```

Gentry-Sahai-Waters encrypts bits, and supports both exclusive or and and, so boolean circuits can
be evaluated on encrypted bits with more than one multiplication. Exclusive or is almost free.
Products of products work up to a multiplicative depth of 2, e.g. `(a & b) & (c & d)`, whereas
chains like `acc = acc & fresh`, e.g. carries of a ripple carry adder, can be very long because
each step adds a small fixed noise. Its key size is the degree of its polynomial ring, and its
default is 2048. Encrypting a bit takes about 70 milliseconds, an and takes about 110 milliseconds,
and a ciphertext is about 256 KB. Integers other than 0 and 1 are rejected with
`lightphe.ErrFloatNotSupported`.

```go
cs, _ := lightphe.New(lightphe.GentrySahaiWaters)

a, _ := cs.EncryptInt(1)
b, _ := cs.EncryptInt(1)
c, _ := cs.EncryptInt(0)
d, _ := cs.EncryptInt(1)

// majority of three bits
ab, _ := a.And(b)
ac, _ := a.And(c)
bc, _ := b.And(c)
majority, _ := ab.Xor(ac)
majority, _ = majority.Xor(bc) // decrypts to 1

// a product of products
cd, _ := c.And(d)
product, _ := ab.And(cd) // decrypts to 0
```

Every ciphertext of these algorithms carries a small noise, which grows with each homomorphic
operation, and decryption silently fails once it grows too much. With default settings, plaintexts
must be less than 2^24. Regev and Lyubashevsky-Peikert-Regev have room for thousands of additions
or multiplications with constants up to a few thousands, and a product of Brakerski-Vaikuntanathan has room for millions of times
more noise. You can increase the plaintext space with `lightphe.WithPlaintextLimit` in exchange of
less room for noise. Floats and tensors are not supported, and they are rejected with
`lightphe.ErrFloatNotSupported`.

### Vector embeddings

Encrypted tensors carry fixed point values, which makes privacy-preserving similarity search and
secure aggregation possible. Elements are encrypted concurrently across the available cores.

```go
cs, err := lightphe.New(lightphe.Paillier)

t1 := []float64{1.005, 2.05, 3.6, 4, 4.02, 3.5}
t2 := []float64{5, 6.2, 7.5, 8.02, 8.02, 4.5}
t3 := []float64{1.03, 2.04, 3.05, 7.02, 2.01, 1.06}

c1, err := cs.EncryptTensor(t1)
c2, err := cs.EncryptTensor(t2)

sum, err := c1.Add(c2)                  // element-wise addition
scaled, err := c1.MultiplyByConstant(3) // scalar multiplication
products, err := c1.MultiplyByPlain(t3) // element-wise product with a plain vector
similarity, err := c1.Dot(t3)           // encrypted dot product, i.e. cosine similarity
```

Real numbers are stored as a scaled integer over an encrypted scale factor, with the sign kept in
the clear because no partially homomorphic scheme can recover it. Adding two elements of opposite
signs therefore yields the modular representative rather than a signed result; the tensor API
documents where this bites.

## Thread safety

A cryptosystem is immutable once built: key material is never written to again, and every
operation allocates its result. A `Cryptosystem`, a `Ciphertext` and a `Tensor` can all
be shared freely between goroutines.

## Contributing

All PRs are welcome. If you are planning a large patch, open an issue first so the design
questions get settled up front.

## LightPHE Ecosystem

`LightPHE` is available across multiple programming languages with consistent APIs and native performance for each ecosystem. Choose the port that fits your stack:

| Language | Repository | Ecosystem Focus |
| :--- | :--- | :--- |
| **Python** | [`lightphe`](https://github.com/serengil/lightphe) | AI, Research & Prototyping |
| **Go** | [`lightphe-go`](https://github.com/serengil/lightphe-go) | Cloud-Native & High-Throughput Microservices |
| **Java** | [`lightphe4j`](https://github.com/serengil/lightphe4j) | Enterprise, Banking & Legacy Systems |
| **TypeScript** | [`lightphe-ts`](https://github.com/serengil/lightphe-ts) | Client-Side Privacy & Node.js Backend |

## Citation

Please cite LightPHE in your publications if it helps your research:

```BibTeX
@article{lightphego,
  title          = {Sustainable Cryptography: Carbon Asymmetry in Partially Homomorphic Encryption in the Cloud},
  author         = {Ozpinar, Alper and Serengil, Sefik Ilkin},
  journal        = {Symmetry},
  volume         = {18},
  number         = {5},
  pages          = {832},
  url            = {https://www.mdpi.com/2073-8994/18/5/832},
  doi            = {10.3390/sym18050832},
  note           = {Special Issue: Symmetry in Cryptography and Cybersecurity},
  year           = {2026}
}
```

## License

`lightphe-go` is licensed under the MIT License - see [`LICENSE`](LICENSE) for details.
