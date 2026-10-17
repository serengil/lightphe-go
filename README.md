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
`Brakerski-Vaikuntanathan`, `Freeman-Boneh-Goh-Nissim`, `Gentry-Halevi-Vaikuntanathan`.

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

| Algorithm | Multiplicatively<br>Homomorphic | Additively<br>Homomorphic | Scalar Multiplication | Bitwise-XOR Homomorphic | Bitwise-AND Homomorphic | Regeneration<br>of Ciphertext | Decision Tree<br>Evaluation | Secure<br>Comparison | Encrypted<br>Argmax |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| RSA | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| ElGamal | ✅ | ❌ | ❌ | ❌ | ❌ | ✅ | ❌ | ❌ | ❌ |
| ExponentialElGamal | ❌ | ✅ | ✅ | ❌ | ❌ | ✅ | ❌ | ❌ | ❌ |
| EllipticCurveElGamal | ❌ | ✅ | ✅ | ❌ | ❌ | ✅ | ❌ | ❌ | ❌ |
| Paillier | ❌ | ✅ | ✅ | ❌ | ❌ | ✅ | ❌ | ❌ | ❌ |
| EllipticCurvePaillier | ❌ | ✅ | ✅ | ❌ | ❌ | ✅ | ❌ | ❌ | ❌ |
| DamgardJurik | ❌ | ✅ | ✅ | ❌ | ❌ | ✅ | ❌ | ❌ | ❌ |
| Benaloh | ❌ | ✅ | ✅ | ❌ | ❌ | ✅ | ❌ | ❌ | ❌ |
| NaccacheStern | ❌ | ✅ | ✅ | ❌ | ❌ | ✅ | ❌ | ❌ | ❌ |
| OkamotoUchiyama | ❌ | ✅ | ✅ | ❌ | ❌ | ✅ | ❌ | ❌ | ❌ |
| JoyeLibert | ❌ | ✅ | ✅ | ❌ | ❌ | ✅ | ❌ | ❌ | ❌ |
| CastagnosLaguillaumie | ❌ | ✅ | ✅ | ❌ | ❌ | ✅ | ❌ | ❌ | ❌ |
| DamgardGeislerKroigaard | ❌ | ✅ | ✅ | ❌ | ❌ | ✅ | ✅ | ✅ | ✅ |
| BressonCatalanoPointcheval | ❌ | ✅ | ✅ | ❌ | ❌ | ✅ | ❌ | ❌ | ❌ |
| CamenischShoup | ❌ | ✅ | ✅ | ❌ | ❌ | ✅ | ❌ | ❌ | ❌ |
| IshaiPaskin | ❌ | ✅ | ✅ | ❌ | ❌ | ✅ | ✅ | ❌ | ❌ |
| Regev | ❌ | ✅ | ✅ | ❌ | ❌ | ✅ | ❌ | ❌ | ❌ |
| GoldwasserMicali | ❌ | ❌ | ❌ | ✅ | ❌ | ✅ | ❌ | ❌ | ❌ |
| SanderYoungYung | ❌ | ❌ | ❌ | ❌ | ✅ | ✅ | ❌ | ❌ | ❌ |
| BonehGohNissim | 1️⃣ | ✅ | ✅ | ❌ | ❌ | ✅ | ❌ | ❌ | ❌ |
| FreemanBonehGohNissim | 1️⃣ | ✅ | ✅ | ❌ | ❌ | ✅ | ❌ | ❌ | ❌ |
| BrakerskiVaikuntanathan | 1️⃣ | ✅ | ✅ | ❌ | ❌ | ✅ | ❌ | ❌ | ❌ |
| GentryHaleviVaikuntanathan | 1️⃣ | ✅ | ✅ | ❌ | ❌ | ✅ | ❌ | ❌ | ❌ |

1️⃣ Boneh-Goh-Nissim, Freeman-Boneh-Goh-Nissim, Brakerski-Vaikuntanathan and
Gentry-Halevi-Vaikuntanathan support one multiplication natively. Most additively homomorphic
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

### Verifiable encryption

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
enough quantum computer could solve with Shor's algorithm. Regev and Brakerski-Vaikuntanathan rely
on learning with errors problems instead, which are believed to be hard for quantum computers too.
Their default key sizes give about 128-bit security against quantum attacks.

Regev is additively homomorphic. Its key size is the lattice dimension, and its default is 2048.

```go
cs, _ := lightphe.New(lightphe.Regev)

c1, _ := cs.EncryptInt(1500)
c2, _ := cs.EncryptInt(2500)

sum, _ := c1.Add(c2)             // decrypts to 4000
scaled, _ := c1.MultiplyByInt(3) // decrypts to 4500
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

Every ciphertext of these algorithms carries a small noise, which grows with each homomorphic
operation, and decryption silently fails once it grows too much. With default settings, plaintexts
must be less than 2^24. Regev has room for thousands of additions or multiplications with constants
up to a few thousands, and a product of Brakerski-Vaikuntanathan has room for millions of times
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
