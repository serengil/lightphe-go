# lightphe-go

<div align="center">

[![Stars](https://img.shields.io/github/stars/serengil/lightphe-go?color=yellow&style=flat&label=%E2%AD%90%20stars)](https://github.com/serengil/lightphe-go/stargazers)
[![License](http://img.shields.io/:license-MIT-green.svg?style=flat)](https://github.com/serengil/lightphe-go/blob/main/LICENSE)
[![DOI](http://img.shields.io/:DOI-10.3390/sym18050832-blue.svg?style=flat)](https://www.mdpi.com/2073-8994/18/5/832)

</div>

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
[`Boneh-Goh-Nissim`](https://sefiks.com/2026/04/02/a-step-by-step-somewhat-homomorphic-encryption-example-with-boneh-goh-nissim-in-python/).

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

| Algorithm | Multiplicatively<br>Homomorphic | Additively<br>Homomorphic | Scalar Multiplication | Bitwise-XOR Homomorphic | Bitwise-AND Homomorphic | Regeneration<br>of Ciphertext |
| --- | --- | --- | --- | --- | --- | --- |
| RSA | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ |
| ElGamal | ✅ | ❌ | ❌ | ❌ | ❌ | ✅ |
| ExponentialElGamal | ❌ | ✅ | ✅ | ❌ | ❌ | ✅ |
| EllipticCurveElGamal | ❌ | ✅ | ✅ | ❌ | ❌ | ✅ |
| Paillier | ❌ | ✅ | ✅ | ❌ | ❌ | ✅ |
| DamgardJurik | ❌ | ✅ | ✅ | ❌ | ❌ | ✅ |
| Benaloh | ❌ | ✅ | ✅ | ❌ | ❌ | ✅ |
| NaccacheStern | ❌ | ✅ | ✅ | ❌ | ❌ | ✅ |
| OkamotoUchiyama | ❌ | ✅ | ✅ | ❌ | ❌ | ✅ |
| GoldwasserMicali | ❌ | ❌ | ❌ | ✅ | ❌ | ✅ |
| SanderYoungYung | ❌ | ❌ | ❌ | ❌ | ✅ | ✅ |
| BonehGohNissim | 1️⃣ | ✅ | ✅ | ❌ | ❌ | ✅ |

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
