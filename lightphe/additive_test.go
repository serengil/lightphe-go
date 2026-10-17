package lightphe_test

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"math/big"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/serengil/lightphe-go/lightphe"
	"github.com/serengil/lightphe-go/lightphe/ecc"
	"github.com/serengil/lightphe-go/lightphe/ecc/curves"
	"github.com/serengil/lightphe-go/lightphe/phe"
	"github.com/serengil/lightphe-go/lightphe/schemes/camenischshoup"
	"github.com/serengil/lightphe-go/lightphe/schemes/ellipticcurvepaillier"
)

// --------------------------------------------------------------------------
// Elliptic Curve Paillier
// --------------------------------------------------------------------------

func TestEllipticCurvePaillierKeysAreWellFormed(t *testing.T) {
	cs := mustBuild(t, phe.EllipticCurvePaillier, lightphe.WithKeySize(testKeySize))
	keys := cs.Scheme().(*ellipticcurvepaillier.Cryptosystem).Keys()
	n, b, g := keys.PublicKey.N, keys.PublicKey.B, keys.PublicKey.G
	p, q, order := keys.PrivateKey.P, keys.PrivateKey.Q, keys.PrivateKey.Order
	nSquared := new(big.Int).Mul(n, n)
	three := big.NewInt(3)

	if new(big.Int).Mul(p, q).Cmp(n) != 0 {
		t.Fatal("n is not p * q")
	}
	if new(big.Int).Mod(p, three).Int64() != 2 || new(big.Int).Mod(q, three).Int64() != 2 {
		t.Fatal("p and q must be 2 mod 3")
	}

	// g is on the curve y^2 = x^3 + b mod n^2
	lhs := new(big.Int).Mul(g.Y, g.Y)
	lhs.Sub(lhs, new(big.Int).Exp(g.X, three, nil)).Sub(lhs, b).Mod(lhs, nSquared)
	if lhs.Sign() != 0 {
		t.Fatal("g is not on the curve")
	}

	// order is odd and divides the group exponent modulo n
	exponent := new(big.Int).Mul(new(big.Int).Add(p, big.NewInt(1)), new(big.Int).Add(q, big.NewInt(1)))
	if order.Bit(0) != 1 || new(big.Int).Mod(exponent, order).Sign() != 0 {
		t.Fatal("order must be odd and divide (p + 1)(q + 1)")
	}
}

func TestEllipticCurvePaillierEdgeCases(t *testing.T) {
	cs := mustBuild(t, phe.EllipticCurvePaillier, lightphe.WithKeySize(testKeySize))
	modulo := cs.PlaintextModulo()
	minusOne := new(big.Int).Sub(modulo, big.NewInt(1))

	for _, m := range []*big.Int{big.NewInt(0), big.NewInt(1), big.NewInt(2), minusOne} {
		c, err := cs.Encrypt(m)
		if err != nil {
			t.Fatalf("encrypting: %v", err)
		}
		if got := mustDecrypt(t, cs, c); got.Cmp(m) != 0 {
			t.Fatalf("decrypted %s, want %s", got, m)
		}

		// doubling, i.e. adding a ciphertext to itself
		doubled, err := c.Add(c)
		if err != nil {
			t.Fatalf("doubling: %v", err)
		}
		want := new(big.Int).Lsh(m, 1)
		if got := mustDecrypt(t, cs, doubled); got.Cmp(want.Mod(want, modulo)) != 0 {
			t.Fatalf("doubling %s decrypted to %s", m, got)
		}

		// adding inverse brings point back to the encryption of 0
		inverse, err := c.MultiplyByConstant(minusOne)
		if err != nil {
			t.Fatalf("scalar multiplication: %v", err)
		}
		zero, err := c.Add(inverse)
		if err != nil {
			t.Fatalf("homomorphic addition: %v", err)
		}
		assertDecrypts(t, cs, zero, 0)

		// multiplying by 0 gives the point at infinity, the encryption of 0
		infinity, err := c.MultiplyByInt(0)
		if err != nil {
			t.Fatalf("scalar multiplication: %v", err)
		}
		assertDecrypts(t, cs, infinity, 0)
		restored, err := infinity.Add(c)
		if err != nil {
			t.Fatalf("homomorphic addition: %v", err)
		}
		if got := mustDecrypt(t, cs, restored); got.Cmp(m) != 0 {
			t.Fatalf("O + E(%s) decrypted to %s", m, got)
		}
	}
}

func TestEllipticCurvePaillierInvalidCiphertext(t *testing.T) {
	cs := mustBuild(t, phe.EllipticCurvePaillier, lightphe.WithKeySize(testKeySize))
	n := cs.PlaintextModulo()
	c := mustEncrypt(t, cs, 5)
	coords, _ := c.Value.(phe.Tuple).Ints()

	for _, invalid := range []phe.Value{
		phe.NewTuple(phe.Int{V: new(big.Int).Add(coords[0], big.NewInt(1))}, phe.Int{V: coords[1]}, phe.Int{V: coords[2]}),
		phe.NewTuple(phe.Int{V: big.NewInt(1)}, phe.Int{V: big.NewInt(1)}, phe.Int{V: new(big.Int).Add(n, big.NewInt(1))}),
	} {
		if _, err := cs.Decrypt(cs.CreateCiphertext(invalid)); !errors.Is(err, phe.ErrInvalidCiphertext) {
			t.Fatalf("decrypting an invalid point returned %v", err)
		}
	}
}

// --------------------------------------------------------------------------
// Bresson-Catalano-Pointcheval
// --------------------------------------------------------------------------

func TestBressonCatalanoPointchevalMasterTrapdoor(t *testing.T) {
	cs := mustBuild(t, phe.BressonCatalanoPointcheval, lightphe.WithKeySize(testKeySize))

	// factorization of n decrypts without the local trapdoor a
	minusOne := new(big.Int).Sub(cs.PlaintextModulo(), big.NewInt(1))
	for _, m := range []*big.Int{big.NewInt(0), big.NewInt(1), big.NewInt(17), big.NewInt(12345), minusOne} {
		c, err := cs.Encrypt(m)
		if err != nil {
			t.Fatalf("encrypting: %v", err)
		}
		got, err := cs.DecryptWithMasterKey(c)
		if err != nil {
			t.Fatalf("decrypting with the master key: %v", err)
		}
		if got.Cmp(m) != 0 {
			t.Fatalf("master key decrypted %s, want %s", got, m)
		}
	}
}

func TestBressonCatalanoPointchevalMasterKeyDecryptsAllUsers(t *testing.T) {
	// authority generates the master key, and publishes n and g with its
	// public key
	authority := mustBuild(t, phe.BressonCatalanoPointcheval, lightphe.WithKeySize(testKeySize))
	publicKeys, err := authority.Keys(true)
	if err != nil {
		t.Fatalf("exporting the public key: %v", err)
	}
	authorityPublic := mustBuild(t, phe.BressonCatalanoPointcheval, lightphe.WithKeys(publicKeys))

	// each user generates its own key pair with the public key of the
	// authority
	aliceKeys, err := authorityPublic.GenerateUserKeys()
	if err != nil {
		t.Fatalf("generating user keys: %v", err)
	}
	bobKeys, err := authorityPublic.GenerateUserKeys()
	if err != nil {
		t.Fatalf("generating user keys: %v", err)
	}
	var doc map[string]map[string]interface{}
	if err := json.Unmarshal(aliceKeys, &doc); err != nil {
		t.Fatalf("decoding user keys: %v", err)
	}
	if len(doc["private_key"]) != 1 || doc["private_key"]["a"] == nil {
		t.Fatalf("user private key must have the local trapdoor only, got %v", doc["private_key"])
	}

	alice := mustBuild(t, phe.BressonCatalanoPointcheval, lightphe.WithKeys(aliceKeys))
	bob := mustBuild(t, phe.BressonCatalanoPointcheval, lightphe.WithKeys(bobKeys))

	aliceC, err := mustEncrypt(t, alice, 123).Add(mustEncrypt(t, alice, 456))
	if err != nil {
		t.Fatalf("homomorphic addition: %v", err)
	}
	bobC, err := mustEncrypt(t, bob, 1000).MultiplyByInt(3)
	if err != nil {
		t.Fatalf("scalar multiplication: %v", err)
	}

	// users decrypt their own ciphertexts, but not each other's
	assertDecrypts(t, alice, aliceC, 579)
	assertDecrypts(t, bob, bobC, 3000)
	if mustDecrypt(t, alice, bobC).Int64() == 3000 || mustDecrypt(t, bob, aliceC).Int64() == 579 {
		t.Fatal("a user decrypted the ciphertext of another user")
	}

	// users do not have the master key
	if _, err := alice.DecryptWithMasterKey(bobC); err == nil || !strings.Contains(err.Error(), "master trapdoor") {
		t.Fatalf("a user decrypting with the master key returned %v", err)
	}

	// authority decrypts ciphertexts of all users without knowing their local
	// trapdoors
	assertMasterDecrypts(t, authority, aliceC, 579)
	assertMasterDecrypts(t, authority, bobC, 3000)

	// authority may keep the master trapdoor only
	privateKeys, err := authority.Keys(false)
	if err != nil {
		t.Fatalf("exporting keys: %v", err)
	}
	masterKeys := withoutField(t, privateKeys, "private_key", "a")
	master := mustBuild(t, phe.BressonCatalanoPointcheval, lightphe.WithKeys(masterKeys))
	assertMasterDecrypts(t, master, aliceC, 579)
	assertMasterDecrypts(t, master, bobC, 3000)
	if _, err := master.Decrypt(aliceC); err == nil || !strings.Contains(err.Error(), "local trapdoor") {
		t.Fatalf("decrypting without the local trapdoor returned %v", err)
	}

	// encryption with the public key of a user is still decryptable
	bobPublic, err := bob.Keys(true)
	if err != nil {
		t.Fatalf("exporting the public key: %v", err)
	}
	restored := mustBuild(t, phe.BressonCatalanoPointcheval, lightphe.WithKeys(bobPublic))
	assertMasterDecrypts(t, master, mustEncrypt(t, restored, 7), 7)
}

func assertMasterDecrypts(t *testing.T, cs *lightphe.Cryptosystem, c *lightphe.Ciphertext, want int64) {
	t.Helper()
	got, err := cs.DecryptWithMasterKey(c)
	if err != nil {
		t.Fatalf("decrypting with the master key: %v", err)
	}
	if got.Int64() != want {
		t.Fatalf("master key decrypted %s, want %d", got, want)
	}
}

func TestBressonCatalanoPointchevalMasterKeyDecryptsTensors(t *testing.T) {
	cs := mustBuild(t, phe.BressonCatalanoPointcheval, lightphe.WithKeySize(testKeySize))
	userKeys, err := cs.GenerateUserKeys()
	if err != nil {
		t.Fatalf("generating user keys: %v", err)
	}
	user := mustBuild(t, phe.BressonCatalanoPointcheval, lightphe.WithKeys(userKeys))

	tensor, err := user.EncryptTensor([]float64{1.5, -2.25, 3})
	if err != nil {
		t.Fatalf("encrypting a tensor: %v", err)
	}
	plain, err := cs.DecryptTensorWithMasterKey(tensor)
	if err != nil {
		t.Fatalf("decrypting a tensor with the master key: %v", err)
	}
	for i, want := range []float64{1.5, -2.25, 3} {
		if plain[i] != want {
			t.Fatalf("tensor element %d decrypted to %v, want %v", i, plain[i], want)
		}
	}
}

func TestBressonCatalanoPointchevalMasterKeyOfAnotherSystem(t *testing.T) {
	cs := mustBuild(t, phe.BressonCatalanoPointcheval, lightphe.WithKeySize(testKeySize))
	other := mustBuild(t, phe.BressonCatalanoPointcheval, lightphe.WithKeySize(testKeySize))
	if _, err := cs.DecryptWithMasterKey(mustEncrypt(t, other, 5)); err == nil ||
		!strings.Contains(err.Error(), "does not share the same n and g") {
		t.Fatalf("decrypting a ciphertext of another master key returned %v", err)
	}
}

func TestBressonCatalanoPointchevalMasterKeyRequiresPrivateKey(t *testing.T) {
	cs := mustBuild(t, phe.BressonCatalanoPointcheval, lightphe.WithKeySize(testKeySize))
	publicFile := filepath.Join(t.TempDir(), "public.json")
	if err := cs.ExportKeys(publicFile, true); err != nil {
		t.Fatalf("exporting the public key: %v", err)
	}
	public := mustBuild(t, phe.BressonCatalanoPointcheval, lightphe.WithKeyFile(publicFile))
	if _, err := public.DecryptWithMasterKey(mustEncrypt(t, public, 5)); !errors.Is(err, phe.ErrMissingPrivateKey) {
		t.Fatalf("decrypting with the master key without a private key returned %v", err)
	}

	// public key is enough to generate user keys
	userKeys, err := public.GenerateUserKeys()
	if err != nil {
		t.Fatalf("generating user keys: %v", err)
	}
	user := mustBuild(t, phe.BressonCatalanoPointcheval, lightphe.WithKeys(userKeys))
	assertMasterDecrypts(t, cs, mustEncrypt(t, user, 9), 9)
}

func TestMasterKeyIsUnsupportedByOtherSchemes(t *testing.T) {
	for _, alg := range []phe.Algorithm{phe.Paillier, phe.RSA, phe.DamgardGeislerKroigaard} {
		cs := mustBuild(t, alg, lightphe.WithKeySize(testKeySize))
		_, err := cs.DecryptWithMasterKey(mustEncrypt(t, cs, 5))
		assertUnsupported(t, "master key decryption on "+alg.String(), err)
		_, err = cs.GenerateUserKeys()
		assertUnsupported(t, "generating user keys on "+alg.String(), err)
	}
}

func TestReadmeMasterKey(t *testing.T) {
	publicFile := filepath.Join(t.TempDir(), "public.json")

	// authority generates the master key and publishes its public key
	authority := mustBuild(t, phe.BressonCatalanoPointcheval, lightphe.WithKeySize(256))
	if err := authority.ExportKeys(publicFile, true); err != nil {
		t.Fatalf("exporting the public key: %v", err)
	}

	// each user generates its own key pair with the public key of the
	// authority
	public := mustBuild(t, phe.BressonCatalanoPointcheval, lightphe.WithKeyFile(publicFile))
	newUser := func() *lightphe.Cryptosystem {
		keys, err := public.GenerateUserKeys()
		if err != nil {
			t.Fatalf("generating user keys: %v", err)
		}
		return mustBuild(t, phe.BressonCatalanoPointcheval, lightphe.WithKeys(keys))
	}
	alice, bob := newUser(), newUser()

	aliceCiphertext, err := mustEncrypt(t, alice, 100).Add(mustEncrypt(t, alice, 50))
	if err != nil {
		t.Fatalf("homomorphic addition: %v", err)
	}
	bobCiphertext := mustEncrypt(t, bob, 200)

	// users decrypt their own ciphertexts only
	assertDecrypts(t, alice, aliceCiphertext, 150)
	if mustDecrypt(t, alice, bobCiphertext).Int64() == 200 {
		t.Fatal("alice decrypted bob's ciphertext")
	}

	// authority decrypts ciphertexts of all users
	assertMasterDecrypts(t, authority, aliceCiphertext, 150)
	assertMasterDecrypts(t, authority, bobCiphertext, 200)
}

// --------------------------------------------------------------------------
// Camenisch-Shoup
// --------------------------------------------------------------------------

func TestCamenischShoupLabeledEncryption(t *testing.T) {
	cs := mustBuild(t, phe.CamenischShoup, lightphe.WithKeySize(testKeySize))
	scheme := cs.Scheme().(*camenischshoup.Cryptosystem)
	n := cs.PlaintextModulo()
	nSquared := new(big.Int).Mul(n, n)

	for _, m := range []*big.Int{big.NewInt(0), big.NewInt(1), big.NewInt(17), new(big.Int).Sub(n, big.NewInt(1))} {
		ciphertext, err := scheme.EncryptWithLabel(m, "some label")
		if err != nil {
			t.Fatalf("encrypting with a label: %v", err)
		}
		if got, err := scheme.DecryptWithLabel(ciphertext, "some label"); err != nil || got.Cmp(m) != 0 {
			t.Fatalf("decrypted %s (%v), want %s", got, err, m)
		}

		// different label
		if _, err := scheme.DecryptWithLabel(ciphertext, "other label"); err == nil || !strings.Contains(err.Error(), "different label") {
			t.Fatalf("decrypting with another label returned %v", err)
		}

		// modified ciphertext
		u, e, v := ciphertext[0], ciphertext[1], ciphertext[2]
		modifiedE := new(big.Int).Mul(e, new(big.Int).Add(n, big.NewInt(1)))
		modifiedE.Mod(modifiedE, nSquared)
		for _, modified := range [][]*big.Int{{u, modifiedE, v}, {u, e, new(big.Int).Add(v, big.NewInt(1))}} {
			if _, err := scheme.DecryptWithLabel(modified, "some label"); !errors.Is(err, phe.ErrInvalidCiphertext) {
				t.Fatalf("decrypting a modified ciphertext returned %v", err)
			}
		}

		// labeled ciphertexts cannot be decrypted without label
		triple := cs.CreateCiphertext(phe.NewTuple(phe.Int{V: u}, phe.Int{V: e}, phe.Int{V: v}))
		if _, err := cs.Decrypt(triple); err == nil || !strings.Contains(err.Error(), "labels") {
			t.Fatalf("decrypting a labeled ciphertext without label returned %v", err)
		}

		// homomorphic operations drop the validity tag
		sum, err := triple.Add(mustEncrypt(t, cs, 3))
		if err != nil {
			t.Fatalf("homomorphic addition: %v", err)
		}
		if sum.Value.(phe.Tuple).Len() != 2 {
			t.Fatal("homomorphic addition kept the validity tag")
		}
		want := new(big.Int).Add(m, big.NewInt(3))
		if got := mustDecrypt(t, cs, sum); got.Cmp(want.Mod(want, n)) != 0 {
			t.Fatalf("decrypted %s, want %s", got, want)
		}
	}
}

// verifiable encryption of secp256k1 secrets requires keys larger than 467
// bits, so the suite shares one cryptosystem.
var (
	verifiableOnce sync.Once
	verifiableCS   *lightphe.Cryptosystem
)

func verifiableCryptosystem(t *testing.T) *lightphe.Cryptosystem {
	t.Helper()
	if testing.Short() {
		t.Skip("verifiable encryption needs 1024-bit keys, which are slow")
	}
	verifiableOnce.Do(func() {
		cs, err := lightphe.New(phe.CamenischShoup, lightphe.WithKeySize(1024))
		if err != nil {
			t.Fatalf("building Camenisch-Shoup: %v", err)
		}
		verifiableCS = cs
	})
	if verifiableCS == nil {
		t.Fatal("Camenisch-Shoup could not be built")
	}
	return verifiableCS
}

func secp256k1(t *testing.T) *ecc.ECC {
	t.Helper()
	curve, err := ecc.New(curves.FormWeierstrass, "secp256k1")
	if err != nil {
		t.Fatalf("building secp256k1: %v", err)
	}
	return curve
}

func publicPoint(t *testing.T, curve *ecc.ECC, secret *big.Int) ecc.Point {
	t.Helper()
	point, err := curve.G().ScalarMul(secret)
	if err != nil {
		t.Fatalf("computing the public point: %v", err)
	}
	return point
}

func randomSecret(t *testing.T, curve *ecc.ECC) *big.Int {
	t.Helper()
	secret, err := rand.Int(rand.Reader, new(big.Int).Sub(curve.N(), big.NewInt(1)))
	if err != nil {
		t.Fatalf("drawing a secret: %v", err)
	}
	return secret.Add(secret, big.NewInt(1))
}

func mustVerify(t *testing.T, cs *lightphe.Cryptosystem, vc *lightphe.VerifiableCiphertext, point ecc.Point, label string) bool {
	t.Helper()
	ok, err := cs.VerifyEncryption(vc, point, label)
	if err != nil {
		t.Fatalf("verifying: %v", err)
	}
	return ok
}

func TestVerifiableEncryption(t *testing.T) {
	cs := verifiableCryptosystem(t)
	curve := secp256k1(t)
	secret := randomSecret(t, curve)
	point := publicPoint(t, curve, secret)
	const label = "release if alice loses access"

	vc, err := cs.EncryptVerifiably(secret, label)
	if err != nil {
		t.Fatalf("encrypting verifiably: %v", err)
	}
	if !mustVerify(t, cs, vc, point, label) {
		t.Fatal("a valid verifiable ciphertext was rejected")
	}
	if got, err := cs.DecryptVerifiableCiphertext(vc, label); err != nil || got.Cmp(secret) != 0 {
		t.Fatalf("decrypted %s (%v), want %s", got, err, secret)
	}

	// wrong label or wrong public point
	if mustVerify(t, cs, vc, point, "other") {
		t.Fatal("a verifiable ciphertext was accepted with another label")
	}
	if mustVerify(t, cs, vc, publicPoint(t, curve, new(big.Int).Add(secret, big.NewInt(1))), label) {
		t.Fatal("a verifiable ciphertext was accepted for another public point")
	}
	if _, err := cs.DecryptVerifiableCiphertext(vc, "other"); err == nil || !strings.Contains(err.Error(), "different label") {
		t.Fatalf("decrypting with another label returned %v", err)
	}

	// it survives a JSON round trip, which is how it would travel over the wire
	data, err := json.Marshal(vc)
	if err != nil {
		t.Fatalf("encoding: %v", err)
	}
	var decoded lightphe.VerifiableCiphertext
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("decoding: %v", err)
	}
	if !mustVerify(t, cs, &decoded, point, label) {
		t.Fatal("a decoded verifiable ciphertext was rejected")
	}
}

func TestVerifiableEncryptionRejectsTampering(t *testing.T) {
	cs := verifiableCryptosystem(t)
	curve := secp256k1(t)
	secret := randomSecret(t, curve)
	point := publicPoint(t, curve, secret)

	vc, err := cs.EncryptVerifiably(secret, "")
	if err != nil {
		t.Fatalf("encrypting verifiably: %v", err)
	}
	if !mustVerify(t, cs, vc, point, "") {
		t.Fatal("a valid verifiable ciphertext was rejected")
	}

	clone := func() *lightphe.VerifiableCiphertext {
		proof := *vc.Proof
		return &lightphe.VerifiableCiphertext{
			Ciphertext: append([]*big.Int{}, vc.Ciphertext...),
			Commitment: vc.Commitment,
			Proof:      &proof,
		}
	}
	increment := func(x *big.Int) *big.Int { return new(big.Int).Add(x, big.NewInt(1)) }

	// modify each part of the ciphertext, commitment and proof
	for i := 0; i < 3; i++ {
		tampered := clone()
		tampered.Ciphertext[i] = increment(tampered.Ciphertext[i])
		if mustVerify(t, cs, tampered, point, "") {
			t.Fatalf("tampering ciphertext item %d was accepted", i)
		}
	}
	tampered := clone()
	tampered.Commitment = increment(tampered.Commitment)
	if mustVerify(t, cs, tampered, point, "") {
		t.Fatal("tampering the commitment was accepted")
	}
	for _, field := range []func(p *phe.Proof){
		func(p *phe.Proof) { p.Challenge = increment(p.Challenge) },
		func(p *phe.Proof) { p.R = increment(p.R) },
		func(p *phe.Proof) { p.S = increment(p.S) },
		func(p *phe.Proof) { p.M = increment(p.M) },
	} {
		tampered := clone()
		field(tampered.Proof)
		if mustVerify(t, cs, tampered, point, "") {
			t.Fatal("tampering the proof was accepted")
		}
	}

	// ciphertext of another secret with the proof of this secret
	other, err := cs.EncryptVerifiably(new(big.Int).Add(secret, big.NewInt(1)), "")
	if err != nil {
		t.Fatalf("encrypting verifiably: %v", err)
	}
	swapped := clone()
	swapped.Ciphertext = other.Ciphertext
	if mustVerify(t, cs, swapped, point, "") {
		t.Fatal("a swapped ciphertext was accepted")
	}

	// proof of another secret for this public point
	if mustVerify(t, cs, other, point, "") {
		t.Fatal("the proof of another secret was accepted")
	}

	// malformed inputs
	noProof := clone()
	noProof.Proof = nil
	for _, malformed := range []*lightphe.VerifiableCiphertext{
		nil, {}, {Ciphertext: []*big.Int{big.NewInt(1), big.NewInt(2)}}, noProof,
	} {
		if mustVerify(t, cs, malformed, point, "") {
			t.Fatal("a malformed verifiable ciphertext was accepted")
		}
	}
}

func TestVerifiableEncryptionSecretRange(t *testing.T) {
	cs := verifiableCryptosystem(t)
	curve := secp256k1(t)
	order := curve.N()

	for _, secret := range []*big.Int{big.NewInt(1), big.NewInt(2), new(big.Int).Sub(order, big.NewInt(1)),
		// secrets are reduced to the order of the curve
		new(big.Int).Add(order, big.NewInt(5)), big.NewInt(-5)} {
		reduced := new(big.Int).Mod(secret, order)
		vc, err := cs.EncryptVerifiably(secret, "")
		if err != nil {
			t.Fatalf("encrypting %s verifiably: %v", secret, err)
		}
		if !mustVerify(t, cs, vc, publicPoint(t, curve, reduced), "") {
			t.Fatalf("verifiable ciphertext of %s was rejected", secret)
		}
		if got, err := cs.DecryptVerifiableCiphertext(vc, ""); err != nil || got.Cmp(reduced) != 0 {
			t.Fatalf("decrypted %s (%v), want %s", got, err, reduced)
		}
	}

	// public point would be the point at infinity
	for _, secret := range []*big.Int{big.NewInt(0), order} {
		if _, err := cs.EncryptVerifiably(secret, ""); err == nil || !strings.Contains(err.Error(), "multiple of the order") {
			t.Fatalf("encrypting %s verifiably returned %v", secret, err)
		}
	}
	vc, err := cs.EncryptVerifiably(big.NewInt(1), "")
	if err != nil {
		t.Fatalf("encrypting verifiably: %v", err)
	}
	if mustVerify(t, cs, vc, curve.O(), "") {
		t.Fatal("the point at infinity was accepted")
	}
}

func TestVerifiableEncryptionOtherCurve(t *testing.T) {
	cs := verifiableCryptosystem(t)
	keys, err := cs.Keys(false)
	if err != nil {
		t.Fatalf("exporting keys: %v", err)
	}
	edwards := mustBuild(t, phe.CamenischShoup, lightphe.WithKeys(keys), lightphe.WithCurve("edwards", "ed25519"))
	curve, err := ecc.New(curves.FormEdwards, "ed25519")
	if err != nil {
		t.Fatalf("building ed25519: %v", err)
	}
	secret := randomSecret(t, curve)

	vc, err := edwards.EncryptVerifiably(secret, "")
	if err != nil {
		t.Fatalf("encrypting verifiably: %v", err)
	}
	if !mustVerify(t, edwards, vc, publicPoint(t, curve, secret), "") {
		t.Fatal("a valid verifiable ciphertext on ed25519 was rejected")
	}
	if got, err := edwards.DecryptVerifiableCiphertext(vc, ""); err != nil || got.Cmp(secret) != 0 {
		t.Fatalf("decrypted %s (%v), want %s", got, err, secret)
	}
}

func TestVerifiableEncryptionSmallKey(t *testing.T) {
	cs := mustBuild(t, phe.CamenischShoup, lightphe.WithKeySize(testKeySize))
	curve := secp256k1(t)
	if _, err := cs.EncryptVerifiably(big.NewInt(5), ""); err == nil || !strings.Contains(err.Error(), "too small for verifiable encryption") {
		t.Fatalf("encrypting verifiably with a small key returned %v", err)
	}
	if _, err := cs.VerifyEncryption(&lightphe.VerifiableCiphertext{}, publicPoint(t, curve, big.NewInt(5)), ""); err == nil ||
		!strings.Contains(err.Error(), "too small for verifiable encryption") {
		t.Fatalf("verifying with a small key returned %v", err)
	}
}

func TestVerifiableEncryptionIsUnsupportedByOtherSchemes(t *testing.T) {
	curve := secp256k1(t)
	for _, alg := range []phe.Algorithm{phe.Paillier, phe.BressonCatalanoPointcheval} {
		cs := mustBuild(t, alg, lightphe.WithKeySize(testKeySize))
		_, err := cs.EncryptVerifiably(big.NewInt(5), "")
		assertUnsupported(t, "verifiable encryption", err)
		_, err = cs.VerifyEncryption(&lightphe.VerifiableCiphertext{}, publicPoint(t, curve, big.NewInt(5)), "")
		assertUnsupported(t, "verifiable encryption", err)
		_, err = cs.DecryptVerifiableCiphertext(&lightphe.VerifiableCiphertext{}, "")
		assertUnsupported(t, "verifiable encryption", err)
	}
}

func TestReadmeVerifiableEncryption(t *testing.T) {
	publicFile := filepath.Join(t.TempDir(), "public.json")

	// trusted third party builds the cryptosystem and publishes its public key
	ttp := verifiableCryptosystem(t)
	if err := ttp.ExportKeys(publicFile, true); err != nil {
		t.Fatalf("exporting the public key: %v", err)
	}

	// alice's wallet key pair on secp256k1
	curve := secp256k1(t)
	privateKey := big.NewInt(123456789)
	publicKey := publicPoint(t, curve, privateKey)

	// alice encrypts her private key for the trusted third party with a proof
	const label = "release only if alice loses access to her wallet"
	alice := mustBuild(t, phe.CamenischShoup, lightphe.WithKeyFile(publicFile))
	escrow, err := alice.EncryptVerifiably(privateKey, label)
	if err != nil {
		t.Fatalf("encrypting verifiably: %v", err)
	}

	// bank verifies it with public keys only
	bank := mustBuild(t, phe.CamenischShoup, lightphe.WithKeyFile(publicFile))
	if !mustVerify(t, bank, escrow, publicKey, label) {
		t.Fatal("the bank rejected a valid escrow")
	}
	if _, err := bank.DecryptVerifiableCiphertext(escrow, label); !errors.Is(err, phe.ErrMissingPrivateKey) {
		t.Fatalf("the bank decrypting the escrow returned %v", err)
	}

	// trusted third party recovers the private key under the same label only
	if got, err := ttp.DecryptVerifiableCiphertext(escrow, label); err != nil || got.Cmp(privateKey) != 0 {
		t.Fatalf("recovered %s (%v), want %s", got, err, privateKey)
	}
}
