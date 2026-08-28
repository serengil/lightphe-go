package phe

// Algorithm identifies a cryptosystem. The string values match the algorithm
// names used by the reference Python implementation so that keys exported by
// one library can be consumed by the other.
type Algorithm string

// Supported cryptosystems.
const (
	RSA                  Algorithm = "RSA"
	ElGamal              Algorithm = "ElGamal"
	ExponentialElGamal   Algorithm = "Exponential-ElGamal"
	EllipticCurveElGamal Algorithm = "EllipticCurve-ElGamal"
	Paillier             Algorithm = "Paillier"
	DamgardJurik         Algorithm = "Damgard-Jurik"
	OkamotoUchiyama      Algorithm = "Okamoto-Uchiyama"
	Benaloh              Algorithm = "Benaloh"
	NaccacheStern        Algorithm = "Naccache-Stern"
	GoldwasserMicali     Algorithm = "Goldwasser-Micali"
	SanderYoungYung      Algorithm = "Sander-Young-Yung"
	BonehGohNissim       Algorithm = "Boneh-Goh-Nissim"
)

// String implements fmt.Stringer.
func (a Algorithm) String() string { return string(a) }

// Algorithms lists every cryptosystem this library ships with.
func Algorithms() []Algorithm {
	return []Algorithm{
		RSA,
		ElGamal,
		ExponentialElGamal,
		EllipticCurveElGamal,
		Paillier,
		DamgardJurik,
		OkamotoUchiyama,
		Benaloh,
		NaccacheStern,
		GoldwasserMicali,
		SanderYoungYung,
		BonehGohNissim,
	}
}
