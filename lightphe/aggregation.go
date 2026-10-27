package lightphe

import (
	"fmt"
	"math"
	"math/big"

	"github.com/serengil/lightphe-go/lightphe/encrypted"
	"github.com/serengil/lightphe-go/lightphe/phe"
)

// ---------------------------------------------------------------------------
// Secure aggregation for federated learning
//
// Each client quantizes its model update to integers and packs many of them
// into a single plaintext, so it encrypts one ciphertext per chunk of values
// instead of one ciphertext per value. Server sums the encrypted updates of
// clients chunk by chunk, and only the sum is decrypted, e.g. by a committee
// holding shares of the private key with threshold decryption.
//   - quantization: x is scaled by 10^precision and rounded, so it is an
//     integer in [-B, B] where B is the maximum value scaled the same way
//   - packing: values are shifted by B to be non-negative, and placed into
//     slots of slot bits, i.e. plaintext = sum of (x_i + B) 2^(slot bits i)
//   - headroom: a slot of the sum of c updates is at most c 2B, so the slot
//     bits are the bit length of max clients 2B, and slots never overflow into
//     each other
//   - unpacking: slot of the sum minus c B is the sum of values of c clients
//
// Reference: Bonawitz, K. et al. (2017). Practical Secure Aggregation for
// Privacy-Preserving Machine Learning. ACM CCS 2017.
//
// Reference: Zhang, C. et al. (2020). BatchCrypt: Efficient Homomorphic
// Encryption for Cross-Silo Federated Learning. USENIX ATC 2020.
// ---------------------------------------------------------------------------

// AggregationLayout is the packing layout of model updates. Updates can be
// summed only if they have the same layout.
type AggregationLayout struct {
	Length     int      `json:"length"`
	Precision  int      `json:"precision"`
	Bound      *big.Int `json:"bound"`
	MaxClients int      `json:"max_clients"`
	SlotBits   int      `json:"slot_bits"`
	Slots      int      `json:"slots"`
}

// Equal reports whether two layouts are the same.
func (l AggregationLayout) Equal(other AggregationLayout) bool {
	return l.Length == other.Length && l.Precision == other.Precision && l.Bound.Cmp(other.Bound) == 0 &&
		l.MaxClients == other.MaxClients && l.SlotBits == other.SlotBits && l.Slots == other.Slots
}

// EncryptedUpdate is an encrypted model update, or an encrypted sum of Count
// updates: chunks of packed values and the layout of packing.
type EncryptedUpdate struct {
	Chunks []*encrypted.Ciphertext
	Layout AggregationLayout
	Count  int
}

// Aggregate is the decrypted sum and mean of Count model updates.
type Aggregate struct {
	Sum   []float64
	Mean  []float64
	Count int
}

func (c *Cryptosystem) requireAggregationSupport() error {
	if c.algorithm != phe.Paillier && c.algorithm != phe.DamgardJurik {
		return fmt.Errorf("lightphe: %s does not support secure aggregation, use Paillier or Damgard-Jurik instead: %w",
			c.algorithm, phe.ErrUnsupportedOperation)
	}
	return nil
}

// roundHalfEven rounds a finite float to the nearest integer, ties to even,
// as Python's round does.
func roundHalfEven(x float64) (*big.Int, error) {
	if math.IsNaN(x) || math.IsInf(x, 0) {
		return nil, fmt.Errorf("lightphe: %v is not a finite number", x)
	}
	out, _ := big.NewFloat(math.RoundToEven(x)).Int(nil)
	return out, nil
}

// buildLayout builds the packing layout of updates.
func buildLayout(length, precision int, maxValue float64, maxClients int, modulo *big.Int) (AggregationLayout, error) {
	if length < 1 {
		return AggregationLayout{}, fmt.Errorf("lightphe: update must have at least one value")
	}
	if maxClients < 1 {
		return AggregationLayout{}, fmt.Errorf("lightphe: maximum number of clients must be a positive integer")
	}
	if !(maxValue > 0) || math.IsInf(maxValue, 0) {
		return AggregationLayout{}, fmt.Errorf("lightphe: maximum value must be a positive number")
	}
	if precision < 0 {
		return AggregationLayout{}, fmt.Errorf("lightphe: precision must be a non-negative integer")
	}

	bound, err := roundHalfEven(maxValue * math.Pow10(precision))
	if err != nil {
		return AggregationLayout{}, err
	}
	if bound.Sign() < 1 {
		return AggregationLayout{}, fmt.Errorf("lightphe: maximum value %v is zero after quantization", maxValue)
	}

	headroom := new(big.Int).Mul(bound, big.NewInt(2*int64(maxClients)))
	slotBits := headroom.BitLen()
	// packed plaintexts must be less than the plaintext modulo
	slots := (modulo.BitLen() - 1) / slotBits
	if slots < 1 {
		return AggregationLayout{}, fmt.Errorf("lightphe: plaintext space is too small for %d-bit slots, use a larger key "+
			"size, a smaller precision, a smaller maximum value or fewer clients", slotBits)
	}
	return AggregationLayout{
		Length:     length,
		Precision:  precision,
		Bound:      bound,
		MaxClients: maxClients,
		SlotBits:   slotBits,
		Slots:      slots,
	}, nil
}

// pack quantizes an update and packs its values into plaintexts, one for each
// chunk of values.
func pack(update []float64, layout AggregationLayout) ([]*big.Int, error) {
	scale := math.Pow10(layout.Precision)
	shifted := make([]*big.Int, len(update))
	for i, x := range update {
		quantized, err := roundHalfEven(x * scale)
		if err != nil {
			return nil, err
		}
		if quantized.CmpAbs(layout.Bound) > 0 {
			return nil, fmt.Errorf("lightphe: value %v of the update exceeds the maximum value", x)
		}
		shifted[i] = quantized.Add(quantized, layout.Bound)
	}

	var plaintexts []*big.Int
	for start := 0; start < len(shifted); start += layout.Slots {
		plaintext := new(big.Int)
		for i := 0; i < layout.Slots && start+i < len(shifted); i++ {
			plaintext.Or(plaintext, new(big.Int).Lsh(shifted[start+i], uint(layout.SlotBits*i)))
		}
		plaintexts = append(plaintexts, plaintext)
	}
	return plaintexts, nil
}

// unpack unpacks the sum of count updates from decrypted plaintexts.
func unpack(plaintexts []*big.Int, layout AggregationLayout, count int) []float64 {
	scale := new(big.Int).Exp(big.NewInt(10), big.NewInt(int64(layout.Precision)), nil)
	shift := new(big.Int).Mul(layout.Bound, big.NewInt(int64(count)))
	mask := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), uint(layout.SlotBits)), big.NewInt(1))

	values := make([]float64, 0, layout.Length)
	for _, plaintext := range plaintexts {
		for i := 0; i < layout.Slots && len(values) < layout.Length; i++ {
			slot := new(big.Int).Rsh(plaintext, uint(layout.SlotBits*i))
			slot.And(slot, mask).Sub(slot, shift)
			value, _ := new(big.Rat).SetFrac(slot, scale).Float64()
			values = append(values, value)
		}
	}
	return values
}

// EncryptUpdate encrypts a model update of a client for secure aggregation in
// federated learning. Values are quantized with the precision of this
// cryptosystem, and many of them are packed into a single ciphertext, so an
// update needs far fewer ciphertexts than its length. Absolute values of the
// update must be at most maxValue, e.g. the clipping bound of gradients, and
// maxClients is the maximum number of updates to be summed, so slots are wide
// enough to sum them without overflow. Public key is enough. Clients must use
// the same key, length, precision, maxValue and maxClients. Supported by
// Paillier and Damgard-Jurik.
func (c *Cryptosystem) EncryptUpdate(update []float64, maxValue float64, maxClients int) (*EncryptedUpdate, error) {
	if err := c.requireAggregationSupport(); err != nil {
		return nil, err
	}
	cs := c.unboosted()
	layout, err := buildLayout(len(update), c.precision, maxValue, maxClients, cs.PlaintextModulo())
	if err != nil {
		return nil, err
	}
	plaintexts, err := pack(update, layout)
	if err != nil {
		return nil, err
	}
	chunks := make([]*encrypted.Ciphertext, len(plaintexts))
	err = parallelDo(len(plaintexts), func(i int) error {
		value, err := cs.Encrypt(plaintexts[i])
		if err != nil {
			return err
		}
		chunks[i] = encrypted.NewCiphertext(c.publicUnboosted(), value)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return &EncryptedUpdate{Chunks: chunks, Layout: layout, Count: 1}, nil
}

// AggregateUpdates sums encrypted updates of clients chunk by chunk. It runs
// on server side and requires the public key only. Server learns nothing
// about updates or their sum. Updates can be outputs of EncryptUpdate or
// AggregateUpdates.
func (c *Cryptosystem) AggregateUpdates(updates []*EncryptedUpdate) (*EncryptedUpdate, error) {
	if err := c.requireAggregationSupport(); err != nil {
		return nil, err
	}
	if len(updates) == 0 || updates[0] == nil {
		return nil, fmt.Errorf("lightphe: encrypted updates must be a non-empty list")
	}
	layout := updates[0].Layout
	count := 0
	for _, update := range updates {
		if update == nil || !update.Layout.Equal(layout) || len(update.Chunks) != len(updates[0].Chunks) {
			return nil, fmt.Errorf("lightphe: encrypted updates must have the same layout, i.e. the same length, " +
				"precision, maximum value and maximum number of clients")
		}
		count += update.Count
	}
	if count > layout.MaxClients {
		return nil, fmt.Errorf("lightphe: sum of %d updates would overflow slots packed for at most %d clients",
			count, layout.MaxClients)
	}

	chunks := append([]*encrypted.Ciphertext{}, updates[0].Chunks...)
	for _, update := range updates[1:] {
		for i, chunk := range update.Chunks {
			sum, err := chunks[i].Add(chunk)
			if err != nil {
				return nil, err
			}
			chunks[i] = sum
		}
	}
	return &EncryptedUpdate{Chunks: chunks, Layout: layout, Count: count}, nil
}

// PartialDecryptAggregate decrypts an encrypted sum of updates partially with
// the share of a shareholder, e.g. a member of a committee of clients.
// Shareholders decrypt sums only, never individual updates. Set prove to true
// to attach proofs of correct partial decryption, which requires keys
// generated with WithSafePrimes(true). It returns a partial decryption for
// each chunk, to be sent to the combiner.
func (c *Cryptosystem) PartialDecryptAggregate(sum *EncryptedUpdate, prove bool) ([]*PartialDecryption, error) {
	if err := c.requireAggregationSupport(); err != nil {
		return nil, err
	}
	if sum == nil {
		return nil, fmt.Errorf("lightphe: nil encrypted sum")
	}
	out := make([]*PartialDecryption, len(sum.Chunks))
	for i, chunk := range sum.Chunks {
		partial, err := c.PartialDecrypt(chunk, prove)
		if err != nil {
			return nil, err
		}
		out[i] = partial
	}
	return out, nil
}

// CombineAggregate restores the sum and the mean of updates from partial
// decryptions of at least threshold many shareholders, each of which is the
// output of PartialDecryptAggregate of a shareholder. Public key is enough.
// Set verify to true to check proofs of partial decryptions, and discard
// invalid or unproven ones.
func (c *Cryptosystem) CombineAggregate(sum *EncryptedUpdate, partials [][]*PartialDecryption, verify bool) (*Aggregate, error) {
	if err := c.requireAggregationSupport(); err != nil {
		return nil, err
	}
	if sum == nil {
		return nil, fmt.Errorf("lightphe: nil encrypted sum")
	}
	plaintexts := make([]*big.Int, len(sum.Chunks))
	for i, chunk := range sum.Chunks {
		chunkPartials := make([]*PartialDecryption, 0, len(partials))
		for _, p := range partials {
			if len(p) != len(sum.Chunks) {
				return nil, fmt.Errorf("lightphe: partial decryptions of an aggregate must have %d chunks", len(sum.Chunks))
			}
			chunkPartials = append(chunkPartials, p[i])
		}
		plaintext, err := c.CombinePartialDecryptions(chunk, chunkPartials, verify)
		if err != nil {
			return nil, err
		}
		plaintexts[i] = plaintext
	}
	return unpackAggregate(sum, plaintexts), nil
}

// DecryptAggregate restores the sum and the mean of updates with the private
// key, if a single party holds it instead of a committee.
func (c *Cryptosystem) DecryptAggregate(sum *EncryptedUpdate) (*Aggregate, error) {
	if err := c.requireAggregationSupport(); err != nil {
		return nil, err
	}
	if sum == nil {
		return nil, fmt.Errorf("lightphe: nil encrypted sum")
	}
	plaintexts := make([]*big.Int, len(sum.Chunks))
	for i, chunk := range sum.Chunks {
		plaintext, err := c.Decrypt(chunk)
		if err != nil {
			return nil, err
		}
		plaintexts[i] = plaintext
	}
	return unpackAggregate(sum, plaintexts), nil
}

func unpackAggregate(sum *EncryptedUpdate, plaintexts []*big.Int) *Aggregate {
	total := unpack(plaintexts, sum.Layout, sum.Count)
	mean := make([]float64, len(total))
	for i, x := range total {
		mean[i] = x / float64(sum.Count)
	}
	return &Aggregate{Sum: total, Mean: mean, Count: sum.Count}
}
