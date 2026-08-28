// Package fixedpoint encodes real numbers for cryptosystems that only speak
// integers.
//
// Two encodings live here:
//
//   - Normalize maps a single float onto the message space as a modular
//     fraction, dividend * divisor^-1 mod m. Arithmetic on it stays exact, but
//     the result only makes sense once it is read back in the same terms.
//   - Fractionize keeps the dividend and the divisor apart, which is what
//     tensors do: the divisor rides along encrypted so that the scale survives
//     multiplication.
package fixedpoint

import (
	"fmt"
	"math"
	"math/big"
	"strconv"
	"strings"

	"github.com/serengil/lightphe-go/lightphe/internal/mathutil"
)

// Normalize maps a non-negative float onto [0, modulo) as
// dividend * divisor^-1 mod modulo, using the number of decimal digits the
// float actually prints with.
func Normalize(value float64, modulo *big.Int) (*big.Int, error) {
	if math.IsNaN(value) || math.IsInf(value, 0) {
		return nil, fmt.Errorf("fixedpoint: %v cannot be encoded", value)
	}
	if value < 0 {
		return nil, fmt.Errorf("fixedpoint: negative float constants are not supported; encode the sign yourself or use a tensor")
	}

	dividend, divisor := Fractionize(value, modulo, DecimalPlaces(value))
	inv, err := mathutil.ModInverse(divisor, modulo)
	if err != nil {
		return nil, fmt.Errorf("fixedpoint: cannot represent %v in the message space: %w", value, err)
	}
	result := new(big.Int).Mul(dividend, inv)
	return result.Mod(result, modulo), nil
}

// Fractionize splits a float into an integer dividend and the power of ten it
// was scaled by. The dividend is reduced modulo modulo, so negative inputs come
// back as their positive representative.
func Fractionize(value float64, modulo *big.Int, precision int) (dividend, divisor *big.Int) {
	if precision < 0 {
		precision = 0
	}
	divisor = new(big.Int).Exp(big.NewInt(10), big.NewInt(int64(precision)), nil)

	// big.Rat holds the float exactly, so scaling and truncating here matches
	// what a decimal library with generous precision would produce.
	scaled := new(big.Rat).SetFloat64(value)
	if scaled == nil {
		return new(big.Int), divisor
	}
	scaled.Mul(scaled, new(big.Rat).SetInt(divisor))

	// Truncate toward zero, then reduce into the message space.
	truncated := new(big.Int).Quo(scaled.Num(), scaled.Denom())
	return truncated.Mod(truncated, modulo), divisor
}

// DecimalPlaces reports how many digits follow the decimal point in the
// shortest representation of value that round-trips.
func DecimalPlaces(value float64) int {
	s := strconv.FormatFloat(value, 'f', -1, 64)
	dot := strings.IndexByte(s, '.')
	if dot < 0 {
		return 0
	}
	return len(s) - dot - 1
}
