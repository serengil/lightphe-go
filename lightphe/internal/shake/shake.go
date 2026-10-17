// Package shake implements the SHAKE-128 extendable output function of FIPS
// 202. Regev and Brakerski-Vaikuntanathan expand their public randomness from
// a seed with it, exactly as the Python library does with hashlib.shake_128,
// so that exported keys stay interchangeable. The standard library only ships
// SHA-3 from Go 1.24 on, and this module supports older versions.
package shake

import "encoding/binary"

// rate128 is the rate of SHAKE-128 in bytes.
const rate128 = 168

// roundConstants of the iota step.
var roundConstants = [24]uint64{
	0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000,
	0x000000000000808B, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
	0x000000000000008A, 0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
	0x000000008000808B, 0x800000000000008B, 0x8000000000008089, 0x8000000000008003,
	0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A,
	0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
}

// rotations of the rho step, indexed by x + 5y.
var rotations = [25]uint{
	0, 1, 62, 28, 27,
	36, 44, 6, 55, 20,
	3, 10, 43, 25, 39,
	41, 45, 15, 21, 8,
	18, 2, 61, 56, 14,
}

func rotl(x uint64, n uint) uint64 { return x<<n | x>>(64-n) }

// keccakF1600 applies the Keccak permutation to the state.
func keccakF1600(a *[25]uint64) {
	var c, d [5]uint64
	var b [25]uint64
	for round := 0; round < 24; round++ {
		// theta
		for x := 0; x < 5; x++ {
			c[x] = a[x] ^ a[x+5] ^ a[x+10] ^ a[x+15] ^ a[x+20]
		}
		for x := 0; x < 5; x++ {
			d[x] = c[(x+4)%5] ^ rotl(c[(x+1)%5], 1)
		}
		for i := 0; i < 25; i++ {
			a[i] ^= d[i%5]
		}
		// rho and pi
		for x := 0; x < 5; x++ {
			for y := 0; y < 5; y++ {
				i := x + 5*y
				r := rotations[i]
				v := a[i]
				if r != 0 {
					v = rotl(v, r)
				}
				b[y+5*((2*x+3*y)%5)] = v
			}
		}
		// chi
		for y := 0; y < 25; y += 5 {
			for x := 0; x < 5; x++ {
				a[y+x] = b[y+x] ^ (^b[y+(x+1)%5] & b[y+(x+2)%5])
			}
		}
		// iota
		a[0] ^= roundConstants[round]
	}
}

// Sum128 returns size bytes of SHAKE-128 output for data.
func Sum128(data []byte, size int) []byte {
	var state [25]uint64

	// absorb with the SHAKE domain separator 0x1F and the final bit 0x80
	padded := make([]byte, (len(data)/rate128+1)*rate128)
	copy(padded, data)
	padded[len(data)] ^= 0x1F
	padded[len(padded)-1] ^= 0x80
	for offset := 0; offset < len(padded); offset += rate128 {
		for i := 0; i < rate128/8; i++ {
			state[i] ^= binary.LittleEndian.Uint64(padded[offset+8*i:])
		}
		keccakF1600(&state)
	}

	// squeeze
	out := make([]byte, size)
	block := make([]byte, rate128)
	for offset := 0; offset < size; offset += rate128 {
		if offset > 0 {
			keccakF1600(&state)
		}
		for i := 0; i < rate128/8; i++ {
			binary.LittleEndian.PutUint64(block[8*i:], state[i])
		}
		copy(out[offset:], block)
	}
	return out
}
