package shake

import (
	"encoding/hex"
	"math/big"
	"testing"
)

// expected outputs are computed with Python's hashlib.shake_128
func TestSum128MatchesPython(t *testing.T) {
	data := make([]byte, 200)
	for i := range data {
		data[i] = byte(i)
	}
	seed := make([]byte, 32)
	big.NewInt(12345).FillBytes(seed)

	cases := []struct {
		data []byte
		size int
		skip int
		want string
	}{
		{nil, 40, 0, "7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef263cb1eea988004b93"},
		{data, 400, 380, "4491ec873fa6be71b2cf3888ff169e5a98c7fa85"},
		{seed, 20, 0, "8e9405902dbce0f47fe3154dad111d1634df5d48"},
	}
	for i, tc := range cases {
		got := hex.EncodeToString(Sum128(tc.data, tc.size)[tc.skip:])
		if got != tc.want {
			t.Fatalf("case %d: got %s, want %s", i, got, tc.want)
		}
	}
}
