package regev

import "testing"

func TestKeysAreWellFormed(t *testing.T) {
	cs, err := Generate(64, nil)
	if err != nil {
		t.Fatalf("generating keys: %v", err)
	}
	keys := cs.Keys()
	n := len(keys.PublicKey.B)
	s := keys.PrivateKey.S
	for _, x := range s {
		if x < -eta || x > eta {
			t.Fatalf("secret entry %d is not small", x)
		}
	}

	// b = A s + e mod q where e is small. A is expanded from the seed entry by
	// entry.
	a := expand(keys.PublicKey.Seed, n)
	q := int64(1) << LogQ
	for i := 0; i < n; i++ {
		var acc uint64
		for j := 0; j < n; j++ {
			acc += a[i*n+j] * uint64(s[j])
		}
		e := int64((keys.PublicKey.B[i] - acc) & qMask)
		if e > q/2 {
			e -= q
		}
		if e < -eta || e > eta {
			t.Fatalf("entry %d of the error is %d, which is not small", i, e)
		}
	}
}
