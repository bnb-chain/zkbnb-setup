package common

import (
	"math/bits"

	"github.com/consensys/gnark-crypto/ecc/bn254"
)

func BitReverseG1(a []bn254.G1Affine) {
	n := uint64(len(a))
	nn := uint64(64 - bits.TrailingZeros64(n))

	for i := uint64(0); i < n; i++ {
		irev := bits.Reverse64(i) >> nn
		if irev > i {
			a[i], a[irev] = a[irev], a[i]
		}
	}
}

func BitReverseG2(a []bn254.G2Affine) {
	n := uint64(len(a))
	nn := uint64(64 - bits.TrailingZeros64(n))

	for i := uint64(0); i < n; i++ {
		irev := bits.Reverse64(i) >> nn
		if irev > i {
			a[i], a[irev] = a[irev], a[i]
		}
	}
}

// Check e(a₁, a₂) = e(b₁, b₂)
func SameRatio(a1, b1 bn254.G1Affine, a2, b2 bn254.G2Affine) bool {
	var na2 bn254.G2Affine
	na2.Neg(&a2)
	res, err := bn254.PairingCheck(
		[]bn254.G1Affine{a1, b1},
		[]bn254.G2Affine{na2, b2})
	if err != nil {
		panic(err)
	}
	return res
}