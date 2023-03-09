package utils

import (
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
)

// Returns [1, a, a², ..., aⁿ⁻¹ ] in Montgomery form
func Powers(a fr.Element, n int) []fr.Element {
	result := make([]fr.Element, n)
	result[0] = fr.NewElement(1)
	for i := 1; i < n; i++ {
		result[i].Mul(&result[i-1], &a)
	}
	return result
}
