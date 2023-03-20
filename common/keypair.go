package common

import (
	"math/big"

	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
)

type PublicKey struct {
	S   bn254.G1Affine
	SX  bn254.G1Affine
	SPX bn254.G2Affine
}

func GenPublicKey(x fr.Element, challenge []byte, dst byte) PublicKey {
	var pk PublicKey
	_, _, g1, _ := bn254.Generators()

	var s fr.Element
	var sBi big.Int
	s.SetRandom()
	s.BigInt(&sBi)
	pk.S.ScalarMultiplication(&g1, &sBi)

	// compute x*sG1
	var xBi big.Int
	x.BigInt(&xBi)
	pk.SX.ScalarMultiplication(&pk.S, &xBi)

	// generate R based on sG1, sxG1, challenge, and domain separation tag (tau, alpha or beta)
	SP := GenSP(pk.S, pk.SX, challenge, dst)

	// compute x*spG2
	pk.SPX.ScalarMultiplication(&SP, &xBi)
	return pk
}

// Generate SP in G₂ as Hash(gˢ, gˢˣ, challenge, dst)
func GenSP(sG1, sxG1 bn254.G1Affine, challenge []byte, dst byte) bn254.G2Affine {
	buffer := append(sG1.Marshal()[:], sxG1.Marshal()...)
	buffer = append(buffer, challenge...)
	spG2, err := bn254.HashToG2(buffer, []byte{dst})
	if err != nil {
		panic(err)
	}
	return spG2
}
