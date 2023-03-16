package setup

import (
	"github.com/consensys/gnark-crypto/ecc/bn254"
)

type PublicKey struct {
	S   bn254.G1Affine
	SX  bn254.G1Affine
	SPX bn254.G2Affine
}

type Phase1Contribution struct {
	G1 struct {
		Tau, AlphaTau, BetaTau bn254.G1Affine
	}
	G2 struct {
		Tau, Beta bn254.G2Affine
	}
	PublicKeys struct {
		Tau, Alpha, Beta PublicKey
	}
	Hash []byte
}
