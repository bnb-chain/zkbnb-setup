package setup

import (
	"crypto/sha256"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
)

func genPublicKey(x fr.Element, challenge []byte, dst byte) PublicKey {
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
	SP := genSP(pk.S, pk.SX, challenge, dst)

	// compute x*spG2
	pk.SPX.ScalarMultiplication(&SP, &xBi)
	return pk
}

// Generate SP in G₂ as Hash(gˢ, gˢˣ, challenge, dst)
func genSP(sG1, sxG1 bn254.G1Affine, challenge []byte, dst byte) bn254.G2Affine {
	buffer := append(sG1.Marshal()[:], sxG1.Marshal()...)
	buffer = append(buffer, challenge...)
	spG2, err := bn254.HashToG2(buffer, []byte{dst})
	if err != nil {
		panic(err)
	}
	return spG2
}

func processSectionG1(dec *bn254.Decoder, enc *bn254.Encoder, len int, element, multiplicand *fr.Element) (*bn254.G1Affine, error) {
	// Simply read previous point, contribute, then write
	var resElement, acc fr.Element
	var g1Tmp, firstPoint bn254.G1Affine
	var resBi big.Int

	for i := 0; i < len; i++ {
		if err := dec.Decode(&g1Tmp); err != nil {
			return nil, err
		}
		if i == 0 {
			acc.SetOne()
		} else {
			acc.Mul(&acc, element)
		}
		resElement.Mul(&acc, multiplicand)
		resElement.BigInt(&resBi)
		g1Tmp.ScalarMultiplication(&g1Tmp, &resBi)
		if !multiplicand.IsOne() && i == 0 {
			firstPoint.Set(&g1Tmp)
		}
		if multiplicand.IsOne() && i == 1 {
			firstPoint.Set(&g1Tmp)
		}
		if err := enc.Encode(&g1Tmp); err != nil {
			return nil, err
		}
	}
	return &firstPoint, nil
}

func processSectionG2(dec *bn254.Decoder, enc *bn254.Encoder, len int, element, multiplicand *fr.Element) (*bn254.G2Affine, error) {
	// Simply read previous point, contribute, then write
	var resElement, acc fr.Element
	var g2Tmp, firstPoint bn254.G2Affine
	var resBi big.Int

	for i := 0; i < len; i++ {
		if err := dec.Decode(&g2Tmp); err != nil {
			return nil, err
		}
		if i == 0 {
			acc.SetOne()
		} else {
			acc.Mul(&acc, element)
		}
		resElement.Mul(&acc, multiplicand)
		resElement.BigInt(&resBi)
		g2Tmp.ScalarMultiplication(&g2Tmp, &resBi)
		if !multiplicand.IsOne() && i == 0 {
			firstPoint.Set(&g2Tmp)
		}
		if multiplicand.IsOne() && i == 1 {
			firstPoint.Set(&g2Tmp)
		}
		if err := enc.Encode(&g2Tmp); err != nil {
			return nil, err
		}
	}
	return &firstPoint, nil
}

func computeHash(c *Phase1Contribution) []byte {
	sha := sha256.New()
	toEncode := []interface{}{
		&c.G1.Tau,
		&c.G1.AlphaTau,
		&c.G1.BetaTau,
		&c.G2.Tau,
		&c.G2.Beta,
		&c.PublicKeys.Tau.S,
		&c.PublicKeys.Tau.SX,
		&c.PublicKeys.Tau.SPX,
		&c.PublicKeys.Alpha.S,
		&c.PublicKeys.Alpha.SX,
		&c.PublicKeys.Alpha.SPX,
		&c.PublicKeys.Beta.S,
		&c.PublicKeys.Beta.SX,
		&c.PublicKeys.Beta.SPX,
	}

	enc := bn254.NewEncoder(sha)
	for _, v := range toEncode {
		enc.Encode(v)
	}

	return sha.Sum(nil)
}

// Check e(a₁, a₂) = e(b₁, b₂)
func sameRatio(a1, b1 bn254.G1Affine, a2, b2 bn254.G2Affine) bool {
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

func defaultPhase1Contribution() Phase1Contribution {
	var c Phase1Contribution
	var one fr.Element
	one.SetOne()
	// Initialize with generators
	_, _, g1, g2 := bn254.Generators()
	c.G1.Tau.Set(&g1)
	c.G1.AlphaTau.Set(&g1)
	c.G1.BetaTau.Set(&g1)
	c.G2.Tau.Set(&g2)
	c.G2.Beta.Set(&g2)

	// Initialize with unit public keys
	c.PublicKeys.Tau = genPublicKey(one, nil, 1)
	c.PublicKeys.Alpha = genPublicKey(one, nil, 2)
	c.PublicKeys.Beta = genPublicKey(one, nil, 3)
	c.Hash = nil
	return c
}
