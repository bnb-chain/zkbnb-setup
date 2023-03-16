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

func (c *Phase1Contribution) computeHash() {
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
	c.Hash = sha.Sum(nil)
}
