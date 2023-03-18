package phase1

import (
	"crypto/sha256"
	"io"

	"github.com/consensys/gnark-crypto/ecc/bn254"
)

type Contribution struct {
	G1 struct {
		Tau, Alpha, Beta bn254.G1Affine
	}
	G2 struct {
		Tau, Beta bn254.G2Affine
	}
	PublicKeys struct {
		Tau, Alpha, Beta PublicKey
	}
	Hash []byte
}

func (c *Contribution) writeTo(writer io.Writer) (int64, error) {
	toEncode := []interface{}{
		&c.G1.Tau,
		&c.G1.Alpha,
		&c.G1.Beta,
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

	enc := bn254.NewEncoder(writer)
	for _, v := range toEncode {
		if err := enc.Encode(v); err != nil {
			return enc.BytesWritten(), err
		}
	}
	nBytes, err := writer.Write(c.Hash)
	return int64(nBytes), err
}

func (c *Contribution) readFrom(reader io.Reader) (int64, error) {
	toDecode := []interface{}{
		&c.G1.Tau,
		&c.G1.Alpha,
		&c.G1.Beta,
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

	dec := bn254.NewDecoder(reader)
	for _, v := range toDecode {
		if err := dec.Decode(v); err != nil {
			return dec.BytesRead(), err
		}
	}
	c.Hash = make([]byte, 32)
	nBytes, err := reader.Read(c.Hash)
	return int64(nBytes), err
}

func computeHash(c *Contribution) []byte {
	sha := sha256.New()
	toEncode := []interface{}{
		&c.G1.Tau,
		&c.G1.Alpha,
		&c.G1.Beta,
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

func defaultContribution() Contribution {
	var c Contribution

	// Initialize with generators
	_, _, g1, g2 := bn254.Generators()
	c.G1.Tau.Set(&g1)
	c.G1.Alpha.Set(&g1)
	c.G1.Beta.Set(&g1)
	c.G2.Tau.Set(&g2)
	c.G2.Beta.Set(&g2)

	c.Hash = nil
	return c
}
