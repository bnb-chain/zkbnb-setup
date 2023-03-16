package setup

import (
	"io"

	"github.com/consensys/gnark-crypto/ecc/bn254"
)

func (c *Phase1Contribution) writeTo(writer io.Writer) (int64, error) {
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

	enc := bn254.NewEncoder(writer)
	for _, v := range toEncode {
		if err := enc.Encode(v); err != nil {
			return enc.BytesWritten(), err
		}
	}
	nBytes, err := writer.Write(c.Hash)
	return int64(nBytes), err
}

func (c *Phase1Contribution) readFrom(reader io.Reader) (int64, error) {
	toDecode := []interface{}{
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
