package phase2

import (
	"crypto/sha256"
	"io"

	"github.com/bnbchain/zkbnb-setup/common"
	"github.com/consensys/gnark-crypto/ecc/bn254"
)

type Contribution struct {
	Delta     bn254.G1Affine
	PublicKey common.PublicKey
	Hash      []byte
}

func (c *Contribution) writeTo(writer io.Writer) (int64, error) {
	toEncode := []interface{}{
		&c.Delta,
		&c.PublicKey.S,
		&c.PublicKey.SX,
		&c.PublicKey.SPX,
	}

	enc := bn254.NewEncoder(writer, bn254.RawEncoding())
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
		&c.Delta,
		&c.PublicKey.S,
		&c.PublicKey.SX,
		&c.PublicKey.SPX,
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
		&c.Delta,
		&c.PublicKey.S,
		&c.PublicKey.SX,
		&c.PublicKey.SPX,
	}

	enc := bn254.NewEncoder(sha, bn254.RawEncoding())
	for _, v := range toEncode {
		enc.Encode(v)
	}

	return sha.Sum(nil)
}
