package phase1

import (
	"crypto/sha256"
	"io"
	"math"
	"os"

	"github.com/bnb-chain/zkbnb-setup/common"
	"github.com/consensys/gnark-crypto/ecc/bn254"
)

const ContributionSize = 640

type Contribution struct {
	G1 struct {
		Tau, Alpha, Beta bn254.G1Affine
	}
	G2 struct {
		Tau, Beta bn254.G2Affine
	}
	PublicKeys struct {
		Tau, Alpha, Beta common.PublicKey
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

func (c *Contribution) ReadFrom(reader io.Reader) (int64, error) {
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

func defaultContribution(transformedPath string) (Contribution, error) {
	var c Contribution
	c.Hash = nil

	// Initialize with generators
	if transformedPath == "" {
		_, _, g1, g2 := bn254.Generators()
		c.G1.Tau.Set(&g1)
		c.G1.Alpha.Set(&g1)
		c.G1.Beta.Set(&g1)
		c.G2.Tau.Set(&g2)
		c.G2.Beta.Set(&g2)
	} else {
		// Read parameters from transformed file
		const G1CompressedSize = 32
		const G2CompressedSize = 64
		inputFile, err := os.Open(transformedPath)
		if err != nil {
			return c, err
		}
		defer inputFile.Close()
		dec := bn254.NewDecoder(inputFile)

		// Read header
		var header Header
		if err := header.ReadFrom(inputFile); err != nil {
			return c, err
		}

		N := int(math.Pow(2, float64(header.Power)))

		var posTauG1 int64 = 3 + G1CompressedSize
		var posAlphaG1 int64 = posTauG1 + int64(2*N-2)*G1CompressedSize
		var posBetaG1 int64 = posAlphaG1 + int64(N)*G1CompressedSize
		var posTauG2 int64 = posBetaG1 + int64(N)*G1CompressedSize + G2CompressedSize
		var posBetaG2 int64 = posTauG2 + int64(N-1)*G2CompressedSize

		// Read TauG1
		if _, err := inputFile.Seek(posTauG1, io.SeekStart); err != nil {
			return c, err
		}
		if err := dec.Decode(&c.G1.Tau); err != nil {
			return c, err
		}

		// Read AlphaG1
		if _, err := inputFile.Seek(posAlphaG1, io.SeekStart); err != nil {
			return c, err
		}
		if err := dec.Decode(&c.G1.Alpha); err != nil {
			return c, err
		}

		// Read BetaG1
		if _, err := inputFile.Seek(posBetaG1, io.SeekStart); err != nil {
			return c, err
		}
		if err := dec.Decode(&c.G1.Beta); err != nil {
			return c, err
		}

		// Read TauG2
		if _, err := inputFile.Seek(posTauG2, io.SeekStart); err != nil {
			return c, err
		}
		if err := dec.Decode(&c.G2.Tau); err != nil {
			return c, err
		}

		// Read BetaG2
		if _, err := inputFile.Seek(posBetaG2, io.SeekStart); err != nil {
			return c, err
		}
		if err := dec.Decode(&c.G2.Beta); err != nil {
			return c, err
		}
	}

	return c, nil
}
