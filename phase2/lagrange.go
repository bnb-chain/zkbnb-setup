package phase2

import (
	"bufio"
	"io"
	"os"

	"github.com/bnbchain/zkbnb-setup/lagrange"
	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/fft"
)

func lagrangeG1(phase1File, lagFile *os.File, position int64, domain *fft.Domain) error {
	if _, err := phase1File.Seek(position, io.SeekStart); err != nil {
		return err
	}

	reader := bufio.NewReader(phase1File)
	writer := bufio.NewWriter(lagFile)
	defer writer.Flush()
	dec := bn254.NewDecoder(reader)
	enc := bn254.NewEncoder(writer)

	size := int(domain.Cardinality)
	buff := make([]bn254.G1Affine, size)
	for i := 0; i < len(buff); i++ {
		if err := dec.Decode(&buff[i]); err != nil {
			return err
		}
	}

	lagrange.ConvertG1(buff, domain)

	if err := enc.Encode(buff); err != nil {
		return err
	}
	return nil
}

func lagrangeG2(phase1File, lagFile *os.File, position int64, domain *fft.Domain) error {
	// Seek to position
	if _, err := phase1File.Seek(position, io.SeekStart); err != nil {
		return err
	}

	reader := bufio.NewReader(phase1File)
	writer := bufio.NewWriter(lagFile)
	defer writer.Flush()
	dec := bn254.NewDecoder(reader)
	enc := bn254.NewEncoder(writer)

	size := int(domain.Cardinality)
	buff := make([]bn254.G2Affine, size)
	for i := 0; i < len(buff); i++ {
		if err := dec.Decode(&buff[i]); err != nil {
			return err
		}
	}

	lagrange.ConvertG2(buff, domain)

	if err := enc.Encode(buff); err != nil {
		return err
	}
	return nil
}
