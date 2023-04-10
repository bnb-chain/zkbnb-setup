package phase2

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"io"
	"math"
	"math/big"
	"os"

	"github.com/bnbchain/zkbnb-setup/common"
	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
)

func Initialize(phase1Path, r1csPath, phase2Path string) error {
	phase1File, err := os.Open(phase1Path)
	if err != nil {
		return err
	}
	defer phase1File.Close()

	phase2File, err := os.Create(phase2Path)
	if err != nil {
		return err
	}
	defer phase2File.Close()

	// 1. Process Headers
	header1, header2, err := processHeader(r1csPath, phase1File, phase2File)
	if err != nil {
		return err
	}

	// 2. Convert phase 1 SRS to Lagrange basis
	if err := processLagrange(header1, header2, phase1File, phase2File); err != nil {
		return err
	}

	// 3. Evaluate A, B, C
	if err := processEvaluations(header1, header2, r1csPath, phase1File); err != nil {
		return err
	}

	// Evaluate Delta and Z
	if err := processDeltaAndZ(header1, header2, phase1File, phase2File); err != nil {
		return err
	}

	// // Evaluate L
	if err := processL(header1, header2, r1csPath, phase2File); err != nil {
		return err
	}

	fmt.Println("Phase 2 has been initialized successfully")
	return nil
}

func Contribute(inputPath, outputPath string) error {
	// Input file
	inputFile, err := os.Open(inputPath)
	if err != nil {
		return err
	}
	defer inputFile.Close()

	// Output file
	outputFile, err := os.Create(outputPath)
	if err != nil {
		return err
	}
	defer outputFile.Close()

	// Read/Write header with extra contribution
	var header Header
	if _, err := header.ReadFrom(inputFile); err != nil {
		return err
	}
	fmt.Printf("Current #Contributions := %d\n", header.Contributions)
	header.Contributions++
	if err := header.writeTo(outputFile); err != nil {
		return err
	}

	buffSize := int(math.Pow(2, 20))
	reader := bufio.NewReaderSize(inputFile, buffSize)
	writer := bufio.NewWriterSize(outputFile, buffSize)
	defer writer.Flush()

	dec := bn254.NewDecoder(reader)
	enc := bn254.NewEncoder(writer, bn254.RawEncoding())

	// Sample toxic parameters
	fmt.Println("Sampling toxic parameters Delta")
	// Sample toxic δ
	var delta, deltaInv fr.Element
	var deltaBI, deltaInvBI big.Int
	delta.SetRandom()
	deltaInv.Inverse(&delta)

	delta.BigInt(&deltaBI)
	deltaInv.BigInt(&deltaInvBI)

	// Process δ₁
	fmt.Println("Processing DeltaG1 and DeltaG2")
	var delta1 bn254.G1Affine
	if err := dec.Decode(&delta1); err != nil {
		return err
	}
	delta1.ScalarMultiplication(&delta1, &deltaBI)
	if err := enc.Encode(&delta1); err != nil {
		return err
	}

	// Process δ₂
	var delta2 bn254.G2Affine
	if err := dec.Decode(&delta2); err != nil {
		return err
	}
	delta2.ScalarMultiplication(&delta2, &deltaBI)
	if err := enc.Encode(&delta2); err != nil {
		return err
	}

	// Process Z using δ⁻¹
	if err = scale(dec, enc, int(header.Domain-1), &deltaInvBI); err != nil {
		return err
	}

	// Copy public part of L as-is
	var tmpPublic bn254.G1Affine
	for i := 0; i < int(header.Public); i++ {
		if err := dec.Decode(&tmpPublic); err != nil {
			return err
		}
		if err := enc.Encode(&tmpPublic); err != nil {
			return err
		}
	}

	// Process private part of L using δ⁻¹
	if err = scale(dec, enc, int(header.Witness), &deltaInvBI); err != nil {
		return err
	}

	// Copy old contributions
	nExistingContributions := int(header.Contributions - 1)
	var c Contribution
	for i := 0; i < nExistingContributions; i++ {
		if _, err := c.readFrom(reader); err != nil {
			return err
		}
		if _, err := c.writeTo(writer); err != nil {
			return err
		}
	}

	// Get hash of previous contribution
	var prevHash []byte
	if nExistingContributions == 0 {
		prevHash = nil
	} else {
		prevHash = c.Hash
	}

	var contribution Contribution
	contribution.Delta.Set(&delta1)
	contribution.PublicKey = common.GenPublicKey(delta, prevHash, 1)
	contribution.Hash = computeHash(&contribution)

	// Write the contribution
	contribution.writeTo(writer)

	fmt.Println("Contirbution has been successful!")
	fmt.Println("Contribution Hash := ", hex.EncodeToString(contribution.Hash))

	return nil
}

func Verify(inputPath, originPath string) error {
	// Input file
	inputFile, err := os.Open(inputPath)
	if err != nil {
		return err
	}
	defer inputFile.Close()

	// Origin file from Phase2.Initialize
	originFile, err := os.Open(originPath)
	if err != nil {
		return err
	}
	defer originFile.Close()

	// Read header
	var header Header
	if _, err := header.ReadFrom(inputFile); err != nil {
		return err
	}
	if header.Contributions == 0 {
		return fmt.Errorf("there are no contributions to verify")
	}
	fmt.Printf("#Contributions := %d\n", header.Contributions)

	// Seek to contributions
	pos := 18 + 192 + int64(header.Domain-1)*64 + int64(header.Witness+header.Public)*64
	if _, err := inputFile.Seek(pos, io.SeekStart); err != nil {
		panic(err)
		return err
	}

	// Use buffered IO to write parameters efficiently
	buffSize := int(math.Pow(2, 20))
	inputReader := bufio.NewReaderSize(inputFile, buffSize)

	_, _, g1, g2 := bn254.Generators()
	var prevDelta = g1
	var prevHash []byte = nil
	var c Contribution
	for i := 0; i < int(header.Contributions); i++ {
		if _, err := c.readFrom(inputReader); err != nil {
			return err
		}
		fmt.Printf("Verifying contribution %d with Hash := %s\n", i+1, hex.EncodeToString(c.Hash))
		if err := verifyContribution(&c, prevDelta, prevHash); err != nil {
			return err
		}
		prevDelta = c.Delta
		prevHash = c.Hash
	}

	// Seek to Parameters
	pos = 18
	if _, err := inputFile.Seek(pos, io.SeekStart); err != nil {
		return err
	}

	inputReader.Reset(inputFile)
	inputDecoder := bn254.NewDecoder(inputReader)

	fmt.Println("Verifying DeltaG1 and DeltaG2")
	// Verify last contribution has the same delta in parameters
	var d1 bn254.G1Affine
	if err := inputDecoder.Decode(&d1); err != nil {
		return err
	}
	if !d1.Equal(&c.Delta) {
		return fmt.Errorf("last contribution delta isn't the same as in parameters")
	}

	var d2 bn254.G2Affine
	if err := inputDecoder.Decode(&d2); err != nil {
		return err
	}

	// Check δ₁ and δ₂ are consistent
	if !common.SameRatio(g1, c.Delta, d2, g2) {
		return fmt.Errorf("deltaG1 and deltaG2 aren't consistent")
	}

	// Seek to Z
	pos += 64 + 128
	if _, err := originFile.Seek(pos, io.SeekStart); err != nil {
		return err
	}
	originReader := bufio.NewReaderSize(originFile, buffSize)
	originDecoder := bn254.NewDecoder(originReader)

	fmt.Println("Verifying update of Z")
	// Check Z is updated correctly from origin to the latest state
	if err := verifyParameter(&d2, &g2, inputDecoder, originDecoder, int(header.Domain-1), "Z"); err != nil {
		return err
	}

	// Check equal public part of L
	fmt.Println("Verifying equality of public part of L")
	if err := verifyEquality(inputDecoder, originDecoder, int(header.Public)); err != nil {
		return err
	}
	fmt.Println("Verifying update of witness part of L")
	// Check L is updated correctly from origin to the latest state
	if err := verifyParameter(&d2, &g2, inputDecoder, originDecoder, int(header.Witness), "L"); err != nil {
		return err
	}

	fmt.Println("Contributions verification has been successful")
	return nil
}
