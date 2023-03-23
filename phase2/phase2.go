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
	"github.com/bnbchain/zkbnb-setup/phase1"
	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	cs_bn254 "github.com/consensys/gnark/constraint/bn254"
)

func Initialize(inputPhase1Path, inputR1csPath, outputPhase2Path, outputEvalsPath string) error {
	// Input Phase 1
	inputPhase1File, err := os.Open(inputPhase1Path)
	if err != nil {
		return err
	}
	defer inputPhase1File.Close()

	// Input R1CS
	inputR1csFile, err := os.Open(inputR1csPath)
	if err != nil {
		return err
	}
	defer inputR1csFile.Close()

	// Output Phase 2
	outputPhase2File, err := os.Create(outputPhase2Path)
	if err != nil {
		return err
	}
	defer outputPhase2File.Close()

	// Output Evaluations
	outputEvalsFile, err := os.Create(outputEvalsPath)
	if err != nil {
		return err
	}
	defer outputEvalsFile.Close()

	// Read R1CS
	fmt.Println("Reading R1CS...")
	var r1cs cs_bn254.R1CS
	if _, err := r1cs.ReadFrom(inputR1csFile); err != nil {
		return err
	}

	// Process Header
	fmt.Println("Processing the header")
	var header1 *phase1.Header
	var header2 *Header
	if header1, header2, err = processHeader(&r1cs, inputPhase1File, outputPhase2File); err != nil {
		return err
	}
	fmt.Printf("Circuit Info, nConstraints:=%d, nInternal:=%d, nPublic:=%d\n", header2.Constraints, header2.Witness, header2.Public)

	// Evaluate constraints
	fmt.Println("Evaluating [A]₁, [B]₁, [B]₂")
	if err := processEvaluations(&r1cs, header1, header2, inputPhase1File, outputEvalsFile); err != nil {
		return err
	}

	// Evaluate Delta and Z
	fmt.Println("Evaluating Delta and Z")
	if err := processDeltaAndZ(header1, header2, inputPhase1File, outputPhase2File); err != nil {
		return err
	}

	// // Evaluate L
	fmt.Println("Evaluating L")
	if err := processL(&r1cs, header1, header2, inputPhase1File, outputPhase2File); err != nil {
		return err
	}

	fmt.Println("Phase 2 has been initialized successfully")
	return nil
}

func InitializeFromPartedR1CS(inputPhase1Path, inputR1csSession, outputPhase2Path, outputEvalsPath string, nbCons, batchSize int) error {
	// Input Phase 1
	inputPhase1File, err := os.Open(inputPhase1Path)
	if err != nil {
		return err
	}
	defer inputPhase1File.Close()

	// Output Phase 2
	outputPhase2File, err := os.Create(outputPhase2Path)
	if err != nil {
		return err
	}
	defer outputPhase2File.Close()

	// Output Evaluations
	outputEvalsFile, err := os.Create(outputEvalsPath)
	if err != nil {
		return err
	}
	defer outputEvalsFile.Close()

	// Read R1CS
	fmt.Println("Reading R1CS...")
	var r1cs cs_bn254.R1CS
	{
		name := fmt.Sprintf("%s.r1cs.E.save", inputR1csSession)
		r1csDump, err := os.Open(name)
		if err != nil {
			return err
		}
		_, err = r1cs.ReadFrom(r1csDump)
		if err != nil {
			return err
		}
	}

	// Process Header
	fmt.Println("Processing the header")
	var header1 *phase1.Header
	var header2 *Header
	if header1, header2, err = processHeader2(&r1cs, nbCons, inputPhase1File, outputPhase2File); err != nil {
		return err
	}
	fmt.Printf("Circuit Info, nConstraints:=%d, nInternal:=%d, nPublic:=%d\n", header2.Constraints, header2.Witness, header2.Public)

	// Evaluate constraints
	fmt.Println("Evaluating [A]₁, [B]₁, [B]₂")
	if err := processEvaluations2(&r1cs, inputR1csSession, nbCons, batchSize, header1, header2, inputPhase1File, outputEvalsFile); err != nil {
		return err
	}

	// Evaluate Delta and Z
	fmt.Println("Evaluating Delta and Z")
	if err := processDeltaAndZ(header1, header2, inputPhase1File, outputPhase2File); err != nil {
		return err
	}

	// // Evaluate L
	fmt.Println("Evaluating L")
	if err := processL2(&r1cs, inputR1csSession, nbCons, batchSize, header1, header2, inputPhase1File, outputPhase2File); err != nil {
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
	if err := header.ReadFrom(inputFile); err != nil {
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
	enc := bn254.NewEncoder(writer)

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
	if err := header.ReadFrom(inputFile); err != nil {
		return err
	}
	if header.Contributions == 0 {
		return fmt.Errorf("there are no contributions to verify")
	}
	fmt.Printf("#Contributions := %d\n", header.Contributions)

	// Seek to contributions
	pos := 18 + 96 + int64(header.Domain-1)*32 + int64(header.Witness+header.Public)*32
	if _, err := inputFile.Seek(pos, io.SeekStart); err != nil {
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
	pos += 32 + 64
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
