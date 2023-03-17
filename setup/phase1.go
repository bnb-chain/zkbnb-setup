package setup

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"math"
	"os"

	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
)

func InitializePhaseOne(power byte, outputPath string) error {
	_, _, g1, g2 := bn254.Generators()
	// output file
	file, err := os.Create(outputPath)
	if err != nil {
		return err
	}
	defer file.Close()

	// Use buffered IO to write parameters efficiently
	// buffer up to 4GB in memory
	buffSize := int(math.Pow(2, 32))
	writer := bufio.NewWriterSize(file, buffSize)
	defer writer.Flush()

	// BN254 encoder using compressed representation of points to save storage space
	enc := bn254.NewEncoder(writer, bn254.RawEncoding())

	N := int(math.Pow(2, float64(power)))
	fmt.Printf("Power %d supports up to %d constraints\n", power, N)

	// Write the power <1 byte>
	writer.WriteByte(power)

	// Write nContributions = 0 <1 byte>
	writer.WriteByte(0)

	// Write [τ⁰]₁, [τ¹]₁, [τ²]₁, …, [τ²ᴺ⁻²]₁
	fmt.Println("1. Writing TauG1")
	for i := 0; i < 2*N-1; i++ {
		enc.Encode(&g1)
	}

	// Write α[τ⁰]₁, α[τ¹]₁, α[τ²]₁, …, α[τᴺ⁻¹]₁
	fmt.Println("2. Writing AlphaTauG1")
	for i := 0; i < N; i++ {
		enc.Encode(&g1)
	}

	// Write β[τ⁰]₁, β[τ¹]₁, β[τ²]₁, …, β[τᴺ⁻¹]₁
	fmt.Println("3. Writing BetaTauG1")
	for i := 0; i < N; i++ {
		enc.Encode(&g1)
	}

	// Write {[τ⁰]₂, [τ¹]₂, [τ²]₂, …, [τᴺ⁻¹]₂}
	fmt.Println("4. Writing TauG2")
	for i := 0; i < N; i++ {
		enc.Encode(&g2)
	}

	// Write [β]₂
	fmt.Println("5. Writing BetaG2")
	enc.Encode(&g2)

	fmt.Println("Initialization has been completed successfully")
	return nil
}

func ContributePhaseOne(inputPath, outputPath string) error {
	// Set buffer size to 4GB
	buffSize := int(math.Pow(2, 32))

	// Input file
	inputFile, err := os.Open(inputPath)
	if err != nil {
		return err
	}
	defer inputFile.Close()
	reader := bufio.NewReaderSize(inputFile, buffSize)
	dec := bn254.NewDecoder(reader)

	// Output file
	outputFile, err := os.Create(outputPath)
	if err != nil {
		return err
	}
	defer outputFile.Close()
	writer := bufio.NewWriterSize(outputFile, buffSize)
	defer writer.Flush()
	enc := bn254.NewEncoder(writer, bn254.RawEncoding())

	// Read/Write power
	power, err := reader.ReadByte()
	if err != nil {
		return err
	}
	fmt.Println("Power := ", power)
	writer.WriteByte(power)

	// Read/Write nContributions+1
	nContributions, err := reader.ReadByte()
	if err != nil {
		return err
	}
	fmt.Println("nContributions := ", nContributions)
	writer.WriteByte(nContributions + 1)

	N := int(math.Pow(2, float64(power)))

	// Sample toxic parameters
	fmt.Println("Sampling toxic parameters Tau, Alpha, and Beta")
	var tau, alpha, beta, one fr.Element
	tau.SetRandom()
	alpha.SetRandom()
	beta.SetRandom()
	one.SetOne()

	var contribution Phase1Contribution

	var firstG1 *bn254.G1Affine
	var firstG2 *bn254.G2Affine

	// Process Tau section
	fmt.Println("Processing TauG1")
	if firstG1, err = processSectionG1(dec, enc, 2*N-1, &tau, &one); err != nil {
		return err
	}
	contribution.G1.Tau.Set(firstG1)

	// Process AlphaTauG1 section
	fmt.Println("Processing AlphaTauG1")
	if firstG1, err = processSectionG1(dec, enc, N, &tau, &alpha); err != nil {
		return err
	}
	contribution.G1.AlphaTau.Set(firstG1)

	// Process BetaTauG1 section
	fmt.Println("Processing BetaTauG1")
	if firstG1, err = processSectionG1(dec, enc, N, &tau, &beta); err != nil {
		return err
	}
	contribution.G1.BetaTau.Set(firstG1)

	// Process TauG2 section
	fmt.Println("Processing TauG2")
	if firstG2, err = processSectionG2(dec, enc, N, &tau, &one); err != nil {
		return err
	}
	contribution.G2.Tau.Set(firstG2)

	// Process BetaG2 section
	fmt.Println("Processing BetaG2")
	if firstG2, err = processSectionG2(dec, enc, 1, &one, &beta); err != nil {
		return err
	}
	contribution.G2.Beta.Set(firstG2)

	// Copy old contributions
	var c Phase1Contribution
	for i := 0; i < int(nContributions); i++ {
		if _, err := c.readFrom(reader); err != nil {
			return err
		}
		if _, err := c.writeTo(writer); err != nil {
			return err
		}
	}

	// Get hash of previous contribution
	var prevHash []byte
	if nContributions == 0 {
		prevHash = nil
	} else {
		prevHash = c.Hash
	}

	// Generate public keys
	contribution.PublicKeys.Tau = genPublicKey(tau, prevHash, 1)
	contribution.PublicKeys.Alpha = genPublicKey(alpha, prevHash, 2)
	contribution.PublicKeys.Beta = genPublicKey(beta, prevHash, 3)
	contribution.Hash = computeHash(&contribution)

	// Write the contribution
	contribution.writeTo(writer)

	fmt.Println("Contirbution has been successful!")
	fmt.Println("Contribution Hash := ", hex.EncodeToString(contribution.Hash))

	return nil
}

func VerifyPhaseOne(inputPath string) error {
	// Input file
	inputFile, err := os.Open(inputPath)
	if err != nil {
		return err
	}
	defer inputFile.Close()
	reader := bufio.NewReader(inputFile)

	// Read/Write power
	power, err := reader.ReadByte()
	if err != nil {
		return err
	}
	fmt.Println("Power := ", power)

	// Read/Write nContributions+1
	nContributions, err := reader.ReadByte()
	if err != nil {
		return err
	}
	fmt.Println("nContributions := ", nContributions)
	N := int(math.Pow(2, float64(power)))

	pos := 384*N + 64
	inputFile.Seek(int64(pos), 1)
	reader.Reset(inputFile)
	var current Phase1Contribution
	prev := defaultPhase1Contribution()
	for i := 0; i < int(nContributions); i++ {
		current.readFrom(reader)
		fmt.Println("Verifying contribution ", i+1)
		if err := verifyPhase1Contribution(current, prev); err != nil {
			return err
		}
		prev = current
	}
	pos = 2
	inputFile.Seek(int64(pos), 0)
	reader.Reset(inputFile)
	
	// Read and verify TauG1
	fmt.Println("Verifying powers of [τ]₁")
	if err := verifyConsistentPowersG1(reader, 2*N-1, current.G2.Tau); err != nil {
		return err
	}

	// Read and verify AlphaTauG1
	fmt.Println("Verifying powers of [ατ]₁")
	if err := verifyConsistentPowersG1(reader, N, current.G2.Tau); err != nil {
		return err
	}

	// Read and verify BetaTauG1
	fmt.Println("Verifying powers of [βτ]₁")
	if err := verifyConsistentPowersG1(reader, N, current.G2.Tau); err != nil {
		return err
	}

	// Read and verify TauG2
	fmt.Println("Verifying powers of [τ]₂")
	if err := verifyConsistentPowersG2(reader, N, current.G1.Tau); err != nil {
		return err
	}
	fmt.Println("Contributions verification has been successful")
	return nil
}
