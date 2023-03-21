package phase2

import (
	"fmt"
	"io"
	"math"
	"os"

	"github.com/bnbchain/zkbnb-setup/phase1"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/fft"
	cs_bn254 "github.com/consensys/gnark/constraint/bn254"
)

func Initialize(inputPhase1Path, inputR1csPath, outputPhase2Path string) error {
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

	// Read R1CS
	fmt.Println("Reading R1CS...")
	var r1cs cs_bn254.R1CS
	r1cs.ReadFrom(inputR1csFile)

	// Compute the hash of R1CS file
	var header2 Header
	inputR1csFile.Seek(0, 0)
	if header2.R1CSHash, err = hashR1CSFile(inputR1csFile); err != nil {
		return err
	}

	// Read the #Constraints
	header2.Constraints = uint32(r1cs.GetNbConstraints())

	var header1 phase1.Header
	if err := header1.ReadFrom(inputPhase1File); err != nil {
		return err
	}
	// Check if phase 1 power can support the current #Constraints
	N := int(math.Pow(2, float64(header1.Power)))
	if N < r1cs.GetNbConstraints() {
		return fmt.Errorf("phase 1 parameters can support up to %d, but the circuit #Constraints are %d", N, r1cs.GetNbConstraints())
	}

	// Initialize the domain
	domain := fft.NewDomain(uint64(r1cs.GetNbConstraints()))
	header2.Domain = uint32(domain.Cardinality)

	// Initialize #Internal and #Public
	header2.Internal = uint32(r1cs.GetNbInternalVariables())
	header2.Public = uint32(r1cs.GetNbPublicVariables())

	// Read [α]₁ , [β]₁ , [β]₂  from phase1 last contribution (Check Phase 1 file format for reference)
	var pos int64 = 35 + 192*int64(N) + int64((header1.Contributions-1)*640)
	if _, err := inputPhase1File.Seek(pos, io.SeekStart); err != nil {
		return err
	}
	var c1 phase1.Contribution
	if _, err := c1.ReadFrom(inputPhase1File); err != nil {
		return err
	}
	// Set [α]₁ , [β]₁ , [β]₂
	header2.G1.Alpha.Set(&c1.G1.Alpha)
	header2.G1.Beta.Set(&c1.G1.Beta)
	header2.G2.Beta.Set(&c1.G2.Beta)

	// Write header of phase 2
	if err := header2.writeTo(outputPhase2File); err != nil {
		return err
	}
	fmt.Println("Header initialized successfully")

	// Evaluate constraints

	return nil
}

func Contribute(inputPath, outputPath string) error {
	return nil
}

func Verify(inputPath string) error {
	return nil
}
