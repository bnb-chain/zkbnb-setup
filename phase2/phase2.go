package phase2

import (
	"fmt"
	"os"

	"github.com/bnbchain/zkbnb-setup/phase1"
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
	fmt.Printf("Circuit Info, nConstraints:=%d, nInternal:=%d, nPublic:=%d\n", header2.Constraints, header2.Internal, header2.Public)

	// Evaluate constraints
	fmt.Println("Evaluating [A]₁, [B]₁, [B]₂")
	if err := processEvaluations(&r1cs, header1, header2, inputPhase1File, outputPhase2File); err != nil {
		return err
	}
	
	// Evaluate Delta and Z
	fmt.Println("Evaluating Delta and Z")
	if err := processDeltaAndZ(header1, header2, inputPhase1File, outputPhase2File); err != nil {
		return err
	}


	return nil
}



func Contribute(inputPath, outputPath string) error {
	return nil
}

func Verify(inputPath string) error {
	return nil
}
