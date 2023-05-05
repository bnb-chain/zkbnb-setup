package phase2

import (
	"bufio"
	"encoding/gob"
	"fmt"
	"io"
	"math"
	"os"
	"runtime"

	"github.com/bnb-chain/zkbnb-setup/phase1"
	"github.com/consensys/gnark-crypto/ecc/bn254"
	cs_bn254 "github.com/consensys/gnark/constraint/bn254"
)

func InitializeFromPartedR1CS(phase1Path, session, phase2Path string, nbCons, nbR1C, batchSize int) error {
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

	// Read R1CS
	fmt.Println("Reading R1CS...")
	cs := &cs_bn254.R1CS{}
	// support nbR1C is small
	cs.LoadFromSplitBinaryConcurrent(session, nbR1C, batchSize, runtime.NumCPU())

	// 1. Process Headers
	header1, header2, err := processHeaderParted(cs, nbCons, phase1File, phase2File)
	if err != nil {
		return err
	}

	// 2. Convert phase 1 SRS to Lagrange basis
	if err := processLagrange(header1, header2, phase1File, phase2File); err != nil {
		return err
	}

	// 3. Process evaluation
	if err := processEvaluationsParted(cs, session, nbCons, nbR1C, batchSize, header1, header2, phase1File); err != nil {
		return err
	}

	// Evaluate Delta and Z
	if err := processDeltaAndZ(header1, header2, phase1File, phase2File); err != nil {
		return err
	}

	// Process parameters
	if err := processPVCKKParted(cs, session, nbCons, batchSize, header1, header2, phase2File); err != nil {
		return err
	}

	fmt.Println("Phase 2 has been initialized successfully")
	return nil
}

// processHeaderParted r1cs has no R1CCore.Constraints included
func processHeaderParted(r1cs *cs_bn254.R1CS, nbCons int, phase1File, phase2File *os.File) (*phase1.Header, *Header, error) {
	fmt.Println("Processing the headers ...")

	var header2 Header
	var header1 phase1.Header

	header2.Constraints = nbCons
	header2.Domain = nextPowerofTwo(header2.Constraints)

	// Check if phase 1 power can support the current #Constraints
	if err := header1.ReadFrom(phase1File); err != nil {
		return nil, nil, err
	}
	N := int(math.Pow(2, float64(header1.Power)))
	if N < header2.Constraints {
		return nil, nil, fmt.Errorf("phase 1 parameters can support up to %d, but the circuit #Constraints are %d", N, header2.Constraints)
	}

	// Initialize Domain, #Wires, #Witness, #Public, #PrivateCommitted
	header2.Wires = r1cs.NbInternalVariables + r1cs.GetNbPublicVariables() + r1cs.GetNbSecretVariables()
	header2.PrivateCommitted = r1cs.CommitmentInfo.NbPrivateCommitted
	header2.Public = r1cs.GetNbPublicVariables()
	header2.Witness = r1cs.GetNbSecretVariables() + r1cs.NbInternalVariables - header2.PrivateCommitted

	if r1cs.CommitmentInfo.Is() { // the commitment itself is defined by a hint so the prover considers it private
		header2.Public++  // but the verifier will need to inject the value itself so on the groth16
		header2.Witness-- // level it must be considered public
	}

	// Write header of phase 2
	if err := header2.write(phase2File); err != nil {
		return nil, nil, err
	}

	fmt.Printf("Circuit Info: #Constraints:=%d\n#Wires:=%d\n#Public:=%d\n#Witness:=%d\n#PrivateCommitted:=%d\n",
		header2.Constraints, header2.Wires, header2.Public, header2.Witness, header2.PrivateCommitted)
	return &header1, &header2, nil
}

func processEvaluationsParted(r1cs *cs_bn254.R1CS, r1csPrefix string, nbCons, nbR1C, batchSize int, header1 *phase1.Header, header2 *Header, phase1File *os.File) error {
	fmt.Println("Processing evaluation of [A]₁, [B]₁, [B]₂")

	lagFile, err := os.Open("srs.lag")
	if err != nil {
		return err
	}
	defer lagFile.Close()

	evalFile, err := os.Create("evals")
	if err != nil {
		return err
	}
	defer evalFile.Close()

	// Read [α]₁ , [β]₁ , [β]₂  from phase1 last contribution (Check Phase 1 file format for reference)
	N := int(math.Pow(2, float64(header1.Power)))
	pos := 35 + 192*int64(N) + int64((header1.Contributions-1)*phase1.ContributionSize)
	if _, err := phase1File.Seek(pos, io.SeekStart); err != nil {
		return err
	}
	var c1 phase1.Contribution
	if _, err := c1.ReadFrom(phase1File); err != nil {
		return err
	}

	// Write [α]₁ , [β]₁ , [β]₂
	enc := bn254.NewEncoder(evalFile)
	if err := enc.Encode(&c1.G1.Alpha); err != nil {
		return err
	}
	if err := enc.Encode(&c1.G1.Beta); err != nil {
		return err
	}
	if err := enc.Encode(&c1.G2.Beta); err != nil {
		return err
	}

	var tauG1 []bn254.G1Affine

	// Deserialize Lagrange SRS TauG1
	dec := bn254.NewDecoder(lagFile)
	if err := dec.Decode(&tauG1); err != nil {
		return err
	}

	// Accumlate {[A]₁}
	buff := make([]bn254.G1Affine, header2.Wires)
	for i := 0; i < nbCons; i++ {
		c := r1cs.GetConstraintToSolve(i)
		for _, t := range c.L {
			accumulateG1(r1cs, &buff[t.WireID()], t, &tauG1[i])
		}
	}
	// Serialize {[A]₁}
	if err := enc.Encode(buff); err != nil {
		return err
	}

	// Reset buff
	buff = make([]bn254.G1Affine, header2.Wires)
	// Accumlate {[B]₁}
	for i := 0; i < nbCons; i++ {
		c := r1cs.GetConstraintToSolve(i)
		for _, t := range c.R {
			accumulateG1(r1cs, &buff[t.WireID()], t, &tauG1[i])
		}
	}
	// Serialize {[B]₁}
	if err := enc.Encode(buff); err != nil {
		return err
	}

	var tauG2 []bn254.G2Affine
	buff2 := make([]bn254.G2Affine, header2.Wires)

	// Seek to Lagrange SRS TauG2 by skipping AlphaTau and BetaTau
	pos = 2*32*int64(header2.Domain) + 2*4
	if _, err := lagFile.Seek(pos, io.SeekCurrent); err != nil {
		return err
	}

	// Deserialize Lagrange SRS TauG2
	if err := dec.Decode(&tauG2); err != nil {
		return err
	}
	// Accumlate {[B]₂}
	for i := 0; i < nbCons; i++ {
		c := r1cs.GetConstraintToSolve(i)
		for _, t := range c.R {
			accumulateG2(r1cs, &buff2[t.WireID()], t, &tauG2[i])
		}
	}
	// Serialize {[B]₂}
	if err := enc.Encode(buff2); err != nil {
		return err
	}

	return nil
}

func processPVCKKParted(r1cs *cs_bn254.R1CS, r1csPrefix string, nbCons, batchSize int, header1 *phase1.Header, header2 *Header, phase2File *os.File) error {
	fmt.Println("Processing PKK, VKK, and CKK")
	lagFile, err := os.Open("srs.lag")
	if err != nil {
		return err
	}
	defer lagFile.Close()

	var buffSRS []bn254.G1Affine
	reader := bufio.NewReader(lagFile)
	writer := bufio.NewWriter(phase2File)
	defer writer.Flush()
	dec := bn254.NewDecoder(reader)
	enc := bn254.NewEncoder(writer)

	// L = O(TauG1) + R(AlphaTauG1) + L(BetaTauG1)
	L := make([]bn254.G1Affine, header2.Wires)

	// Deserialize Lagrange SRS TauG1
	if err := dec.Decode(&buffSRS); err != nil {
		return err
	}

	for i := 0; i < nbCons; i++ {
		c := r1cs.GetConstraintToSolve(i)
		// Output(Tau)
		for _, t := range c.O {
			accumulateG1(r1cs, &L[t.WireID()], t, &buffSRS[i])
		}
	}

	// Deserialize Lagrange SRS AlphaTauG1
	if err := dec.Decode(&buffSRS); err != nil {
		return err
	}
	for i := 0; i < nbCons; i++ {
		c := r1cs.GetConstraintToSolve(i)
		// Right(AlphaTauG1)
		for _, t := range c.R {
			accumulateG1(r1cs, &L[t.WireID()], t, &buffSRS[i])
		}
	}

	// Deserialize Lagrange SRS BetaTauG1
	if err := dec.Decode(&buffSRS); err != nil {
		return err
	}
	for i := 0; i < nbCons; i++ {
		c := r1cs.GetConstraintToSolve(i)
		// Left(BetaTauG1)
		for _, t := range c.L {
			accumulateG1(r1cs, &L[t.WireID()], t, &buffSRS[i])
		}
	}

	pkk, vkk, ckk := filterL(L, header2, &r1cs.CommitmentInfo)
	// Write PKK
	for i := 0; i < len(pkk); i++ {
		if err := enc.Encode(&pkk[i]); err != nil {
			return err
		}
	}

	// VKK
	evalFile, err := os.OpenFile("evals", os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer evalFile.Close()
	evalWriter := bufio.NewWriter(evalFile)
	defer evalWriter.Flush()
	evalEnc := bn254.NewEncoder(evalWriter)
	if err := evalEnc.Encode(vkk); err != nil {
		return err
	}

	// Write CKK
	if err := evalEnc.Encode(ckk); err != nil {
		return err
	}

	// Write CommitmentInfo
	cmtEnc := gob.NewEncoder(evalWriter)
	if err := cmtEnc.Encode(r1cs.CommitmentInfo); err != nil {
		return err
	}

	return nil
}
