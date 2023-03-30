package phase2

import (
	"bufio"
	"encoding/gob"
	"fmt"
	"io"
	"math"
	"os"

	"github.com/bnbchain/zkbnb-setup/phase1"
	"github.com/consensys/gnark-crypto/ecc/bn254"
	cs_bn254 "github.com/consensys/gnark/constraint/bn254"
)

func InitializeFromPartedR1CS(phase1Path, r1csPrefix, phase2Path string, nbCons, batchSize int) error {
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
	var r1cs cs_bn254.R1CS
	{
		name := fmt.Sprintf("%s.r1cs.E.save", r1csPrefix)
		r1csDump, err := os.Open(name)
		if err != nil {
			return err
		}
		_, err = r1cs.ReadFrom(r1csDump)
		if err != nil {
			return err
		}
	}

	// 1. Process Headers
	// TODO: we just need the nbConstraints from r1cs not the whole thing
	header1, header2, err := processHeaderParted(&r1cs, nbCons, phase1File, phase2File)
	if err != nil {
		return err
	}

	// 2. Convert phase 1 SRS to Lagrange basis
	if err := processLagrange(header1, header2, phase1File, phase2File); err != nil {
		return err
	}

	// 3. Evaluate A, B, C
	if err := processEvaluationsParted(&r1cs, r1csPrefix, nbCons, batchSize, header1, header2, phase1File); err != nil {
		return err
	}

	// Evaluate Delta and Z
	if err := processDeltaAndZ(header1, header2, phase1File, phase2File); err != nil {
		return err
	}

	// // Evaluate L
	if err := processLParted(&r1cs, r1csPrefix, nbCons, batchSize, header1, header2, phase2File); err != nil {
		return err
	}

	fmt.Println("Phase 2 has been initialized successfully")
	return nil
}

// processHeaderParted r1cs has no R1CCore.Constraints included
func processHeaderParted(r1cs *cs_bn254.R1CS, nbCons int, phase1File, phase2File *os.File) (*phase1.Header, *Header, error) {
	var header2 Header
	var header1 phase1.Header

	// Read the #Constraints
	header2.Constraints = uint32(nbCons)

	// Check if phase 1 power can support the current #Constraints
	if err := header1.ReadFrom(phase1File); err != nil {
		return nil, nil, err
	}
	N := int(math.Pow(2, float64(header1.Power)))
	if N < nbCons {
		return nil, nil, fmt.Errorf("phase 1 parameters can support up to %d, but the circuit #Constraints are %d", N, r1cs.GetNbConstraints())
	}

	nextPowerofTwo := func(number int) int {
		res := 2
		for i := 1; i < 28; i++ { // max power is 28
			if res >= number {
				return res
			} else {
				res *= 2
			}
		}
		// Shouldn't happen
		panic("the power is beyond 28")
	}
	// Initialize Domain, #Witness and #Public
	header2.Domain = uint32(nextPowerofTwo(nbCons))
	header2.Witness = uint32(r1cs.GetNbInternalVariables() + r1cs.GetNbSecretVariables())
	header2.Public = uint32(r1cs.GetNbPublicVariables())

	// Write header of phase 2
	if err := header2.writeTo(phase2File); err != nil {
		return nil, nil, err
	}

	return &header1, &header2, nil
}

func processEvaluationsParted(r1cs *cs_bn254.R1CS, r1csPrefix string, nbCons, batchSize int, header1 *phase1.Header, header2 *Header, phase1File *os.File) error {
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
	pos := 35 + 192*int64(N) + int64((header1.Contributions-1)*640)
	if _, err := phase1File.Seek(pos, io.SeekStart); err != nil {
		return err
	}
	var c1 phase1.Contribution
	if _, err := c1.ReadFrom(phase1File); err != nil {
		return err
	}

	// Write [α]₁ , [β]₁ , [β]₂
	enc := bn254.NewEncoder(evalFile)
	dec := bn254.NewDecoder(lagFile)
	if err := enc.Encode(&c1.G1.Alpha); err != nil {
		return err
	}
	if err := enc.Encode(&c1.G1.Beta); err != nil {
		return err
	}
	if err := enc.Encode(&c1.G2.Beta); err != nil {
		return err
	}

	nWires := header2.Witness + header2.Public
	var tauG1 []bn254.G1Affine

	// Deserialize Lagrange SRS TauG1
	if err := dec.Decode(&tauG1); err != nil {
		return err
	}

	// Accumlate {[A]₁}
	buff := make([]bn254.G1Affine, nWires)
	for i := 0; i < nbCons; {
		fmt.Println("processing", i, "/", nbCons)
		// read R1C[i, min(i+batchSize, end)]
		ccs2 := &cs_bn254.R1CS{}
		iNew := i + batchSize
		if iNew > nbCons {
			iNew = nbCons
		}
		name := fmt.Sprintf("%s.r1cs.Cons.%d.%d.save", r1csPrefix, i, iNew)
		csFile, err := os.Open(name)
		if err != nil {
			return err
		}
		reader := bufio.NewReader(csFile)
		enc := gob.NewDecoder(reader)
		err = enc.Decode(ccs2)
		if err != nil {
			return err
		}
		for j, c := range ccs2.R1CSCore.Constraints {
			for _, t := range c.L {
				accumulateG1(r1cs, &buff[t.WireID()], t, &tauG1[j+i])
			}
		}

		i = iNew
	}
	// Serialize {[A]₁}
	if err := enc.Encode(buff); err != nil {
		return err
	}

	// Reset buff
	buff = make([]bn254.G1Affine, nWires)
	// Accumlate {[B]₁}
	for i := 0; i < nbCons; {
		fmt.Println("processing", i, "/", nbCons)
		// read R1C[i, min(i+batchSize, end)]
		ccs2 := &cs_bn254.R1CS{}
		iNew := i + batchSize
		if iNew > nbCons {
			iNew = nbCons
		}
		name := fmt.Sprintf("%s.r1cs.Cons.%d.%d.save", r1csPrefix, i, iNew)
		csFile, err := os.Open(name)
		if err != nil {
			return err
		}
		reader := bufio.NewReader(csFile)
		enc := gob.NewDecoder(reader)
		err = enc.Decode(ccs2)
		if err != nil {
			return err
		}
		for j, c := range ccs2.R1CSCore.Constraints {
			for _, t := range c.R {
				accumulateG1(r1cs, &buff[t.WireID()], t, &tauG1[j+i])
			}
		}

		i = iNew
	}
	// Serialize {[B]₁}
	if err := enc.Encode(buff); err != nil {
		return err
	}

	var tauG2 []bn254.G2Affine
	buff2 := make([]bn254.G2Affine, nWires)

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
	for i := 0; i < nbCons; {
		fmt.Println("processing", i, "/", nbCons)
		// read R1C[i, min(i+batchSize, end)]
		ccs2 := &cs_bn254.R1CS{}
		iNew := i + batchSize
		if iNew > nbCons {
			iNew = nbCons
		}
		name := fmt.Sprintf("%s.r1cs.Cons.%d.%d.save", r1csPrefix, i, iNew)
		csFile, err := os.Open(name)
		if err != nil {
			return err
		}
		reader := bufio.NewReader(csFile)
		enc := gob.NewDecoder(reader)
		err = enc.Decode(ccs2)
		if err != nil {
			return err
		}
		for j, c := range ccs2.R1CSCore.Constraints {
			for _, t := range c.R {
				accumulateG2(r1cs, &buff2[t.WireID()], t, &tauG2[j+i])
			}
		}

		i = iNew
	}
	// Serialize {[B]₂}
	if err := enc.Encode(buff2); err != nil {
		return err
	}

	return nil
}


func processLParted(r1cs *cs_bn254.R1CS, r1csPrefix string, nbCons, batchSize int, header1 *phase1.Header, header2 *Header, phase2File *os.File) error {
	fmt.Println("Processing L")
	lagFile, err := os.Open("srs.lag")
	if err != nil {
		return err
	}
	defer lagFile.Close()

	nWires := header2.Witness + header2.Public
	var TauG1, AlphaTauG1, BetaTauG1 []bn254.G1Affine

	reader := bufio.NewReader(lagFile)
	writer := bufio.NewWriter(phase2File)
	defer writer.Flush()
	dec := bn254.NewDecoder(reader)
	enc := bn254.NewEncoder(writer)

	// L =  Output(TauG1) + Right(AlphaTauG1) + Left(BetaTauG1)
	L := make([]bn254.G1Affine, nWires)

	// Deserialize Lagrange SRS TauG1
	if err := dec.Decode(&TauG1); err != nil {
		return err
	}
	// Deserialize Lagrange SRS AlphaTauG1
	if err := dec.Decode(&AlphaTauG1); err != nil {
		return err
	}
	// Deserialize Lagrange SRS BetaTauG1
	if err := dec.Decode(&BetaTauG1); err != nil {
		return err
	}

	for i := 0; i < nbCons; {
		fmt.Println("processing", i, "/", nbCons)
		// read R1C[i, min(i+batchSize, end)]
		ccs2 := &cs_bn254.R1CS{}
		iNew := i + batchSize
		if iNew > nbCons {
			iNew = nbCons
		}
		name := fmt.Sprintf("%s.r1cs.Cons.%d.%d.save", r1csPrefix, i, iNew)
		csFile, err := os.Open(name)
		if err != nil {
			return err
		}
		reader := bufio.NewReader(csFile)
		enc := gob.NewDecoder(reader)
		err = enc.Decode(ccs2)
		if err != nil {
			return err
		}
		for j, c := range ccs2.R1CSCore.Constraints {
			// Output(Tau)
			for _, t := range c.O {
				accumulateG1(r1cs, &L[t.WireID()], t, &TauG1[j+i])
			}
			// Right(AlphaTauG1)
			for _, t := range c.R {
				accumulateG1(r1cs, &L[t.WireID()], t, &AlphaTauG1[j+i])
			}
			// Left(BetaTauG1)
			for _, t := range c.L {
				accumulateG1(r1cs, &L[t.WireID()], t, &BetaTauG1[j+i])
			}
		}

		i = iNew
	}

	// Write L
	for i := 0; i < len(L); i++ {
		if err := enc.Encode(&L[i]); err != nil {
			return err
		}
	}
	return nil
}