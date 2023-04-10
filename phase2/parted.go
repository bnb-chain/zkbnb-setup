package phase2

import (
	"bufio"
	"encoding/gob"
	"fmt"
	"github.com/consensys/gnark/constraint"
	"io"
	"math"
	"os"
	"runtime"
	"sync"

	"github.com/bnbchain/zkbnb-setup/phase1"
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
	// E part
	{
		cs2 := &cs_bn254.R1CS{}

		name := fmt.Sprintf("%s.r1cs.E12.save", session)
		if _, err := os.Stat(name); err == nil {
			csFile, err := os.Open(name)
			if err != nil {
				panic(err)
			}
			reader := bufio.NewReader(csFile)
			dec := gob.NewDecoder(reader)
			err = dec.Decode(&cs2.R1CSCore.System.HintFnWiresToIdx)
			if err != nil {
				panic(err)
			}
			cs.R1CSCore.System.HintFnWiresToIdx = cs2.R1CSCore.System.HintFnWiresToIdx
		}
	}
	{
		cs2 := &cs_bn254.R1CS{}

		name := fmt.Sprintf("%s.r1cs.E13.save", session)
		if _, err := os.Stat(name); err == nil {
			csFile, err := os.Open(name)
			if err != nil {
				panic(err)
			}
			reader := bufio.NewReader(csFile)
			dec := gob.NewDecoder(reader)
			err = dec.Decode(&cs2.R1CSCore.System.HintFnInputsToIdx)
			if err != nil {
				panic(err)
			}
			cs.R1CSCore.System.HintFnInputsToIdx = cs2.R1CSCore.System.HintFnInputsToIdx
		}
	}
	{
		cs2 := &cs_bn254.R1CS{}

		name := fmt.Sprintf("%s.r1cs.E14.save", session)
		if _, err := os.Stat(name); err == nil {
			csFile, err := os.Open(name)
			if err != nil {
				panic(err)
			}
			reader := bufio.NewReader(csFile)
			dec := gob.NewDecoder(reader)
			err = dec.Decode(&cs2.R1CSCore.System.IndexedWires)
			if err != nil {
				panic(err)
			}
			cs.R1CSCore.System.IndexedWires = cs2.R1CSCore.System.IndexedWires
		}
	}
	{
		cs2 := &cs_bn254.R1CS{}

		name := fmt.Sprintf("%s.r1cs.E15.save", session)
		if _, err := os.Stat(name); err == nil {
			csFile, err := os.Open(name)
			if err != nil {
				panic(err)
			}
			reader := bufio.NewReader(csFile)
			dec := gob.NewDecoder(reader)
			err = dec.Decode(&cs2.R1CSCore.System.IndexedInputs)
			if err != nil {
				panic(err)
			}
			cs.R1CSCore.System.IndexedInputs = cs2.R1CSCore.System.IndexedInputs
		}
	}
	{
		cs2 := &cs_bn254.R1CS{}

		name := fmt.Sprintf("%s.r1cs.E1.save", session)
		csFile, err := os.Open(name)
		if err != nil {
			panic(err)
		}
		reader := bufio.NewReader(csFile)
		dec := gob.NewDecoder(reader)
		err = dec.Decode(cs2)
		if err != nil {
			panic(err)
		}

		cs.R1CSCore.System.GnarkVersion = cs2.R1CSCore.System.GnarkVersion
		cs.R1CSCore.System.ScalarField = cs2.R1CSCore.System.ScalarField
		cs.R1CSCore.System.NbInternalVariables = cs2.R1CSCore.System.NbInternalVariables
		cs.R1CSCore.System.Public = make([]string, len(cs2.R1CSCore.System.Public)) // for calling nbPub
		cs.R1CSCore.System.Secret = make([]string, len(cs2.R1CSCore.System.Secret)) // for calling nbSecret
		// cs.R1CSCore.System.Logs = cs2.R1CSCore.System.Logs               // Todo
		// cs.R1CSCore.System.DebugInfo = cs2.R1CSCore.System.DebugInfo     // Todo
		// cs.R1CSCore.System.SymbolTable = cs2.R1CSCore.System.SymbolTable // Todo
		// cs.R1CSCore.System.MDebug = cs2.R1CSCore.System.MDebug           // Todo

		cs.R1CSCore.System.NbHintFnWires = cs2.R1CSCore.System.NbHintFnWires
		cs.R1CSCore.System.NbHintFnInputs = cs2.R1CSCore.System.NbHintFnInputs
		cs.R1CSCore.System.MHints = cs2.R1CSCore.System.MHints
		cs.R1CSCore.System.MHintsDependencies = cs2.R1CSCore.System.MHintsDependencies

		cs.R1CSCore.System.CommitmentInfo = cs2.R1CSCore.System.CommitmentInfo
		cs.R1CSCore.System.GKRMeta = cs2.R1CSCore.System.GKRMeta
	}
	{
		cs2 := &cs_bn254.R1CS{}

		name := fmt.Sprintf("%s.r1cs.E2.save", session)
		csFile, err := os.Open(name)
		if err != nil {
			panic(err)
		}
		_, err = cs2.ReadFrom(csFile)
		if err != nil {
			panic(err)
		}
		cs.R1CSCore.LazyCons = cs2.R1CSCore.LazyCons
	}
	{
		cs2 := &cs_bn254.R1CS{}

		name := fmt.Sprintf("%s.r1cs.E3.save", session)
		csFile, err := os.Open(name)
		if err != nil {
			panic(err)
		}
		_, err = cs2.ReadFrom(csFile)
		if err != nil {
			panic(err)
		}
		cs.R1CSCore.LazyConsMap = cs2.R1CSCore.LazyConsMap
	}
	{
		cs2 := &cs_bn254.R1CS{}

		name := fmt.Sprintf("%s.r1cs.E4.save", session)
		csFile, err := os.Open(name)
		if err != nil {
			panic(err)
		}
		_, err = cs2.ReadFrom(csFile)
		if err != nil {
			panic(err)
		}
		cs.CoeffTable = cs2.CoeffTable
		cs.R1CSCore.StaticConstraints = cs2.R1CSCore.StaticConstraints
	}

	// 1. Process Headers
	// TODO: we just need the nbConstraints from r1cs not the whole thing
	header1, header2, err := processHeaderParted(cs, nbCons, phase1File, phase2File)
	if err != nil {
		return err
	}

	// 2. Convert phase 1 SRS to Lagrange basis
	if err := processLagrange(header1, header2, phase1File, phase2File); err != nil {
		return err
	}

	// 3. Evaluate A, B, C
	if err := processEvaluationsParted(cs, session, nbCons, nbR1C, batchSize, header1, header2, phase1File); err != nil {
		return err
	}

	// Evaluate Delta and Z
	if err := processDeltaAndZ(header1, header2, phase1File, phase2File); err != nil {
		return err
	}

	// // Evaluate L
	if err := processLParted(cs, session, nbCons, batchSize, header1, header2, phase2File); err != nil {
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

func processEvaluationsParted(r1cs *cs_bn254.R1CS, r1csPrefix string, nbCons, nbR1C, batchSize int, header1 *phase1.Header, header2 *Header, phase1File *os.File) error {
	fmt.Println("Processing evaluation of [A]₁, [B]₁, [B]₂")

	lagFile, err := os.Open("srs.lag")
	if err != nil {
		return err
	}
	defer lagFile.Close()

	// Restore r1cs.constraint.R1C, suppose r1cs Lazified with small nbR1C
	r1cs.R1CSCore.Constraints = make([]constraint.R1C, nbR1C)
	var wg sync.WaitGroup
	nCore := runtime.NumCPU()
	chTasks := make(chan int, nCore)
	for core := 0; core < nCore; core++ {
		go func() {
			for i := range chTasks {
				cs2 := &cs_bn254.R1CS{}
				iNew := i + batchSize
				if iNew > nbR1C {
					iNew = nbR1C
				}
				name := fmt.Sprintf("%s.r1cs.Cons.%d.%d.save", r1csPrefix, i, iNew)
				csFile, err := os.Open(name)
				if err != nil {
					panic(err)
				}
				reader := bufio.NewReader(csFile)
				dec := gob.NewDecoder(reader)
				err = dec.Decode(cs2)
				if err != nil {
					panic(err)
				}
				copy(r1cs.R1CSCore.Constraints[i:iNew], cs2.R1CSCore.Constraints)

				wg.Done()
			}
		}()
	}

	evalFile, err := os.Create("evals")
	if err != nil {
		return err
	}
	defer evalFile.Close()

	// Read [α]₁ , [β]₁ , [β]₂  from phase1 last contribution (Check Phase 1 file format for reference)
	N := int(math.Pow(2, float64(header1.Power)))
	pos := 67 + 384*int64(N) + int64((header1.Contributions-1)*phase1.ContributionSize)
	if _, err := phase1File.Seek(pos, io.SeekStart); err != nil {
		return err
	}
	var c1 phase1.Contribution
	if _, err := c1.ReadFrom(phase1File); err != nil {
		return err
	}

	// Write [α]₁ , [β]₁ , [β]₂
	enc := bn254.NewEncoder(evalFile, bn254.RawEncoding())
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
	for i := 0; i < nbCons; i++ {
		c := r1cs.GetConstraintToSolve(i)
		for _, t := range c.L {
			accumulateG1(r1cs, &buff[t.WireID()], t, &tauG1[i])
		}
	}
	if err := enc.Encode(buff); err != nil {
		return err
	}

	// Reset buff
	buff = make([]bn254.G1Affine, nWires)
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
	buff2 := make([]bn254.G2Affine, nWires)

	// Seek to Lagrange SRS TauG2 by skipping AlphaTau and BetaTau
	pos = 2*64*int64(header2.Domain) + 2*4
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
	for i := 0; i < nbCons; i++ {
		c := r1cs.GetConstraintToSolve(i)
		// Output(Tau)
		for _, t := range c.O {
			accumulateG1(r1cs, &L[t.WireID()], t, &TauG1[i])
		}
	}
	// Deserialize Lagrange SRS AlphaTauG1
	if err := dec.Decode(&AlphaTauG1); err != nil {
		return err
	}
	for i := 0; i < nbCons; i++ {
		c := r1cs.GetConstraintToSolve(i)
		// Right(AlphaTauG1)
		for _, t := range c.R {
			accumulateG1(r1cs, &L[t.WireID()], t, &AlphaTauG1[i])
		}
	}
	// Deserialize Lagrange SRS BetaTauG1
	if err := dec.Decode(&BetaTauG1); err != nil {
		return err
	}
	for i := 0; i < nbCons; i++ {
		c := r1cs.GetConstraintToSolve(i)
		// Left(BetaTauG1)
		for _, t := range c.L {
			accumulateG1(r1cs, &L[t.WireID()], t, &BetaTauG1[i])
		}
	}

	// Write L
	for i := 0; i < len(L); i++ {
		if err := enc.Encode(&L[i]); err != nil {
			return err
		}
	}
	return nil
}
