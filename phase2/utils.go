package phase2

import (
	"bufio"
	"bytes"
	"encoding/gob"
	"errors"
	"fmt"
	"io"
	"math"
	"math/big"
	"os"

	"github.com/bnbchain/zkbnb-setup/common"
	"github.com/bnbchain/zkbnb-setup/phase1"
	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark/constraint"
	cs_bn254 "github.com/consensys/gnark/constraint/bn254"
)

func processHeader(r1cs *cs_bn254.R1CS, inputPhase1File, outputPhase2File *os.File) (*phase1.Header, *Header, error) {
	var header2 Header
	var header1 phase1.Header

	// Read the #Constraints
	header2.Constraints = uint32(r1cs.GetNbConstraints())

	// Check if phase 1 power can support the current #Constraints
	if err := header1.ReadFrom(inputPhase1File); err != nil {
		return nil, nil, err
	}
	N := int(math.Pow(2, float64(header1.Power)))
	if N < r1cs.GetNbConstraints() {
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
	header2.Domain = uint32(nextPowerofTwo(r1cs.GetNbConstraints()))
	header2.Witness = uint32(r1cs.GetNbInternalVariables() + r1cs.GetNbSecretVariables())
	header2.Public = uint32(r1cs.GetNbPublicVariables())

	// Write header of phase 2
	if err := header2.writeTo(outputPhase2File); err != nil {
		return nil, nil, err
	}

	return &header1, &header2, nil
}

// processHeader2 r1cs has no R1CCore.Constraints included
func processHeader2(r1cs *cs_bn254.R1CS, nbCons int, inputPhase1File, outputPhase2File *os.File) (*phase1.Header, *Header, error) {
	var header2 Header
	var header1 phase1.Header

	// Read the #Constraints
	header2.Constraints = uint32(nbCons)

	// Check if phase 1 power can support the current #Constraints
	if err := header1.ReadFrom(inputPhase1File); err != nil {
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
	if err := header2.writeTo(outputPhase2File); err != nil {
		return nil, nil, err
	}

	return &header1, &header2, nil
}

func processEvaluations(r1cs *cs_bn254.R1CS, header1 *phase1.Header, header2 *Header, inputPhase1File *os.File, outputEvalsFile *os.File) error {
	// Read [α]₁ , [β]₁ , [β]₂  from phase1 last contribution (Check Phase 1 file format for reference)
	N := int(math.Pow(2, float64(header1.Power)))
	pos := 35 + 192*int64(N) + int64((header1.Contributions-1)*640)
	if _, err := inputPhase1File.Seek(pos, io.SeekStart); err != nil {
		return err
	}
	var c1 phase1.Contribution
	if _, err := c1.ReadFrom(inputPhase1File); err != nil {
		return err
	}

	dec := bn254.NewDecoder(inputPhase1File)
	enc := bn254.NewEncoder(outputEvalsFile)

	// Write [α]₁ , [β]₁ , [β]₂
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
	tauG1 := make([]bn254.G1Affine, N)

	// Deserialize Lagrange SRS TauG1
	if err := dec.Decode(&tauG1); err != nil {
		return err
	}

	// Accumlate {[A]₁}
	buff := make([]bn254.G1Affine, nWires)
	for i, c := range r1cs.Constraints {
		for _, t := range c.L {
			accumulateG1(r1cs, &buff[t.WireID()], t, &tauG1[i])
		}
	}
	// Serialize {[A]₁}
	if err := enc.Encode(buff); err != nil {
		return err
	}

	// Reset buff
	buff = make([]bn254.G1Affine, nWires)
	// Accumlate {[B]₁}
	for i, c := range r1cs.Constraints {
		for _, t := range c.R {
			accumulateG1(r1cs, &buff[t.WireID()], t, &tauG1[i])
		}
	}
	// Serialize {[B]₁}
	if err := enc.Encode(buff); err != nil {
		return err
	}

	tauG2 := make([]bn254.G2Affine, N)
	buff2 := make([]bn254.G2Affine, nWires)

	// Seek to Lagrange SRS TauG2 by skipping AlphaTau and BetaTau
	pos = 2*32*int64(N) + 2*4
	if _, err := inputPhase1File.Seek(pos, io.SeekCurrent); err != nil {
		return err
	}

	// Deserialize Lagrange SRS TauG2
	if err := dec.Decode(&tauG2); err != nil {
		return err
	}
	// Accumlate {[B]₂}
	for i, c := range r1cs.Constraints {
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

func processEvaluations2(r1cs *cs_bn254.R1CS, r1csPrefix string, nbCons, batchSize int, header1 *phase1.Header, header2 *Header, inputPhase1File *os.File, outputEvalsFile *os.File) error {
	// Read [α]₁ , [β]₁ , [β]₂  from phase1 last contribution (Check Phase 1 file format for reference)
	N := int(math.Pow(2, float64(header1.Power)))
	pos := 35 + 192*int64(N) + int64((header1.Contributions-1)*640)
	if _, err := inputPhase1File.Seek(pos, io.SeekStart); err != nil {
		return err
	}
	var c1 phase1.Contribution
	if _, err := c1.ReadFrom(inputPhase1File); err != nil {
		return err
	}

	dec := bn254.NewDecoder(inputPhase1File)
	enc := bn254.NewEncoder(outputEvalsFile)

	// Write [α]₁ , [β]₁ , [β]₂
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
	tauG1 := make([]bn254.G1Affine, N)

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

	tauG2 := make([]bn254.G2Affine, N)
	buff2 := make([]bn254.G2Affine, nWires)

	// Seek to Lagrange SRS TauG2 by skipping AlphaTau and BetaTau
	pos = 2*32*int64(N) + 2*4
	if _, err := inputPhase1File.Seek(pos, io.SeekCurrent); err != nil {
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

func processL(r1cs *cs_bn254.R1CS, header1 *phase1.Header, header2 *Header, inputPhase1File *os.File, outputPhase2File *os.File) error {
	N := int(math.Pow(2, float64(header1.Power)))
	// Seek Lagrange SRS TauG1
	var pos int64 = 3 + 192*int64(N) + 32 + int64((header1.Contributions)*640)
	if _, err := inputPhase1File.Seek(pos, io.SeekStart); err != nil {
		return err
	}
	nWires := header2.Witness + header2.Public
	buffSRS := make([]bn254.G1Affine, N)

	buffSize := int(math.Pow(2, 20))
	reader := bufio.NewReaderSize(inputPhase1File, buffSize)
	writer := bufio.NewWriterSize(outputPhase2File, buffSize)
	defer writer.Flush()
	dec := bn254.NewDecoder(reader)
	enc := bn254.NewEncoder(writer)

	// L =  Output(TauG1) + Right(AlphaTauG1) + Left(BetaTauG1)
	L := make([]bn254.G1Affine, nWires)

	// Deserialize Lagrange SRS TauG1
	if err := dec.Decode(&buffSRS); err != nil {
		return err
	}
	for i, c := range r1cs.Constraints {
		// Output(Tau)
		for _, t := range c.O {
			accumulateG1(r1cs, &L[t.WireID()], t, &buffSRS[i])
		}
	}

	// Deserialize Lagrange SRS AlphaTauG1
	if err := dec.Decode(&buffSRS); err != nil {
		return err
	}
	for i, c := range r1cs.Constraints {
		// Right(AlphaTauG1)
		for _, t := range c.R {
			accumulateG1(r1cs, &L[t.WireID()], t, &buffSRS[i])
		}
	}

	// Deserialize Lagrange SRS BetaTauG1
	if err := dec.Decode(&buffSRS); err != nil {
		return err
	}
	for i, c := range r1cs.Constraints {
		// Left(BetaTauG1)
		for _, t := range c.L {
			accumulateG1(r1cs, &L[t.WireID()], t, &buffSRS[i])
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

func processL2(r1cs *cs_bn254.R1CS, r1csPrefix string, nbCons, batchSize int, header1 *phase1.Header, header2 *Header, inputPhase1File *os.File, outputPhase2File *os.File) error {
	N := int(math.Pow(2, float64(header1.Power)))
	// Seek Lagrange SRS TauG1
	var pos int64 = 3 + 192*int64(N) + 32 + int64((header1.Contributions)*640)
	if _, err := inputPhase1File.Seek(pos, io.SeekStart); err != nil {
		return err
	}
	nWires := header2.Witness + header2.Public
	TauG1 := make([]bn254.G1Affine, N)
	AlphaTauG1 := make([]bn254.G1Affine, N)
	BetaTauG1 := make([]bn254.G1Affine, N)

	buffSize := int(math.Pow(2, 20))
	reader := bufio.NewReaderSize(inputPhase1File, buffSize)
	writer := bufio.NewWriterSize(outputPhase2File, buffSize)
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
func processDeltaAndZ(header1 *phase1.Header, header2 *Header, inputPhase1File, outputPhase2File *os.File) error {
	buffSize := int(math.Pow(2, 20))
	reader := bufio.NewReaderSize(inputPhase1File, buffSize)
	writer := bufio.NewWriterSize(outputPhase2File, buffSize)
	defer writer.Flush()
	dec := bn254.NewDecoder(reader)
	enc := bn254.NewEncoder(writer)

	// Write [δ]₁ and [δ]₂
	_, _, g1, g2 := bn254.Generators()
	if err := enc.Encode(&g1); err != nil {
		return err
	}
	if err := enc.Encode(&g2); err != nil {
		return err
	}

	// Seek to TauG1
	var pos int64 = 3
	if _, err := inputPhase1File.Seek(pos, io.SeekStart); err != nil {
		return err
	}
	reader.Reset(inputPhase1File)
	N := int(math.Pow(2, float64(header1.Power)))
	tauG1 := make([]bn254.G1Affine, 2*N-1)
	for i := 0; i < len(tauG1); i++ {
		if err := dec.Decode(&tauG1[i]); err != nil {
			return err
		}
	}

	// Calculate Z
	n := int(header2.Domain)
	Z := make([]bn254.G1Affine, n)
	for i := 0; i < n-1; i++ {
		Z[i].Sub(&tauG1[i+n], &tauG1[i])
	}
	common.BitReverseG1(Z)
	Z = Z[:n-1]
	// Write Z
	for i := 0; i < len(Z); i++ {
		if err := enc.Encode(&Z[i]); err != nil {
			return err
		}
	}
	return nil
}

func accumulateG1(r1cs *cs_bn254.R1CS, res *bn254.G1Affine, t constraint.Term, value *bn254.G1Affine) {
	cID := t.CoeffID()
	switch cID {
	case constraint.CoeffIdZero:
		return
	case constraint.CoeffIdOne:
		res.Add(res, value)
	case constraint.CoeffIdMinusOne:
		res.Sub(res, value)
	case constraint.CoeffIdTwo:
		res.Add(res, value).Add(res, value)
	default:
		var tmp bn254.G1Affine
		var vBi big.Int
		r1cs.Coefficients[cID].BigInt(&vBi)
		tmp.ScalarMultiplication(value, &vBi)
		res.Add(res, &tmp)
	}
}

func accumulateG2(r1cs *cs_bn254.R1CS, res *bn254.G2Affine, t constraint.Term, value *bn254.G2Affine) {
	cID := t.CoeffID()
	switch cID {
	case constraint.CoeffIdZero:
		return
	case constraint.CoeffIdOne:
		res.Add(res, value)
	case constraint.CoeffIdMinusOne:
		res.Sub(res, value)
	case constraint.CoeffIdTwo:
		res.Add(res, value).Add(res, value)
	default:
		var tmp bn254.G2Affine
		var vBi big.Int
		r1cs.Coefficients[cID].BigInt(&vBi)
		tmp.ScalarMultiplication(value, &vBi)
		res.Add(res, &tmp)
	}
}

func scale(dec *bn254.Decoder, enc *bn254.Encoder, N int, delta *big.Int) error {
	// Allocate batch with smallest of (N, batchSize)
	const batchSize = 1048576 // 2^20
	var initialSize = int(math.Min(float64(N), float64(batchSize)))
	buff := make([]bn254.G1Affine, initialSize)

	remaining := N
	for remaining > 0 {
		// Read batch
		readCount := int(math.Min(float64(remaining), float64(batchSize)))
		fmt.Println("Iterations ", int(remaining/readCount))
		for i := 0; i < readCount; i++ {
			if err := dec.Decode(&buff[i]); err != nil {
				return err
			}
		}

		// Process the batch
		common.Parallelize(readCount, func(start, end int) {
			for i := start; i < end; i++ {
				buff[i].ScalarMultiplication(&buff[i], delta)
			}
		})

		// Write batch
		for i := 0; i < readCount; i++ {
			if err := enc.Encode(&buff[i]); err != nil {
				return err
			}
		}

		// Update remaining
		remaining -= readCount
	}

	return nil
}

func verifyContribution(c *Contribution, prevDelta bn254.G1Affine, prevHash []byte) error {
	// Compute SP for δ
	deltaSP := common.GenSP(c.PublicKey.S, c.PublicKey.SX, prevHash, 1)

	// Check for knowledge of δ
	if !common.SameRatio(c.PublicKey.S, c.PublicKey.SX, c.PublicKey.SPX, deltaSP) {
		return errors.New("couldn't verify knowledge of Delta")
	}

	// Check for valid update δ using previous parameters
	if !common.SameRatio(c.Delta, prevDelta, deltaSP, c.PublicKey.SPX) {
		return errors.New("couldn't verify that [δ]₁ is based on previous contribution")
	}
	// Verify contribution hash
	b := computeHash(c)
	if !bytes.Equal(c.Hash, b) {
		return fmt.Errorf("contribution hash is invalid")
	}

	return nil
}
