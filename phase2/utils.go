package phase2

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"math"
	"math/big"
	"os"

	"github.com/bnbchain/zkbnb-setup/common"
	"github.com/bnbchain/zkbnb-setup/phase1"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/fft"
	"github.com/consensys/gnark/constraint"
	cs_bn254 "github.com/consensys/gnark/constraint/bn254"
)

func processHeader(r1csPath string, phase1File, phase2File *os.File) (*phase1.Header, *Header, error) {
	fmt.Println("Processing the headers ...")

	var header2 Header
	var header1 phase1.Header

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

	// Read the #Constraints
	r1csFile, err := os.Open(r1csPath)
	if err != nil {
		return nil, nil, err
	}
	defer r1csFile.Close()
	var r1cs cs_bn254.R1CS
	if _, err := r1cs.ReadFrom(r1csFile); err != nil {
		return nil, nil, err
	}
	header2.Constraints = uint32(r1cs.GetNbConstraints())

	// Check if phase 1 power can support the current #Constraints
	if err := header1.ReadFrom(phase1File); err != nil {
		return nil, nil, err
	}
	N := int(math.Pow(2, float64(header1.Power)))
	if N < r1cs.GetNbConstraints() {
		return nil, nil, fmt.Errorf("phase 1 parameters can support up to %d, but the circuit #Constraints are %d", N, header2.Constraints)
	}
	// Initialize Domain, #Witness and #Public
	header2.Domain = uint32(nextPowerofTwo(r1cs.GetNbConstraints()))
	header2.Witness = uint32(r1cs.GetNbInternalVariables() + r1cs.GetNbSecretVariables())
	header2.Public = uint32(r1cs.GetNbPublicVariables())

	// Write header of phase 2
	if err := header2.writeTo(phase2File); err != nil {
		return nil, nil, err
	}
	fmt.Printf("Circuit Info, nConstraints:=%d, nInternal:=%d, nPublic:=%d\n", header2.Constraints, header2.Witness, header2.Public)
	return &header1, &header2, nil
}

func processLagrange(header1 *phase1.Header, header2 *Header, phase1File, phase2File *os.File) error {
	fmt.Println("Converting to Lagrange basis ...")
	domain := fft.NewDomain(uint64(header2.Domain))
	N := int(math.Pow(2, float64(header1.Power)))

	lagFile, err := os.Create("srs.lag")
	if err != nil {
		return err
	}
	defer lagFile.Close()

	// TauG1
	fmt.Println("Converting TauG1")
	pos := int64(3)
	if err := lagrangeG1(phase1File, lagFile, pos, domain); err != nil {
		return err
	}
	// AlphaTauG1
	fmt.Println("Converting AlphaTauG1")
	pos += 64 * (2*int64(N) - 1)
	if err := lagrangeG1(phase1File, lagFile, pos, domain); err != nil {
		return err
	}

	// BetaTauG1
	fmt.Println("Converting BetaTauG1")
	pos += 64 * int64(N)
	if err := lagrangeG1(phase1File, lagFile, pos, domain); err != nil {
		return err
	}

	// TauG2
	fmt.Println("Converting TauG2")
	pos += 64 * int64(N)
	if err := lagrangeG2(phase1File, lagFile, pos, domain); err != nil {
		return err
	}

	return nil
}

func processEvaluations(header1 *phase1.Header, header2 *Header, r1csPath string, phase1File *os.File) error {
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

	// Read R1CS File
	r1csFile, err := os.Open(r1csPath)
	if err != nil {
		return err
	}
	defer r1csFile.Close()
	var r1cs cs_bn254.R1CS
	if _, err := r1cs.ReadFrom(r1csFile); err != nil {
		return err
	}

	// Deserialize Lagrange SRS TauG1
	dec := bn254.NewDecoder(lagFile)
	if err := dec.Decode(&tauG1); err != nil {
		return err
	}

	// Accumlate {[A]₁}
	buff := make([]bn254.G1Affine, nWires)
	for i, c := range r1cs.Constraints {
		for _, t := range c.L {
			accumulateG1(&r1cs, &buff[t.WireID()], t, &tauG1[i])
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
			accumulateG1(&r1cs, &buff[t.WireID()], t, &tauG1[i])
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
	for i, c := range r1cs.Constraints {
		for _, t := range c.R {
			accumulateG2(&r1cs, &buff2[t.WireID()], t, &tauG2[i])
		}
	}
	// Serialize {[B]₂}
	if err := enc.Encode(buff2); err != nil {
		return err
	}

	return nil
}

func processDeltaAndZ(header1 *phase1.Header, header2 *Header, phase1File, phase2File *os.File) error {
	fmt.Println("Processing Delta and Z")
	reader := bufio.NewReader(phase1File)
	writer := bufio.NewWriter(phase2File)
	defer writer.Flush()
	dec := bn254.NewDecoder(reader)
	enc := bn254.NewEncoder(writer, bn254.RawEncoding())

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
	if _, err := phase1File.Seek(pos, io.SeekStart); err != nil {
		return err
	}
	reader.Reset(phase1File)

	n := int(header2.Domain)
	tauG1 := make([]bn254.G1Affine, 2*n-1)
	for i := 0; i < len(tauG1); i++ {
		if err := dec.Decode(&tauG1[i]); err != nil {
			return err
		}
	}

	// Calculate Z
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

func processL(header1 *phase1.Header, header2 *Header, r1csPath string, phase2File *os.File) error {
	fmt.Println("Processing L")
	lagFile, err := os.Open("srs.lag")
	if err != nil {
		return err
	}
	defer lagFile.Close()

	// Read R1CS File
	r1csFile, err := os.Open(r1csPath)
	if err != nil {
		return err
	}
	defer r1csFile.Close()
	var r1cs cs_bn254.R1CS
	if _, err := r1cs.ReadFrom(r1csFile); err != nil {
		return err
	}

	nWires := header2.Witness + header2.Public
	var buffSRS []bn254.G1Affine
	reader := bufio.NewReader(lagFile)
	writer := bufio.NewWriter(phase2File)
	defer writer.Flush()
	dec := bn254.NewDecoder(reader)
	enc := bn254.NewEncoder(writer, bn254.RawEncoding())

	// L =  Output(TauG1) + Right(AlphaTauG1) + Left(BetaTauG1)
	L := make([]bn254.G1Affine, nWires)

	// Deserialize Lagrange SRS TauG1
	if err := dec.Decode(&buffSRS); err != nil {
		return err
	}
	for i, c := range r1cs.Constraints {
		// Output(Tau)
		for _, t := range c.O {
			accumulateG1(&r1cs, &L[t.WireID()], t, &buffSRS[i])
		}
	}

	// Deserialize Lagrange SRS AlphaTauG1
	if err := dec.Decode(&buffSRS); err != nil {
		return err
	}
	for i, c := range r1cs.Constraints {
		// Right(AlphaTauG1)
		for _, t := range c.R {
			accumulateG1(&r1cs, &L[t.WireID()], t, &buffSRS[i])
		}
	}

	// Deserialize Lagrange SRS BetaTauG1
	if err := dec.Decode(&buffSRS); err != nil {
		return err
	}
	for i, c := range r1cs.Constraints {
		// Left(BetaTauG1)
		for _, t := range c.L {
			accumulateG1(&r1cs, &L[t.WireID()], t, &buffSRS[i])
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
func verifyEquality(inputDecoder, originDecoder *bn254.Decoder, size int) error {
	var in, or bn254.G1Affine
	for i := 0; i < size; i++ {
		if err := inputDecoder.Decode(&in); err != nil {
			return err
		}
		if err := originDecoder.Decode(&or); err != nil {
			return err
		}
		if !in.Equal(&or) {
			return fmt.Errorf("inequal points detected")
		}
	}
	return nil
}

func verifyParameter(delta, g *bn254.G2Affine, inputDecoder, originDecoder *bn254.Decoder, size int, field string) error {
	// aggregate points
	if in, or, err := aggregate(inputDecoder, originDecoder, size); err != nil {
		return nil
	} else {
		if !common.SameRatio(*in, *or, *delta, *g) {
			return fmt.Errorf("inconsistent update to %s", field)
		}
	}
	return nil
}

func aggregate(inputDecoder, originDecoder *bn254.Decoder, size int) (*bn254.G1Affine, *bn254.G1Affine, error) {
	var inG, orG, tmp bn254.G1Affine
	// Allocate batch with smallest of (N, batchSize)
	const batchSize = 1048576 // 2^20
	var initialSize = int(math.Min(float64(size), float64(batchSize)))
	buff := make([]bn254.G1Affine, initialSize)
	r := make([]fr.Element, size)

	remaining := size
	for remaining > 0 {

		// generate randomness
		common.Parallelize(len(r), func(start, end int) {
			for i := start; i < end; i++ {
				r[i].SetRandom()
			}
		})

		// Read from input
		readCount := int(math.Min(float64(remaining), float64(batchSize)))
		fmt.Println("Iterations ", int(remaining/readCount))
		for i := 0; i < readCount; i++ {
			if err := inputDecoder.Decode(&buff[i]); err != nil {
				return nil, nil, err
			}
		}

		// Aggregate input
		if _, err := tmp.MultiExp(buff[:readCount], r[:readCount], ecc.MultiExpConfig{}); err != nil {
			return nil, nil, err
		}
		inG.Add(&inG, &tmp)

		// Read from origin
		for i := 0; i < readCount; i++ {
			if err := originDecoder.Decode(&buff[i]); err != nil {
				return nil, nil, err
			}
		}

		// Aggregate origin
		if _, err := tmp.MultiExp(buff[:readCount], r[:readCount], ecc.MultiExpConfig{}); err != nil {
			return nil, nil, err
		}
		orG.Add(&orG, &tmp)

		// Update remaining
		remaining -= readCount
	}

	return &inG, &orG, nil
}
