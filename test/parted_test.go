package test

import (
	"bufio"
	"encoding/gob"
	"fmt"
	bn254r1cs "github.com/consensys/gnark/constraint/bn254"
	"github.com/consensys/gnark/std/hash/mimc"
	"os"
	"testing"

	"github.com/bnbchain/zkbnb-setup/keys"
	"github.com/bnbchain/zkbnb-setup/phase1"
	"github.com/bnbchain/zkbnb-setup/phase2"
	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
)

// Circuit defines a pre-image knowledge proof
// mimc(secret preImage) = public hash
const (
	Cnt = 6
)

type BigCircuit struct {
	// struct tag on a variable is optional
	// default uses variable name and secret visibility.
	PreImage frontend.Variable
	Hash     frontend.Variable `gnark:",public"`
}

// Define declares the circuit's constraints
// Hash = mimc(PreImage)
func (circuit *BigCircuit) Define(api frontend.API) error {
	cnt := 1 << Cnt

	for i := 0; i < cnt; i++ {
		// hash function
		mimc, _ := mimc.NewMiMC(api)

		// specify constraints
		// mimc(preImage) == hash
		mimc.Write(circuit.PreImage)
		api.AssertIsEqual(circuit.Hash, mimc.Sum())
	}

	return nil
}

func TestSetupFromPartedR1CS(t *testing.T) {

	// Compile the circuit
	var myCircuit BigCircuit
	ccs, err := frontend.Compile(bn254.ID.ScalarField(), r1cs.NewBuilder, &myCircuit)
	if err != nil {
		t.Error(err)
	}
	nbCons := ccs.GetNbConstraints()
	batchSize := 10000

	SplitDumpR1CSBinary(ccs.(*bn254r1cs.R1CS), "Foo", 10000)

	var power byte = 9 + Cnt

	// Initialize to Phase 1
	if err := phase1.Initialize(power, "0.ph1"); err != nil {
		t.Error(err)
	}

	// Contribute to Phase 1
	if err := phase1.Contribute("0.ph1", "1.ph1"); err != nil {
		t.Error(err)
	}
	if err := phase1.Contribute("1.ph1", "2.ph1"); err != nil {
		t.Error(err)
	}
	if err := phase1.Contribute("2.ph1", "3.ph1"); err != nil {
		t.Error(err)
	}
	if err := phase1.Contribute("3.ph1", "4.ph1"); err != nil {
		t.Error(err)
	}

	// Verify Phase 1 contributions
	if err := phase1.Verify("4.ph1"); err != nil {
		t.Error(err)
	}

	// Phase 2 initialization
	if err := phase2.InitializeFromPartedR1CS("4.ph1", "Foo", "0.ph2", nbCons, batchSize); err != nil {
		t.Error(err)
	}

	// Contribute to Phase 2
	if err := phase2.Contribute("0.ph2", "1.ph2"); err != nil {
		t.Error(err)
	}

	// if err := phase2.Contribute("1.ph2", "2.ph2"); err != nil {
	// 	t.Error(err)
	// }

	// if err := phase2.Contribute("2.ph2", "3.ph2"); err != nil {
	// 	t.Error(err)
	// }

	// Verify Phase 2 contributions
	if err := phase2.Verify("1.ph2", "0.ph2"); err != nil {
		t.Error(err)
	}

	if err := keys.ExtractKeys("1.ph2"); err != nil {
		t.Error(err)
	}
}

func SplitDumpR1CSBinary(ccs *bn254r1cs.R1CS, session string, batchSize int) error {
	// E part
	{
		ccs2 := &bn254r1cs.R1CS{}
		ccs2.CoeffTable = ccs.CoeffTable
		ccs2.R1CSCore.System = ccs.R1CSCore.System

		name := fmt.Sprintf("%s.r1cs.E.save", session)
		csFile, err := os.Create(name)
		if err != nil {
			return err
		}
		// cnt, err := ccs2.WriteTo(csFile)
		// fmt.Println("written ", cnt, name)
		ccs2.WriteTo(csFile)
	}

	N := len(ccs.R1CSCore.Constraints)
	for i := 0; i < N; {
		// dump R1C[i, min(i+batchSize, end)]
		ccs2 := &bn254r1cs.R1CS{}
		iNew := i + batchSize
		if iNew > N {
			iNew = N
		}
		ccs2.R1CSCore.Constraints = ccs.R1CSCore.Constraints[i:iNew]
		name := fmt.Sprintf("%s.r1cs.Cons.%d.%d.save", session, i, iNew)
		csFile, err := os.Create(name)
		if err != nil {
			return err
		}
		// cnt, err := ccs2.WriteTo(csFile)
		// fmt.Println("written ", cnt, name)
		writer := bufio.NewWriter(csFile)
		enc := gob.NewEncoder(writer)
		err = enc.Encode(ccs2)
		if err != nil {
			panic(err)
		}
		//ccs2.WriteTo(csFile)

		i = iNew
	}

	return nil
}