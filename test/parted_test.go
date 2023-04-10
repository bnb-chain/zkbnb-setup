package test

import (
	"fmt"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/std/hash/mimc"
	"testing"

	"github.com/bnbchain/zkbnb-setup/phase1"
	"github.com/bnbchain/zkbnb-setup/phase2"
	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
)

// Circuit defines a pre-image knowledge proof
// mimc(secret preImage) = public hash
const (
	Cnt = 17
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
	ccs := groth16.NewCS(ecc.BN254)
	var nbCons, nbR1C, batchSize int
	{
		var myCircuit BigCircuit
		var err error
		ccs, err = frontend.Compile(bn254.ID.ScalarField(), r1cs.NewBuilder, &myCircuit)
		if err != nil {
			t.Error(err)
		}
		fmt.Println("Before Lazify: ", ccs.GetNbR1C(), "/", ccs.GetNbConstraints())
		ccs.Lazify()
		nbCons = ccs.GetNbConstraints()
		nbR1C = ccs.GetNbR1C()
		fmt.Println("After Lazify: ", ccs.GetNbR1C(), "/", ccs.GetNbConstraints())
		batchSize = 100000

		ccs.SplitDumpBinary("Foo", batchSize)
	}

	var power byte = 9 + Cnt

	// Initialize to Phase 1
	if err := phase1.Initialize(power, "0.ph1"); err != nil {
		t.Error(err)
	}

	// Contribute to Phase 1
	if err := phase1.Contribute("0.ph1", "1.ph1"); err != nil {
		t.Error(err)
	}
	// if err := phase1.Contribute("1.ph1", "2.ph1"); err != nil {
	// 	t.Error(err)
	// }
	// if err := phase1.Contribute("2.ph1", "3.ph1"); err != nil {
	// 	t.Error(err)
	// }
	// if err := phase1.Contribute("3.ph1", "4.ph1"); err != nil {
	// 	t.Error(err)
	// }

	// Verify Phase 1 contributions
	if err := phase1.Verify("1.ph1"); err != nil {
		t.Error(err)
	}

	// Phase 2 initialization
	if err := phase2.InitializeFromPartedR1CS("1.ph1", "Foo", "0.ph2", nbCons, nbR1C, batchSize); err != nil {
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

	// if err := keys.ExtractKeys("1.ph2"); err != nil {
	// 	t.Error(err)
	// }
}
