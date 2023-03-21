package test

import (
	"os"
	"testing"

	"github.com/bnbchain/zkbnb-setup/phase1"
	"github.com/bnbchain/zkbnb-setup/phase2"
	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/hash/mimc"
)

// Circuit defines a pre-image knowledge proof
// mimc(secret preImage) = public hash
type Circuit struct {
	// struct tag on a variable is optional
	// default uses variable name and secret visibility.
	PreImage frontend.Variable
	Hash     frontend.Variable `gnark:",public"`
}

// Define declares the circuit's constraints
// Hash = mimc(PreImage)
func (circuit *Circuit) Define(api frontend.API) error {
	// hash function
	mimc, _ := mimc.NewMiMC(api)

	// specify constraints
	// mimc(preImage) == hash
	mimc.Write(circuit.PreImage)
	api.AssertIsEqual(circuit.Hash, mimc.Sum())

	return nil
}
func TestSetup(t *testing.T) {

	// Compile the circuit
	var myCircuit Circuit
	ccs, err := frontend.Compile(bn254.ID.ScalarField(), r1cs.NewBuilder, &myCircuit)
	if err != nil {
		t.Error(err)
	}
	writer, err := os.Create("circuit.r1cs")
	if err != nil {
		t.Error(err)
	}
	defer writer.Close()
	ccs.WriteTo(writer)


	var power byte = 10
	
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

	if err := phase1.Finalize("4.ph1"); err != nil {
		t.Error(err)
	}

	// Phase 2 initialization
	err = phase2.Initialize("4.ph1", "circuit.r1cs", "0.ph2")
	if err != nil {
		t.Error(err)
	}

}
