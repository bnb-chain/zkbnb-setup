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
func TestPhase2Initialize(t *testing.T) {
	phase1.Initialize(10, "0.ph1")
	phase1.Contribute("0.ph1", "1.ph1")

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

	// Phase 2 initialization
	err = phase2.Initialize("1.ph1", "circuit.r1cs", "0.ph2")
	if err != nil {
		t.Error(err)
	}

}
