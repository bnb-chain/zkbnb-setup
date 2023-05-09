package test

import (
	"fmt"
	"os"
	"runtime"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/std/hash/mimc"
	"github.com/stretchr/testify/assert"

	"github.com/bnb-chain/zkbnb-setup/keys"
	"github.com/bnb-chain/zkbnb-setup/phase1"
	"github.com/bnb-chain/zkbnb-setup/phase2"
	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
)

// Circuit defines a pre-image knowledge proof
// mimc(secret preImage) = public hash
const (
	Cnt = 3
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
	if err := phase1.Verify("4.ph1", ""); err != nil {
		t.Error(err)
	}

	// Phase 2 initialization
	if err := phase2.InitializeFromPartedR1CS("4.ph1", "Foo", "0.ph2", nbCons, nbR1C, batchSize); err != nil {
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

	if err := keys.ExtractSplitKeys("1.ph2", "Foo"); err != nil {
		t.Error(err)
	}
}

func TestProveFromPK(t *testing.T) {
	// Compile the circuit
	var myCircuit BigCircuit
	ccs, _ := frontend.Compile(bn254.ID.ScalarField(), r1cs.NewBuilder, &myCircuit)
	ccs.Lazify()

	// Read PK and VK
	pkk := groth16.NewProvingKey(ecc.BN254)
	pkFile, _ := os.Open("pk")
	defer pkFile.Close()
	vkFile, _ := os.Open("vk")
	defer vkFile.Close()
	pkk.ReadFrom(pkFile)
	vkk := groth16.NewVerifyingKey(ecc.BN254)
	vkk.ReadFrom(vkFile)

	assignment := &BigCircuit{
		PreImage: "16130099170765464552823636852555369511329944820189892919423002775646948828469",
		Hash:     "12886436712380113721405259596386800092738845035233065858332878701083870690753",
	}
	witness, _ := frontend.NewWitness(assignment, bn254.ID.ScalarField())
	prf, err := groth16.Prove(ccs, pkk, witness)
	if err != nil {
		panic(err)
	}
	pubWitness, err := witness.Public()
	if err != nil {
		panic(err)
	}
	err = groth16.Verify(prf, vkk, pubWitness)
	if err != nil {
		panic(err)
	}
}

func TestProveFromSplitPK(t *testing.T) {
	// Compile the circuit
	nbR1C := 8
	nbCons := 2648
	session := "Foo"
	batchSize := 100000
	cs2 := groth16.NewCS(ecc.BN254)
	cs2.LoadFromSplitBinaryConcurrent(session, nbR1C, batchSize, runtime.NumCPU())
	fmt.Println("nbCons:", cs2.GetNbConstraints(), nbCons, "nbR1C:", cs2.GetNbR1C())

	vk := groth16.NewVerifyingKey(ecc.BN254)
	name := fmt.Sprintf("%s.vk.save", session)
	vkFile, err := os.Open(name)
	assert.NoError(t, err)
	_, err = vk.ReadFrom(vkFile)
	assert.NoError(t, err)

	assignment := &BigCircuit{
		PreImage: "16130099170765464552823636852555369511329944820189892919423002775646948828469",
		Hash:     "12886436712380113721405259596386800092738845035233065858332878701083870690753",
	}
	witness, _ := frontend.NewWitness(assignment, bn254.ID.ScalarField())

	pks, err := groth16.ReadSegmentProveKey(ecc.BN254, session)
	assert.NoError(t, err)

	prf, err := groth16.ProveRoll(cs2, pks[0], pks[1], witness, session)
	assert.NoError(t, err)

	pubWitness, err := witness.Public()
	assert.NoError(t, err)
	err = groth16.Verify(prf, vk, pubWitness)
	assert.NoError(t, err)
}
