package setup

import (
	"bufio"
	"bytes"
	"errors"
	"runtime"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
)

func verifyPhase1Contribution(current, prev Phase1Contribution) error {
	// Compute SP for τ, α, β
	tauSP := genSP(current.PublicKeys.Tau.S, current.PublicKeys.Tau.SX, prev.Hash[:], 1)
	alphaSP := genSP(current.PublicKeys.Alpha.S, current.PublicKeys.Alpha.SX, prev.Hash[:], 2)
	betaSP := genSP(current.PublicKeys.Beta.S, current.PublicKeys.Beta.SX, prev.Hash[:], 3)

	// Check for knowledge of toxic parameters
	if !sameRatio(current.PublicKeys.Tau.S, current.PublicKeys.Tau.SX, current.PublicKeys.Tau.SPX, tauSP) {
		return errors.New("couldn't verify public key of τ")
	}
	if !sameRatio(current.PublicKeys.Alpha.S, current.PublicKeys.Alpha.SX, current.PublicKeys.Alpha.SPX, alphaSP) {
		return errors.New("couldn't verify public key of α")
	}
	if !sameRatio(current.PublicKeys.Beta.S, current.PublicKeys.Beta.SX, current.PublicKeys.Beta.SPX, betaSP) {
		return errors.New("couldn't verify public key of β")
	}

	// Check for valid updates using previous parameters
	if !sameRatio(current.G1.Tau, prev.G1.Tau, tauSP, current.PublicKeys.Tau.SPX) {
		return errors.New("couldn't verify that [τ]₁ is based on previous contribution")
	}
	if !sameRatio(current.G1.AlphaTau, prev.G1.AlphaTau, alphaSP, current.PublicKeys.Alpha.SPX) {
		return errors.New("couldn't verify that [α]₁ is based on previous contribution")
	}
	if !sameRatio(current.G1.BetaTau, prev.G1.BetaTau, betaSP, current.PublicKeys.Beta.SPX) {
		return errors.New("couldn't verify that [β]₁ is based on previous contribution")
	}
	if !sameRatio(current.PublicKeys.Tau.S, current.PublicKeys.Tau.SX, current.G2.Tau, prev.G2.Tau) {
		return errors.New("couldn't verify that [τ]₂ is based on previous contribution")
	}
	if !sameRatio(current.PublicKeys.Beta.S, current.PublicKeys.Beta.SX, current.G2.Beta, prev.G2.Beta) {
		return errors.New("couldn't verify that [β]₂ is based on previous contribution")
	}

	// Check hash of the contribution
	h := computeHash(&current)
	if !bytes.Equal(current.Hash, h) {
		return errors.New("couldn't verify hash of contribution")
	}

	return nil
}
func verifyConsistentPowersG1(reader *bufio.Reader, len int, tau bn254.G2Affine) error {
	_, _, _, g2 := bn254.Generators()
	nc := runtime.NumCPU()
	dec := bn254.NewDecoder(reader)
	A := make([]bn254.G1Affine, len)
	for i := 0; i < len; i++ {
		if err := dec.Decode(&A[i]); err != nil {
			return err
		}
	}

	r := make([]fr.Element, len-1)
	for i := 0; i < len-1; i++ {
		r[i].SetRandom()
	}
	var L1, L2 bn254.G1Affine
	if _, err := L1.MultiExp(A[:len-1], r, ecc.MultiExpConfig{NbTasks: nc / 2}); err != nil {
		return err
	}
	if _, err := L2.MultiExp(A[1:], r, ecc.MultiExpConfig{NbTasks: nc / 2}); err != nil {
		return err
	}
	if !sameRatio(L1, L2, tau, g2) {
		return errors.New("failed pairing check")
	} else {
		return nil
	}
}

func verifyConsistentPowersG2(reader *bufio.Reader, len int, tau bn254.G1Affine) error {
	_, _, g1, _ := bn254.Generators()
	nc := runtime.NumCPU()
	dec := bn254.NewDecoder(reader)
	A := make([]bn254.G2Affine, len)
	for i := 0; i < len; i++ {
		if err := dec.Decode(&A[i]); err != nil {
			return err
		}
	}

	r := make([]fr.Element, len-1)
	for i := 0; i < len-1; i++ {
		r[i].SetRandom()
	}
	var L1, L2 bn254.G2Affine
	if _, err := L1.MultiExp(A[:len-1], r, ecc.MultiExpConfig{NbTasks: nc / 2}); err != nil {
		return err
	}
	if _, err := L2.MultiExp(A[1:], r, ecc.MultiExpConfig{NbTasks: nc / 2}); err != nil {
		return err
	}
	if !sameRatio(g1, tau, L1, L2) {
		return errors.New("failed pairing check")
	} else {
		return nil
	}
}
