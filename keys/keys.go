package keys

import (
	"bufio"
	"fmt"
	"math"
	"os"

	"github.com/bnbchain/zkbnb-setup/phase2"
	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/fft"
)

type ProvingKey struct {
	Domain fft.Domain
	// [α]₁ , [β]₁, [δ]₁, [A(t)]₁, [B(t)]₁, [Kpk(t)]₁, [Z(t)]₁
	G1 struct {
		Alpha, Beta, Delta bn254.G1Affine
		A, B, Z            []bn254.G1Affine
		K                  []bn254.G1Affine // the indexes correspond to the private wires
	}

	// [β]₂ , [δ]₂, [B(t)]₂
	G2 struct {
		Beta, Delta bn254.G2Affine
		B           []bn254.G2Affine
	}

	// if InfinityA[i] == true, the point G1.A[i] == infinity
	InfinityA, InfinityB     []bool
	NbInfinityA, NbInfinityB uint64
}

type VerifyingKey struct {
	// [α]₁, [Kvk]₁
	G1 struct {
		Alpha, Beta, Delta bn254.G1Affine
		K                  []bn254.G1Affine
	}

	// [β]₂, [δ]₂, [γ]₂,
	G2 struct {
		Beta, Delta, Gamma bn254.G2Affine
	}
}

func ExtractKeys(phase2Path string) error {
	// Phase 2 file
	phase2File, err := os.Open(phase2Path)
	if err != nil {
		return err
	}
	defer phase2File.Close()

	// Evaluations
	evalsFile, err := os.Open("evals")
	if err != nil {
		return err
	}
	defer evalsFile.Close()

	// Use buffered IO to write parameters efficiently
	buffSize := int(math.Pow(2, 20))
	ph2Reader := bufio.NewReaderSize(phase2File, buffSize)
	evalsReader := bufio.NewReaderSize(evalsFile, buffSize)

	var header phase2.Header
	if _, err := header.ReadFrom(ph2Reader); err != nil {
		return err
	}

	decPh2 := bn254.NewDecoder(ph2Reader)
	decEvals := bn254.NewDecoder(evalsReader)

	var pk ProvingKey
	pkFile, err := os.Create("pk")
	if err != nil {
		return err
	}
	defer pkFile.Close()
	pkWriter := bufio.NewWriterSize(pkFile, buffSize)
	defer pkWriter.Flush()

	var vk VerifyingKey
	vkFile, err := os.Create("vk")
	if err != nil {
		return err
	}
	defer vkFile.Close()
	vkWriter := bufio.NewWriterSize(vkFile, buffSize)
	defer vkWriter.Flush()

	// Set cardinality
	pk.Domain = *fft.NewDomain(uint64(header.Domain))

	// Read [α]₁
	if err := decEvals.Decode(&pk.G1.Alpha); err != nil {
		return err
	}
	vk.G1.Alpha.Set(&pk.G1.Alpha)

	// Read [β]₁
	if err := decEvals.Decode(&pk.G1.Beta); err != nil {
		return err
	}
	vk.G1.Beta.Set(&pk.G1.Beta)

	// Read [β]₂
	if err := decEvals.Decode(&pk.G2.Beta); err != nil {
		return err
	}
	vk.G2.Beta.Set(&pk.G2.Beta)

	// Read [A]₁
	nWires := int(header.Public + header.Witness)
	buff := make([]bn254.G1Affine, nWires)
	if err := decEvals.Decode(&buff); err != nil {
		return err
	}
	pk.G1.A, pk.InfinityA, pk.NbInfinityA = filterInfinityG1(buff)

	// Read [B]₁
	if err := decEvals.Decode(&buff); err != nil {
		return err
	}
	pk.G1.B, pk.InfinityB, pk.NbInfinityB = filterInfinityG1(buff)

	// Read [B]₂
	buff2 := make([]bn254.G2Affine, nWires)
	if err := decEvals.Decode(&buff2); err != nil {
		return err
	}
	pk.G2.B, _, _ = filterInfinityG2(buff2)

	// Read [δ]₁
	if err := decPh2.Decode(&pk.G1.Delta); err != nil {
		return err
	}
	vk.G1.Delta.Set(&pk.G1.Delta)

	// Read [δ]₂
	if err := decPh2.Decode(&pk.G2.Delta); err != nil {
		return err
	}
	vk.G2.Delta.Set(&pk.G2.Delta)

	// Set [γ]₂
	_, _, _, g2 := bn254.Generators()
	vk.G2.Gamma.Set(&g2)

	// Read [Z]₁
	pk.G1.Z = make([]bn254.G1Affine, header.Domain-1)
	for i := 0; i < len(pk.G1.Z); i++ {
		if err := decPh2.Decode(&pk.G1.Z[i]); err != nil {
			return err
		}
	}

	// Read VKK
	vk.G1.K = make([]bn254.G1Affine, header.Public)
	for i := 0; i < len(vk.G1.K); i++ {
		if err := decPh2.Decode(&vk.G1.K[i]); err != nil {
			return err
		}
	}

	// Read L
	pk.G1.K = make([]bn254.G1Affine, header.Witness)
	for i := 0; i < len(pk.G1.K); i++ {
		if err := decPh2.Decode(&pk.G1.K[i]); err != nil {
			return err
		}
	}

	if _, err := pk.WriteTo(pkWriter, false); err != nil {
		return err
	}

	if _, err := vk.WriteTo(vkWriter, false); err != nil {
		return err
	}

	fmt.Println("Keys pk and vk have been extracted successfully")
	return nil
}

func filterInfinityG1(buff []bn254.G1Affine) ([]bn254.G1Affine, []bool, uint64) {
	infinityAt := make([]bool, len(buff))
	filtered := make([]bn254.G1Affine, len(buff))
	j := 0
	for i, e := range buff {
		if e.IsInfinity() {
			infinityAt[i] = true
			continue
		}
		filtered[j] = buff[i]
		j++
	}
	return filtered[:j], infinityAt, uint64(len(buff) - j)
}

func filterInfinityG2(buff []bn254.G2Affine) ([]bn254.G2Affine, []bool, uint64) {
	infinityAt := make([]bool, len(buff))
	filtered := make([]bn254.G2Affine, len(buff))
	j := 0
	for i, e := range buff {
		if e.IsInfinity() {
			infinityAt[i] = true
			continue
		}
		filtered[j] = buff[i]
		j++
	}
	return filtered[:j], infinityAt, uint64(len(buff) - j)

}
