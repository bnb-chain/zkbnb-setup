package keys

import (
	"bufio"
	"fmt"
	"io"
	"os"

	"github.com/bnbchain/zkbnb-setup/phase2"
	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/fft"
)

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

func extractPK(phase2Path string) error {
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
	ph2Reader := bufio.NewReader(phase2File)
	evalsReader := bufio.NewReader(evalsFile)

	var header phase2.Header
	if _, err := header.ReadFrom(ph2Reader); err != nil {
		return err
	}

	decPh2 := bn254.NewDecoder(ph2Reader)
	decEvals := bn254.NewDecoder(evalsReader)

	pkFile, err := os.Create("pk")
	if err != nil {
		return err
	}
	defer pkFile.Close()
	pkWriter := bufio.NewWriter(pkFile)
	defer pkWriter.Flush()
	encPk := bn254.NewEncoder((pkWriter))

	var alphaG1, betaG1, deltaG1 bn254.G1Affine
	var betaG2, deltaG2 bn254.G2Affine

	// 0. Write domain
	domain := fft.NewDomain(uint64(header.Domain))
	domain.WriteTo(pkWriter)

	// 1. Read/Write [α]₁
	if err := decEvals.Decode(&alphaG1); err != nil {
		return err
	}
	if err := encPk.Encode(&alphaG1); err != nil {
		return err
	}

	// 2. Read/Write [β]₁
	if err := decEvals.Decode(&betaG1); err != nil {
		return err
	}
	if err := encPk.Encode(&betaG1); err != nil {
		return err
	}

	// 3. Read/Write [δ]₁
	if err := decPh2.Decode(&deltaG1); err != nil {
		return err
	}
	if err := encPk.Encode(&deltaG1); err != nil {
		return err
	}

	// Read [β]₂
	if err := decEvals.Decode(&betaG2); err != nil {
		return err
	}
	// Read [δ]₂
	if err := decPh2.Decode(&deltaG2); err != nil {
		return err
	}

	// 4. Read, Filter, Write A
	var buffG1 []bn254.G1Affine
	if err := decEvals.Decode(&buffG1); err != nil {
		return err
	}
	buffG1, infinityA, nbInfinityA := filterInfinityG1(buffG1)
	if err := encPk.Encode(buffG1); err != nil {
		return err
	}

	// 5. Read, Filter, Write B
	if err := decEvals.Decode(&buffG1); err != nil {
		return err
	}
	buffG1, infinityB, nbInfinityB := filterInfinityG1(buffG1)
	if err := encPk.Encode(buffG1); err != nil {
		return err
	}

	// 6. Read/Write Z
	buffG1 = make([]bn254.G1Affine, int(header.Domain)-1)
	for i := 0; i < int(header.Domain)-1; i++ {
		if err := decPh2.Decode(&buffG1[i]); err != nil {
			return err
		}
	}
	if err := encPk.Encode(buffG1); err != nil {
		return err
	}

	// 7. Read/Write K (ie. private part of L)
	pos := int64((header.Public+header.Domain-1)*32 + 96 + 18)
	if _, err := phase2File.Seek(pos, io.SeekStart); err != nil {
		return err
	}
	ph2Reader.Reset(phase2File)
	buffG1 = make([]bn254.G1Affine, int(header.Witness))
	for i := 0; i < int(header.Witness); i++ {
		if err := decPh2.Decode(&buffG1[i]); err != nil {
			return err
		}
	}
	if err := encPk.Encode(buffG1); err != nil {
		return err
	}

	// 8. Write [β]₂
	if err := encPk.Encode(&betaG2); err != nil {
		return err
	}

	// 9. Write [δ]₂
	if err := encPk.Encode(&deltaG2); err != nil {
		return err
	}

	// 10. Read, Filter, Write B₂
	var buffG2 []bn254.G2Affine
	if err := decEvals.Decode(&buffG2); err != nil {
		return err
	}
	buffG2, _, _ = filterInfinityG2(buffG2)
	if err := encPk.Encode(buffG2); err != nil {
		return err
	}
	buffG2 = nil

	// 11. Write nbWires
	nbWires := uint64(header.Public + header.Witness)
	if err := encPk.Encode(&nbWires); err != nil {
		return err
	}

	// 12. Write nbInfinityA
	if err := encPk.Encode(&nbInfinityA); err != nil {
		return err
	}

	// 13. Write nbInfinityB
	if err := encPk.Encode(&nbInfinityB); err != nil {
		return err
	}

	// 14. Write infinityA
	if err := encPk.Encode(&infinityA); err != nil {
		return err
	}

	// 15. Write infinityB
	if err := encPk.Encode(&infinityB); err != nil {
		return err
	}

	return nil
}

func extractVK(phase2Path string) error {
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
	ph2Reader := bufio.NewReader(phase2File)
	evalsReader := bufio.NewReader(evalsFile)

	var header phase2.Header
	if _, err := header.ReadFrom(ph2Reader); err != nil {
		return err
	}

	decPh2 := bn254.NewDecoder(ph2Reader)
	decEvals := bn254.NewDecoder(evalsReader)

	vkFile, err := os.Create("vk")
	if err != nil {
		return err
	}
	defer vkFile.Close()
	vkWriter := bufio.NewWriter(vkFile)
	defer vkWriter.Flush()
	encVk := bn254.NewEncoder((vkWriter))

	var alphaG1, betaG1, deltaG1 bn254.G1Affine
	var betaG2, deltaG2 bn254.G2Affine

	// 1. Read/Write [α]₁
	if err := decEvals.Decode(&alphaG1); err != nil {
		return err
	}
	if err := encVk.Encode(&alphaG1); err != nil {
		return err
	}

	// 2. Read/Write [β]₁
	if err := decEvals.Decode(&betaG1); err != nil {
		return err
	}
	if err := encVk.Encode(&betaG1); err != nil {
		return err
	}

	// 3. Read/write [β]₂
	if err := decEvals.Decode(&betaG2); err != nil {
		return err
	}
	if err := encVk.Encode(&betaG2); err != nil {
		return err
	}

	// 4. Read/Write [γ]₂
	_, _, _, gammaG2 := bn254.Generators()
	if err := encVk.Encode(&gammaG2); err != nil {
		return err
	}

	// 5. Read/Write [δ]₁
	if err := decPh2.Decode(&deltaG1); err != nil {
		return err
	}
	if err := encVk.Encode(&deltaG1); err != nil {
		return err
	}

	// 6. Read/Write [δ]₂
	if err := decPh2.Decode(&deltaG2); err != nil {
		return err
	}
	if err := encVk.Encode(&deltaG2); err != nil {
		return err
	}

	// 7. Read/Write K
	pos := int64((header.Domain-1)*32 + 96 + 18)
	if _, err := phase2File.Seek(pos, io.SeekStart); err != nil {
		return err
	}
	ph2Reader.Reset(phase2File)

	buffG1 := make([]bn254.G1Affine, header.Public)
	for i := 0; i < len(buffG1); i++ {
		if err := decPh2.Decode(&buffG1[i]); err != nil {
			return err
		}
	}
	if err := encVk.Encode(buffG1); err != nil {
		return err
	}

	return nil
}

func ExtractKeys(phase2Path string) error {
	fmt.Println("Extracting proving key")
	if err := extractPK(phase2Path); err != nil {
		return err
	}
	fmt.Println("Extracting verifying key")
	if err := extractVK(phase2Path); err != nil {
		return err
	}
	fmt.Println("Keys have been extracted successfully")
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
