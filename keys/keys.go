package keys

import (
	"bufio"
	"encoding/gob"
	"fmt"
	"github.com/bnbchain/zkbnb-setup/phase2"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/fft"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/pedersen"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/constraint"
	"io"
	"os"
)

type VerifyingKey struct {
	G1 struct {
		Alpha       bn254.G1Affine
		Beta, Delta bn254.G1Affine   // unused, here for compatibility purposes
		K           []bn254.G1Affine // The indexes correspond to the public wires
	}

	G2 struct {
		Beta, Delta, Gamma bn254.G2Affine
	}

	CommitmentKey  pedersen.Key
	CommitmentInfo constraint.Commitment // since the verifier doesn't input a constraint system, this needs to be provided here
}

func (vk *VerifyingKey) writeTo(w io.Writer) (int64, error) {
	n, err := vk.CommitmentKey.WriteTo(w)
	if err != nil {
		return n, err
	}
	enc := bn254.NewEncoder(w, bn254.RawEncoding())

	// [α]1,[β]1,[β]2,[γ]2,[δ]1,[δ]2
	if err := enc.Encode(&vk.G1.Alpha); err != nil {
		return n + enc.BytesWritten(), err
	}
	if err := enc.Encode(&vk.G1.Beta); err != nil {
		return n + enc.BytesWritten(), err
	}
	if err := enc.Encode(&vk.G2.Beta); err != nil {
		return n + enc.BytesWritten(), err
	}
	if err := enc.Encode(&vk.G2.Gamma); err != nil {
		return n + enc.BytesWritten(), err
	}
	if err := enc.Encode(&vk.G1.Delta); err != nil {
		return n + enc.BytesWritten(), err
	}
	if err := enc.Encode(&vk.G2.Delta); err != nil {
		return n + enc.BytesWritten(), err
	}

	// uint32(len(Kvk)),[Kvk]1
	if err := enc.Encode(vk.G1.K); err != nil {
		return n + enc.BytesWritten(), err
	}

	encGob := gob.NewEncoder(w)
	if err := encGob.Encode(vk.CommitmentInfo); err != nil {
		return n + enc.BytesWritten(), err
	}
	return n + enc.BytesWritten(), nil
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
	if err := header.Read(ph2Reader); err != nil {
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
	buffG1 = make([]bn254.G1Affine, header.Domain-1)
	for i := 0; i < header.Domain-1; i++ {
		if err := decPh2.Decode(&buffG1[i]); err != nil {
			return err
		}
	}
	if err := encPk.Encode(buffG1); err != nil {
		return err
	}

	// 7. Read/Write PKK
	buffG1 = make([]bn254.G1Affine, header.Witness)
	for i := 0; i < header.Witness; i++ {
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
	nbWires := uint64(header.Wires)
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

func extractSplitPK(phase2Path, session string) error {
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
	if err := header.Read(ph2Reader); err != nil {
		return err
	}

	decPh2 := bn254.NewDecoder(ph2Reader)
	decEvals := bn254.NewDecoder(evalsReader)

	name := fmt.Sprintf("%s.pk.E.save", session)
	pkEFile, err := os.Create(name)
	if err != nil {
		return err
	}
	defer pkEFile.Close()
	pkEWriter := bufio.NewWriter(pkEFile)
	defer pkEWriter.Flush()
	encPkE := bn254.NewEncoder(pkEWriter, bn254.RawEncoding())

	name = fmt.Sprintf("%s.pk.A.save", session)
	pkAFile, err := os.Create(name)
	if err != nil {
		return err
	}
	defer pkAFile.Close()
	pkAWriter := bufio.NewWriter(pkAFile)
	defer pkAWriter.Flush()
	encPkA := bn254.NewEncoder(pkAWriter, bn254.RawEncoding())

	name = fmt.Sprintf("%s.pk.B1.save", session)
	pkB1File, err := os.Create(name)
	if err != nil {
		return err
	}
	defer pkB1File.Close()
	pkB1Writer := bufio.NewWriter(pkB1File)
	defer pkB1Writer.Flush()
	encPkB1 := bn254.NewEncoder(pkB1Writer, bn254.RawEncoding())

	name = fmt.Sprintf("%s.pk.Z.save", session)
	pkZFile, err := os.Create(name)
	if err != nil {
		return err
	}
	defer pkZFile.Close()
	pkZWriter := bufio.NewWriter(pkZFile)
	defer pkZWriter.Flush()
	encPkZ := bn254.NewEncoder(pkZWriter, bn254.RawEncoding())

	name = fmt.Sprintf("%s.pk.K.save", session)
	pkKFile, err := os.Create(name)
	if err != nil {
		return err
	}
	defer pkKFile.Close()
	pkKWriter := bufio.NewWriter(pkKFile)
	defer pkKWriter.Flush()
	encPkK := bn254.NewEncoder(pkKWriter, bn254.RawEncoding())

	name = fmt.Sprintf("%s.pk.B2.save", session)
	pkB2File, err := os.Create(name)
	if err != nil {
		return err
	}
	defer pkB2File.Close()
	pkB2Writer := bufio.NewWriter(pkB2File)
	defer pkB2Writer.Flush()
	encPkB2 := bn254.NewEncoder(pkB2Writer, bn254.RawEncoding())

	var alphaG1, betaG1, deltaG1 bn254.G1Affine
	var betaG2, deltaG2 bn254.G2Affine

	// 0. Write domain
	// domain := fft.NewDomain(uint64(header.Domain))
	// domain.WriteTo(pkEWriter)

	// 0. Write Card
	Cardinality := uint64(header.Domain)
	if err := encPkE.Encode(Cardinality); err != nil {
		return err
	}

	// 1. Read/Write [α]₁
	if err := decEvals.Decode(&alphaG1); err != nil {
		return err
	}
	if err := encPkE.Encode(&alphaG1); err != nil {
		return err
	}

	// 2. Read/Write [β]₁
	if err := decEvals.Decode(&betaG1); err != nil {
		return err
	}
	if err := encPkE.Encode(&betaG1); err != nil {
		return err
	}

	// 3. Read/Write [δ]₁
	if err := decPh2.Decode(&deltaG1); err != nil {
		return err
	}
	if err := encPkE.Encode(&deltaG1); err != nil {
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
	if err := encPkA.Encode(buffG1); err != nil {
		return err
	}

	// 5. Read, Filter, Write B
	if err := decEvals.Decode(&buffG1); err != nil {
		return err
	}
	buffG1, infinityB, nbInfinityB := filterInfinityG1(buffG1)
	if err := encPkB1.Encode(buffG1); err != nil {
		return err
	}

	// 6. Read/Write Z
	buffG1 = make([]bn254.G1Affine, header.Domain-1)
	for i := 0; i < header.Domain-1; i++ {
		if err := decPh2.Decode(&buffG1[i]); err != nil {
			return err
		}
	}
	if err := encPkZ.Encode(buffG1); err != nil {
		return err
	}

	// 7. Read/Write PKK
	buffG1 = make([]bn254.G1Affine, header.Witness)
	for i := 0; i < header.Witness; i++ {
		if err := decPh2.Decode(&buffG1[i]); err != nil {
			return err
		}
	}
	if err := encPkK.Encode(buffG1); err != nil {
		return err
	}

	// 8. Write [β]₂
	if err := encPkE.Encode(&betaG2); err != nil {
		return err
	}

	// 9. Write [δ]₂
	if err := encPkE.Encode(&deltaG2); err != nil {
		return err
	}

	// 10. Read, Filter, Write B₂
	var buffG2 []bn254.G2Affine
	if err := decEvals.Decode(&buffG2); err != nil {
		return err
	}
	buffG2, _, _ = filterInfinityG2(buffG2)
	if err := encPkB2.Encode(buffG2); err != nil {
		return err
	}
	buffG2 = nil

	// 11. Write nbWires
	nbWires := uint64(header.Wires)
	if err := encPkE.Encode(nbWires); err != nil {
		return err
	}

	// 12. Write nbInfinityA
	if err := encPkE.Encode(&nbInfinityA); err != nil {
		return err
	}

	// 13. Write nbInfinityB
	if err := encPkE.Encode(&nbInfinityB); err != nil {
		return err
	}

	// 14. Write infinityA
	if err := encPkE.Encode(&infinityA); err != nil {
		return err
	}

	// 15. Write infinityB
	if err := encPkE.Encode(&infinityB); err != nil {
		return err
	}

	return nil
}

func extractVK(phase2Path string) error {
	vk := VerifyingKey{}
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
	if err := header.Read(ph2Reader); err != nil {
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

	// 1. Read [α]₁
	if err := decEvals.Decode(&vk.G1.Alpha); err != nil {
		return err
	}

	// 2. Read [β]₁
	if err := decEvals.Decode(&vk.G1.Beta); err != nil {
		return err
	}

	// 3. Read [β]₂
	if err := decEvals.Decode(&vk.G2.Beta); err != nil {
		return err
	}

	// 4. Set [γ]₂
	_, _, _, gammaG2 := bn254.Generators()
	vk.G2.Gamma.Set(&gammaG2)

	// 5. Read [δ]₁
	if err := decPh2.Decode(&vk.G1.Delta); err != nil {
		return err
	}

	// 6. Read [δ]₂
	if err := decPh2.Decode(&vk.G2.Delta); err != nil {
		return err
	}

	// 7. Read VKK
	pos := int64(128*(header.Wires+1) + 12)
	if _, err := evalsFile.Seek(pos, io.SeekStart); err != nil {
		return err
	}
	evalsReader.Reset(evalsFile)
	if err := decEvals.Decode(&vk.G1.K); err != nil {
		return err
	}

	// 8. TODO: Extract commitment key
	// var ckk []bn254.G1Affine
	// if err := decEvals.Decode(&ckk); err != nil {
	// 	return err
	// }
	// vk.CommitmentKey, err = pedersen.Setup(ckk)
	// if err != nil {
	// 	return err
	// }
	// if _, err := vk.writeTo(vkWriter); err != nil {
	// 	return err
	// }
	return nil
}

func extractSplitVK(phase2Path, session string) error {
	vk := VerifyingKey{}
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
	if err := header.Read(ph2Reader); err != nil {
		return err
	}

	decPh2 := bn254.NewDecoder(ph2Reader)
	decEvals := bn254.NewDecoder(evalsReader)

	name := fmt.Sprintf("%s.vk.save", session)
	vkFile, err := os.Create(name)
	if err != nil {
		return err
	}
	defer vkFile.Close()
	vkWriter := bufio.NewWriter(vkFile)
	defer vkWriter.Flush()

	// 1. Read [α]₁
	if err := decEvals.Decode(&vk.G1.Alpha); err != nil {
		return err
	}

	// 2. Read [β]₁
	if err := decEvals.Decode(&vk.G1.Beta); err != nil {
		return err
	}

	// 3. Read [β]₂
	if err := decEvals.Decode(&vk.G2.Beta); err != nil {
		return err
	}

	// 4. Set [γ]₂
	_, _, _, gammaG2 := bn254.Generators()
	vk.G2.Gamma.Set(&gammaG2)

	// 5. Read [δ]₁
	if err := decPh2.Decode(&vk.G1.Delta); err != nil {
		return err
	}

	// 6. Read [δ]₂
	if err := decPh2.Decode(&vk.G2.Delta); err != nil {
		return err
	}

	// 7. Read VKK
	pos := int64(128*(header.Wires+1) + 12)
	if _, err := evalsFile.Seek(pos, io.SeekStart); err != nil {
		return err
	}
	evalsReader.Reset(evalsFile)
	if err := decEvals.Decode(&vk.G1.K); err != nil {
		return err
	}

	// 8. Setup commitment key
	var ckk []bn254.G1Affine
	if err := decEvals.Decode(&ckk); err != nil {
		return err
	}
	vk.CommitmentKey, err = pedersen.Setup(ckk)
	if err != nil {
		return err
	}
	if _, err := vk.writeTo(vkWriter); err != nil {
		return err
	}

	// Write the commitment key so that it can be read in pk separately
	name = fmt.Sprintf("%s.pk.CommitmentKey.save", session)
	commitmentKeyFile, err := os.Create(name)
	if err != nil {
		return err
	}
	defer commitmentKeyFile.Close()
	vk.CommitmentKey.WriteTo(commitmentKeyFile)
	_, err = vk.CommitmentKey.WriteTo(commitmentKeyFile)
	if err != nil {
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

func ExtractSplitKeys(phase2Path, session string) error {
	fmt.Println("Extracting proving key")
	if err := extractSplitPK(phase2Path, session); err != nil {
		return err
	}
	fmt.Println("Extracting verifying key")
	if err := extractSplitVK(phase2Path, session); err != nil {
		return err
	}
	fmt.Println("Keys have been extracted successfully")
	return nil
}

func ExportSol(session string) error {
	filename := session + ".sol"
	fmt.Printf("Exporting %s\n", filename)
	f, _ := os.Open(session + ".vk.save")
	verifyingKey := groth16.NewVerifyingKey(ecc.BN254)
	_, err := verifyingKey.ReadFrom(f)
	if err != nil {
		panic(fmt.Errorf("read file error"))
	}
	err = f.Close()
	f, err = os.Create(filename)
	if err != nil {
		panic(err)
	}
	err = verifyingKey.ExportSolidity(f)
	if err != nil {
		panic(err)
	}
	fmt.Printf("%s has been extracted successfully\n", filename)
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
