package phase1

import (
	"bufio"
	"fmt"
	"math"
	"os"

	"github.com/consensys/gnark-crypto/ecc/bn254"
)

func Initialize(power byte, filePath string) error {
	_, _, g1, g2 := bn254.Generators()
	file, err := os.Create(filePath)
	if err != nil {
		return err
	}
	defer file.Close()

	// Use buffered IO to write parameters efficiently
	// buffer up to 2^16 in memory
	buffSize := len(g1.RawBytes()) * int(math.Pow(2, 16))
	writer := bufio.NewWriterSize(file, buffSize)

	// 1. Write the power
	writer.WriteByte(power)

	n := int(math.Pow(2, float64(power)))
	// 2. Write {[τ⁰]₁, [τ¹]₁, [τ²]₁, …, [τ²ⁿ⁻²]₁}

	fmt.Println("Writing tauG1...")
	for i := 0; i < 2*n-1; i++ {
		writer.Write(g1.Marshal())
	}

	// 3. Write {[τ⁰]₂, [τ¹]₂, [τ²]₂, …, [τⁿ⁻¹]₂}
	fmt.Println("Writing tauG2...")
	for i := 0; i < 2*n; i++ {
		writer.Write(g2.Marshal())
	}

	// 4. Write {α[τ⁰]₁, α[τ¹]₁, α[τ²]₁, …, α[τⁿ⁻¹]₁}
	fmt.Println("Writing alphatauG1...")
	for i := 0; i < 2*n; i++ {
		writer.Write(g1.Marshal())
	}

	// 5. Write {β[τ⁰]₁, β[τ¹]₁, β[τ²]₁, …, β[τⁿ⁻¹]₁}
	fmt.Println("Writing betatauG1...")
	for i := 0; i < 2*n; i++ {
		writer.Write(g1.Marshal())
	}

	// 6. {[β]₂}
	fmt.Println("Writing betatauG2")
	writer.Write(g2.Marshal())

	fmt.Println("Initialization has been completed successfully")
	return nil
}