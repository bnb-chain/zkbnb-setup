package setup

import (
	"bufio"
	"fmt"
	"math"
	"os"

	"github.com/consensys/gnark-crypto/ecc/bn254"
)

func InitializePhaseOne(power byte) error {
	_, _, g1, g2 := bn254.Generators()
	// output file
	file, err := os.Create("output.ph1")
	if err != nil {
		return err
	}
	defer file.Close()

	// Use buffered IO to write parameters efficiently
	// buffer up to 256MB in memory
	buffSize := len(g1.RawBytes()) * int(math.Pow(2, 23))
	writer := bufio.NewWriterSize(file, buffSize)
	defer writer.Flush()

	// BN254 encoder using compressed representation of points to save storage space
	enc := bn254.NewEncoder(writer)

	N := int(math.Pow(2, float64(power)))
	fmt.Printf("Power %d supports up to %d constraints\n", power, N)

	// 1. Write the power <1byte>
	writer.WriteByte(power)

	// 2. Write nContributions = 0 <2bytes>
	writer.WriteByte(0)
	writer.WriteByte(0)

	// 2. Write [τ⁰]₁, [τ¹]₁, [τ²]₁, …, [τ²ᴺ⁻²]₁
	fmt.Println("1. Writing TauG1")
	for i:=0; i< 2*N-1; i++ {
		enc.Encode(&g1)
	}

	// 3. Write α[τ⁰]₁, α[τ¹]₁, α[τ²]₁, …, α[τᴺ⁻¹]₁
	fmt.Println("2. Writing AlphaTauG1")
	for i:=0; i< N; i++ {
		enc.Encode(&g1)
	}

	// 4. Write β[τ⁰]₁, β[τ¹]₁, β[τ²]₁, …, β[τᴺ⁻¹]₁
	fmt.Println("3. Writing BetaTauG1")
	for i:=0; i< N; i++ {
		enc.Encode(&g1)
	}

	// 5. Write {[τ⁰]₂, [τ¹]₂, [τ²]₂, …, [τᴺ⁻¹]₂}
	fmt.Println("4. Writing TauG2")
	for i:=0; i< N; i++ {
		enc.Encode(&g2)
	}

	// 6. Write [β]₂
	fmt.Println("4. Writing BetaG2")
	enc.Encode(&g2)

	fmt.Println("Initialization has been completed successfully")
	return nil
}