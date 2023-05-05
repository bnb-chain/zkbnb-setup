package lagrange

import (
	"math/big"
	"math/bits"
	"runtime"

	"github.com/bnb-chain/zkbnb-setup/common"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/fft"
)

type Empty struct {
}

func butterflyG1(a *bn254.G1Jac, b *bn254.G1Jac) {
	t := *a
	a.AddAssign(b)
	t.SubAssign(b)
	*b = t
}

// KerDIF8 is a kernel that process an FFT of size 8
func kerDIF8G1(a []bn254.G1Jac, twiddles [][]fr.Element, stage int) {
	butterflyG1(&a[0], &a[4])
	butterflyG1(&a[1], &a[5])
	butterflyG1(&a[2], &a[6])
	butterflyG1(&a[3], &a[7])

	var twiddle big.Int
	twiddles[stage+0][1].BigInt(&twiddle)
	a[5].ScalarMultiplication(&a[5], &twiddle)
	twiddles[stage+0][2].BigInt(&twiddle)
	a[6].ScalarMultiplication(&a[6], &twiddle)
	twiddles[stage+0][3].BigInt(&twiddle)
	a[7].ScalarMultiplication(&a[7], &twiddle)
	butterflyG1(&a[0], &a[2])
	butterflyG1(&a[1], &a[3])
	butterflyG1(&a[4], &a[6])
	butterflyG1(&a[5], &a[7])
	twiddles[stage+1][1].BigInt(&twiddle)
	a[3].ScalarMultiplication(&a[3], &twiddle)
	twiddles[stage+1][1].BigInt(&twiddle)
	a[7].ScalarMultiplication(&a[7], &twiddle)
	butterflyG1(&a[0], &a[1])
	butterflyG1(&a[2], &a[3])
	butterflyG1(&a[4], &a[5])
	butterflyG1(&a[6], &a[7])
}

// parallelize threshold for a single butterfly op, if the fft stage is not parallelized already
const butterflyThreshold = 16

func difFFTG1(a []bn254.G1Jac, twiddles [][]fr.Element, stage, maxSplits int, chDone chan struct{}) {
	if chDone != nil {
		defer close(chDone)
	}

	n := len(a)
	if n == 1 {
		return
	} else if n == 8 {
		kerDIF8G1(a, twiddles, stage)
		return
	}
	m := n >> 1

	if (m > butterflyThreshold) && (stage < maxSplits) {
		// 1 << stage == estimated used CPUs
		numCPU := runtime.NumCPU() / (1 << (stage))
		common.Parallelize(m, func(start, end int) {
			var twiddle big.Int
			for i := start; i < end; i++ {
				butterflyG1(&a[i], &a[i+m])
				twiddles[stage][i].BigInt(&twiddle)
				a[i+m].ScalarMultiplication(&a[i+m], &twiddle)
			}
		}, numCPU)
	} else {
		// i == 0
		butterflyG1(&a[0], &a[m])
		var twiddle big.Int
		for i := 1; i < m; i++ {
			butterflyG1(&a[i], &a[i+m])
			twiddles[stage][i].BigInt(&twiddle)
			a[i+m].ScalarMultiplication(&a[i+m], &twiddle)
		}
	}

	if m == 1 {
		return
	}

	nextStage := stage + 1
	if stage < maxSplits {
		chDone := make(chan struct{}, 1)
		go difFFTG1(a[m:n], twiddles, nextStage, maxSplits, chDone)
		difFFTG1(a[0:m], twiddles, nextStage, maxSplits, nil)
		<-chDone
	} else {
		difFFTG1(a[0:m], twiddles, nextStage, maxSplits, nil)
		difFFTG1(a[m:n], twiddles, nextStage, maxSplits, nil)
	}
}

func bitReversePointsG1(a []bn254.G1Jac) {
	n := uint64(len(a))
	nn := uint64(64 - bits.TrailingZeros64(n))

	numCPU := uint64(runtime.NumCPU())
	chDone := make(chan Empty, numCPU)

	for id := 0; id < int(numCPU); id++ {
		start := n / numCPU * uint64(id)
		end := n / numCPU * uint64(id+1)
		if id == int(numCPU-1) {
			end = n
		}
		go func(start uint64, end uint64) {
			for j := start; j < end; j++ {
				irev := bits.Reverse64(j) >> nn
				if irev > j {
					a[j], a[irev] = a[irev], a[j]
				}
			}
			chDone <- Empty{}
		}(start, end)
	}
	for i := 0; i < int(numCPU); i++ {
		<-chDone
	}
}

func ConvertG1(buff []bn254.G1Affine, domain *fft.Domain) {
	numCPU := uint64(runtime.NumCPU())
	maxSplits := bits.TrailingZeros64(ecc.NextPowerOfTwo(numCPU))
	jac := make([]bn254.G1Jac, len(buff))
	for i := 0; i < len(buff); i++ {
		jac[i].FromAffine(&buff[i])
	}

	difFFTG1(jac, domain.TwiddlesInv, 0, maxSplits, nil)
	bitReversePointsG1(jac)
	var invBigint big.Int
	domain.CardinalityInv.BigInt(&invBigint)
	common.Parallelize(len(jac), func(start, end int) {
		for i := start; i < end; i++ {
			jac[i].ScalarMultiplication(&jac[i], &invBigint)
		}
	})

	common.Parallelize(len(buff), func(start, end int) {
		for i := start; i < end; i++ {
			buff[i].FromJacobian(&jac[i])
		}
	})
}
