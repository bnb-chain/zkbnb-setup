package test

import (
	"testing"

	"github.com/bnb-chain/zkbnb-setup/phase1"
)

func TestTransform(t *testing.T) {
	phase1.Transform("challenge", "transformed", 2, 2)
}
